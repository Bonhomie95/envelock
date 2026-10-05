"""Gmail parity: silent-access read-watch and onboarding backfill.

The Graph work landed first; Gmail's read state is the UNREAD label and its
history is an `after:` query, so both needed their own path. These pin that a
Gmail mailbox gets the same silent-access alert and the same warm-baseline
backfill a Graph mailbox does.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from envelock.core.enums import SourceMechanism
from envelock.security.crypto import seal

RAW = (
    b"From: Jane <jane@partner.example>\r\n"
    b"To: admin@example.com\r\n"
    b"Subject: history item\r\n"
    b"Message-ID: <hist-g@partner.example>\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"body\r\n"
)


class _GmailTransport:
    """Routes by Gmail URL shape: unread list, metadata (Message-ID), raw, list."""

    def __init__(self, *, unread: list[str], msg_ids: dict[str, str], history: list[str]) -> None:
        self._unread = unread
        self._msg_ids = msg_ids
        self._history = history

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        if "is%3Aunread" in url or "is:unread" in url:
            return {"messages": [{"id": i} for i in self._unread]}
        if "format=metadata" in url:
            gid = url.split("/messages/")[1].split("?")[0]
            mid = self._msg_ids.get(gid)
            return {"payload": {"headers": [{"name": "Message-ID", "value": mid}] if mid else []}}
        if "format=raw" in url:
            return {"raw": base64.urlsafe_b64encode(RAW).decode().rstrip("=")}
        # history / generic list
        return {"messages": [{"id": i} for i in self._history]}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return b""


async def _gmail_mailbox(session, *, armed: bool, snapshot: list[str] | None):  # noqa: ANN001
    from envelock.models import Mailbox, MailboxCredential, SensorDevice, Tenant

    tid, mid = uuid4(), uuid4()
    session.add(Tenant(id=tid, name="Gmail Co", plan="complete", payment_method_ok=True))
    await session.flush()
    session.add(
        Mailbox(
            id=mid, tenant_id=tid, address="admin@example.com", mailbox_class="protected",
            sources=[SourceMechanism.GMAIL_API.value], is_active=True, silent_access_armed=armed,
        )
    )
    await session.flush()
    if armed:
        session.add(
            SensorDevice(
                tenant_id=tid, user_id=uuid4(), mailbox_id=mid,
                prefix="p", hashed="h", client="browser", device_fingerprint="fp-123456",
            )
        )
    token = json.dumps({"access_token": "a", "refresh_token": "r", "scope": "mail"})
    sealed = seal(token.encode(), aad=str(mid).encode())
    session.add(
        MailboxCredential(
            mailbox_id=mid, tenant_id=tid, kind="oauth_token",
            ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek, key_id=sealed.key_id,
            token_expires_at=datetime.now(UTC) + timedelta(hours=1),
            imap_unseen_uids=snapshot,
        )
    )
    await session.commit()
    return tid, mid


async def test_gmail_silent_access_judges_a_read(client, monkeypatch) -> None:  # noqa: ANN001, ARG001
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential
    from envelock.platform import sensor as sensor_rules
    from envelock.workers import oauth_fetch

    seen: list[str] = []

    class _V:
        alerted = True

    async def _fake_eval(session, *, mailbox, message_ref, owned_domains, **kw):  # noqa: ANN001, ARG001
        seen.append(message_ref)
        return _V()

    monkeypatch.setattr(sensor_rules, "evaluate_read", _fake_eval)

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            _tid, mid = await _gmail_mailbox(session, armed=True, snapshot=["g1", "g2"])
    # g1 was unread last poll, now not unread (read); g2 still unread.
    transport = _GmailTransport(unread=["g2"], msg_ids={"g1": "<g1@x>"}, history=[])
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            result = await oauth_fetch._watch_reads_gmail(
                session, mailbox, cred,
                access_token="t",  # noqa: S106 — fake token
                owned=frozenset(), transport=transport,
            )
            await session.commit()

    assert seen == ["<g1@x>"], seen
    assert result == {"observed": 1, "alerted": 1}, result
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            assert set(cred.imap_unseen_uids) == {"g2"}, cred.imap_unseen_uids


async def test_gmail_backfill_analyses_history(client) -> None:  # noqa: ANN001, ARG001
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox
    from envelock.workers.oauth_fetch import backfill_oauth_mailbox

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            _tid, mid = await _gmail_mailbox(session, armed=False, snapshot=None)
    transport = _GmailTransport(unread=[], msg_ids={}, history=["h1", "h2"])
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            result = await backfill_oauth_mailbox(session, mailbox, days=90, transport=transport)

    assert result["ok"] is True and result["analysed"] == 2, result
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            assert mailbox.backfilled_at is not None
