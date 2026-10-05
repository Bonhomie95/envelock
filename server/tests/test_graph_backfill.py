"""Onboarding backfill (E11) over Graph.

Only IMAP mailboxes were backfilled, so a Microsoft 365 mailbox onboarded with
cold A9/A12 baselines and silently stayed that way. backfill_oauth_mailbox pulls
recent history via Graph (/me, delegated token) and runs each message through the
pipeline for learning — never quarantining old mail.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from envelock.core.enums import SourceMechanism
from envelock.security.crypto import seal

RAW = (
    b"From: Jane <jane@partner.example>\r\n"
    b"To: admin@cyberlex.store\r\n"
    b"Subject: last quarter's numbers\r\n"
    b"Message-ID: <hist-1@partner.example>\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Attached as usual. Talk soon.\r\n"
)


class _HistoryTransport:
    """One page of history: a listing, then raw MIME per message id."""

    def __init__(self, ids: list[str]) -> None:
        self._ids = ids
        self.listing_urls: list[str] = []

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        self.listing_urls.append(url)
        return {"value": [{"id": i} for i in self._ids]}  # no nextLink → one page

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return RAW


@pytest.fixture
async def graph_mailbox(client):  # noqa: ANN001, ARG001 — builds the schema
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential, Tenant

    tid, mid = uuid4(), uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(Tenant(id=tid, name="Graph Co", plan="complete", payment_method_ok=True))
            await session.flush()
            session.add(
                Mailbox(
                    id=mid, tenant_id=tid, address="admin@cyberlex.store",
                    mailbox_class="protected", sources=[SourceMechanism.GRAPH_API.value],
                    is_active=True,
                )
            )
            await session.flush()
            token = json.dumps({"access_token": "a", "refresh_token": "r", "scope": "mail"})
            sealed = seal(token.encode(), aad=str(mid).encode())
            session.add(
                MailboxCredential(
                    mailbox_id=mid, tenant_id=tid, kind="oauth_token",
                    ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek,
                    key_id=sealed.key_id,
                    token_expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
            )
            await session.commit()
    return tid, mid


async def test_graph_backfill_analyses_history_and_marks_done(graph_mailbox) -> None:
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox
    from envelock.workers.oauth_fetch import backfill_oauth_mailbox

    _tid, mid = graph_mailbox
    transport = _HistoryTransport(["h1"])
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            result = await backfill_oauth_mailbox(
                session, mailbox, days=90, transport=transport
            )

    assert result["ok"] is True, result
    assert result["analysed"] == 1, result
    # The history listing filtered by date and read /me, not /users/{label}.
    assert any("receivedDateTime%20ge" in u for u in transport.listing_urls)
    assert all("/users/" not in u for u in transport.listing_urls)

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            assert mailbox.backfilled_at is not None, "backfill did not mark the mailbox done"
