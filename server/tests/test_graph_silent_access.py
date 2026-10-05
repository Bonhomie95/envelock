"""Silent-access (C11) read-watch on a Graph mailbox.

The sensor's headline promise — a message read while none of the owner's
devices were open — ran only in the IMAP worker. This drives the Graph
read-watch directly: it must notice a message that went unread -> read since
the last poll and run the shared C11 evaluation on it, while leaving still-
unread and merely-deleted messages alone, and refusing to act when there is no
armed sensor.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.channels.mail.api_fetch import ReadState
from envelock.core.enums import SourceMechanism


class _Transport:
    def __init__(self, states: list[ReadState]) -> None:
        self._states = states

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        return {
            "value": [
                {"id": s.ref, "isRead": s.is_read, "internetMessageId": s.message_id}
                for s in self._states
            ]
        }

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return b""


@pytest.fixture
async def armed_graph_mailbox(client):  # noqa: ANN001, ARG001 — builds the schema
    from datetime import UTC, datetime

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential, SensorDevice, Tenant

    tid, mid = uuid4(), uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(Tenant(id=tid, name="Graph Co", plan="complete", payment_method_ok=True))
            await session.flush()
            session.add(
                Mailbox(
                    id=mid, tenant_id=tid, address="admin@cyberlex.store",
                    mailbox_class="protected", sources=[SourceMechanism.GRAPH_API.value],
                    is_active=True, silent_access_armed=True,
                )
            )
            await session.flush()
            # An enrolled (non-revoked) sensor — arming is meaningless without one.
            session.add(
                SensorDevice(
                    tenant_id=tid, user_id=uuid4(), mailbox_id=mid,
                    prefix="pfx", hashed="h", client="outlook",
                    device_fingerprint="fp-123456",
                )
            )
            session.add(
                MailboxCredential(
                    mailbox_id=mid, tenant_id=tid, kind="oauth_token",
                    ciphertext=b"x", wrapped_dek=b"y", key_id="k",
                    token_expires_at=datetime.now(UTC),
                    imap_unseen_uids=["m1", "m2"],  # last poll's unread snapshot
                )
            )
            await session.commit()
    return tid, mid


async def test_a_read_with_no_live_device_is_evaluated(armed_graph_mailbox, monkeypatch) -> None:  # noqa: ANN001
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential
    from envelock.platform import sensor as sensor_rules
    from envelock.workers import oauth_fetch

    seen: list[str] = []

    class _Verdict:
        alerted = True

    async def _fake_eval(session, *, mailbox, message_ref, owned_domains, **kw):  # noqa: ANN001, ARG001
        seen.append(message_ref)
        return _Verdict()

    monkeypatch.setattr(sensor_rules, "evaluate_read", _fake_eval)

    tid, mid = armed_graph_mailbox
    # m1 was unread last poll and is now READ (someone opened it); m2 still
    # unread; m3 is new unread. Only m1 is a read to judge.
    states = [
        ReadState(ref="m1", message_id="<m1@x>", is_read=True),
        ReadState(ref="m2", message_id="<m2@x>", is_read=False),
        ReadState(ref="m3", message_id="<m3@x>", is_read=False),
    ]
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            result = await oauth_fetch._watch_reads_graph(
                session, mailbox, cred,
                access_token="t",  # noqa: S106 — not a secret, a fake token
                owned=frozenset({"cyberlex.store"}),
                transport=_Transport(states),
            )
            await session.commit()

    assert seen == ["<m1@x>"], f"expected only the read message judged, got {seen}"
    assert result == {"observed": 1, "alerted": 1}, result

    # The snapshot is now the current unread set, so next poll has a fresh baseline.
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            assert set(cred.imap_unseen_uids) == {"m2", "m3"}, cred.imap_unseen_uids


async def test_no_armed_sensor_means_no_watch(armed_graph_mailbox, monkeypatch) -> None:  # noqa: ANN001
    """Disarm the mailbox: the read-watch must do nothing and clear its snapshot,
    so re-arming later starts fresh rather than replaying old reads."""
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential
    from envelock.platform import sensor as sensor_rules
    from envelock.workers import oauth_fetch

    async def _boom(*a, **k):  # noqa: ANN002, ANN003, ARG001
        raise AssertionError("evaluate_read must not run when disarmed")

    monkeypatch.setattr(sensor_rules, "evaluate_read", _boom)

    tid, mid = armed_graph_mailbox
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mid)
            mailbox.silent_access_armed = False
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            result = await oauth_fetch._watch_reads_graph(
                session, mailbox, cred,
                access_token="t",  # noqa: S106 — not a secret, a fake token
                owned=frozenset(),
                transport=_Transport([ReadState("m1", "<m1@x>", True)]),
            )
            await session.commit()
    assert result == {"observed": 0, "alerted": 0}
