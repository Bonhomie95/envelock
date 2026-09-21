"""On-demand quarantine of an already-delivered message.

The dashboard button used to be a placeholder that always answered "not
available yet" — the pipeline threw away the IMAP UID, so nothing could name
the message to move. Now `Message.source_ref` persists the handle, and a human
decision hours after delivery still moves the mail:

* a process holding the decrypting key acts immediately
  (`quarantine_persisted_message`);
* one that cannot (API under split custody) records
  `quarantine_requested_at`, and the IMAP worker executes it on its next cycle.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from envelock.models import Message
from envelock.workers.imap_fetch import quarantine_persisted_message, sync_mailbox
from tests.test_imap_live import (
    FakeImapClient,
    _connected_mailbox,
    _factory_for,
    _phishing_raw,
)

pytestmark = pytest.mark.asyncio


async def test_source_ref_is_persisted_for_imap_mail(session) -> None:
    mailbox = await _connected_mailbox(session)
    client = FakeImapClient(messages={101: _phishing_raw("101")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    stored = (
        await session.execute(select(Message).where(Message.mailbox_id == mailbox.id))
    ).scalars().first()
    assert stored is not None
    assert stored.source_ref == "101"


async def test_persisted_message_can_be_quarantined_later(session) -> None:
    mailbox = await _connected_mailbox(session)
    client = FakeImapClient(messages={7: _phishing_raw("7")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    stored = (
        await session.execute(select(Message).where(Message.mailbox_id == mailbox.id))
    ).scalars().first()
    assert stored is not None and stored.quarantined_at is None

    # The message is still in the fake inbox (MEDIUM never auto-quarantines);
    # a human decides it should go.
    client.messages[7] = _phishing_raw("7")  # message still present server-side
    ok, why = await quarantine_persisted_message(
        session, stored, client_factory=_factory_for(client)
    )
    assert ok, why
    assert stored.quarantined_at is not None
    assert client.moved and client.moved[-1][0] == 7


async def test_requested_quarantine_runs_on_next_worker_cycle(session) -> None:
    mailbox = await _connected_mailbox(session)
    client = FakeImapClient(messages={9: _phishing_raw("9")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    stored = (
        await session.execute(select(Message).where(Message.mailbox_id == mailbox.id))
    ).scalars().first()
    assert stored is not None

    # The API (unable to decrypt under split custody) records the decision.
    client.messages[9] = _phishing_raw("9")
    stored.quarantine_requested_at = datetime.now(UTC)
    await session.commit()

    # Next poll cycle executes it.
    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    assert summary["ok"] is True
    await session.refresh(stored)
    assert stored.quarantined_at is not None
    assert stored.quarantine_requested_at is None
    assert (9, "Envelock-Quarantine") in client.moved or client.moved
