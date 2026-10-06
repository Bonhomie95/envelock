"""Outbound wiring: C5 signature tampering + A12 reply-latency learning.

These are the two things the Sent-folder scan unlocks. C5 fires when the bank
details in the owner's own signature change; the reply-latency learner gives A12
the per-counterparty baseline it needs. Both were dead before: C5 had no event
source and median_reply_seconds was never written.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.core.enums import SourceMechanism
from envelock.db import get_sessionmaker
from envelock.db_rls import system_scope
from envelock.models import Counterparty, Finding, Mailbox, Message, Tenant

OWNED = frozenset({"cyberlex.store"})

SIG_BASE = """\
Thanks,
Dana

--
Dana Okoro, Finance
Account: GB33BUKB20201555555555
"""

SIG_CHANGED = """\
Thanks,
Dana

--
Dana Okoro, Finance
Account: GB94BARC10201530093459
"""


@pytest.fixture
async def mailbox(client):  # noqa: ANN001, ARG001 — client builds the schema
    tid, mid = uuid4(), uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(Tenant(id=tid, name="Cyberlex", plan="complete", payment_method_ok=True))
            await session.flush()
            session.add(
                Mailbox(
                    id=mid, tenant_id=tid, address="dana@cyberlex.store",
                    mailbox_class="protected", sources=[SourceMechanism.IMAP_IDLE.value],
                    is_active=True,
                )
            )
            await session.commit()
    return tid, mid


async def _watch(mid, body):  # noqa: ANN001, ANN202
    from envelock.workers.outbound import watch_signature

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mb = await session.get(Mailbox, mid)
            alerted = await watch_signature(
                session, mb, body, source=SourceMechanism.IMAP_IDLE,
                owned=OWNED, recipients=[],
            )
            await session.commit()
    return alerted


async def test_c5_fires_only_on_a_bank_detail_change(mailbox) -> None:  # noqa: ANN001
    tid, mid = mailbox

    # First sent signature ever seen: baseline, never an alert.
    assert await _watch(mid, SIG_BASE) is False

    # Same bank details again (wording could drift): still no alert.
    assert await _watch(mid, SIG_BASE) is False

    # The account in the signature changed — someone is redirecting our payments.
    assert await _watch(mid, SIG_CHANGED) is True

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            c5 = (
                await session.execute(select(Finding).where(Finding.service == "C5"))
            ).scalars().all()
            assert len(c5) == 1, f"expected exactly one C5 finding, got {len(c5)}"
            assert c5[0].tier == "critical"

    # The change is now the baseline, so the next identical sync does not re-alert.
    assert await _watch(mid, SIG_CHANGED) is False


async def test_reply_latency_is_learned_from_a_matched_thread(mailbox) -> None:  # noqa: ANN001
    """An inbound reply to a message we sent teaches the counterparty's reply
    time — the baseline A12 compares a stall against."""
    from envelock.channels.mail.parser import parse_message
    from envelock.platform.pipeline import analyse_event

    tid, mid = mailbox
    sent_at = datetime.now(UTC) - timedelta(hours=2)

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            # A message we sent two hours ago, awaiting a reply.
            session.add(
                Message(
                    id=uuid4(), tenant_id=tid, mailbox_id=mid,
                    rfc_message_id="<out-1@cyberlex.store>",
                    thread_key="<out-1@cyberlex.store>",
                    direction="outbound", sender_address="dana@cyberlex.store",
                    sent_at=sent_at, received_at=sent_at, source="imap_idle",
                )
            )
            await session.commit()

    reply = (
        "From: Vendor <ap@vendor.com>\n"
        "To: dana@cyberlex.store\n"
        "Subject: Re: the order\n"
        "Message-ID: <r1@vendor.com>\n"
        "In-Reply-To: <out-1@cyberlex.store>\n"
        "References: <out-1@cyberlex.store>\n"
        "Content-Type: text/plain\n\n"
        "Got it, thanks — all looks fine on our end.\n"
    )
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            event = parse_message(
                reply.encode(), tenant_id=tid, mailbox_id=mid,
                source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
            )
            await analyse_event(session, event, tenant_id=tid, owned_domains=OWNED)
            await session.commit()

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            cp = (
                await session.execute(
                    select(Counterparty).where(Counterparty.registrable_domain == "vendor.com")
                )
            ).scalar_one()
            # ~2h; EMA seeds on the first sample, so it is the exact gap.
            assert cp.median_reply_seconds is not None
            assert 7000 <= cp.median_reply_seconds <= 7400, cp.median_reply_seconds
