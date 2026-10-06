"""A12 reply-stall sweep.

A12 cannot fire at ingest (no time has passed), so the sweep is where it lives:
an outbound payment thread whose counterparty has gone silent past their own
baseline. The sweep must raise exactly one alert, never repeat it, and stay quiet
when the counterparty has in fact replied.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.db import get_sessionmaker
from envelock.db_rls import system_scope
from envelock.models import Counterparty, Finding, Mailbox, Message, Tenant


async def _msg(session, **kw):  # noqa: ANN001, ANN202
    base = {"id": uuid4(), "source": "imap_idle"}
    base.update(kw)
    m = Message(**base)
    session.add(m)
    await session.flush()
    return m


@pytest.fixture
async def stalled_thread(client):  # noqa: ANN001, ARG001 — client builds the schema
    """A vendor who usually replies in 1h, an invoice we sent 5h ago, no reply."""
    tid, mid = uuid4(), uuid4()
    now = datetime.now(UTC)
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(Tenant(id=tid, name="Cyberlex", plan="complete", payment_method_ok=True))
            await session.flush()
            session.add(
                Mailbox(
                    id=mid, tenant_id=tid, address="dana@cyberlex.store",
                    mailbox_class="protected", sources=["imap_idle"], is_active=True,
                )
            )
            session.add(
                Counterparty(
                    tenant_id=tid, registrable_domain="vendor.com",
                    first_seen_at=now - timedelta(days=30), last_seen_at=now - timedelta(hours=5),
                    message_count=20, median_reply_seconds=3600, verified_phone="+18035551234",
                )
            )
            # Their original request (inbound) anchors the thread + names them.
            await _msg(
                session, tenant_id=tid, mailbox_id=mid, thread_key="<t1@vendor.com>",
                direction="inbound", sender_address="ap@vendor.com",
                received_at=now - timedelta(hours=6), rfc_message_id="<t1@vendor.com>",
            )
            # Our reply with payment, sent 5h ago — well past 3× their 1h norm.
            await _msg(
                session, tenant_id=tid, mailbox_id=mid, thread_key="<t1@vendor.com>",
                direction="outbound", sender_address="dana@cyberlex.store",
                sent_at=now - timedelta(hours=5), received_at=now - timedelta(hours=5),
                rfc_message_id="<t2@cyberlex.store>", payment_amount=4200.0,
                payment_currency="GBP",
            )
            await session.commit()
    return tid, mid


async def _sweep():  # noqa: ANN202
    from envelock.workers.stall_sweep import sweep_stalled_payment_threads

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            return await sweep_stalled_payment_threads(session)


async def test_sweep_raises_a12_once(stalled_thread) -> None:  # noqa: ANN001
    result = await _sweep()
    assert result["stall_alerts"] == 1, result

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            a12 = (
                await session.execute(select(Finding).where(Finding.service == "A12"))
            ).scalars().all()
            assert len(a12) == 1
            assert a12[0].evidence["counterparty"] == "vendor.com"

    # Idempotent: the message already carries an A12 finding, so no second alert.
    assert (await _sweep())["stall_alerts"] == 0


async def test_a_reply_prevents_the_stall_alert(stalled_thread) -> None:  # noqa: ANN001
    tid, mid = stalled_thread
    now = datetime.now(UTC)
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            # The vendor replied an hour ago — nothing is stalled.
            await _msg(
                session, tenant_id=tid, mailbox_id=mid, thread_key="<t1@vendor.com>",
                direction="inbound", sender_address="ap@vendor.com",
                received_at=now - timedelta(hours=1), rfc_message_id="<t3@vendor.com>",
            )
            await session.commit()

    assert (await _sweep())["stall_alerts"] == 0
