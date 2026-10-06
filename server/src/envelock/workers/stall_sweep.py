"""A12 reply-stall sweep.

A12 asks a question that cannot be answered when a message arrives: *has the
counterparty gone silent?* At the moment we send a payment mail, zero time has
passed, so the ingest-time detection never fires on its own. The stall is a
property of elapsed time, so it is discovered here, on a timer.

Each cycle looks at the payment mail we have sent, and raises A12 for any whose
counterparty has now been silent for more than ``STALL_MULTIPLIER`` times their
own usual reply time (learned in `pipeline._update_reply_latency`). The threshold
and the finding are the detection's own (`detections.content`), so there is one
definition of a stall, not two. Idempotent: a message that already has an A12
finding is never alerted again.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import MailDirection
from envelock.db import get_sessionmaker
from envelock.detections.content import a12_finding, stall_overdue
from envelock.models import Counterparty, Finding, Message
from envelock.risk.engine import assess
from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.stallsweep")

#: Only threads sent within this window are swept. A thread silent for months is
#: not a live payment risk and the counterparty baseline has long since moved on.
LOOKBACK_DAYS = 30
#: Cap per cycle so one busy tenant cannot monopolise a sweep.
MAX_PER_CYCLE = 500


async def sweep_stalled_payment_threads(
    session: AsyncSession, *, now: datetime | None = None
) -> dict:
    """Raise A12 for every overdue, unanswered outbound payment thread."""
    from envelock.channels.mail.forward_runner import _recipients
    from envelock.notify.dispatch import deliver_pending
    from envelock.platform.alerts import raise_alert

    at = now or datetime.now(UTC)
    floor = at - timedelta(days=LOOKBACK_DAYS)

    candidates = (
        (
            await session.execute(
                select(Message)
                .where(
                    Message.direction == MailDirection.OUTBOUND.value,
                    Message.payment_amount.is_not(None),
                    Message.sent_at.is_not(None),
                    Message.sent_at >= floor,
                )
                .order_by(Message.sent_at.asc())
                .limit(MAX_PER_CYCLE)
            )
        )
        .scalars()
        .all()
    )

    raised = 0
    for msg in candidates:
        sent_at = _aware(msg.sent_at)
        if sent_at is None or not msg.thread_key:
            continue
        waiting = (at - sent_at).total_seconds()

        # Already alerted on this exact message? Never repeat.
        if await _has_a12(session, msg):
            continue

        # Who are we waiting on, and have they in fact replied since?
        counterparty_domain = await _thread_counterparty(session, msg)
        if counterparty_domain is None:
            continue  # a thread with no external party has no one to stall
        if await _replied_since(session, msg, after=sent_at):
            continue

        cp = (
            await session.execute(
                select(Counterparty).where(
                    Counterparty.tenant_id == msg.tenant_id,
                    Counterparty.registrable_domain == counterparty_domain,
                )
            )
        ).scalar_one_or_none()
        if cp is None or not stall_overdue(cp.median_reply_seconds, waiting):
            continue

        finding = a12_finding(
            domain=counterparty_domain,
            waiting_seconds=waiting,
            median_reply_seconds=cp.median_reply_seconds,  # type: ignore[arg-type]
            verified_phone=cp.verified_phone,
        )
        assessment = assess([finding])
        if assessment is None or not assessment.is_alertable:
            continue
        recipients = await _recipients(session, msg.tenant_id)
        alert = await raise_alert(
            session,
            tenant_id=msg.tenant_id,
            mailbox_id=msg.mailbox_id,
            assessment=assessment,
            findings=[finding],
            message_id=msg.id,
            recipients=recipients,
            counterparty_domain=counterparty_domain,
        )
        await deliver_pending(session, alert_id=alert.id)
        raised += 1

    await session.commit()
    return {"stall_alerts": raised, "scanned": len(candidates)}


async def _has_a12(session: AsyncSession, msg: Message) -> bool:
    row = (
        await session.execute(
            select(Finding.id)
            .where(Finding.message_id == msg.id, Finding.service == "A12")
            .limit(1)
        )
    ).first()
    return row is not None


async def _thread_counterparty(session: AsyncSession, msg: Message) -> str | None:
    """The external party in this thread — the sender of any inbound message that
    shares the thread key. That is who an A12 stall is about."""
    inbound = (
        (
            await session.execute(
                select(Message.sender_address).where(
                    Message.tenant_id == msg.tenant_id,
                    Message.thread_key == msg.thread_key,
                    Message.direction == MailDirection.INBOUND.value,
                )
            )
        )
        .scalars()
        .all()
    )
    for addr in inbound:
        domain = registrable_domain((addr or "").rpartition("@")[2].lower())
        if domain:
            return domain
    return None


async def _replied_since(session: AsyncSession, msg: Message, *, after: datetime) -> bool:
    row = (
        await session.execute(
            select(Message.id)
            .where(
                and_(
                    Message.tenant_id == msg.tenant_id,
                    Message.thread_key == msg.thread_key,
                    Message.direction == MailDirection.INBOUND.value,
                    Message.received_at > after,
                )
            )
            .limit(1)
        )
    ).first()
    return row is not None


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def run() -> dict:
    """Scheduler entrypoint — platform-wide, under the system scope the scheduler
    already binds."""
    async with get_sessionmaker()() as session:
        return await sweep_stalled_payment_threads(session)


__all__ = ["run", "sweep_stalled_payment_threads"]
