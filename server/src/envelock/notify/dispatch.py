"""Actually deliver the notifications the alert pipeline queues (PRD §8.1).

`alerts.raise_alert` records one `NotificationDelivery` row per ladder rung in the
`pending` state; without this module those rows are never sent. `deliver_pending`
resolves each rung's destination, calls the matching sender, and records the
outcome so the delivery ledger reflects what actually happened — `sent`,
`skipped` (rung not configured / no destination), or `failed`.

`run_escalation_cycle` is the free E6 safety net made to run: it escalates
unacknowledged Criticals to IT and, only when the ladder says so, to the paid SMS
rung. Acknowledgement — not delivery — is the signal, exactly as §8.1 requires.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.config import get_settings
from envelock.core.enums import AlertTier
from envelock.models import Alert, Mailbox, NotificationDelivery, PushSubscription, User
from envelock.notify.ladder import (
    EscalationPolicy,
    Recipient,
    Rung,
    should_escalate_to_sms,
)
from envelock.notify.senders import Dispatcher, notification_from_alert
from envelock.obs.metrics import observe_delivery
from envelock.platform import alerts as alert_svc


async def _destination(
    session: AsyncSession, delivery: NotificationDelivery, alert: Alert
) -> str | None:
    """Where this rung goes. In-app always has one; the rest need a registered
    out-of-band address, phone, or push subscription (PRD §8.2)."""
    rung = Rung(delivery.rung)
    if rung is Rung.L0_IN_APP:
        return str(delivery.user_id) if delivery.user_id else "dashboard"

    user = await session.get(User, delivery.user_id) if delivery.user_id else None
    if rung is Rung.L2_EMAIL:
        if user is None:
            return None
        # Fall back to the login email when no dedicated out-of-band address is
        # registered — `out_of_band_email` had NO write path, so requiring it
        # meant the email rung never fired for anyone. One hard rule survives
        # the fallback: never deliver the alert INTO the mailbox it is about;
        # if that box is compromised, the attacker reads their own alert.
        mailbox = (
            await session.get(Mailbox, alert.mailbox_id) if alert.mailbox_id else None
        )
        for to in (user.out_of_band_email, user.email):
            if to and not (mailbox and to.lower() == mailbox.address.lower()):
                return to
        return None
    if rung is Rung.L3_SMS:
        return user.phone if user else None
    if rung is Rung.L1_PUSH:
        sub = (
            await session.execute(
                select(PushSubscription).where(PushSubscription.user_id == delivery.user_id)
            )
        ).scalars().first()
        return sub.endpoint if sub else None
    return None


async def deliver_pending(
    session: AsyncSession,
    *,
    alert_id: UUID | None = None,
    tenant_id: UUID | None = None,
    dispatcher: Dispatcher | None = None,
) -> list[NotificationDelivery]:
    """Send every pending delivery for an alert (or a whole tenant). Idempotent:
    a row leaves `pending` once attempted, so re-running never double-sends."""
    dispatcher = dispatcher or Dispatcher()
    query = select(NotificationDelivery).where(NotificationDelivery.status == "pending")
    if alert_id is not None:
        query = query.where(NotificationDelivery.alert_id == alert_id)
    if tenant_id is not None:
        query = query.where(NotificationDelivery.tenant_id == tenant_id)

    rows = (await session.execute(query)).scalars().all()
    touched: list[NotificationDelivery] = []
    for row in rows:
        alert = await session.get(Alert, row.alert_id)
        if alert is None:
            row.status = "skipped"
            row.error = "alert gone"
            observe_delivery(rung=row.rung, status=row.status)
            touched.append(row)
            continue
        rung = Rung(row.rung)
        dest = await _destination(session, row, alert)
        if not dest:
            row.status = "skipped"
            row.error = "no destination"
            observe_delivery(rung=row.rung, status=row.status)
            touched.append(row)
            continue
        note = notification_from_alert(alert, row.tenant_id)
        if rung is Rung.L2_EMAIL:
            # Email is the rung with room for the full report — which message,
            # what we found, and whether anything is required of the reader.
            # Push and SMS are length-constrained and keep the title.
            from envelock.notify.report import report_for_alert

            report = await report_for_alert(
                session, alert, url_base=get_settings().web_base_url
            )
            if report is not None:
                note = replace(note, report=report)
        if rung is Rung.L1_PUSH:
            # Web Push needs the subscription's encryption keys, not just the
            # endpoint — fetch them and hand them to the sender.
            sub = (
                await session.execute(
                    select(PushSubscription).where(
                        PushSubscription.user_id == row.user_id
                    )
                )
            ).scalars().first()
            keys = {"p256dh": sub.p256dh, "auth": sub.auth} if sub else None
            result = await dispatcher.push.send(note, to=dest, keys=keys)
        else:
            result = await dispatcher.sender(rung).send(note, to=dest)
        if result.delivered:
            row.status = "sent"
            row.cost_micros = result.cost_micros
            row.error = None
        else:
            # An unconfigured rung is skipped (infra not set up), not failed.
            row.status = "skipped" if "not configured" in result.reason else "failed"
            row.error = result.reason
        # A notification rung failing quietly is the failure that costs the
        # customer money — they never hear about the alert we correctly raised.
        # Counted by rung and status so "L2 email has been 100% failed for an
        # hour" is a graph, not a support ticket.
        observe_delivery(rung=row.rung, status=row.status)
        touched.append(row)
    return touched


async def run_escalation_cycle(
    session: AsyncSession,
    *,
    tenant_id: UUID | None = None,
    dispatcher: Dispatcher | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Escalate unacknowledged Criticals (E6). Meant to run on a short interval
    from an ops scheduler; returns what it did for observability."""
    dispatcher = dispatcher or Dispatcher()
    steps = await alert_svc.due_escalations(session, tenant_id=tenant_id, now=now)
    done: list[dict] = []
    for step in steps:
        alert = await session.get(Alert, step.alert_id)
        if alert is None:
            continue
        await alert_svc.mark_escalated(
            session, alert_id=step.alert_id, tenant_id=alert.tenant_id, to=step.to
        )
        # Escalation is the one place the paid SMS rung is allowed to fire.
        sms_dest = None
        admins = (
            await session.execute(
                select(User).where(User.tenant_id == alert.tenant_id, User.is_admin.is_(True))
            )
        ).scalars().all()
        for admin in admins:
            # Only a proven phone receives the paid rung — an unverified number
            # is as likely to be an attacker's as the owner's.
            if admin.phone and admin.phone_verified:
                sms_dest = admin.phone
                break

        # Ask the ladder whether this actually warrants the metered channel,
        # rather than sending on age alone. This is what makes
        # ENVELOCK_ESCALATE_UNACKED_COUNT mean something: a tenant with a pile of
        # unacknowledged notifications is not reading them, and that is its own
        # reason to reach for the phone — previously the setting was read from
        # the environment, parsed into config, and consulted by nothing.
        decision = None
        if sms_dest:
            raised = alert.created_at
            if raised.tzinfo is None:
                raised = raised.replace(tzinfo=UTC)
            unacked = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(Alert)
                        .where(
                            Alert.tenant_id == alert.tenant_id,
                            Alert.state == "open",
                            Alert.acknowledged_at.is_(None),
                        )
                    )
                ).scalar_one()
            )
            settings = get_settings()
            decision = should_escalate_to_sms(
                tier=AlertTier(alert.tier),
                raised_at=raised,
                now=now or datetime.now(UTC),
                acknowledged=alert.acknowledged_at is not None,
                unacked_total=unacked,
                recipient=Recipient(
                    user_id="",
                    is_admin=True,
                    has_push_subscription=False,
                    out_of_band_email=None,
                    phone=sms_dest,
                    # An admin reachable only by SMS at this point: if they had a
                    # working push channel they would already have been reached
                    # by it, and the ladder treats "no sensor" as its own reason
                    # to allow the metered rung.
                    has_sensor=False,
                ),
                policy=EscalationPolicy(
                    critical_after_seconds=settings.escalate_critical_after_seconds,
                    unacked_count=settings.escalate_unacked_count,
                ),
            )

        sent_sms = False
        if sms_dest and decision is not None:
            result = await dispatcher.sms.send(
                notification_from_alert(alert, alert.tenant_id), to=sms_dest
            )
            sent_sms = result.delivered

        # E6's promise is "IT LEARNS when a user ignores a Critical" — before
        # this, the whole cycle was an audit row plus (maybe) one SMS on a
        # deployment with a verified phone. On the default deployment it told
        # nobody anything. Email every admin at each escalation stage, on the
        # same never-into-the-attacked-mailbox rule as the alert rung.
        emailed = 0
        if dispatcher.email.configured:
            note = notification_from_alert(alert, alert.tenant_id)
            note = replace(
                note,
                title=f"UNACKNOWLEDGED for {step.minutes_open} min: {note.title}",
            )
            mailbox = (
                await session.get(Mailbox, alert.mailbox_id)
                if alert.mailbox_id
                else None
            )
            for admin in admins:
                to = admin.out_of_band_email or admin.email
                if not to or (mailbox and to.lower() == mailbox.address.lower()):
                    continue
                sent = await dispatcher.email.send(note, to=to)
                if sent.delivered:
                    emailed += 1

        done.append(
            {
                "alert_id": str(step.alert_id),
                "to": step.to,
                "minutes_open": step.minutes_open,
                "sms_sent": sent_sms,
                "emails_sent": emailed,
                "sms_reason": decision.reason if decision else None,
            }
        )
    return done
