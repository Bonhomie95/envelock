"""Group E — alert lifecycle, oversight and escalation (E1–E6).

Persistence-backed: alerts, findings and the audit trail all live in Postgres so
E5 ("IT sees who read it, who acted, who ignored it") is answerable after a
restart.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import AlertTier
from envelock.detections.base import FindingResult
from envelock.models import Alert, AuditEvent, Finding, NotificationDelivery
from envelock.notify.ladder import Recipient, initial_rungs
from envelock.risk.engine import RiskAssessment


class AuditAction:
    ALERT_RAISED = "alert.raised"
    ALERT_VIEWED = "alert.viewed"
    ALERT_ACKNOWLEDGED = "alert.acknowledged"
    ALERT_RESOLVED = "alert.resolved"
    ALERT_DISMISSED = "alert.dismissed"
    ALERT_ESCALATED = "alert.escalated"
    ALERT_UNREAD = "alert.marked_unread"
    MESSAGE_QUARANTINED = "message.quarantined"
    MAILBOX_CONNECTED = "mailbox.connected"
    SETTINGS_CHANGED = "settings.changed"
    SENSOR_PAIRING_CREATED = "sensor.pairing_created"
    SENSOR_ENROLLED = "sensor.enrolled"
    SENSOR_REVOKED = "sensor.revoked"
    SILENT_ACCESS_ARMED = "sensor.silent_access_armed"
    SILENT_ACCESS_DISARMED = "sensor.silent_access_disarmed"


async def record_audit(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    action: str,
    actor_id: UUID | None = None,
    target_type: str | None = None,
    target_id: UUID | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    event = AuditEvent(
        id=uuid4(),
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail or {},
    )
    session.add(event)
    return event


async def raise_alert(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    mailbox_id: UUID | None,
    assessment: RiskAssessment,
    findings: list[FindingResult],
    message_id: UUID | None = None,
    recipients: list[Recipient] | None = None,
    counterparty_domain: str | None = None,
    ai_verdict: str | None = None,
    ai_flagged: bool = False,
    amount_at_risk: float | None = None,
    amount_currency: str | None = None,
) -> Alert:
    """Persist an alert plus its evidence, and fan out the free ladder rungs."""
    alert = Alert(
        id=uuid4(),
        tenant_id=tenant_id,
        mailbox_id=mailbox_id,
        tier=assessment.tier.value,
        title=assessment.title[:255],
        body=assessment.body,
        counterparty_domain=counterparty_domain,
        requires_callback=assessment.requires_callback,
        callback_phone=assessment.callback_phone,
        state="open",
        ai_flagged=ai_flagged,
        ai_verdict=ai_verdict,
        amount_at_risk=amount_at_risk,
        amount_currency=amount_currency,
    )
    session.add(alert)
    await session.flush()

    for f in findings:
        session.add(
            Finding(
                id=uuid4(),
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                message_id=message_id,
                alert_id=alert.id,
                service=f.service,
                tier=f.tier.value,
                score=f.score,
                summary=f.summary,
                evidence=f.evidence,
            )
        )

    for recipient in recipients or []:
        decision = initial_rungs(assessment.tier, recipient)
        for rung in decision.rungs:
            session.add(
                NotificationDelivery(
                    id=uuid4(),
                    tenant_id=tenant_id,
                    alert_id=alert.id,
                    user_id=UUID(recipient.user_id) if recipient.user_id else None,
                    rung=rung.value,
                    channel=rung.name.lower(),
                    status="pending",
                )
            )

    await record_audit(
        session,
        tenant_id=tenant_id,
        action=AuditAction.ALERT_RAISED,
        target_type="alert",
        target_id=alert.id,
        detail={"tier": assessment.tier.value, "services": list(assessment.services)},
    )

    # Queue the outbound SIEM delivery in THIS transaction. Enqueuing here rather
    # than after the commit is what makes "every alert reaches your SIEM" true:
    # the delivery row and the alert commit together, so there is no window in
    # which an alert exists and its delivery does not.
    from envelock.governance.export import WebhookEvent
    from envelock.workers.webhook_delivery import enqueue as enqueue_webhook

    await enqueue_webhook(
        session,
        tenant_id=tenant_id,
        event=WebhookEvent.ALERT_RAISED,
        data={
            "alert_id": str(alert.id),
            "tier": assessment.tier.value,
            "title": assessment.title,
            "body": assessment.body,
            "services": list(assessment.services),
            "score": assessment.score,
            "mailbox_id": str(mailbox_id) if mailbox_id else None,
            "counterparty_domain": counterparty_domain,
            "ai_flagged": ai_flagged,
            "requires_callback": assessment.requires_callback,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
        },
    )
    return alert


async def acknowledge(
    session: AsyncSession, *, alert_id: UUID, tenant_id: UUID, actor_id: UUID
) -> Alert | None:
    """Acknowledgement — not delivery — stops the escalation clock (PRD §8.1)."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != tenant_id:
        return None
    alert.state = "acked"
    alert.acknowledged_at = datetime.now(UTC)
    alert.acknowledged_by = actor_id
    await record_audit(
        session,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=AuditAction.ALERT_ACKNOWLEDGED,
        target_type="alert",
        target_id=alert.id,
    )
    return alert


#: Tiers whose confirmation is a strong enough fraud signal to share on the E8
#: graph. Resolving a Medium/Low as "handled" is not a fraud confirmation.
_GRAPH_FEED_TIERS = frozenset({AlertTier.CRITICAL.value, AlertTier.HIGH.value})


async def _tenant_may_feed_graph(session: AsyncSession, tenant_id: UUID) -> bool:
    """Cross-tenant influence requires skin in the game: a DNS-verified domain."""
    from envelock.models import Domain

    verified = (
        await session.execute(
            select(Domain.id)
            .where(Domain.tenant_id == tenant_id, Domain.verified_at.is_not(None))
            .limit(1)
        )
    ).first()
    return verified is not None


async def alert_bank_identifiers(session: AsyncSession, alert: Alert) -> list[dict]:
    """The bank accounts an alert is about: the changed account (A1) and any
    already-known fraud account (A15), as `[{scheme, identifier}]`."""
    from envelock.models import Finding

    findings = (
        await session.execute(
            select(Finding).where(Finding.alert_id == alert.id, Finding.service.in_(("A1", "A15")))
        )
    ).scalars().all()
    seen: dict[str, dict] = {}
    for f in findings:
        ev = f.evidence or {}
        for item in (ev.get("new_identifiers") or []) + (ev.get("fraud_accounts") or []):
            if item.get("identifier"):
                seen.setdefault(item["identifier"], item)
    return list(seen.values())


async def report_fraud_accounts(session: AsyncSession, alert: Alert) -> int:
    from envelock.platform import fraud_accounts

    return await fraud_accounts.report(
        session,
        tenant_id=alert.tenant_id,
        identifiers=await alert_bank_identifiers(session, alert),
    )


async def resolve(
    session: AsyncSession,
    *,
    alert_id: UUID,
    tenant_id: UUID,
    actor_id: UUID | None,
    dismissed: bool = False,
) -> Alert | None:
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != tenant_id:
        return None
    alert.state = "dismissed" if dismissed else "resolved"
    alert.resolved_at = datetime.now(UTC)

    # Label the AI verdict with the human's answer. A resolved High/Critical is a
    # confirmed fraud; a dismissal is a false positive. This is how the labeled
    # corpus for the phase-2 fine-tuned classifier accumulates — for free, as a
    # side effect of customers doing their job.
    from envelock.models import LlmVerdictRecord

    verdict_rows = (
        (
            await session.execute(
                select(LlmVerdictRecord).where(LlmVerdictRecord.alert_id == alert.id)
            )
        )
        .scalars()
        .all()
    )
    for row in verdict_rows:
        row.human_disposition = "dismissed" if dismissed else "confirmed"
        row.labeled_at = datetime.now(UTC)

    # Closing the moat loop (E8): a human confirming a real High/Critical is the
    # strongest fraud signal we get — stronger than a manual lookalike report.
    # Feed the counterparty to the cross-tenant graph so every other tenant is
    # protected. Dismissal (a false positive) deliberately does not feed it.
    propagated = False
    if (
        not dismissed
        and alert.counterparty_domain
        and alert.tier in _GRAPH_FEED_TIERS
        # Only a tenant that has PROVEN control of a domain may feed the shared
        # graph. A free signup that never verifies costs nothing to create in
        # pairs — and two colluding throwaway tenants self-mailing spoofed
        # alerts could otherwise vote any domain fraudulent for every customer.
        and await _tenant_may_feed_graph(session, tenant_id)
    ):
        from envelock.platform import graph_store
        from envelock.platform.graph import GRAPH, Verdict

        entry = GRAPH.report(
            domain=alert.counterparty_domain,
            verdict=Verdict.FRAUDULENT,
            tenant_id=tenant_id,
        )
        await graph_store.persist_report(
            session, entry, GRAPH.reporters_of(alert.counterparty_domain)
        )
        propagated = entry.actionable

    # The payment half of the same loop: the bank account this fraud asked for
    # is recorded so it is flagged for every other customer (A15).
    accounts_reported = 0
    if not dismissed and await _tenant_may_feed_graph(session, tenant_id):
        accounts_reported = await report_fraud_accounts(session, alert)

    await record_audit(
        session,
        tenant_id=tenant_id,
        actor_id=actor_id,
        action=AuditAction.ALERT_DISMISSED if dismissed else AuditAction.ALERT_RESOLVED,
        target_type="alert",
        target_id=alert.id,
        detail=(
            {"graph_propagated": propagated, "fraud_accounts_reported": accounts_reported}
            if not dismissed
            else None
        ),
    )
    return alert


@dataclass(frozen=True, slots=True)
class EscalationStep:
    alert_id: UUID
    tier: AlertTier
    to: str
    minutes_open: int


async def due_escalations(
    session: AsyncSession, *, tenant_id: UUID | None = None, now: datetime | None = None
) -> list[EscalationStep]:
    """E6 — IT learns when a user ignores a Critical.

    This free safety net is what makes it defensible to delay the paid SMS rung.
    Pass `tenant_id` to scope an on-demand run to one tenant; the background job
    leaves it unset to sweep every tenant.
    """
    now = now or datetime.now(UTC)
    query = select(Alert).where(
        Alert.state == "open", Alert.tier == AlertTier.CRITICAL.value
    )
    if tenant_id is not None:
        query = query.where(Alert.tenant_id == tenant_id)
    rows = (await session.execute(query)).scalars()

    steps: list[EscalationStep] = []
    for alert in rows:
        created = alert.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        minutes = int((now - created).total_seconds() // 60)

        # Each stage fires exactly once. Matching on age alone meant an alert
        # older than an hour matched "all_admins" on EVERY cycle — a fresh audit
        # entry and a fresh SMS every sixty seconds until someone acknowledged
        # it, which is how a customer learns to ignore our notifications.
        reached = alert.escalated_to
        if minutes >= 60 and reached != "all_admins":
            target = "all_admins"
        elif minutes >= 15 and reached is None:
            target = "it_admin"
        else:
            continue
        steps.append(
            EscalationStep(
                alert_id=alert.id, tier=AlertTier.CRITICAL, to=target, minutes_open=minutes
            )
        )
    return steps


async def mark_escalated(
    session: AsyncSession, *, alert_id: UUID, tenant_id: UUID, to: str
) -> None:
    alert = await session.get(Alert, alert_id)
    if alert is None:
        return
    alert.escalated_at = datetime.now(UTC)
    alert.escalated_to = to
    await record_audit(
        session,
        tenant_id=tenant_id,
        action=AuditAction.ALERT_ESCALATED,
        target_type="alert",
        target_id=alert_id,
        detail={"to": to},
    )


#: An alert only counts toward prevented loss once a human has confirmed it was
#: real fraud. An open alert might still be dismissed tomorrow, and a dismissed
#: one was a false positive — counting either would produce a headline figure the
#: customer can disprove from their own records, which is worse than having no
#: figure at all.
_PREVENTED_TIERS = frozenset({AlertTier.HIGH.value, AlertTier.CRITICAL.value})


def prevented_loss(alerts: Sequence[Alert]) -> dict:
    """Money that a confirmed payment-fraud alert stopped, per currency.

    Per currency, never summed. Adding £ to ₦ yields a number that is not true in
    either, and this is the one figure a customer will check against their own
    ledger — being approximately right here is being wrong.

    `unpriced` is the count of confirmed frauds that carried no amount (the
    message named no figure, or it predates this field). It is returned rather
    than hidden so the UI can say "at least X, across N incidents, plus M we
    could not price" instead of implying the total is complete.
    """
    totals: dict[str, float] = {}
    counted = 0
    unpriced = 0
    for a in alerts:
        if a.state != "resolved" or a.tier not in _PREVENTED_TIERS:
            continue
        if a.amount_at_risk is None or a.amount_currency is None:
            unpriced += 1
            continue
        totals[a.amount_currency] = totals.get(a.amount_currency, 0.0) + a.amount_at_risk
        counted += 1
    return {
        "by_currency": [
            {"currency": ccy, "amount": round(total, 2)}
            for ccy, total in sorted(totals.items(), key=lambda kv: -kv[1])
        ],
        "incidents": counted,
        "unpriced_incidents": unpriced,
    }


async def oversight_summary(session: AsyncSession, *, tenant_id: UUID) -> dict:
    """E4/E5 — what the IT dashboard shows, including who ignored what."""
    alerts = (
        (await session.execute(select(Alert).where(Alert.tenant_id == tenant_id)))
        .scalars()
        .all()
    )
    now = datetime.now(UTC)

    def _age_minutes(a: Alert) -> int:
        created = a.created_at if a.created_at.tzinfo else a.created_at.replace(tzinfo=UTC)
        return int((now - created).total_seconds() // 60)

    open_alerts = [a for a in alerts if a.state == "open"]
    return {
        "prevented_loss": prevented_loss(alerts),
        "total": len(alerts),
        "open": len(open_alerts),
        "critical_open": sum(1 for a in open_alerts if a.tier == AlertTier.CRITICAL.value),
        "acknowledged": sum(1 for a in alerts if a.acknowledged_at is not None),
        "unacknowledged_over_15m": sum(
            1
            for a in open_alerts
            if a.tier == AlertTier.CRITICAL.value and _age_minutes(a) >= 15
        ),
        "by_tier": {
            tier.value: sum(1 for a in alerts if a.tier == tier.value)
            for tier in AlertTier
        },
    }


