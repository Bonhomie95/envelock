"""Plan entitlement — one answer for the API *and* the workers.

The seat cap is only real if it holds at both ends: the API refuses to ADD a
mailbox beyond the plan (api/tenants), and the pollers refuse to KEEP PROTECTING
mailboxes the tenant is no longer entitled to (a lapsed unpaid trial, or seats
beyond a downgraded plan's capacity). Without the second half, every trial
tenant keeps full live protection forever, free.
"""

from __future__ import annotations

from datetime import UTC, datetime

from envelock.billing.pricing import Plan, included_mailbox_seats
from envelock.models import Mailbox, Tenant


def mailbox_entitled(tenant: Tenant) -> bool:
    """Content mailboxes (Channel 1/2) need a paid plan or an active trial. Guard
    is Channel-3-only and free — it protects domains, not mailboxes (PRD §12.3)."""
    ends = tenant.trial_ends_at
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_active = bool(ends and ends > datetime.now(UTC))
    return trial_active or tenant.payment_method_ok


def effective_plan(tenant: Tenant) -> str:
    """Guard once the trial has lapsed unpaid, else the subscribed plan."""
    return tenant.plan if mailbox_entitled(tenant) else Plan.GUARD.value


def mailbox_capacity(tenant: Tenant) -> int:
    """How many mailboxes this tenant may protect right now: the plan's included
    seats plus any purchased, or 0 on Guard (no mailboxes without a paid
    plan/trial). During the trial the tenant sits on the top plan."""
    plan = effective_plan(tenant)
    if plan == Plan.GUARD.value:
        return 0
    return included_mailbox_seats(plan) + max(0, tenant.extra_mailbox_seats or 0)


def entitled_mailboxes(tenant: Tenant, mailboxes: list[Mailbox]) -> list[Mailbox]:
    """The subset of this tenant's mailboxes the pollers may protect.

    Zero when not entitled; otherwise the oldest ``capacity`` mailboxes —
    deterministic, so a downgrade doesn't shuffle which seats stay protected
    between poll cycles.
    """
    if not mailbox_entitled(tenant):
        return []
    cap = mailbox_capacity(tenant)
    ordered = sorted(mailboxes, key=lambda m: (m.created_at or datetime.min, m.id.hex))
    return ordered[:cap]


__all__ = [
    "effective_plan",
    "entitled_mailboxes",
    "mailbox_capacity",
    "mailbox_entitled",
]
