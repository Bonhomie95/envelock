"""Pricing engine — PRD §12.

Structure: platform fee per mail-carrying domain + volume-banded per-mailbox fee,
pooled across domains. Two mailbox classes (§12.2) so whole-domain coverage stays
affordable, which is what closes the "attacker enters via an unprotected mailbox"
hole.

Price is identical across integration tiers — a customer does not pay more for
being on HiNet.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Plan(StrEnum):
    GUARD = "guard"  # Channel 3 only — free forever
    ESSENTIAL = "essential"
    COMPLETE = "complete"
    SOLO = "solo"  # no-domain segment (PRD §12.6)


class BillingTerm(StrEnum):
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMIANNUAL = "semiannual"
    ANNUAL = "annual"


#: Term discounts. Monthly stays unpenalised — annual prepay is genuinely hard
#: for SMBs in our markets.
TERM_DISCOUNT: dict[BillingTerm, float] = {
    BillingTerm.MONTHLY: 0.00,
    BillingTerm.QUARTERLY: 0.05,
    BillingTerm.SEMIANNUAL: 0.10,
    BillingTerm.ANNUAL: 0.20,
}

#: Platform fee per mail-carrying domain, in cents.
PLATFORM_CENTS: dict[Plan, int] = {
    Plan.GUARD: 0,
    Plan.ESSENTIAL: 1500,
    Plan.COMPLETE: 3150,
    Plan.SOLO: 0,
}

#: Mailbox seats included with each plan — the number of mailboxes a tenant may
#: protect before buying more. Guard protects domains only (no mailboxes). During
#: the trial the tenant sits on the top plan, so the trial allowance is COMPLETE's.
#: Additional seats can be purchased on top (Tenant.extra_mailbox_seats).
PLAN_MAILBOX_SEATS: dict[Plan, int] = {
    Plan.GUARD: 0,
    Plan.SOLO: 1,
    Plan.ESSENTIAL: 5,
    Plan.COMPLETE: 5,
}

#: Monthly price of each mailbox beyond the plan's included allowance, in cents.
#: The first-band protected rate below, so an extra seat costs exactly what that
#: mailbox adds to the plan's own price (Complete: $31.50 platform + 5 × $3.50
#: = $49).
#: Charged through a per-seat Stripe Price (ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_*)
#: whose amount must match this.
EXTRA_MAILBOX_CENTS: dict[Plan, int] = {
    Plan.ESSENTIAL: 200,
    Plan.COMPLETE: 350,
}


#: The largest mailbox count the self-serve checkout will price. Above this the
#: flat per-seat rate stops reflecting our costs and the banded ladder below
#: (PRD §12.9C) is the right instrument — but that needs graduated Stripe prices
#: and usage reporting, so above the ceiling we say "talk to us" rather than
#: quote a number we cannot charge.
SELF_SERVE_MAILBOX_CEILING = 50


def included_mailbox_seats(plan: str) -> int:
    try:
        return PLAN_MAILBOX_SEATS[Plan(plan)]
    except (ValueError, KeyError):
        return 0


def extra_mailbox_cents(plan: str) -> int | None:
    try:
        return EXTRA_MAILBOX_CENTS.get(Plan(plan))
    except ValueError:
        return None

#: Additional mail-carrying domains cost half. Defensive/parked domains are free
#: and unlimited — monitoring one costs a daily DNS lookup.
ADDITIONAL_DOMAIN_RATE = 0.5

#: (upper_bound_inclusive, cents_per_mailbox). Marginal: each band applies only
#: to mailboxes falling within it.
_BANDS: tuple[int, ...] = (10, 50, 200, 1000, 10**9)

_PROTECTED_RATES: dict[Plan, tuple[int, ...]] = {
    Plan.ESSENTIAL: (200, 170, 140, 100, 70),
    Plan.COMPLETE: (350, 300, 240, 175, 120),
}
_MONITORED_RATES: tuple[int, ...] = (60, 50, 40, 30, 20)

#: Flat per-mailbox pricing for the no-domain segment.
SOLO_CENTS = 600
SOLO_TEAM_CENTS = 500
SOLO_TEAM_MIN = 3


@dataclass(frozen=True, slots=True)
class Quote:
    plan: Plan
    term: BillingTerm
    platform_cents: int
    protected_cents: int
    monitored_cents: int
    subtotal_cents: int
    discount_cents: int
    total_cents: int
    breakdown: dict

    @property
    def total_usd(self) -> float:
        return self.total_cents / 100


def self_serve_cents(plan: str, mailboxes: int, *, term: str = BillingTerm.MONTHLY) -> int:
    """What Stripe actually charges, to the cent.

    This is the ONLY function that may answer a customer-facing price question.
    `quote()` below implements the PRD §12.9 banded ladder, which is a different
    (better, cheaper-at-scale) model that nothing bills yet — and the public
    quote endpoint was serving it, understating a 500-mailbox Essential plan by
    $402/month against the invoice Stripe would send. A price we quote and a
    price we charge have to come from one place.

    The shape is the subscription's: a per-domain platform fee plus every seat at
    the plan's per-seat rate, with the plan's included seats as a floor — which is
    why five mailboxes and one mailbox both cost $25 on Essential.
    """
    try:
        plan_enum = Plan(plan)
        term_enum = BillingTerm(term)
    except ValueError:
        return 0
    if plan_enum is Plan.GUARD:
        return 0
    rate = EXTRA_MAILBOX_CENTS.get(plan_enum)
    if rate is None:  # Solo has no per-domain platform fee; price it flat.
        return SOLO_CENTS * max(0, mailboxes)
    billed_seats = max(mailboxes, included_mailbox_seats(plan_enum.value))
    subtotal = PLATFORM_CENTS[plan_enum] + billed_seats * rate
    return subtotal - int(subtotal * TERM_DISCOUNT[term_enum])


def _banded_cost(count: int, rates: tuple[int, ...]) -> tuple[int, list[dict]]:
    """Marginal banding across `_BANDS`."""
    total = 0
    detail: list[dict] = []
    remaining = count
    lower = 0
    for bound, rate in zip(_BANDS, rates, strict=True):
        if remaining <= 0:
            break
        in_band = min(remaining, bound - lower)
        if in_band > 0:
            cost = in_band * rate
            total += cost
            detail.append(
                {"band": f"{lower + 1}-{bound if bound < 10**9 else '+'}",
                 "count": in_band, "rate_cents": rate, "cents": cost}
            )
            remaining -= in_band
        lower = bound
    return total, detail


def quote(
    *,
    plan: Plan,
    term: BillingTerm = BillingTerm.MONTHLY,
    mail_domains: int = 1,
    protected: int = 0,
    monitored: int = 0,
    solo_mailboxes: int = 0,
) -> Quote:
    """Monthly-equivalent cost. Mailbox bands pool across all domains."""
    if plan is Plan.GUARD:
        return Quote(plan, term, 0, 0, 0, 0, 0, 0, {"note": "Guard is free forever"})

    if plan is Plan.SOLO:
        rate = SOLO_TEAM_CENTS if solo_mailboxes >= SOLO_TEAM_MIN else SOLO_CENTS
        subtotal = rate * solo_mailboxes
        discount = int(subtotal * TERM_DISCOUNT[term])
        return Quote(
            plan, term, 0, subtotal, 0, subtotal, discount, subtotal - discount,
            {"mailboxes": solo_mailboxes, "rate_cents": rate},
        )

    base = PLATFORM_CENTS[plan]
    extra_domains = max(0, mail_domains - 1)
    platform = base + int(base * ADDITIONAL_DOMAIN_RATE) * extra_domains

    protected_cents, protected_detail = _banded_cost(protected, _PROTECTED_RATES[plan])
    monitored_cents, monitored_detail = _banded_cost(monitored, _MONITORED_RATES)

    subtotal = platform + protected_cents + monitored_cents
    discount = int(subtotal * TERM_DISCOUNT[term])

    return Quote(
        plan=plan,
        term=term,
        platform_cents=platform,
        protected_cents=protected_cents,
        monitored_cents=monitored_cents,
        subtotal_cents=subtotal,
        discount_cents=discount,
        total_cents=subtotal - discount,
        breakdown={
            "mail_domains": mail_domains,
            "platform": {"base_cents": base, "additional_domains": extra_domains},
            "protected": protected_detail,
            "monitored": monitored_detail,
            "term_discount_pct": int(TERM_DISCOUNT[term] * 100),
        },
    )



