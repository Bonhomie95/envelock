"""Billing endpoints — the payment gate and trial ledger (PRD §12.7, §17.1).

The funnel (§12.7) is: sign up free → verify the domain → **payment method
required (THE GATE)** → integration + backfill → trial clock starts. This module
is the gate: it verifies a real payment instrument, records the append-only
domain-trial ledger entry that makes "one trial per domain, ever" enforceable,
and marks the tenant clear to integrate.

Billing is owner-only (PRD §15.1). Nothing here charges an account that has no
payment method attached — cost is incurred only after the gate is passed.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import CurrentUser, OwnerUser, SystemScoped
from envelock.billing import payments, trial
from envelock.billing.pricing import included_mailbox_seats
from envelock.config import get_settings
from envelock.db import get_session
from envelock.models import Domain, DomainTrialLedger, Tenant, User
from envelock.util.domains import is_free_mail, registrable_domain

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/billing", tags=["billing"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/providers")
async def payment_providers(principal: CurrentUser) -> dict:
    """Which payment rails are wired. One acquirer per region keeps conversion
    independent of geography (PRD §12.8)."""
    return {"configured": payments.configured_providers()}


class ConfirmRequest(BaseModel):
    provider: str
    #: Instrument reference collected client-side (a Stripe pm_…, or the acquirer's
    #: stored-payment-method / transaction reference).
    reference: str = Field(min_length=1, max_length=256)
    #: DEPRECATED and ignored. The trial identifier is derived SERVER-SIDE from
    #: the tenant's own domain/owner — a caller-chosen identifier let an attacker
    #: point the one-trial-per-domain ledger at a free-mail string and mint
    #: unlimited trials.
    identifier: str | None = Field(default=None, max_length=320)


async def _trial_identifier(session: AsyncSession, tenant_id, owner_id) -> str:  # noqa: ANN001
    """What the trial ledger locks on: the tenant's earliest domain, else the
    owner's own email. Never caller-supplied."""
    reg = (
        await session.execute(
            select(Domain.registrable_domain)
            .where(Domain.tenant_id == tenant_id)
            .order_by(Domain.created_at.asc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if reg:
        return reg
    owner = await session.get(User, owner_id)
    return owner.email if owner else ""


@router.post("/confirm")
async def confirm_payment_method(
    req: ConfirmRequest, principal: OwnerUser, session: Session
) -> dict:
    """Verify the instrument, record the trial ledger, open the gate.

    The domain trial ledger is append-only and permanent — it survives account
    deletion, which *is* the anti-abuse mechanism (§12.7). A registrable domain is
    not personal data, so retaining it through erasure is defensible.
    """
    provider = payments.provider_for(req.provider)
    if provider is None:
        raise HTTPException(404, "unknown payment provider")
    if not provider.is_configured():
        raise HTTPException(503, f"{req.provider} isn't available right now.")

    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    try:
        instrument = await provider.verify_instrument(req.reference)
    except payments.PaymentError as exc:
        logger.warning("payment instrument verification failed: %s", exc)
        raise HTTPException(
            402,
            "We couldn't verify that payment method. Check the details and try again.",
        ) from exc

    identifier = await _trial_identifier(session, tenant.id, principal.user_id)
    key = trial.trial_key(identifier, instrument.fingerprint)
    reg = registrable_domain(identifier)
    is_domain_trial = bool(reg and not is_free_mail(reg))

    existing = None
    related: list[trial.LedgerEntry] = []
    row: DomainTrialLedger | None = None
    if is_domain_trial:
        row = await session.get(DomainTrialLedger, reg)
        if row is not None:
            existing = _to_entry(row)
        # Related-domain / shared-instrument soft flag (§12.7).
        if instrument.fingerprint:
            fp_rows = (
                (
                    await session.execute(
                        select(DomainTrialLedger).where(
                            DomainTrialLedger.payment_fingerprint
                            == instrument.fingerprint
                        )
                    )
                )
                .scalars()
                .all()
            )
            related = [_to_entry(r) for r in fp_rows if r.registrable_domain != reg]

    settings = get_settings()
    decision = trial.evaluate(
        identifier=identifier,
        existing=existing,
        related_entries=related,
        payment_fingerprint=instrument.fingerprint,
        trial_days=settings.trial_days,
    )

    # THE GATE. Verification of an instrument OBJECT is not payment authorisation
    # — a Stripe PaymentMethod is mintable client-side with the publishable key
    # and any Luhn-valid number, and none of the API-only acquirers charge here
    # either. Entitlement therefore opens only from a provider whose
    # verification IS authorisation (the dev sandbox) — for everything real, the
    # verified PAID webhook (`stripe_webhook` → `_activate_paid_plan`) is the
    # single source of entitlement.
    gate_passed = bool(provider.grants_entitlement) or bool(tenant.payment_method_ok)
    if provider.grants_entitlement:
        tenant.payment_method_ok = True

    # This tenant's own trial (started at signup) is not abuse — a customer adding
    # a card mid-trial must never be told "already used".
    own_trial = row is not None and row.first_tenant_id == tenant.id
    eligibility = "active" if own_trial else decision.eligibility.value
    trial_allowed = True if own_trial else decision.allowed

    now = datetime.now(UTC)
    started_trial = False
    # The signup trial already set the dates and ledger row, so this is a no-op on
    # the common path; it only fires for a tenant that reached billing without a
    # trial yet (e.g. a domain whose trial was used before this tenant existed).
    # Gated the same way as the gate itself: a trial is an entitlement.
    if provider.grants_entitlement and decision.allowed and tenant.trial_started_at is None:
        if is_domain_trial and row is None:
            session.add(
                DomainTrialLedger(
                    registrable_domain=reg,
                    first_trial_at=now,
                    first_tenant_id=tenant.id,
                    outcome="active",
                    payment_fingerprint=instrument.fingerprint,
                )
            )
        tenant.trial_started_at = now
        tenant.trial_ends_at = now + timedelta(days=settings.trial_days)
        started_trial = True
    elif own_trial and row is not None and instrument.fingerprint and not row.payment_fingerprint:
        # Backfill the fingerprint now that we have one — keeps the anti-abuse lock
        # meaningful for a trial that started before any card was on file.
        row.payment_fingerprint = instrument.fingerprint

    await session.commit()

    return {
        "gate_passed": gate_passed,
        # Real card rails open the gate through hosted Checkout + the paid
        # webhook; tell the client where to go instead of pretending.
        "next": None if gate_passed else "checkout",
        "trial_key": key,
        "eligibility": eligibility,
        "trial_allowed": trial_allowed,
        "trial_started": started_trial,
        "trial_ends_at": tenant.trial_ends_at.isoformat()
        if tenant.trial_ends_at
        else None,
        "reason": decision.reason,
        "instrument": {
            "provider": instrument.provider,
            "brand": instrument.brand,
            "last4": instrument.last4,
            "reusable": instrument.reusable,
            # The fingerprint is anti-abuse state, never returned to the client.
        },
    }


def _to_entry(row: DomainTrialLedger) -> trial.LedgerEntry:
    return trial.LedgerEntry(
        registrable_domain=row.registrable_domain,
        first_trial_at=row.first_trial_at,
        outcome=row.outcome,
        payment_fingerprint=row.payment_fingerprint,
        override_by=str(row.override_by) if row.override_by else None,
    )


class SeatsRequest(BaseModel):
    count: int = Field(ge=1, le=500, description="how many extra mailbox seats to buy")
    provider: str
    reference: str = Field(min_length=1, max_length=256)


@router.post("/seats")
async def buy_mailbox_seats(
    req: SeatsRequest, principal: OwnerUser, session: Session
) -> dict:
    """Buy additional mailbox seats on top of the plan's included allowance.

    Same instrument-verification model as `/confirm`: the payment method is
    verified, then the tenant's capacity grows by `count`. This is what an admin
    is sent to when a mailbox add hits the plan cap."""
    provider = payments.provider_for(req.provider)
    if provider is None or not provider.is_configured():
        raise HTTPException(503, f"{req.provider} isn't available right now.")
    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    if not provider.grants_entitlement:
        # Instrument verification is not a payment (see /confirm). Seats are
        # capacity — granting them for a client-mintable card object handed out
        # unlimited free mailboxes. Card seats ride the Stripe subscription
        # instead: at checkout, then PUT /billing/seats.
        raise HTTPException(
            409,
            "Add extra mailboxes at checkout, or from Billing once your plan is "
            "active. Nothing was charged.",
        )
    try:
        await provider.verify_instrument(req.reference)
    except payments.PaymentError as exc:
        logger.warning("payment instrument verification failed: %s", exc)
        raise HTTPException(
            402,
            "We couldn't verify that payment method. Check the details and try again.",
        ) from exc

    tenant.extra_mailbox_seats = (tenant.extra_mailbox_seats or 0) + req.count
    tenant.payment_method_ok = True
    await session.commit()
    return {
        "extra_mailbox_seats": tenant.extra_mailbox_seats,
        "purchased": req.count,
    }


# ── Stripe hosted Checkout (the real card flow) ──────────────────────────────
_PAID_PLANS = {"essential", "complete"}


#: Billing terms the checkout offers. Monthly stays the default: annual prepay is
#: genuinely hard for a small finance team, and penalising it would cost us the
#: customers this product is for.
TERMS = ("monthly", "annual")


def _price_for(plan: str, term: str = "monthly") -> str | None:
    s = get_settings()
    if term == "annual":
        return {
            "essential": s.stripe_price_essential_annual,
            "complete": s.stripe_price_complete_annual,
        }.get(plan)
    return {"essential": s.stripe_price_essential, "complete": s.stripe_price_complete}.get(plan)


def _extra_price_for(plan: str, term: str = "monthly") -> str | None:
    """The per-seat Stripe Price for mailboxes beyond the plan's included five."""
    s = get_settings()
    if term == "annual":
        return {
            "essential": s.stripe_price_extra_mailbox_essential_annual,
            "complete": s.stripe_price_extra_mailbox_complete_annual,
        }.get(plan)
    return {
        "essential": s.stripe_price_extra_mailbox_essential,
        "complete": s.stripe_price_extra_mailbox_complete,
    }.get(plan)


def _plan_for_price(price_id: str | None) -> str | None:
    """Map a Stripe Price back to the plan it grants — across EVERY term.

    This is the entitlement path: `_apply_subscription` uses it to decide what a
    subscription is for. Miss a term here and an annual customer's
    `subscription.created` webhook resolves to no plan, so someone who has paid
    for a year is silently left on Guard. Adding a term means adding it here.
    """
    if not price_id:
        return None
    for plan in _PAID_PLANS:
        for term in TERMS:
            if _price_for(plan, term) == price_id:
                return plan
    return None


def _is_extra_price(price_id: str | None) -> bool:
    return bool(price_id) and price_id in {
        _extra_price_for(p, t) for p in _PAID_PLANS for t in TERMS
    }


def _item_price(item: dict) -> str | None:
    price = item.get("price")
    return price.get("id") if isinstance(price, dict) else price


def _subscription_items(sub: dict) -> list[dict]:
    return list(((sub.get("items") or {}).get("data")) or [])


def _term_of(sub: dict) -> str:
    """Which term this subscription is on, read off its own Price IDs.

    Stripe refuses to mix billing intervals on one subscription, so a seat or
    plan change has to reuse the term already there. Derived rather than stored:
    a `billing_term` column would be a second copy of a fact Stripe owns, and the
    copy is what goes stale after a change made in the Stripe dashboard.
    """
    annual = {
        _price_for(p, "annual") for p in _PAID_PLANS
    } | {_extra_price_for(p, "annual") for p in _PAID_PLANS}
    # Drop unset settings. An env file with `ENVELOCK_..._ANNUAL=` yields the
    # empty string, not None, so discarding only None would leave "" in the set —
    # harmless today because a Stripe id is never empty, and exactly the kind of
    # thing that stops being harmless when someone reuses this set.
    annual = {pid for pid in annual if pid}
    for item in _subscription_items(sub):
        if _item_price(item) in annual:
            return "annual"
    return "monthly"


def _apply_subscription(tenant: Tenant, sub: dict) -> None:
    """Mirror a Stripe subscription onto the tenant — Stripe is the source of
    truth for what is paid for. The plan comes from the plan-priced item, the
    extra seats from the per-seat items. Unknown prices are left alone rather
    than guessed at."""
    if sub.get("id"):
        tenant.stripe_subscription_id = sub["id"]
    items = _subscription_items(sub)
    if not items:
        return
    plan: str | None = None
    extra = 0
    for item in items:
        pid = _item_price(item)
        if (matched := _plan_for_price(pid)) is not None:
            plan = matched
        elif _is_extra_price(pid):
            extra += int(item.get("quantity") or 0)
    if plan:
        tenant.plan = plan
    tenant.extra_mailbox_seats = extra
    # Mirror when this period ends and whether it will renew, so the expiry
    # warnings have a date without calling Stripe on every scheduler tick.
    # `cancel_at_period_end` is what turns a calm "renews on the 14th" notice
    # into a countdown: it is the difference between a charge and a cut-off.
    period_end = sub.get("current_period_end")
    if isinstance(period_end, int):
        tenant.subscription_period_end = datetime.fromtimestamp(period_end, UTC)
    tenant.subscription_cancel_at_period_end = bool(sub.get("cancel_at_period_end"))


async def _apply_subscription_change(
    stripe: payments.HostedCheckoutProvider,
    sub_id: str,
    *,
    items: list[dict[str, str]],
    charge_now: bool,
    tenant_id: object,
    what: str,
) -> None:
    """Write items to a live subscription, blaming the card only when Stripe
    actually declined it.

    Every caller that charges a customer goes through here. Split across callers
    this logic drifted: one path told a customer with a perfectly good card to
    update it because Stripe had rejected OUR request with a 400.
    """
    try:
        await stripe.update_subscription(sub_id, items=items, charge_now=charge_now)
    except payments.PaymentError as exc:
        if exc.card_declined:
            logger.warning("%s declined for tenant %s: %s", what, tenant_id, exc)
            raise HTTPException(
                402,
                f"The payment for {what} didn't go through, so nothing changed. "
                "Update your card under Manage billing and try again.",
            ) from exc
        logger.error("%s FAILED for tenant %s (not a decline): %s", what, tenant_id, exc)
        raise HTTPException(
            502,
            f"We couldn't change {what} just now. Nothing was charged and nothing "
            "changed — please try again, and contact support if it keeps happening.",
        ) from exc


#: Statuses Stripe will still let us bill against. Anything else is finished:
#: its items are frozen, and a write to it fails with a 400 that has nothing to
#: do with the customer's card.
_BILLABLE_STATUSES = ("active", "trialing", "past_due", "unpaid", "incomplete")


async def _live_subscription(
    session: AsyncSession, tenant: Tenant, stripe: payments.HostedCheckoutProvider
) -> dict:
    """The subscription we may actually charge for this tenant.

    A stored id can go stale: the customer re-subscribed through Checkout and a
    webhook was missed, or an orphan was cancelled. Writing to a cancelled
    subscription is rejected by Stripe with `invalid_canceled_subscription_fields`
    — a 400 that used to surface to the customer as "update your card". So look
    up the live one Stripe knows about before giving up, and only then refuse.
    """
    sub_id = tenant.stripe_subscription_id or ""
    sub: dict | None = None
    if sub_id:
        try:
            sub = await stripe.get_subscription(sub_id)
        except payments.PaymentError as exc:
            logger.warning("subscription %s could not be loaded: %s", sub_id, exc)
    if sub is not None and sub.get("status") in _BILLABLE_STATUSES:
        return sub

    logger.error(
        "tenant %s points at subscription %r with status %r — looking for the "
        "live one before refusing.",
        tenant.id,
        sub_id,
        (sub or {}).get("status"),
    )
    if await _adopt_existing_subscription(session, tenant):
        replacement = tenant.stripe_subscription_id or ""
        if replacement and replacement != sub_id:
            return await _stripe_call(
                stripe.get_subscription(replacement), "load your subscription"
            )
    raise HTTPException(
        409,
        "We can't find an active subscription for your workspace, so there's "
        "nothing to change. Nothing was charged. Start a plan on the billing "
        "page, or contact support if you believe you're already paying.",
    )


async def _stripe_call[T](call: Awaitable[T], what: str) -> T:
    """A Stripe request that isn't a charge. Stripe being down or rejecting the
    request is reported as such, never as an unhandled 500."""
    try:
        return await call
    except payments.PaymentError as exc:
        logger.warning("stripe %s failed: %s", what, exc)
        raise HTTPException(
            502,
            f"Our payment provider couldn't {what} just now. Nothing was charged — "
            "please try again in a minute.",
        ) from exc


def _stripe_or_503() -> payments.HostedCheckoutProvider:
    stripe = payments.hosted_checkout_provider("stripe")
    if stripe is None or not stripe.is_configured():
        raise HTTPException(503, "Card billing isn't available right now.")
    return stripe


async def _mailboxes_in_use(session: AsyncSession, tenant_id: UUID) -> int:
    from envelock.api.tenants import _mailbox_count

    return await _mailbox_count(session, tenant_id)


#: Stripe Checkout only accepts a trial end at least 48 hours out.
_MIN_CHECKOUT_TRIAL = timedelta(hours=49)


def _checkout_trial_end(tenant: Tenant) -> int | None:
    """Envelock's own trial end as a Stripe trial, so the first charge lands
    when the trial ends (what the billing page promises), not at checkout."""
    ends = tenant.trial_ends_at
    if ends is None:
        return None
    if ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    if ends - datetime.now(UTC) < _MIN_CHECKOUT_TRIAL:
        return None
    return int(ends.timestamp())


async def _adopt_existing_subscription(session: AsyncSession, tenant: Tenant) -> bool:
    """Reconcile a subscription Stripe is billing that we never recorded.

    Best effort: if the lookup fails we proceed to checkout rather than block a
    customer from paying, because the ordinary path still has the guard above.
    """
    stripe = payments.provider_for("stripe")
    finder = getattr(stripe, "find_live_subscription_for_tenant", None)
    if finder is None:
        return False
    try:
        sub = await finder(str(tenant.id))
    except Exception as exc:  # noqa: BLE001 — never block a payment over this
        logger.warning("could not check Stripe for an existing subscription: %s", exc)
        return False
    if not sub:
        return False

    logger.error(
        "tenant %s has a live Stripe subscription (%s) we had no record of — "
        "adopting it. A webhook was missed; without this the customer would have "
        "paid a second time.",
        tenant.id,
        sub.get("id"),
    )
    _apply_subscription(tenant, sub)
    # `_apply_subscription` mirrors plan and seats but not entitlement: that is
    # normally set by the checkout event we never received.
    tenant.payment_method_ok = True
    if customer := sub.get("customer"):
        tenant.stripe_customer_id = customer if isinstance(customer, str) else customer.get("id")
    await session.commit()
    return True


async def _primary_domain(session: AsyncSession, tenant_id: UUID) -> str | None:
    return (
        await session.execute(
            select(Domain.registrable_domain)
            .where(Domain.tenant_id == tenant_id)
            .order_by(Domain.created_at.asc())
            .limit(1)
        )
    ).scalar_one_or_none()


class CheckoutRequest(BaseModel):
    plan: str = Field(description="essential | complete")
    extra_mailboxes: int = Field(
        default=0, ge=0, le=500, description="mailboxes beyond the plan's included five"
    )
    term: str = Field(
        default="monthly",
        description="monthly | annual (annual is the same plan at the annual discount)",
    )


@router.post("/checkout")
async def create_checkout(
    req: CheckoutRequest, principal: OwnerUser, session: Session
) -> dict:
    """Start a hosted Stripe Checkout for a paid plan and return the redirect URL.

    The card is entered on Stripe's own page (no card data touches us). On success
    Stripe fires `checkout.session.completed` to our webhook, which is what
    actually flips the plan on — see `stripe_webhook`.
    """
    plan = req.plan.strip().lower()
    if plan not in _PAID_PLANS:
        raise HTTPException(422, "choose the Essential or Complete plan")
    term = req.term.strip().lower()
    if term not in TERMS:
        raise HTTPException(422, "choose a monthly or annual term")

    stripe = payments.hosted_checkout_provider("stripe")
    if stripe is None or not stripe.is_configured():
        raise HTTPException(503, "Card checkout isn't available right now.")
    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    if tenant.stripe_subscription_id:
        # A second Checkout opens a second subscription — billed twice.
        raise HTTPException(
            409,
            "You already have a subscription. Change your plan or mailbox seats "
            "on this page instead — you won't be billed twice.",
        )

    # The guard above trusts OUR record, and our record is written by the webhook.
    # So the one situation it cannot cover is the one that matters: a checkout
    # that succeeded while the webhook was failing. The customer sees no plan,
    # pays again, and is billed twice — which is exactly what happened on staging,
    # twice, before anyone noticed two live subscriptions on one tenant.
    #
    # So ask Stripe, which is the source of truth for what is being billed. If it
    # already has a live subscription for this tenant, adopt it rather than just
    # refusing: that repairs the missed webhook instead of leaving the customer
    # stuck looking at a plan they have already paid for.
    adopted = await _adopt_existing_subscription(session, tenant)
    if adopted:
        raise HTTPException(
            409,
            "You already have an active subscription — we've just reconnected it "
            "to your workspace. Reload this page; you have not been charged twice.",
        )

    extra_items: list[tuple[str, int]] = []
    if req.extra_mailboxes:
        extra_price = _extra_price_for(plan, term)
        if not extra_price:
            raise HTTPException(
                503,
                "Extra mailboxes can't be bought online right now — check out "
                "without them, or contact support.",
            )
        extra_items.append((extra_price, req.extra_mailboxes))
    price_id = _price_for(plan, term)
    if not price_id:
        # Never silently fall back to the monthly Price: that would charge a
        # month for what the customer chose to pay for a year, on our terms.
        logger.warning("no %s checkout price configured for plan %s", term, plan)
        raise HTTPException(
            503,
            f"The {plan.capitalize()} plan isn't available for checkout "
            f"{'annually' if term == 'annual' else 'right now'} — "
            "please contact support.",
        )

    user = await session.get(User, principal.user_id)
    domain = await _primary_domain(session, principal.tenant_id)
    base = get_settings().public_base_url.rstrip("/")
    checkout = await _stripe_call(
        stripe.create_checkout_session(
            price_id=price_id,
            customer_email=user.email if user else "",
            # Stripe substitutes the real id into {CHECKOUT_SESSION_ID} on redirect.
            success_url=f"{base}/billing?status=success&session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{base}/billing?status=cancel",
            client_reference_id=str(principal.tenant_id),
            metadata={
                "tenant_id": str(principal.tenant_id),
                "plan": plan,
                "domain": domain or "",
                "extra_mailboxes": str(req.extra_mailboxes),
            },
            extra_items=extra_items,
            trial_end=_checkout_trial_end(tenant),
            customer_id=tenant.stripe_customer_id,
        ),
        "start checkout",
    )
    return {"url": checkout.url, "id": checkout.id}


async def _activate_paid_plan(
    session: AsyncSession,
    *,
    tenant_id: str,
    plan: str | None,
    domain: str | None,
    customer_id: str | None = None,
    subscription_id: str | None = None,
    extra_mailboxes: str | None = None,
) -> bool:
    """Open the gate and set the plan after a verified payment. Idempotent — Stripe
    retries webhooks, and setting these fields twice is harmless."""
    try:
        tid = UUID(tenant_id)
    except (ValueError, TypeError):
        return False
    tenant = await session.get(Tenant, tid)
    if tenant is None:
        return False

    # Read before the flag is set: Stripe retries webhooks, and without this
    # every retry would look like a fresh activation and send the email again.
    newly_paid = not tenant.payment_method_ok
    tenant.payment_method_ok = True
    if plan in _PAID_PLANS:
        tenant.plan = plan
    if customer_id and not tenant.stripe_customer_id:
        tenant.stripe_customer_id = customer_id
    if subscription_id:
        tenant.stripe_subscription_id = subscription_id
    if extra_mailboxes and extra_mailboxes.isdigit():
        tenant.extra_mailbox_seats = int(extra_mailboxes)

    now = datetime.now(UTC)
    reg = registrable_domain(domain or "")
    if reg and not is_free_mail(reg):
        row = await session.get(DomainTrialLedger, reg)
        if row is None:
            session.add(
                DomainTrialLedger(
                    registrable_domain=reg,
                    first_trial_at=now,
                    first_tenant_id=tenant.id,
                    outcome="active",
                )
            )
    if tenant.trial_started_at is None:
        tenant.trial_started_at = now
        tenant.trial_ends_at = now + timedelta(days=get_settings().trial_days)
    # A new paid period starts here, so the previous period's "expires soon"
    # warnings are spent. Clearing the mark is what lets the next period warn.
    tenant.renewal_reminder_days = None

    await session.commit()
    if newly_paid:
        from envelock.notify.account import app_url, notify_admins, plan_label, plan_title

        named = plan_label(tenant.plan)
        await notify_admins(
            session,
            tenant.id,
            subject=f"{plan_title(tenant.plan)} is active",
            heading=f"{plan_title(tenant.plan)} is active",
            preheader="Your payment went through — mailbox protection is on.",
            paragraphs=[
                f"Your payment went through and {named} is now active.",
                "Mailbox protection stays on for as long as the plan is.",
            ],
            text=(
                f"Your payment went through and {named} is now active.\n\n"
                f"Open your dashboard:\n{app_url('/dashboard')}"
            ),
            cta_label="Open my dashboard",
            cta_url=app_url("/dashboard"),
            footnote="You can change plan, seats or card at any time in Billing.",
        )
    return True


@router.post("/stripe/webhook", dependencies=[SystemScoped])
async def stripe_webhook(request: Request, session: Session) -> dict:
    """Stripe's server-to-server confirmation — the source of truth for activation.

    The signature is verified against the endpoint's signing secret before any
    state changes, so a forged or replayed POST is rejected. Only
    `checkout.session.completed` activates a plan.

    `SystemScoped` on this one route, not the router: Stripe calls it with no
    session, and it finds the tenant from the customer id in the payload. Under
    RLS with no tenant bound, that lookup matches nothing and the UPDATE touches
    zero rows — so a customer would pay, Stripe would report success, and the
    plan would silently never activate. The signature check above is what
    authenticates the caller; the rest of this router stays enforced, because
    every other route there serves a signed-in tenant its own billing data.
    """
    settings = get_settings()
    secret = (
        settings.stripe_webhook_secret.get_secret_value()
        if settings.stripe_webhook_secret
        else ""
    )
    payload = await request.body()
    sig = request.headers.get("stripe-signature")
    try:
        event = payments.verify_stripe_webhook(payload, sig, secret)
    except payments.WebhookError as exc:
        # Loud, because of what it means. Stripe retries a rejected webhook for
        # days and then gives up, and every one of these is a payment that will
        # never activate or a cancellation that will never downgrade. A 400 in an
        # access log is not a signal anybody reads; this is.
        logger.error(
            "Stripe webhook REJECTED (%s). Stripe is being told to go away, so "
            "payments are not activating and cancellations are not downgrading. "
            "The usual cause is ENVELOCK_STRIPE_WEBHOOK_SECRET not matching the "
            "signing secret of the endpoint in the Stripe dashboard%s.",
            exc,
            " — and it is currently unset" if not secret else "",
        )
        raise HTTPException(400, f"webhook verification failed: {exc}") from exc

    etype = event.get("type")
    obj = (event.get("data") or {}).get("object") or {}
    meta = obj.get("metadata") or {}

    if etype in ("checkout.session.completed", "checkout.session.async_payment_succeeded"):
        # `completed` fires even when the payment has NOT settled — delayed rails
        # (ACH debit, SEPA, boleto) complete the session with
        # payment_status="unpaid" and only later succeed or fail. Activating on
        # `completed` alone granted a paid plan for a payment that could bounce.
        # Activate only on a settled session; the async_payment_succeeded event
        # covers the delayed rails, and a later failure never activated anything.
        if obj.get("payment_status") in ("paid", "no_payment_required"):
            await _activate_paid_plan(
                session,
                tenant_id=obj.get("client_reference_id") or meta.get("tenant_id") or "",
                plan=meta.get("plan"),
                domain=meta.get("domain"),
                customer_id=obj.get("customer"),
                subscription_id=obj.get("subscription"),
                extra_mailboxes=meta.get("extra_mailboxes"),
            )
        else:
            logger.info(
                "checkout session %s completed with payment_status=%s — awaiting settlement",
                obj.get("id"),
                obj.get("payment_status"),
            )
    elif etype == "checkout.session.async_payment_failed":
        logger.warning(
            "async payment failed for checkout session %s (tenant %s) — no activation",
            obj.get("id"),
            meta.get("tenant_id"),
        )
    elif etype in ("customer.subscription.created", "customer.subscription.updated"):
        # Plan or seat changes made anywhere (this app, the Stripe portal, the
        # Stripe dashboard) land here, so what we grant always matches what the
        # customer is billed for.
        if obj.get("status") in ("active", "trialing", "past_due"):
            tenant = await _tenant_for_event(
                session, tenant_id=meta.get("tenant_id"), customer_id=obj.get("customer")
            )
            if tenant is not None and tenant.stripe_subscription_id in (None, obj.get("id")):
                _apply_subscription(tenant, obj)
                await session.commit()
        elif obj.get("status") in ("unpaid", "canceled", "incomplete_expired"):
            # A subscription that ends does not always arrive as `deleted`: when
            # dunning is configured to "mark unpaid" rather than cancel, Stripe
            # keeps the subscription and only changes its status. Relying on
            # `deleted` alone therefore leaves a switch in the Stripe dashboard
            # that silently hands every non-paying customer the full plan forever.
            await _downgrade_to_guard(
                session,
                tenant_id=meta.get("tenant_id"),
                customer_id=obj.get("customer"),
                subscription_id=obj.get("id"),
            )
    elif etype in ("invoice.paid", "invoice.payment_succeeded"):
        # A renewal charge settled. Nothing to change — the subscription events
        # already carry plan and seats — but the customer gets told what came off
        # their card, which is the difference between a receipt and a surprise.
        # `billing_reason` filters out the first invoice, whose "plan is active"
        # email `_activate_paid_plan` has already sent.
        if obj.get("billing_reason") == "subscription_cycle":
            tenant = await _tenant_for_event(
                session, tenant_id=meta.get("tenant_id"), customer_id=obj.get("customer")
            )
            if tenant is not None:
                # A new period has begun, so the last one's warnings are spent.
                tenant.renewal_reminder_days = None
                await session.commit()
                await _notify_renewal_paid(session, tenant, obj)
    elif etype == "invoice.payment_failed":
        # The card was declined. Stripe will retry on its own schedule, and the
        # plan stays live meanwhile — but if nobody tells the customer, the first
        # they hear of it is protection stopping, which reads as us breaking.
        tenant = await _tenant_for_event(
            session, tenant_id=meta.get("tenant_id"), customer_id=obj.get("customer")
        )
        if tenant is not None:
            await _notify_payment_failed(session, tenant, obj)
    elif etype == "customer.subscription.deleted":
        # Subscription ended (canceled or lapsed) → fall back to Guard (free).
        # Never locked out — Guard keeps domain/brand monitoring on.
        await _downgrade_to_guard(
            session,
            tenant_id=meta.get("tenant_id"),
            customer_id=obj.get("customer"),
            subscription_id=obj.get("id"),
        )

    return {"received": True}


def _invoice_amount(invoice: dict) -> str:
    """"$49.00" from Stripe's integer cents, or "" when the payload is odd.

    Stripe reports zero-decimal currencies (JPY, KRW) in whole units, so
    dividing by 100 there would understate the charge a hundredfold. Rather
    than carry that table, an unrecognised shape yields an empty string and the
    email simply omits the amount — a receipt with no figure is recoverable, a
    receipt with the wrong figure is not.
    """
    cents = invoice.get("amount_paid")
    if cents is None:
        cents = invoice.get("amount_due")
    currency = (invoice.get("currency") or "").upper()
    if not isinstance(cents, int) or not currency:
        return ""
    if currency in {"JPY", "KRW", "VND", "CLP", "ISK"}:
        return f"{cents:,} {currency}"
    symbol = {"USD": "$", "EUR": "€", "GBP": "£"}.get(currency, "")
    body = f"{cents / 100:,.2f}"
    return f"{symbol}{body}" if symbol else f"{body} {currency}"


async def _notify_seats_changed(
    session: AsyncSession, tenant: Tenant, *, before: int, after: int
) -> None:
    """Confirm a seat change in writing, because it moved money.

    Adding seats charges the card the moment the button is pressed. Saying
    nothing leaves a charge the customer did not expect and cannot check
    against anything — and if someone else in the workspace made the change,
    the people who can act on it never hear about it at all.
    """
    from envelock.notify.account import app_url, notify_admins

    added = after - before
    capacity = included_mailbox_seats(tenant.plan) + after
    if added > 0:
        noun = "mailbox" if added == 1 else "mailboxes"
        subject = f"{added} more {noun} added to your Envelock plan"
        heading = f"{added} {noun} added"
        money = (
            "Your card was charged the prorated difference for the rest of this "
            "billing period. The exact amount is on the invoice in Billing."
        )
    else:
        noun = "mailbox" if added == -1 else "mailboxes"
        subject = f"{-added} {noun} released from your Envelock plan"
        heading = f"{-added} {noun} released"
        money = (
            "Nothing was charged. The unused time is credited against your next "
            "invoice."
        )
    counts = f"You can now protect {capacity} mailboxes ({before} → {after} extra seats)."
    await notify_admins(
        session,
        tenant.id,
        subject=subject,
        heading=heading,
        preheader=counts,
        paragraphs=[counts, money],
        text=f"{counts}\n\n{money}\n\nInvoices and receipts:\n{app_url('/billing')}",
        cta_label="View invoices",
        cta_url=app_url("/billing"),
        footnote="Change plan, seats or card at any time in Billing.",
    )


async def _notify_plan_changed(
    session: AsyncSession, tenant: Tenant, *, before: str, after: str
) -> None:
    """Confirm a plan change in writing. An upgrade is charged on the spot."""
    from envelock.notify.account import app_url, notify_admins, plan_title

    upgrade = _PLAN_ORDER.index(after) > _PLAN_ORDER.index(before)
    moved = f"Your workspace moved from {plan_title(before)} to {plan_title(after)}."
    money = (
        "Your card was charged the prorated difference for the rest of this billing "
        "period. The exact amount is on the invoice in Billing."
        if upgrade
        else "Nothing was charged. The difference is credited against your next invoice."
    )
    await notify_admins(
        session,
        tenant.id,
        subject=f"Your Envelock plan is now {plan_title(after)}",
        heading=f"Now on {plan_title(after)}",
        preheader=moved,
        paragraphs=[moved, money],
        text=f"{moved}\n\n{money}\n\nInvoices and receipts:\n{app_url('/billing')}",
        cta_label="View invoices",
        cta_url=app_url("/billing"),
        footnote="Change plan, seats or card at any time in Billing.",
    )


async def _notify_renewal_paid(session: AsyncSession, tenant: Tenant, invoice: dict) -> None:
    from envelock.notify.account import app_url, notify_admins, plan_label, plan_title

    amount = _invoice_amount(invoice)
    named = plan_label(tenant.plan)
    charged = f"{amount} " if amount else ""
    await notify_admins(
        session,
        tenant.id,
        subject=f"Envelock renewed — {amount}" if amount else "Your Envelock plan renewed",
        heading=f"{plan_title(tenant.plan)} renewed",
        preheader=f"{charged}charged. Protection continues uninterrupted.",
        paragraphs=[
            f"{plan_title(tenant.plan)} renewed and {charged}was charged to your card."
            if amount
            else f"{plan_title(tenant.plan)} renewed successfully.",
            "Protection continues uninterrupted. Nothing for you to do.",
        ],
        text=(
            f"{named} renewed and {charged}was charged to your card.\n\n"
            f"Invoices and receipts:\n{app_url('/billing')}"
        ),
        cta_label="View invoices",
        cta_url=app_url("/billing"),
        footnote="Change plan, seats or card at any time in Billing.",
    )


async def _notify_payment_failed(session: AsyncSession, tenant: Tenant, invoice: dict) -> None:
    from envelock.notify.account import app_url, notify_admins

    amount = _invoice_amount(invoice)
    of = f" of {amount}" if amount else ""
    await notify_admins(
        session,
        tenant.id,
        subject="Your Envelock payment failed — action needed",
        heading="Your payment failed",
        preheader="Update your card to keep mailbox protection on.",
        paragraphs=[
            f"We couldn't take your Envelock payment{of}. Your card may have "
            "expired, been replaced, or been declined.",
            "Protection is still on. We'll retry automatically — but if the "
            "payment keeps failing, your workspace drops to Guard (free) and "
            "mailbox protection stops.",
        ],
        text=(
            f"We couldn't take your Envelock payment{of}.\n\n"
            "Protection is still on and we'll retry automatically. If the payment "
            "keeps failing, your workspace drops to Guard (free) and mailbox "
            "protection stops.\n\n"
            f"Update your card:\n{app_url('/billing')}"
        ),
        cta_label="Update my card",
        cta_url=app_url("/billing"),
        footnote="You are never locked out — your data and settings are kept either way.",
    )


async def _tenant_for_event(
    session: AsyncSession, *, tenant_id: str | None, customer_id: str | None
) -> Tenant | None:
    """The tenant a Stripe event is about: the metadata tenant_id, or failing
    that the Stripe customer id."""
    tenant: Tenant | None = None
    if tenant_id:
        try:
            tenant = await session.get(Tenant, UUID(tenant_id))
        except (ValueError, TypeError):
            tenant = None
    if tenant is None and customer_id:
        tenant = (
            await session.execute(
                select(Tenant).where(Tenant.stripe_customer_id == customer_id)
            )
        ).scalar_one_or_none()
    return tenant


async def _has_another_live_subscription(tenant: Tenant, *, ended: str) -> bool:
    """Whether Stripe is still billing this tenant on some OTHER subscription.

    Fail closed on purpose: if we cannot reach Stripe we report False and the
    downgrade proceeds, because the alternative is granting a paid plan to
    someone who cancelled whenever Stripe is unreachable.
    """
    stripe = payments.provider_for("stripe")
    finder = getattr(stripe, "find_live_subscription_for_tenant", None)
    if finder is None:
        return False
    try:
        sub = await finder(str(tenant.id))
    except Exception as exc:  # noqa: BLE001 — a lookup failure is not a grant
        logger.warning("could not confirm the end of %s with Stripe: %s", ended, exc)
        return False
    return bool(sub and sub.get("id") and sub["id"] != ended)


async def _downgrade_to_guard(
    session: AsyncSession,
    *,
    tenant_id: str | None,
    customer_id: str | None,
    subscription_id: str | None = None,
) -> bool:
    """Drop a tenant to Guard when their subscription ends. Idempotent."""
    tenant = await _tenant_for_event(session, tenant_id=tenant_id, customer_id=customer_id)
    if tenant is None:
        return False
    if (
        subscription_id
        and tenant.stripe_subscription_id
        and tenant.stripe_subscription_id != subscription_id
    ):
        # An old subscription ending must not cancel the one they pay for now.
        return False
    if subscription_id and await _has_another_live_subscription(
        tenant, ended=subscription_id
    ):
        # Our stored id can be the stale one: a duplicate subscription was
        # cancelled, and nothing corrected the pointer afterwards. The id check
        # above then MATCHES the dead subscription and we would cut off a
        # customer who is still paying — Stripe is the authority on that, so ask
        # it before taking protection away.
        logger.error(
            "ignoring the end of subscription %s for tenant %s: Stripe still has "
            "a live subscription for them. Our stored id was stale.",
            subscription_id,
            tenant.id,
        )
        return False
    was_paid = tenant.payment_method_ok
    tenant.plan = "guard"
    tenant.payment_method_ok = False
    tenant.stripe_subscription_id = None
    tenant.extra_mailbox_seats = 0
    tenant.renewal_reminder_days = None
    await session.commit()
    if was_paid:
        from envelock.notify.account import app_url, notify_admins

        await notify_admins(
            session,
            tenant.id,
            subject="Your Envelock plan has ended — mailbox protection is off",
            heading="Your plan has ended",
            preheader="Mailbox protection has stopped. Domain monitoring continues.",
            paragraphs=[
                "Your subscription has ended, so your workspace has dropped to "
                "Guard (free).",
                "Domain and brand monitoring continue. Mailbox protection has "
                "stopped — new mail is no longer being checked.",
            ],
            text=(
                "Your Envelock subscription has ended, so your workspace has "
                "dropped to Guard (free).\n\n"
                "Domain and brand monitoring continue. Mailbox protection has "
                "stopped.\n\n"
                f"Restart a plan:\n{app_url('/billing')}"
            ),
            cta_label="Restart my plan",
            cta_url=app_url("/billing"),
            footnote=(
                "Your data and settings are kept — restarting a plan turns "
                "protection back on without reconnecting anything."
            ),
        )
    return True


# ── Changing a live Stripe subscription ─────────────────────────────────────
_PLAN_ORDER = ("essential", "complete")


class SetSeatsRequest(BaseModel):
    extra_mailboxes: int = Field(ge=0, le=500, description="total seats beyond the plan's five")


@router.put("/seats")
async def set_mailbox_seats(
    req: SetSeatsRequest, principal: OwnerUser, session: Session
) -> dict:
    """Set how many extra mailbox seats the tenant pays for, on its Stripe
    subscription. More seats are charged (prorated) right away and granted only
    once that payment succeeds; fewer seats are credited on the next invoice."""
    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")
    if not tenant.stripe_subscription_id:
        raise HTTPException(
            409, "Start your plan first — you can add extra mailboxes at checkout."
        )
    stripe = _stripe_or_503()
    used = await _mailboxes_in_use(session, tenant.id)
    floor = max(0, used - included_mailbox_seats(tenant.plan))
    if req.extra_mailboxes < floor:
        raise HTTPException(
            409,
            f"You're protecting {used} mailboxes, so you need at least {floor} "
            f"extra seat{'' if floor == 1 else 's'}. Remove mailboxes first, then "
            "reduce seats.",
        )
    current = tenant.extra_mailbox_seats or 0
    if req.extra_mailboxes == current:
        # Not an error, but the customer clicked a button and nothing moved, so
        # say so rather than returning a success that looks like a no-op.
        logger.info(
            "seat change for tenant %s was a no-op: already at %d seats",
            tenant.id,
            current,
        )
    if req.extra_mailboxes != current:
        sub = await _live_subscription(session, tenant, stripe)
        # The seat Price has to match the subscription's own interval: Stripe will
        # not hold a monthly line and a yearly line together, and defaulting to
        # monthly would bill an annual customer on our terms rather than theirs.
        extra_price = _extra_price_for(tenant.plan, _term_of(sub))
        if not extra_price:
            raise HTTPException(
                503,
                "Extra mailboxes can't be bought online right now — contact support.",
            )
        seat_items = [i for i in _subscription_items(sub) if _is_extra_price(_item_price(i))]
        ops: list[dict[str, str]] = []
        if seat_items:
            head, *rest = seat_items
            if req.extra_mailboxes:
                ops.append(
                    {"id": head["id"], "price": extra_price, "quantity": str(req.extra_mailboxes)}
                )
            else:
                ops.append({"id": head["id"], "deleted": "true"})
            ops.extend({"id": i["id"], "deleted": "true"} for i in rest)
        elif req.extra_mailboxes:
            ops.append({"price": extra_price, "quantity": str(req.extra_mailboxes)})
        if ops:
            await _apply_subscription_change(
                stripe,
                sub["id"],
                items=ops,
                charge_now=req.extra_mailboxes > current,
                tenant_id=tenant.id,
                what="the extra mailboxes",
            )
        tenant.extra_mailbox_seats = req.extra_mailboxes
        await session.commit()
        logger.info(
            "seats changed for tenant %s: %d -> %d (%s)",
            tenant.id,
            current,
            req.extra_mailboxes,
            extra_price,
        )
        await _notify_seats_changed(
            session, tenant, before=current, after=req.extra_mailboxes
        )
    return {
        "extra_mailbox_seats": tenant.extra_mailbox_seats,
        "capacity": included_mailbox_seats(tenant.plan) + tenant.extra_mailbox_seats,
    }


async def change_subscription_plan(session: AsyncSession, tenant: Tenant, target: str) -> None:
    """Move a Stripe subscriber to another paid plan by swapping the price on the
    subscription they already have. An upgrade is charged (prorated) before it
    is granted; a downgrade is credited. Used by /tenant/plan — without this, a
    paying Essential customer could switch to Complete for free."""
    if target == tenant.plan:
        return
    if target not in _PAID_PLANS:
        raise HTTPException(
            409,
            "To stop paying, cancel under Manage billing. You keep your plan until "
            "the end of the period you've paid for, then move to Guard (free).",
        )
    stripe = _stripe_or_503()
    sub = await _live_subscription(session, tenant, stripe)
    # Keep them on the term they bought: an annual subscriber switching plan must
    # land on the annual Price, not be quietly moved to monthly billing.
    term = _term_of(sub)
    new_price = _price_for(target, term)
    if not new_price:
        raise HTTPException(503, f"The {target.capitalize()} plan isn't available right now.")
    ops: list[dict[str, str]] = []
    for item in _subscription_items(sub):
        pid = _item_price(item)
        if _plan_for_price(pid):
            ops.append({"id": item["id"], "price": new_price})
        elif _is_extra_price(pid):
            seat_price = _extra_price_for(target, term)
            if not seat_price:
                raise HTTPException(
                    503, "Additional mailbox pricing for this plan is unavailable. "
                    "Your subscription has not changed. Contact support.",
                )
            ops.append({"id": item["id"], "price": seat_price})
    if not ops:
        raise HTTPException(
            409, "We couldn't find your plan on the subscription — contact support."
        )
    upgrade = tenant.plan not in _PLAN_ORDER or (
        _PLAN_ORDER.index(target) > _PLAN_ORDER.index(tenant.plan)
    )
    await _apply_subscription_change(
        stripe,
        sub["id"],
        items=ops,
        charge_now=upgrade,
        tenant_id=tenant.id,
        what="the new plan",
    )
    tenant.plan = target


class PortalRequest(BaseModel):
    return_path: str = Field(default="/billing", max_length=200)


@router.post("/portal")
async def billing_portal(
    req: PortalRequest, principal: OwnerUser, session: Session
) -> dict:
    """Open the Stripe-hosted billing portal for the tenant's customer so they can
    update the card, view invoices, or cancel — all self-service."""
    stripe = payments.hosted_checkout_provider("stripe")
    if stripe is None or not stripe.is_configured():
        raise HTTPException(503, "billing portal isn't enabled on this deployment")
    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None or not tenant.stripe_customer_id:
        raise HTTPException(409, "no billing account yet — add a payment method first")
    # Only allow returning to an in-app path, never an arbitrary absolute URL.
    path = req.return_path if req.return_path.startswith("/") else "/billing"
    base = get_settings().public_base_url.rstrip("/")
    url = await _stripe_call(
        stripe.create_billing_portal_session(
            customer_id=tenant.stripe_customer_id, return_url=f"{base}{path}"
        ),
        "open the billing portal",
    )
    return {"url": url}
