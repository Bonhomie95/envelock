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


def _price_for(plan: str) -> str | None:
    s = get_settings()
    return {"essential": s.stripe_price_essential, "complete": s.stripe_price_complete}.get(plan)


def _extra_price_for(plan: str) -> str | None:
    """The per-seat Stripe Price for mailboxes beyond the plan's included five."""
    s = get_settings()
    return {
        "essential": s.stripe_price_extra_mailbox_essential,
        "complete": s.stripe_price_extra_mailbox_complete,
    }.get(plan)


def _plan_for_price(price_id: str | None) -> str | None:
    if not price_id:
        return None
    for plan in _PAID_PLANS:
        if _price_for(plan) == price_id:
            return plan
    return None


def _is_extra_price(price_id: str | None) -> bool:
    return bool(price_id) and price_id in {_extra_price_for(p) for p in _PAID_PLANS}


def _item_price(item: dict) -> str | None:
    price = item.get("price")
    return price.get("id") if isinstance(price, dict) else price


def _subscription_items(sub: dict) -> list[dict]:
    return list(((sub.get("items") or {}).get("data")) or [])


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
    extra_items: list[tuple[str, int]] = []
    if req.extra_mailboxes:
        extra_price = _extra_price_for(plan)
        if not extra_price:
            raise HTTPException(
                503,
                "Extra mailboxes can't be bought online right now — check out "
                "without them, or contact support.",
            )
        extra_items.append((extra_price, req.extra_mailboxes))
    price_id = _price_for(plan)
    if not price_id:
        logger.warning("no checkout price configured for plan %s", plan)
        raise HTTPException(
            503,
            f"The {plan.capitalize()} plan isn't available for checkout right now — "
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

    await session.commit()
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
    tenant.plan = "guard"
    tenant.payment_method_ok = False
    tenant.stripe_subscription_id = None
    tenant.extra_mailbox_seats = 0
    await session.commit()
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
    extra_price = _extra_price_for(tenant.plan)
    if not extra_price:
        raise HTTPException(
            503, "Extra mailboxes can't be bought online right now — contact support."
        )
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
    if req.extra_mailboxes != current:
        sub = await _stripe_call(
            stripe.get_subscription(tenant.stripe_subscription_id), "load your subscription"
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
        try:
            if ops:
                await stripe.update_subscription(
                    tenant.stripe_subscription_id,
                    items=ops,
                    charge_now=req.extra_mailboxes > current,
                )
        except payments.PaymentError as exc:
            logger.warning("seat change failed for tenant %s: %s", tenant.id, exc)
            raise HTTPException(
                402,
                "The payment for the extra mailboxes didn't go through, so nothing "
                "changed. Update your card under Manage billing and try again.",
            ) from exc
        tenant.extra_mailbox_seats = req.extra_mailboxes
        await session.commit()
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
    new_price = _price_for(target)
    if not new_price:
        raise HTTPException(503, f"The {target.capitalize()} plan isn't available right now.")
    sub_id = tenant.stripe_subscription_id or ""
    sub = await _stripe_call(stripe.get_subscription(sub_id), "load your subscription")
    ops: list[dict[str, str]] = []
    for item in _subscription_items(sub):
        pid = _item_price(item)
        if _plan_for_price(pid):
            ops.append({"id": item["id"], "price": new_price})
        elif _is_extra_price(pid) and (seat_price := _extra_price_for(target)):
            ops.append({"id": item["id"], "price": seat_price})
    if not ops:
        raise HTTPException(
            409, "We couldn't find your plan on the subscription — contact support."
        )
    upgrade = tenant.plan not in _PLAN_ORDER or (
        _PLAN_ORDER.index(target) > _PLAN_ORDER.index(tenant.plan)
    )
    try:
        await stripe.update_subscription(sub_id, items=ops, charge_now=upgrade)
    except payments.PaymentError as exc:
        logger.warning("plan change failed for tenant %s: %s", tenant.id, exc)
        raise HTTPException(
            402,
            "The payment for the new plan didn't go through, so your plan hasn't "
            "changed. Update your card under Manage billing and try again.",
        ) from exc
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
