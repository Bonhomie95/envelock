"""Does Stripe charge what the pricing page says? Verified, not assumed.

`pricing.py` decides what a plan costs. Stripe decides what the customer is
actually billed. Nothing connected the two: the code only ever handed Stripe a
Price ID and trusted whatever amount sat behind it. A Price created with the
wrong figure, or two env vars pointing at the same Product, produces a perfectly
healthy-looking deployment that bills the wrong number — and the first report of
it is a customer's statement.

That is not hypothetical. Checked against the test account that drives this
deployment, both configured Prices were wrong in two ways at once:

    ENVELOCK_STRIPE_PRICE_ESSENTIAL -> product "Essential", $49.00/month
    ENVELOCK_STRIPE_PRICE_COMPLETE  -> product "Essential", $98.00/month

Both exactly double their intended price, and both pointing at the same Product,
so every invoice would also have been titled "Essential". Nothing in the product
noticed, because nothing looked.

Best effort and never fatal: a Stripe outage must not stop the API from starting
and protecting mail. A mismatch is logged at ERROR with both figures, which is
the one thing that makes it findable before a customer finds it.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def expected_prices() -> dict[str, tuple[int, str, str]]:
    """setting name -> (expected cents, interval, human label).

    The monthly plan Price carries the WHOLE plan — platform fee plus the five
    included seats — because that is what the subscription's first line is. Extra
    seats are their own per-unit Price.
    """
    from envelock.billing.pricing import (
        EXTRA_MAILBOX_CENTS,
        PLATFORM_CENTS,
        TERM_DISCOUNT,
        BillingTerm,
        Plan,
        included_mailbox_seats,
    )

    out: dict[str, tuple[int, str, str]] = {}
    annual_off = TERM_DISCOUNT[BillingTerm.ANNUAL]
    for plan in (Plan.ESSENTIAL, Plan.COMPLETE):
        seat = EXTRA_MAILBOX_CENTS[plan]
        whole = PLATFORM_CENTS[plan] + included_mailbox_seats(plan.value) * seat
        name = plan.value
        out[f"stripe_price_{name}"] = (whole, "month", f"{name} plan, monthly")
        out[f"stripe_price_extra_mailbox_{name}"] = (
            seat,
            "month",
            f"{name} extra mailbox, monthly",
        )
        yearly = (whole - int(whole * annual_off)) * 12
        yearly_seat = (seat - int(seat * annual_off)) * 12
        out[f"stripe_price_{name}_annual"] = (yearly, "year", f"{name} plan, annual")
        out[f"stripe_price_extra_mailbox_{name}_annual"] = (
            yearly_seat,
            "year",
            f"{name} extra mailbox, annual",
        )
    return out


async def check_stripe_prices() -> list[dict]:
    """Compare every configured Price against `pricing.py`. Returns the problems."""
    from envelock.billing import payments
    from envelock.config import get_settings

    # Every exit path below says something. Silence used to mean any of four
    # different things — no Stripe key, no prices set, the task collected before
    # it ran, or everything fine — and an operator grepping the log could not
    # tell which. That ambiguity is the failure this module exists to remove, so
    # it must not reappear in the module itself.
    stripe = payments.provider_for("stripe")
    if stripe is None or not stripe.is_configured():
        logger.warning(
            "Stripe prices NOT verified: no Stripe secret key is configured in "
            "this process, so nothing checked that we charge what the pricing "
            "page says. Card checkout is unavailable here too."
        )
        return []
    # Only Stripe can answer "what does this Price actually charge", and the
    # shared PaymentProvider protocol has no business growing a method for it.
    get_price = getattr(stripe, "get_price", None)
    if get_price is None:
        logger.warning(
            "Stripe prices NOT verified: the configured provider cannot retrieve "
            "a Price."
        )
        return []

    settings = get_settings()
    problems: list[dict] = []
    seen: dict[str, str] = {}

    for setting, (want_cents, want_interval, label) in expected_prices().items():
        price_id = getattr(settings, setting, None)
        if not price_id:
            continue  # Unset is handled where it is used, with an honest 503.
        if price_id in seen:
            problems.append(
                {
                    "setting": setting,
                    "problem": "duplicate",
                    "detail": f"same Price as {seen[price_id]}",
                }
            )
            logger.error(
                "Stripe price misconfigured: %s and %s are the SAME Price (%s), so "
                "one of the two plans bills at the other's rate.",
                seen[price_id],
                setting,
                price_id,
            )
            continue
        seen[price_id] = setting

        try:
            price = await get_price(price_id)
        except Exception as exc:  # noqa: BLE001 — never fail boot over this
            logger.warning("could not verify Stripe price %s (%s): %s", setting, price_id, exc)
            continue

        got_cents = price.get("unit_amount")
        got_interval = (price.get("recurring") or {}).get("interval")
        if got_cents != want_cents or got_interval != want_interval:
            problems.append(
                {
                    "setting": setting,
                    "problem": "amount",
                    "expected_cents": want_cents,
                    "actual_cents": got_cents,
                    "expected_interval": want_interval,
                    "actual_interval": got_interval,
                }
            )
            logger.error(
                "Stripe price misconfigured: %s (%s) charges %s per %s, but %s is "
                "$%.2f per %s. Customers on this plan are billed the wrong amount. "
                "Fix the Price in the Stripe dashboard, or point the setting at the "
                "right one.",
                setting,
                price_id,
                f"${got_cents / 100:.2f}" if got_cents is not None else "nothing",
                got_interval or "?",
                label,
                want_cents / 100,
                want_interval,
            )

    # A Price nobody can pay for is as useless as a wrong one. Stripe confirms a
    # payment server-to-server, and that POST is authenticated ONLY by the
    # signing secret — without it `stripe_webhook` rejects every call with a 400,
    # so the customer is charged, Stripe reports success, and the plan never
    # turns on. Nothing else in the system would notice until someone complained
    # that they had paid and nothing happened.
    if not settings.stripe_webhook_secret:
        problems.append({"setting": "stripe_webhook_secret", "problem": "missing"})
        logger.error(
            "Stripe is configured for checkout but ENVELOCK_STRIPE_WEBHOOK_SECRET "
            "is not set. Stripe confirms payment through that webhook and it is "
            "signed — unsigned calls are rejected, so NO payment can activate a "
            "plan. Customers would be charged and get nothing."
        )

    if not seen:
        logger.warning(
            "Stripe prices NOT verified: no Price IDs are configured, so no plan "
            "can be bought. Set ENVELOCK_STRIPE_PRICE_* (see .env.example)."
        )
    elif not problems:
        logger.info("Stripe prices verified: %d match the pricing table", len(seen))
    return problems


#: The events this deployment acts on. `api/billing.stripe_webhook` ignores
#: everything else, and without these Stripe simply never tells us what happened.
#: `checkout.session.completed` is the one that ACTIVATES a paid plan and
#: `customer.subscription.deleted` is the one that ENDS it — a Stripe endpoint
#: created from the dashboard's default subscription preset carries neither, so
#: payments succeed and activate nothing, and cancellations never downgrade.
REQUIRED_WEBHOOK_EVENTS = frozenset(
    {
        "checkout.session.completed",
        "checkout.session.async_payment_succeeded",
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "invoice.paid",
        "invoice.payment_failed",
    }
)


def _key_is_test() -> bool:
    from envelock.config import get_settings

    key = get_settings().stripe_secret_key
    return bool(key) and key.get_secret_value().startswith("sk_test")


async def check_webhook_events() -> list[str]:
    """Which events we act on that Stripe will never send us.

    Found the hard way: a real test payment succeeded and the plan did not turn
    on, because the endpoint had eighteen events enabled and not one of them was
    `checkout.session.completed`. Everything else looked perfect — correct
    Prices, correct secret, endpoint enabled, right URL.
    """
    from envelock.billing import payments

    stripe = payments.provider_for("stripe")
    if stripe is None or not stripe.is_configured():
        return []
    lister = getattr(stripe, "list_webhook_endpoints", None)
    if lister is None:
        return []

    try:
        body = await lister()
    except Exception as exc:  # noqa: BLE001 — never fail boot over this
        logger.warning("could not check which Stripe webhook events are enabled: %s", exc)
        return []

    # Which Stripe MODE this deployment is in, and whether the endpoints belong
    # to it. Test and live are separate worlds with separate endpoints and
    # separate signing secrets, and the dashboard shows whichever mode its toggle
    # is set to — so copying "the" signing secret from the wrong one produces an
    # endpoint that looks perfect and rejects every delivery. Nothing in the
    # product said which mode it was in, which is what made that invisible.
    all_endpoints = body.get("data", [])
    key_is_live = not _key_is_test()
    wrong_mode = [e for e in all_endpoints if bool(e.get("livemode")) != key_is_live]
    logger.info(
        "Stripe mode: %s (%d webhook endpoint(s) in this mode)",
        "LIVE" if key_is_live else "TEST",
        len(all_endpoints) - len(wrong_mode),
    )
    if wrong_mode:
        logger.warning(
            "%d Stripe webhook endpoint(s) belong to the other mode and will "
            "never receive this deployment's events. Their signing secrets will "
            "not validate here either.",
            len(wrong_mode),
        )

    endpoints = [
        e
        for e in all_endpoints
        if e.get("status") == "enabled" and bool(e.get("livemode")) == key_is_live
    ]
    if not endpoints:
        logger.error(
            "Stripe has NO enabled webhook endpoint, so nothing can tell us a "
            "payment succeeded. Customers would be charged and never activated."
        )
        return sorted(REQUIRED_WEBHOOK_EVENTS)

    # Any one endpoint carrying an event is enough — Stripe delivers to all.
    delivered: set[str] = set()
    for e in endpoints:
        events = set(e.get("enabled_events", []))
        delivered |= REQUIRED_WEBHOOK_EVENTS if "*" in events else events

    missing = sorted(REQUIRED_WEBHOOK_EVENTS - delivered)
    if missing:
        logger.error(
            "Stripe will never send %d event(s) this deployment acts on: %s. "
            "%sAdd them to the endpoint in the Stripe dashboard.",
            len(missing),
            ", ".join(missing),
            (
                "Without `checkout.session.completed` a successful payment "
                "activates nothing. "
                if "checkout.session.completed" in missing
                else ""
            ),
        )
    else:
        logger.info(
            "Stripe webhook events verified: all %d we act on are enabled",
            len(REQUIRED_WEBHOOK_EVENTS),
        )
    return missing


__all__ = [
    "REQUIRED_WEBHOOK_EVENTS",
    "check_stripe_prices",
    "check_webhook_events",
    "expected_prices",
]
