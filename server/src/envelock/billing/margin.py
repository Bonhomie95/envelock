"""Does a marginal mailbox still make money? Answered at boot, not in a meeting.

The AI judge is the only per-message variable cost in the product, and its price
is set by two knobs that live far apart: the model name (`llm/providers`) and the
monthly call cap (`config.llm_max_calls_per_mailbox_month`). Neither one knows
what a mailbox sells for.

That is the whole risk. Today's default — `gpt-4o-mini`, 200 calls — costs about
nine cents per mailbox per month at the cap, against a marginal Complete seat of
$3.50. Swapping to a frontier model without touching the cap multiplies that by
thirty or more and quietly takes an annual-discounted seat underwater, and
nothing anywhere would say so: the bill arrives from the model vendor a month
later, spread across every tenant.

So this computes the worst case and compares it to the least we would ever be
paid for that mailbox. It warns rather than refuses: a pricing concern must not
be able to take mail protection offline.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

#: Tokens per judge call, worst case. The prompt is hard-bounded — `judge.py`
#: clamps the body to 4000 characters, the subject to 500 and the sender to 320,
#: and asks for at most 300 tokens back — so this is an upper bound on a real
#: call, not an average. Characters-to-tokens at a deliberately pessimistic 3:1.
WORST_CASE_INPUT_TOKENS = 2_000
WORST_CASE_OUTPUT_TOKENS = 300

#: How much of a marginal seat's revenue the AI may consume before we say so.
#: Well under 1.0: the seat also has to cover polling, storage, reputation
#: lookups and the margin the business runs on.
AI_COGS_WARN_FRACTION = 0.25


def worst_case_ai_cents_per_mailbox_month() -> int | None:
    """Upper bound on judge spend for one mailbox in one month, or None when no
    AI provider is configured (Guard-only deployments, and the test suite)."""
    from envelock.config import get_settings
    from envelock.llm.providers import _PRICE_PER_MTOK  # noqa: PLC2701

    s = get_settings()
    if s.llm_provider == "none":
        return None
    model = {
        "anthropic": s.anthropic_model,
        "openai": s.openai_model,
        "local": s.local_llm_model,
    }.get(s.llm_provider, "")

    for prefix, (price_in, price_out) in _PRICE_PER_MTOK.items():
        if model.startswith(prefix):
            per_call = (
                WORST_CASE_INPUT_TOKENS / 1_000_000 * price_in
                + WORST_CASE_OUTPUT_TOKENS / 1_000_000 * price_out
            )
            return int(round(per_call * s.llm_max_calls_per_mailbox_month * 100))
    # A self-hosted or unpriced model: the marginal cost is our own hardware,
    # which this function cannot see and which does not scale per call.
    return None


def cheapest_marginal_seat_cents() -> int:
    """The least we are ever paid for one extra mailbox: the smallest paid plan's
    per-seat rate, on the longest term, with its discount applied."""
    from envelock.billing.pricing import EXTRA_MAILBOX_CENTS, TERM_DISCOUNT

    rate = min(EXTRA_MAILBOX_CENTS.values())
    return rate - int(rate * max(TERM_DISCOUNT.values()))


def check_ai_margin() -> dict:
    """Report (and log) whether the AI cap is safe against the cheapest seat."""
    ai = worst_case_ai_cents_per_mailbox_month()
    seat = cheapest_marginal_seat_cents()
    if ai is None:
        return {"ok": True, "reason": "no metered AI provider configured"}

    fraction = ai / seat if seat else float("inf")
    result = {
        "ok": fraction <= AI_COGS_WARN_FRACTION,
        "worst_case_ai_cents": ai,
        "cheapest_seat_cents": seat,
        "fraction_of_seat": round(fraction, 3),
    }
    if fraction > 1.0:
        logger.error(
            "AI cost exceeds seat revenue: at the %d-call cap this model can "
            "spend %.2f per mailbox per month against %.2f of revenue for the "
            "cheapest marginal seat. Every mailbox past the included five loses "
            "money. Lower ENVELOCK_LLM_MAX_CALLS_PER_MAILBOX_MONTH or use a "
            "cheaper model.",
            _cap(),
            ai / 100,
            seat / 100,
        )
    elif not result["ok"]:
        logger.warning(
            "AI cost is %.0f%% of the cheapest marginal seat (%.2f of %.2f per "
            "mailbox per month at the %d-call cap). Still profitable, but the "
            "seat also has to cover polling, storage and lookups.",
            fraction * 100,
            ai / 100,
            seat / 100,
            _cap(),
        )
    else:
        logger.info(
            "AI margin ok: worst case %.2f per mailbox-month (%.0f%% of the "
            "cheapest marginal seat at %.2f)",
            ai / 100,
            fraction * 100,
            seat / 100,
        )
    return result


def _cap() -> int:
    from envelock.config import get_settings

    return get_settings().llm_max_calls_per_mailbox_month


__all__ = [
    "check_ai_margin",
    "cheapest_marginal_seat_cents",
    "worst_case_ai_cents_per_mailbox_month",
]
