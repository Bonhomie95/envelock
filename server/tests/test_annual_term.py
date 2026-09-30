"""Annual billing, and the two ways adding a term breaks a paying customer.

`TERM_DISCOUNT` has defined a 20% annual discount since the pricing engine was
written, and nothing could sell it: checkout took no term at all. Annual prepay
is what funds the ~113 days a business customer takes to be worth $1k/month, so
it is worth having — but a term is not a cosmetic option. Two failures it can
cause, both silent, both tested here:

1. **The webhook stops recognising the plan.** `_plan_for_price` maps a Stripe
   Price back to the plan it grants. Knowing only monthly IDs, an annual
   subscriber's `subscription.created` resolves to nothing and someone who has
   paid for a year sits on Guard.
2. **A term gets mixed on one subscription.** Stripe will not hold a monthly line
   and a yearly line together, and a seat or plan change that defaults to monthly
   would bill an annual customer on our terms instead of theirs.
"""

from __future__ import annotations

import pytest

from envelock.api import billing
from envelock.billing.pricing import self_serve_cents

ANNUAL_IDS = {
    "stripe_price_essential_annual": "price_ess_yr",
    "stripe_price_complete_annual": "price_cmp_yr",
    "stripe_price_extra_mailbox_essential_annual": "price_ess_seat_yr",
    "stripe_price_extra_mailbox_complete_annual": "price_cmp_seat_yr",
}
MONTHLY_IDS = {
    "stripe_price_essential": "price_ess_mo",
    "stripe_price_complete": "price_cmp_mo",
    "stripe_price_extra_mailbox_essential": "price_ess_seat_mo",
    "stripe_price_extra_mailbox_complete": "price_cmp_seat_mo",
}


@pytest.fixture
def prices(monkeypatch):  # noqa: ANN001, ANN201
    for field, value in {**MONTHLY_IDS, **ANNUAL_IDS}.items():
        monkeypatch.setenv(f"ENVELOCK_{field.upper()}", value)
    from envelock.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _sub(*price_ids: str) -> dict:
    return {"items": {"data": [{"id": f"si_{i}", "price": {"id": p}}
                               for i, p in enumerate(price_ids)]}}


def test_an_annual_price_still_maps_to_its_plan(prices) -> None:  # noqa: ARG001
    """The failure that would leave a year's payment on Guard."""
    assert billing._plan_for_price("price_cmp_yr") == "complete"
    assert billing._plan_for_price("price_ess_yr") == "essential"
    # And monthly still works.
    assert billing._plan_for_price("price_cmp_mo") == "complete"
    assert billing._plan_for_price(None) is None
    assert billing._plan_for_price("price_unknown") is None


def test_annual_seat_prices_are_recognised_as_seats(prices) -> None:  # noqa: ARG001
    """Otherwise `_apply_subscription` reads a seat line as a plan line."""
    for pid in ("price_ess_seat_yr", "price_cmp_seat_yr",
                "price_ess_seat_mo", "price_cmp_seat_mo"):
        assert billing._is_extra_price(pid), pid
    assert not billing._is_extra_price("price_cmp_yr")


def test_the_term_is_read_off_the_subscription(prices) -> None:  # noqa: ARG001
    assert billing._term_of(_sub("price_cmp_yr")) == "annual"
    assert billing._term_of(_sub("price_cmp_mo")) == "monthly"
    # A seat line alone is enough to identify the term.
    assert billing._term_of(_sub("price_cmp_seat_yr")) == "annual"
    # Nothing recognisable: assume monthly, which is the safe default — it is
    # what every existing subscription is.
    assert billing._term_of(_sub()) == "monthly"
    assert billing._term_of(_sub("price_mystery")) == "monthly"


def test_prices_are_resolved_per_term(prices) -> None:  # noqa: ARG001
    assert billing._price_for("complete", "annual") == "price_cmp_yr"
    assert billing._price_for("complete", "monthly") == "price_cmp_mo"
    assert billing._price_for("complete") == "price_cmp_mo"  # default
    assert billing._extra_price_for("essential", "annual") == "price_ess_seat_yr"


def test_an_unconfigured_annual_price_is_absent_not_the_monthly_one(
    monkeypatch,
) -> None:  # noqa: ANN001
    """Falling back to monthly would charge a month for a year's commitment.

    The setting is blanked explicitly rather than assumed empty: a real `.env`
    sits beside these tests and pydantic reads it, so once the annual Prices were
    configured this passed alone and failed in the suite.
    """
    from envelock.config import get_settings

    for field in (*ANNUAL_IDS, *MONTHLY_IDS):
        monkeypatch.setenv(f"ENVELOCK_{field.upper()}", "")
    get_settings.cache_clear()
    try:
        # Falsy, not necessarily None: an env file line with nothing after the
        # `=` gives the empty string. Every guard in `api/billing` is written
        # `if not price_id`, which is what makes that safe — an `is None` check
        # there would have sailed past an empty setting and handed Stripe "".
        assert not billing._price_for("complete", "annual")
        assert not billing._price_for("complete", "monthly")
        assert not billing._extra_price_for("essential", "annual")
    finally:
        get_settings.cache_clear()


def test_the_annual_discount_is_on_the_billed_price() -> None:
    """$240/yr Essential and $470.40/yr Complete — the amounts the Stripe Prices
    must carry. If these drift, the invoice and the pricing page disagree."""
    assert self_serve_cents("essential", 5, term="annual") * 12 == 24000
    assert self_serve_cents("complete", 5, term="annual") * 12 == 47040
