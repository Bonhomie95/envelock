"""Stripe has to charge what the pricing page says.

`pricing.py` decides what a plan costs; Stripe decides what the card is actually
debited. Nothing joined the two — the code handed Stripe a Price ID and trusted
whatever amount sat behind it — so a Price typed in wrong produced a deployment
that looked completely healthy and billed the wrong number.

This is not a hypothetical. The account driving the staging deployment had both
Prices wrong in two ways at once: each was exactly double its intended figure,
and both pointed at the same Product, so every invoice would also have been
titled "Essential".

    stripe_price_essential -> product "Essential", $49.00/month   (should be $25)
    stripe_price_complete  -> product "Essential", $98.00/month   (should be $49)
"""

from __future__ import annotations

import pytest

from envelock.billing.price_check import check_stripe_prices, expected_prices

#: Not a credential — the fake client below never calls Stripe. It only has to
#: be non-empty so `is_configured()` is true.
FAKE_KEY = "sk_test_notreal"  # noqa: S105


def test_the_expected_table_matches_the_published_pricing() -> None:
    """The figures the pricing page sells, restated independently."""
    e = expected_prices()
    assert e["stripe_price_essential"][:2] == (2500, "month")
    assert e["stripe_price_complete"][:2] == (4900, "month")
    assert e["stripe_price_extra_mailbox_essential"][:2] == (200, "month")
    assert e["stripe_price_extra_mailbox_complete"][:2] == (350, "month")
    # Annual: the monthly figure less 20%, times twelve.
    assert e["stripe_price_essential_annual"][:2] == (24000, "year")
    assert e["stripe_price_complete_annual"][:2] == (47040, "year")
    assert e["stripe_price_extra_mailbox_essential_annual"][:2] == (1920, "year")
    assert e["stripe_price_extra_mailbox_complete_annual"][:2] == (3360, "year")


class _FakeStripe:
    """Stands in for the Stripe client, returning whatever the test says."""

    id = "stripe"
    grants_entitlement = False

    def __init__(self, prices: dict) -> None:
        self._prices = prices

    def is_configured(self) -> bool:
        return True

    async def get_price(self, price_id: str) -> dict:
        return self._prices[price_id]


def _price(cents: int, interval: str = "month") -> dict:
    return {"unit_amount": cents, "recurring": {"interval": interval}}


@pytest.fixture
def stripe(monkeypatch):  # noqa: ANN001, ANN201
    def install(prices: dict, **settings: str) -> None:
        from envelock.billing import payments
        from envelock.config import get_settings

        monkeypatch.setitem(payments._PROVIDERS, "stripe", _FakeStripe(prices))
        # Blank every price setting first. A real `.env` sits beside these tests
        # and pydantic reads it, so without this the check also walks the eight
        # REAL price IDs, asks the fake client for them, and gets a KeyError that
        # the outage handler swallows — the test then passes alone and fails in
        # the suite, which is the worst way for a test to be wrong.
        for setting in expected_prices():
            monkeypatch.setenv(f"ENVELOCK_{setting.upper()}", "")
        for k, v in settings.items():
            monkeypatch.setenv(f"ENVELOCK_{k.upper()}", v)
        get_settings.cache_clear()

    yield install
    from envelock.config import get_settings

    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_correct_prices_raise_nothing(stripe, price_log) -> None:  # noqa: ANN001
    stripe(
        {"p_ess": _price(2500), "p_cmp": _price(4900)},
        stripe_secret_key=FAKE_KEY,
        stripe_price_essential="p_ess",
        stripe_price_complete="p_cmp",
    )
    assert await check_stripe_prices() == []
    assert not [m for m in price_log.messages if "misconfigured" in m], price_log.messages


@pytest.mark.asyncio
async def test_a_doubled_price_is_caught_with_both_figures(stripe, price_log) -> None:  # noqa: ANN001
    """The exact fault found in the real account."""
    stripe(
        {"p_ess": _price(4900), "p_cmp": _price(9800)},
        stripe_secret_key=FAKE_KEY,
        stripe_price_essential="p_ess",
        stripe_price_complete="p_cmp",
    )
    problems = await check_stripe_prices()
    assert len(problems) == 2, problems
    assert {p["setting"] for p in problems} == {
        "stripe_price_essential",
        "stripe_price_complete",
    }
    assert problems[0]["actual_cents"] == 4900
    assert problems[0]["expected_cents"] == 2500
    # The operator has to be able to act on the log alone.
    joined = price_log.text
    assert "$49.00" in joined and "$25.00" in joined, joined


@pytest.mark.asyncio
async def test_two_settings_sharing_one_price_is_caught(stripe, price_log) -> None:  # noqa: ANN001
    """Both plans pointing at the same Price bills one of them at the other's
    rate, and no amount check would notice: each lookup on its own is fine."""
    stripe(
        {"p_same": _price(2500)},
        stripe_secret_key=FAKE_KEY,
        stripe_price_essential="p_same",
        stripe_price_complete="p_same",
    )
    problems = await check_stripe_prices()
    assert any(p["problem"] == "duplicate" for p in problems), problems
    assert "SAME Price" in price_log.text, price_log.messages


@pytest.mark.asyncio
async def test_a_monthly_price_in_an_annual_slot_is_caught(stripe, price_log) -> None:  # noqa: ANN001
    """Right amount, wrong interval: $240 once a year and $240 every month are
    the same number and a twelvefold difference in what we collect."""
    stripe(
        {"p_yr": _price(24000, "month")},
        stripe_secret_key=FAKE_KEY,
        stripe_price_essential_annual="p_yr",
    )
    problems = await check_stripe_prices()
    assert price_log.messages
    assert problems and problems[0]["actual_interval"] == "month"
    assert problems[0]["expected_interval"] == "year"


@pytest.mark.asyncio
async def test_a_stripe_outage_does_not_fail_the_check(stripe, price_log) -> None:  # noqa: ANN001
    """Verifying prices must never stop the API starting and protecting mail."""

    class _Broken(_FakeStripe):
        async def get_price(self, price_id: str) -> dict:
            raise RuntimeError("stripe is down")

    from envelock.billing import payments
    from envelock.config import get_settings

    stripe({}, stripe_secret_key=FAKE_KEY, stripe_price_essential="p_ess")
    payments._PROVIDERS["stripe"] = _Broken({})
    get_settings.cache_clear()
    assert await check_stripe_prices() == []
    assert "could not verify" in price_log.text, price_log.messages


@pytest.mark.asyncio
async def test_no_stripe_configured_is_silent() -> None:
    from envelock.config import get_settings

    get_settings.cache_clear()
    assert await check_stripe_prices() == []


@pytest.fixture
def price_log(logged):  # noqa: ANN001, ANN201
    return logged("envelock.billing.price_check")
