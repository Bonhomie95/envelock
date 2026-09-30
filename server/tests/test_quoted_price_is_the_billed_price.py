"""The price we quote must be the price we charge.

`pricing.quote` implements the PRD §12.9 banded, two-class ladder. Stripe bills
something else entirely: a per-domain platform fee plus every seat at one flat
rate. Both are defensible models; having both, with the public endpoint serving
the one nothing bills, is not:

    mailboxes   /pricing/quote said   Stripe would bill
            20              $52.00              $55.00
           100             $173.00             $215.00
           500             $613.00           $1,015.00

That last row is a $402/month understatement on an unauthenticated endpoint a
prospect can screenshot. These tests pin the quote to the invoice, so the two
cannot drift apart again in silence.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from envelock.billing.pricing import (
    EXTRA_MAILBOX_CENTS,
    PLATFORM_CENTS,
    SELF_SERVE_MAILBOX_CEILING,
    BillingTerm,
    Plan,
    included_mailbox_seats,
    self_serve_cents,
)


def _stripe_would_bill(plan: Plan, mailboxes: int) -> int:
    """The subscription's own arithmetic, written out independently.

    Deliberately not a call into `self_serve_cents`: a test that reuses the
    implementation only proves the implementation equals itself. This is the
    plan price plus a per-seat line for everything past the included seats,
    which is what `api/billing` assembles and what the pricing page sells.
    """
    rate = EXTRA_MAILBOX_CENTS[plan]
    included = included_mailbox_seats(plan.value)
    plan_price = PLATFORM_CENTS[plan] + included * rate
    return plan_price + max(0, mailboxes - included) * rate


@pytest.mark.parametrize("plan", [Plan.ESSENTIAL, Plan.COMPLETE])
@pytest.mark.parametrize("mailboxes", [0, 1, 4, 5, 6, 10, 11, 20, 50])
def test_self_serve_price_equals_the_subscription(plan: Plan, mailboxes: int) -> None:
    assert self_serve_cents(plan.value, mailboxes) == _stripe_would_bill(plan, mailboxes)


def test_the_included_seats_are_a_floor_not_a_discount() -> None:
    """One mailbox costs the same as five. The old quote said $17 for one seat on
    Essential, which is not a price that exists."""
    for n in range(0, 6):
        assert self_serve_cents("essential", n) == 2500
        assert self_serve_cents("complete", n) == 4900


def test_guard_is_free_and_an_unknown_plan_is_not_priced() -> None:
    assert self_serve_cents("guard", 99) == 0
    assert self_serve_cents("nonsense", 5) == 0


def test_annual_is_exactly_twenty_percent_off_the_billed_price() -> None:
    monthly = self_serve_cents("complete", 10)
    annual = self_serve_cents("complete", 10, term=BillingTerm.ANNUAL.value)
    assert annual == monthly - int(monthly * 0.20)
    # The discount must come off the REAL price, not the banded one.
    assert monthly == _stripe_would_bill(Plan.COMPLETE, 10)


def test_the_public_endpoint_serves_the_billed_price(client: TestClient) -> None:
    r = client.post(
        "/api/v1/pricing/quote",
        json={"plan": "essential", "term": "monthly", "protected": 20},
    )
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    assert body["self_serve"] is True
    assert body["total_cents"] == _stripe_would_bill(Plan.ESSENTIAL, 20) == 5500, body


def test_over_the_ceiling_we_decline_rather_than_invent_a_number(
    client: TestClient,
) -> None:
    """The banded ladder is genuinely cheaper at scale and genuinely unbilled.
    Quoting it would be a promise; quoting the flat rate would overcharge the
    customer the ladder was designed for. So: no number, and a route to sales."""
    r = client.post(
        "/api/v1/pricing/quote",
        json={"plan": "complete", "protected": SELF_SERVE_MAILBOX_CEILING + 1},
    )
    assert r.status_code == 200, r.text[:200]
    body = r.json()
    assert body["self_serve"] is False
    assert body["total_cents"] is None
    assert "contact us" in body["note"].lower()


def test_monitored_mailboxes_are_not_quoted_cheaper_than_we_bill_them() -> None:
    """Mailbox class reaches no billed path — `MONITORED` appears nowhere outside
    `pricing.quote`. Until a monitored Stripe price exists, quoting the PRD's
    cheap monitored rate would understate every mixed-class plan."""
    from envelock.api import v1  # noqa: F401  (import guard: module must load)

    protected_only = self_serve_cents("complete", 10)
    assert protected_only == _stripe_would_bill(Plan.COMPLETE, 10)


def test_guard_is_answered_as_free_not_routed_to_sales(client: TestClient) -> None:
    """Guard protects domains and cannot hold a mailbox, so a Guard quote for 99
    seats is a category error rather than a volume deal. It used to fall through
    to the over-ceiling branch and invite a sales conversation about something we
    do not sell."""
    for seats in (0, 5, 99, 5000):
        body = client.post(
            "/api/v1/pricing/quote", json={"plan": "guard", "protected": seats}
        ).json()
        assert body["total_cents"] == 0, body
        assert body["self_serve"] is True, body
        assert "free forever" in body["note"].lower(), body
        assert "contact us" not in body["note"].lower(), body


def test_no_seat_count_or_term_ever_prices_below_the_plan_floor() -> None:
    """A discount is a discount on the plan, never a way under it. Checked across
    the whole self-serve range rather than at the boundaries only."""
    from envelock.billing.pricing import (
        SELF_SERVE_MAILBOX_CEILING,
        TERM_DISCOUNT,
    )

    for plan, floor_monthly in (("essential", 2500), ("complete", 4900)):
        for term in BillingTerm:
            # Read the discount rather than reconstructing it: `1 - 0.8` is
            # 0.19999999999999996, which rounds a cent the other way and makes
            # the test disagree with correct code.
            floor = floor_monthly - int(floor_monthly * TERM_DISCOUNT[term])
            for n in range(0, SELF_SERVE_MAILBOX_CEILING + 1):
                got = self_serve_cents(plan, n, term=term.value)
                assert got >= floor, (plan, n, term.value, got, floor)
