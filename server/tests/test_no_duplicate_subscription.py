"""A customer must never end up paying for two subscriptions at once.

`create_checkout` refuses a second checkout when `tenant.stripe_subscription_id`
is set — and that field is written by the webhook, so the guard is blind in
exactly the situation that produces duplicates: a checkout that succeeded while
the webhook was failing. The customer sees no plan, pays again, and is billed
twice.

That is not hypothetical. It happened on staging: two live subscriptions on one
tenant at $470.40/year each, created minutes apart, because a signature mismatch
was silently rejecting every delivery.

So the second guard asks Stripe, which is the source of truth for what is being
billed — and adopts what it finds, because refusing alone would leave the
customer staring at a plan they have already paid for.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.billing import payments
from envelock.config import get_settings
from envelock.main import app

PW = "correct horse battery staple 9"
PRICES = {
    "ENVELOCK_STRIPE_PRICE_ESSENTIAL": "price_ess",
    "ENVELOCK_STRIPE_PRICE_COMPLETE": "price_cmp",
}


class _Stripe:
    """Records what was asked of Stripe, and can hold an 'existing' subscription."""

    def __init__(self) -> None:
        self.existing: dict | None = None
        self.checkouts = 0
        self.search_failed = False

    async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002
        if "/subscriptions/search" in url:
            if self.search_failed:
                raise payments.PaymentError("stripe search is down")
            return {"data": [self.existing] if self.existing else []}
        if "checkout/sessions" in url:
            self.checkouts += 1
            return {"id": "cs_new", "url": "https://checkout.stripe.com/c/pay/cs_new"}
        return {}


@pytest.fixture
def stripe(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Stripe]:
    monkeypatch.setenv("ENVELOCK_STRIPE_SECRET_KEY", "sk_test_x")
    for k, v in PRICES.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    fake = _Stripe()
    payments.set_default_transport(fake)
    yield fake
    payments.set_default_transport(None)
    get_settings.cache_clear()


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _signup(client: TestClient, slug: str) -> tuple[dict, str]:
    email = f"owner@{slug}.example"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": slug},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    tokens = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": slug, "domain": f"{slug}.example"},
        headers=h,
    )
    return h, client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]


def _live_sub(tenant_id: str) -> dict:
    return {
        "id": "sub_already",
        "status": "trialing",
        "customer": "cus_already",
        "metadata": {"tenant_id": tenant_id, "plan": "complete"},
        "items": {"data": [{"id": "si_1", "price": {"id": "price_cmp"}, "quantity": 1}]},
    }


def test_a_missed_webhook_does_not_let_a_customer_pay_twice(
    client: TestClient, stripe: _Stripe
) -> None:
    """The staging failure, reproduced: Stripe is billing, we never recorded it,
    and the customer clicks pay again."""
    h, tid = _signup(client, "dupe-co")
    stripe.existing = _live_sub(tid)

    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 409, r.text[:200]
    assert stripe.checkouts == 0, "a second subscription was opened"
    assert "not been charged twice" in r.json()["detail"]


def test_the_adopted_subscription_actually_activates_the_plan(
    client: TestClient, stripe: _Stripe
) -> None:
    """Refusing alone would leave them looking at a plan they had paid for."""
    h, tid = _signup(client, "adopt-co")
    stripe.existing = _live_sub(tid)

    client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)

    body = client.get("/api/v1/tenant", headers=h).json()
    assert body["plan"] == "complete", body
    assert body["trial"]["payment_method_ok"] is True, (
        "adopted the subscription but not the entitlement, so the plan would "
        "still evaporate when the trial clock ran out"
    )
    assert body["billing"]["subscription"] is True
    assert body["features"]["identity_detections"] is True


def test_a_tenant_with_no_subscription_still_reaches_checkout(
    client: TestClient, stripe: _Stripe
) -> None:
    """The guard must not block the ordinary first purchase."""
    h, _tid = _signup(client, "first-co")
    stripe.existing = None

    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 200, r.text[:200]
    assert stripe.checkouts == 1
    assert r.json()["url"].startswith("https://checkout.stripe.com/")


def test_a_failing_lookup_does_not_stop_someone_paying(
    client: TestClient, stripe: _Stripe
) -> None:
    """Availability over perfection: if Stripe's search is down we let the
    customer buy. The duplicate is rare and recoverable; refusing every payment
    during a Stripe incident is neither."""
    h, _tid = _signup(client, "searchdown-co")
    stripe.search_failed = True

    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 200, r.text[:200]
    assert stripe.checkouts == 1


def test_a_cancelled_subscription_is_not_adopted(
    client: TestClient, stripe: _Stripe
) -> None:
    """Only something Stripe is actually billing counts. Adopting a cancelled
    subscription would hand out a paid plan for free."""
    h, tid = _signup(client, "cancelled-co")
    dead = _live_sub(tid)
    dead["status"] = "canceled"
    stripe.existing = dead

    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 200, "a cancelled subscription blocked a real purchase"
    # `plan` proves nothing here: a fresh signup is ALREADY on Complete, because
    # the trial runs on the top plan. Entitlement is what adoption would grant.
    body = client.get("/api/v1/tenant", headers=h).json()
    assert body["trial"]["payment_method_ok"] is False, (
        "a cancelled subscription was adopted, handing out a paid plan for free"
    )
    assert body["billing"]["subscription"] is False
