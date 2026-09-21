"""Extra mailbox seats and plan changes on a live Stripe subscription.

Complete and Essential each include five mailboxes; every mailbox beyond that
is a paid seat on the same subscription. These prove, against a recording fake
of Stripe's API:

* checkout carries the extra seats and Envelock's own trial end (no charge
  before the trial ends — what the billing page promises);
* a second checkout is refused (it would open a second, parallel subscription);
* more seats / an upgrade are charged BEFORE they're granted, and a declined
  card changes nothing;
* a paying customer can't switch plans by just recording the choice;
* Stripe-side changes (portal, dashboard) sync back through the webhook.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.billing import payments
from envelock.config import get_settings
from envelock.main import app

SECRET = "whsec_test"  # noqa: S105 — test secret
PRICES = {
    "ENVELOCK_STRIPE_PRICE_ESSENTIAL": "price_ess",
    "ENVELOCK_STRIPE_PRICE_COMPLETE": "price_cmp",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_ESSENTIAL": "price_ess_seat",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE": "price_cmp_seat",
}


class _Stripe:
    """Holds one subscription and applies item updates the way Stripe does."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.items: list[dict] = [{"id": "si_plan", "price": {"id": "price_cmp"}, "quantity": 1}]
        self.decline = False

    def sub(self) -> dict:
        return {"id": "sub_1", "status": "active", "items": {"data": self.items}}

    async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002
        self.calls.append((method, url, dict(data or {})))
        if "checkout/sessions" in url:
            return {"id": "cs_1", "url": "https://checkout.stripe.com/c/pay/cs_1"}
        if url.endswith("/subscriptions/sub_1") and method == "GET":
            return self.sub()
        if url.endswith("/subscriptions/sub_1") and method == "POST":
            if self.decline:
                raise payments.PaymentError("402: card_declined")
            form = data or {}
            idx = sorted({k.split("]")[0].split("[")[1] for k in form if k.startswith("items[")})
            for i in idx:
                prefix = f"items[{i}]"
                f = {
                    k.split("][")[1].rstrip("]"): v
                    for k, v in form.items()
                    if k.startswith(prefix)
                }
                if "id" in f:
                    item = next(x for x in self.items if x["id"] == f["id"])
                    if f.get("deleted") == "true":
                        self.items.remove(item)
                        continue
                    if "price" in f:
                        item["price"] = {"id": f["price"]}
                    if "quantity" in f:
                        item["quantity"] = int(f["quantity"])
                else:
                    self.items.append(
                        {"id": f"si_{len(self.items)}", "price": {"id": f["price"]},
                         "quantity": int(f["quantity"])}
                    )
            return self.sub()
        return {}

    def updates(self) -> list[dict]:
        return [d for m, u, d in self.calls if m == "POST" and u.endswith("/subscriptions/sub_1")]


@pytest.fixture
def stripe(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Stripe]:
    monkeypatch.setenv("ENVELOCK_STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", SECRET)
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


def _owner(client: TestClient, domain: str) -> tuple[dict[str, str], str]:
    email, pw = f"owner@{domain}", "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register", json={"email": email, "password": pw, "tenant_name": "Acme"}
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": "Acme", "domain": domain}, headers=h)
    return h, client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]


def _sign(payload: bytes) -> str:
    import hashlib
    import hmac

    t = str(int(time.time()))
    mac = hmac.new(SECRET.encode(), f"{t}.".encode() + payload, hashlib.sha256)
    return f"t={t},v1={mac.hexdigest()}"


def _event(client: TestClient, etype: str, obj: dict) -> None:
    payload = json.dumps({"type": etype, "data": {"object": obj}}).encode()
    r = client.post(
        "/api/v1/billing/stripe/webhook",
        content=payload,
        headers={"Stripe-Signature": _sign(payload), "Content-Type": "application/json"},
    )
    assert r.status_code == 200


def _paid(client: TestClient, tid: str, domain: str, extra: int = 0) -> None:
    _event(
        client,
        "checkout.session.completed",
        {
            "client_reference_id": tid,
            "customer": "cus_1",
            "subscription": "sub_1",
            "payment_status": "paid",
            "metadata": {"tenant_id": tid, "plan": "complete", "domain": domain,
                         "extra_mailboxes": str(extra)},
        },
    )


def _add(client: TestClient, h: dict, addr: str) -> int:
    return client.post(
        "/api/v1/mailboxes", json={"address": addr, "mailbox_class": "protected"}, headers=h
    ).status_code


def test_complete_includes_five_and_checkout_sells_the_rest(
    client: TestClient, stripe: _Stripe
) -> None:
    h, _ = _owner(client, "seats-a.example")
    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["mailboxes"]["capacity"] == 5
    assert t["billing"] == {"subscription": False, "extra_mailbox_cents": 350}

    r = client.post(
        "/api/v1/billing/checkout", json={"plan": "complete", "extra_mailboxes": 3}, headers=h
    )
    assert r.status_code == 200
    form = next(d for m, u, d in stripe.calls if "checkout/sessions" in u)
    assert form["line_items[0][price]"] == "price_cmp"
    assert form["line_items[1][price]"] == "price_cmp_seat"
    assert form["line_items[1][quantity]"] == "3"
    # The signup trial is still running, so the first charge waits for its end.
    assert int(form["subscription_data[trial_end]"]) > time.time() + 48 * 3600


def test_paid_checkout_grants_the_seats_and_blocks_a_second_checkout(
    client: TestClient, stripe: _Stripe
) -> None:
    h, tid = _owner(client, "seats-b.example")
    _paid(client, tid, "seats-b.example", extra=2)
    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["mailboxes"]["capacity"] == 7
    assert t["billing"]["subscription"] is True

    again = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert again.status_code == 409


def test_more_seats_are_charged_before_they_are_granted(
    client: TestClient, stripe: _Stripe
) -> None:
    h, tid = _owner(client, "seats-c.example")
    _paid(client, tid, "seats-c.example")

    stripe.decline = True
    r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 4}, headers=h)
    assert r.status_code == 402
    assert client.get("/api/v1/tenant", headers=h).json()["mailboxes"]["capacity"] == 5

    stripe.decline = False
    r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 4}, headers=h)
    assert r.status_code == 200 and r.json()["capacity"] == 9
    sent = stripe.updates()[-1]
    assert sent["proration_behavior"] == "always_invoice"
    assert sent["payment_behavior"] == "error_if_incomplete"
    assert any(i["price"]["id"] == "price_cmp_seat" and i["quantity"] == 4 for i in stripe.items)

    # Reducing is credited on the next invoice, not charged now.
    r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 1}, headers=h)
    assert r.status_code == 200 and r.json()["capacity"] == 6
    assert stripe.updates()[-1]["proration_behavior"] == "create_prorations"


def test_seats_cannot_drop_below_the_mailboxes_in_use(
    client: TestClient, stripe: _Stripe
) -> None:
    h, tid = _owner(client, "seats-d.example")
    _paid(client, tid, "seats-d.example", extra=2)
    for i in range(7):
        assert _add(client, h, f"box{i}@seats-d.example") == 201
    r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 1}, headers=h)
    assert r.status_code == 409
    assert "at least 2" in r.json()["detail"]


def test_a_paying_customer_changes_plan_through_stripe(
    client: TestClient, stripe: _Stripe
) -> None:
    h, tid = _owner(client, "seats-e.example")
    _paid(client, tid, "seats-e.example")

    down = client.post("/api/v1/tenant/plan", json={"plan": "essential"}, headers=h)
    assert down.status_code == 200 and down.json()["subscribed_plan"] == "essential"
    assert stripe.items[0]["price"]["id"] == "price_ess"
    assert stripe.updates()[-1]["proration_behavior"] == "create_prorations"

    # The upgrade back is charged first; a decline leaves them on Essential.
    stripe.decline = True
    up = client.post("/api/v1/tenant/plan", json={"plan": "complete"}, headers=h)
    assert up.status_code == 402
    assert client.get("/api/v1/tenant", headers=h).json()["subscribed_plan"] == "essential"

    # Guard means cancelling, which happens in the Stripe portal.
    stripe.decline = False
    guard = client.post("/api/v1/tenant/plan", json={"plan": "guard"}, headers=h)
    assert guard.status_code == 409


def test_stripe_side_changes_sync_back(client: TestClient, stripe: _Stripe) -> None:
    h, tid = _owner(client, "seats-f.example")
    _paid(client, tid, "seats-f.example")
    _event(
        client,
        "customer.subscription.updated",
        {
            "id": "sub_1",
            "customer": "cus_1",
            "status": "active",
            "metadata": {"tenant_id": tid},
            "items": {"data": [
                {"id": "si_plan", "price": {"id": "price_ess"}, "quantity": 1},
                {"id": "si_seat", "price": {"id": "price_ess_seat"}, "quantity": 6},
            ]},
        },
    )
    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["subscribed_plan"] == "essential"
    assert t["mailboxes"]["capacity"] == 11

    # An older subscription ending doesn't cancel the live one.
    _event(client, "customer.subscription.deleted",
           {"id": "sub_old", "customer": "cus_1", "metadata": {"tenant_id": tid}})
    assert client.get("/api/v1/tenant", headers=h).json()["subscribed_plan"] == "essential"

    _event(client, "customer.subscription.deleted",
           {"id": "sub_1", "customer": "cus_1", "metadata": {"tenant_id": tid}})
    t = client.get("/api/v1/tenant", headers=h).json()
    assert t["subscribed_plan"] == "guard"
    assert t["billing"]["subscription"] is False
    assert t["mailboxes"]["extra_seats"] == 0


def test_a_stripe_outage_is_reported_not_a_500(client: TestClient, stripe: _Stripe) -> None:
    class _Down:
        async def request(self, *a, **k):  # noqa: ANN002, ANN003, ANN202
            raise payments.PaymentError("503 from api.stripe.com")

    h, _ = _owner(client, "seats-g.example")
    payments.set_default_transport(_Down())
    r = client.post("/api/v1/billing/checkout", json={"plan": "complete"}, headers=h)
    assert r.status_code == 502
    assert "Nothing was charged" in r.json()["detail"]


def test_a_returning_customer_keeps_their_stripe_customer(
    client: TestClient, stripe: _Stripe
) -> None:
    h, tid = _owner(client, "seats-h.example")
    _paid(client, tid, "seats-h.example")
    _event(client, "customer.subscription.deleted",
           {"id": "sub_1", "customer": "cus_1", "metadata": {"tenant_id": tid}})
    r = client.post("/api/v1/billing/checkout", json={"plan": "essential"}, headers=h)
    assert r.status_code == 200
    form = [d for m, u, d in stripe.calls if "checkout/sessions" in u][-1]
    assert form["customer"] == "cus_1"
    assert "customer_email" not in form
