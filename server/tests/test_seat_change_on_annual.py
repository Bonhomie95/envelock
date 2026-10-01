"""Changing mailbox seats on an ANNUAL subscription.

Seats were always bought monthly, so the seat Price was resolved from the plan
alone. Annual added a second interval, and Stripe refuses to hold a monthly line
and a yearly line on one subscription — so the seat Price now has to match the
term already on the subscription, read off the subscription itself.

That resolution moved after the Stripe round-trip when annual landed. This pins
the path end to end for both terms, because a seat change that silently does
nothing is indistinguishable from a dead button.
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
SECRET = "whsec_test"  # noqa: S105 — test secret
PRICES = {
    "ENVELOCK_STRIPE_PRICE_COMPLETE": "price_cmp",
    "ENVELOCK_STRIPE_PRICE_COMPLETE_ANNUAL": "price_cmp_yr",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE": "price_cmp_seat",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE_ANNUAL": "price_cmp_seat_yr",
}


class _Stripe:
    def __init__(self, plan_price: str) -> None:
        self.items = [{"id": "si_plan", "price": {"id": plan_price}, "quantity": 1}]
        self.updates: list[dict] = []

    def sub(self) -> dict:
        return {"id": "sub_1", "status": "active", "items": {"data": self.items}}

    async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002
        if "/subscriptions/search" in url:
            return {"data": []}
        if url.endswith("/subscriptions/sub_1") and method == "GET":
            return self.sub()
        if url.endswith("/subscriptions/sub_1") and method == "POST":
            form = dict(data or {})
            self.updates.append(form)
            idx = sorted({k.split("]")[0].split("[")[1] for k in form if k.startswith("items[")})
            for i in idx:
                f = {
                    k.split("][")[1].rstrip("]"): v
                    for k, v in form.items()
                    if k.startswith(f"items[{i}]")
                }
                if "id" in f:
                    item = next(x for x in self.items if x["id"] == f["id"])
                    if f.get("deleted") == "true":
                        self.items.remove(item)
                    else:
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

    def seat_prices_sent(self) -> list[str]:
        out = []
        for form in self.updates:
            out += [v for k, v in form.items() if k.endswith("[price]")]
        return out


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVELOCK_STRIPE_SECRET_KEY", "sk_test_x")
    monkeypatch.setenv("ENVELOCK_STRIPE_WEBHOOK_SECRET", SECRET)
    for k, v in PRICES.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()


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


async def _give_subscription(slug: str) -> None:
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Tenant

    with system_scope("test: a live subscription"):
        async with get_sessionmaker()() as s:
            t = (await s.execute(select(Tenant).where(Tenant.name == slug))).scalar_one()
            t.plan = "complete"
            t.payment_method_ok = True
            t.stripe_subscription_id = "sub_1"
            t.stripe_customer_id = "cus_1"
            await s.commit()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("term", "plan_price", "expected_seat_price"),
    [
        ("monthly", "price_cmp", "price_cmp_seat"),
        ("annual", "price_cmp_yr", "price_cmp_seat_yr"),
    ],
)
async def test_adding_seats_uses_the_subscriptions_own_term(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    term: str,
    plan_price: str,
    expected_seat_price: str,
) -> None:
    _env(monkeypatch)
    fake = _Stripe(plan_price)
    payments.set_default_transport(fake)
    try:
        # A slug that is a valid mail domain: an underscore is not, and signup
        # correctly refuses it, which failed this test for the wrong reason.
        slug = f"seats-{term}"
        h, _tid = _signup(client, slug)
        await _give_subscription(slug)

        r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 3}, headers=h)
        assert r.status_code == 200, r.text[:300]
        assert r.json()["extra_mailbox_seats"] == 3, r.json()
        assert r.json()["capacity"] == 8, r.json()
        assert expected_seat_price in fake.seat_prices_sent(), (
            f"seats were billed on the wrong interval: sent "
            f"{fake.seat_prices_sent()}, expected {expected_seat_price}"
        )
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_the_capacity_actually_rises_so_the_mailbox_can_be_added(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Buying a seat has to end in being able to use it — otherwise the customer
    has paid for a number on a page."""
    _env(monkeypatch)
    payments.set_default_transport(_Stripe("price_cmp_yr"))
    try:
        slug = "seats-usable"
        h, _tid = _signup(client, slug)
        await _give_subscription(slug)

        for i in range(5):
            client.post(
                "/api/v1/mailboxes",
                json={"address": f"m{i}@{slug}.example", "mailbox_class": "protected",
                      "sources": []},
                headers=h,
            )
        over = client.post(
            "/api/v1/mailboxes",
            json={"address": f"m5@{slug}.example", "mailbox_class": "protected",
                  "sources": []},
            headers=h,
        )
        assert over.status_code == 402, "the plan's five seats were not enforced"

        assert client.put(
            "/api/v1/billing/seats", json={"extra_mailboxes": 1}, headers=h
        ).status_code == 200

        now = client.post(
            "/api/v1/mailboxes",
            json={"address": f"m5@{slug}.example", "mailbox_class": "protected",
                  "sources": []},
            headers=h,
        )
        assert now.status_code in (200, 201), (
            f"a purchased seat did not become usable: {now.status_code} {now.text[:200]}"
        )
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()


# ── What the customer is told when it fails ──────────────────────────────────
class _FailingStripe(_Stripe):
    """Fails the update with a chosen HTTP status and body."""

    def __init__(self, plan_price: str, status: int, body: str) -> None:
        super().__init__(plan_price)
        self.status, self.body = status, body

    async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002
        if url.endswith("/subscriptions/sub_1") and method == "POST":
            raise payments.PaymentError(
                f"{url} returned {self.status}: {self.body}",
                status_code=self.status,
                card_declined=self.status == 402 or "card_error" in self.body,
            )
        return await super().request(method, url, headers=headers, json=json, data=data)


@pytest.mark.asyncio
async def test_a_real_decline_tells_them_to_fix_their_card(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _env(monkeypatch)
    payments.set_default_transport(
        _FailingStripe("price_cmp_yr", 402, '{"error":{"type":"card_error"}}')
    )
    try:
        slug = "decline-co"
        h, _tid = _signup(client, slug)
        await _give_subscription(slug)
        r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 2}, headers=h)
        assert r.status_code == 402, r.text[:200]
        assert "Update your card" in r.json()["detail"]
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()


@pytest.mark.asyncio
async def test_our_own_bad_request_does_not_blame_their_card(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every non-2xx from Stripe used to be reported as "your payment didn't go
    through, update your card" — including a validation error that is entirely
    ours. That sends someone to re-enter a card that was never the problem, and
    buries the real fault. It cost a live debugging round."""
    _env(monkeypatch)
    payments.set_default_transport(
        _FailingStripe(
            "price_cmp_yr", 400, '{"error":{"type":"invalid_request_error"}}'
        )
    )
    try:
        slug = "badreq-co"
        h, _tid = _signup(client, slug)
        await _give_subscription(slug)
        r = client.put("/api/v1/billing/seats", json={"extra_mailboxes": 2}, headers=h)
        assert r.status_code == 502, r.text[:200]
        detail = r.json()["detail"]
        assert "card" not in detail.lower(), detail
        assert "Nothing was charged" in detail
    finally:
        payments.set_default_transport(None)
        get_settings.cache_clear()
