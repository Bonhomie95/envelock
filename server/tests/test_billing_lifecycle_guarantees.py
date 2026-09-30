"""The three promises the business rests on, each driven end to end.

Not the gate functions in isolation — those have their own tests — but the real
sequence a customer lives through, over the API, through the signed Stripe
webhook, with entitlement read back out of the database afterwards:

1. **Paying during the trial hands the plan over to the payment.** From that
   moment the trial clock is irrelevant: when it runs out nothing changes, no
   grace period is consumed, and nobody loses protection because a countdown
   they had already paid to stop reached zero.
2. **A trial that lapses unpaid stops everything that costs us money.** Every
   door: adding a mailbox, connecting one, feeding the pipeline, pairing the
   sensor, running a backfill.
3. **A subscription that ends does the same.** Cancelled in the Stripe portal,
   in the dashboard, or by dunning — the tenant lands on Guard, keeps domain
   monitoring, and protects no mailbox.

Each is asserted at the ENDPOINT, because a dashboard that hides a button is not
enforcement: the request can still be made by hand.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.billing import payments
from envelock.config import get_settings
from envelock.main import app

SECRET = "whsec_test"  # noqa: S105 — test secret
PW = "correct horse battery staple 9"
PRICES = {
    "ENVELOCK_STRIPE_PRICE_ESSENTIAL": "price_ess",
    "ENVELOCK_STRIPE_PRICE_COMPLETE": "price_cmp",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_ESSENTIAL": "price_ess_seat",
    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE": "price_cmp_seat",
}


class _Stripe:
    def __init__(self) -> None:
        self.items = [{"id": "si_plan", "price": {"id": "price_cmp"}, "quantity": 1}]

    async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002
        if "checkout/sessions" in url:
            return {"id": "cs_1", "url": "https://checkout.stripe.com/c/pay/cs_1"}
        if url.endswith("/subscriptions/sub_1"):
            return {"id": "sub_1", "status": "active", "items": {"data": self.items}}
        return {}


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
    assert r.status_code == 200, r.text[:200]


def _signup(client: TestClient, slug: str) -> tuple[dict, str]:
    """A real registration, through MFA, with the domain bootstrapped."""
    email = f"owner@{slug}.example"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": slug},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    # MFA is skippable by design (it can be turned on later from the dashboard),
    # and this file is about billing, not authentication.
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


async def _set_trial(slug: str, *, days: int | None) -> None:
    """Move only the trial clock. `days=None` puts it in the past."""
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Tenant

    with system_scope("test: move the trial clock"):
        async with get_sessionmaker()() as s:
            tenant = (
                await s.execute(select(Tenant).where(Tenant.name == slug))
            ).scalar_one()
            now = datetime.now(UTC)
            tenant.trial_ends_at = (
                now + timedelta(days=days) if days is not None else now - timedelta(days=1)
            )
            if tenant.trial_started_at is None:
                tenant.trial_started_at = now - timedelta(days=1)
            await s.commit()


def _tenant(client: TestClient, h: dict) -> dict:
    r = client.get("/api/v1/tenant", headers=h)
    assert r.status_code == 200, r.text[:200]
    return r.json()


def _pay(client: TestClient, tid: str, slug: str, plan: str = "complete") -> None:
    _event(
        client,
        "checkout.session.completed",
        {
            "client_reference_id": tid,
            "customer": "cus_1",
            "subscription": "sub_1",
            "payment_status": "paid",
            "metadata": {
                "tenant_id": tid,
                "plan": plan,
                "domain": f"{slug}.example",
                "extra_mailboxes": "0",
            },
        },
    )


def _every_paid_door(client: TestClient, h: dict, slug: str, mailbox_id: str) -> dict:
    """Every request that starts, resumes or feeds live mail protection."""
    return {
        "add a mailbox": client.post(
            "/api/v1/mailboxes",
            json={
                "address": f"new@{slug}.example",
                "mailbox_class": "protected",
                "sources": [],
            },
            headers=h,
        ).status_code,
        "connect over IMAP": client.post(
            f"/api/v1/mailboxes/{mailbox_id}/connect/imap",
            json={
                "host": "imap.example.com",
                "port": 993,
                "username": f"pay@{slug}.example",
                "password": PW,
            },
            headers=h,
        ).status_code,
        "feed the pipeline": client.post(
            "/api/v1/ingest",
            json={
                "raw_message": "From: a@b.example\nSubject: hi\n\nbody",
                "mailbox_address": f"pay@{slug}.example",
            },
            headers=h,
        ).status_code,
        "pair the sensor": client.post(
            "/api/v1/sensor/pairings", json={"mailbox_id": mailbox_id}, headers=h
        ).status_code,
        "run a backfill": client.post(
            f"/api/v1/mailboxes/{mailbox_id}/backfill", headers=h
        ).status_code,
    }


# ── 1. Paying during the trial ───────────────────────────────────────────────
@pytest.mark.asyncio
async def test_paying_during_the_trial_hands_the_plan_to_the_payment(
    client: TestClient, stripe: _Stripe
) -> None:
    """The guarantee: once they have paid, the trial clock cannot take anything
    away. Proven by paying with days still on the clock, then running the clock
    out and showing NOTHING changes."""
    slug = "paid-midtrial-co"
    h, tid = _signup(client, slug)
    await _set_trial(slug, days=9)

    before = _tenant(client, h)
    assert before["trial"]["active"] is True
    assert before["trial"]["payment_method_ok"] is False

    _pay(client, tid, slug, plan="complete")

    paid = _tenant(client, h)
    assert paid["plan"] == "complete"
    assert paid["trial"]["payment_method_ok"] is True, "the payment did not register"
    assert paid["trial_ended"] is False
    assert paid["mailboxes"]["capacity"] == 5
    assert paid["features"] == {
        "ai_on_links": True,
        "auto_remediation": True,
        "identity_detections": True,
    }

    # Now run the trial clock out. This is the moment that used to end everything.
    await _set_trial(slug, days=None)
    after = _tenant(client, h)

    assert after["plan"] == "complete", (
        "a paying customer was dropped to Guard when their trial clock expired — "
        f"got {after['plan']!r}"
    )
    assert after["trial_ended"] is False, (
        "a paying customer is being told their trial ended; they bought their way "
        "out of it"
    )
    assert after["mailboxes"]["capacity"] == 5
    assert after["features"] == paid["features"]
    assert after["mailboxes"]["can_add"] is True


@pytest.mark.asyncio
async def test_a_paying_customer_is_not_shown_a_trial_countdown(
    client: TestClient, stripe: _Stripe
) -> None:
    """`trial.active` stays true until the clock runs out even after payment —
    that is correct (the free days were bought and paid for), and it is why every
    countdown in the UI is guarded on `payment_method_ok`. This pins the pair of
    fields the dashboard, billing page and profile all read."""
    slug = "countdown-co"
    h, tid = _signup(client, slug)
    await _set_trial(slug, days=9)
    _pay(client, tid, slug)

    t = _tenant(client, h)["trial"]
    assert t["payment_method_ok"] is True
    # The UI condition, stated here so a change to either field is caught:
    shows_countdown = bool(t["active"]) and not t["payment_method_ok"]
    assert shows_countdown is False


# ── 2. A trial that lapses unpaid ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_lapsed_trial_closes_every_door(client: TestClient) -> None:
    slug = "lapsed-co"
    h, _tid = _signup(client, slug)
    mailbox = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{slug}.example",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=h,
    ).json()["id"]

    await _set_trial(slug, days=None)

    body = _tenant(client, h)
    assert body["plan"] == "guard"
    assert body["trial_ended"] is True
    assert body["mailboxes"]["capacity"] == 0
    assert body["mailboxes"]["can_add"] is False
    assert body["features"] == {
        "ai_on_links": False,
        "auto_remediation": False,
        "identity_detections": False,
    }

    doors = _every_paid_door(client, h, slug, mailbox)
    assert all(code == 402 for code in doors.values()), (
        f"a lapsed trial kept a paid capability: {doors}"
    )


@pytest.mark.asyncio
async def test_a_lapsed_trial_keeps_what_guard_is_owed(client: TestClient) -> None:
    """Never locked out. Guard is free forever, so the workspace, its alert
    history and its domain must all still be there — anything else would be
    holding a customer's own data hostage."""
    slug = "lapsed-keeps-co"
    h, _tid = _signup(client, slug)
    await _set_trial(slug, days=None)

    assert client.get("/api/v1/alerts", headers=h).status_code == 200
    assert client.get("/api/v1/mailboxes", headers=h).status_code == 200
    body = _tenant(client, h)
    assert body["domains"], "the tenant lost its domain when the trial lapsed"


# ── 3. A subscription that ends ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_a_cancelled_subscription_closes_every_door(
    client: TestClient, stripe: _Stripe
) -> None:
    """Cancelled in the portal, the dashboard, or by dunning — all arrive as
    `customer.subscription.deleted`."""
    slug = "cancelled-co"
    h, tid = _signup(client, slug)
    mailbox = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{slug}.example",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=h,
    ).json()["id"]

    _pay(client, tid, slug, plan="complete")
    await _set_trial(slug, days=None)  # the trial is long gone; the plan is what pays
    assert _tenant(client, h)["plan"] == "complete"

    _event(
        client,
        "customer.subscription.deleted",
        {"id": "sub_1", "customer": "cus_1", "metadata": {"tenant_id": tid}},
    )

    body = _tenant(client, h)
    assert body["plan"] == "guard", (
        f"a cancelled subscription kept its plan: {body['plan']!r}"
    )
    assert body["mailboxes"]["capacity"] == 0
    assert body["features"] == {
        "ai_on_links": False,
        "auto_remediation": False,
        "identity_detections": False,
    }

    doors = _every_paid_door(client, h, slug, mailbox)
    assert all(code == 402 for code in doors.values()), (
        f"a cancelled subscription kept a paid capability: {doors}"
    )


@pytest.mark.asyncio
async def test_a_subscription_marked_unpaid_also_closes_every_door(
    client: TestClient, stripe: _Stripe
) -> None:
    """Stripe does not always delete. With dunning set to "mark unpaid" it keeps
    the subscription and only changes its status — a switch in the Stripe
    dashboard that would otherwise hand a non-paying customer the full plan
    forever."""
    slug = "unpaid-co"
    h, tid = _signup(client, slug)
    _pay(client, tid, slug, plan="complete")
    await _set_trial(slug, days=None)
    assert _tenant(client, h)["plan"] == "complete"

    _event(
        client,
        "customer.subscription.updated",
        {
            "id": "sub_1",
            "customer": "cus_1",
            "status": "unpaid",
            "metadata": {"tenant_id": tid},
        },
    )
    assert _tenant(client, h)["plan"] == "guard"


@pytest.mark.asyncio
async def test_a_declined_renewal_does_not_cut_them_off_immediately(
    client: TestClient, stripe: _Stripe
) -> None:
    """`invoice.payment_failed` is a warning, not a cancellation: Stripe retries
    on its own schedule and the plan stays live meanwhile. Cutting protection on
    the first decline would punish a customer for an expired card — and it is
    mail fraud protection, so the cost of being wrong is somebody's money."""
    slug = "declined-co"
    h, tid = _signup(client, slug)
    _pay(client, tid, slug, plan="complete")
    await _set_trial(slug, days=None)

    _event(
        client,
        "invoice.payment_failed",
        {"id": "in_1", "customer": "cus_1", "metadata": {"tenant_id": tid}},
    )
    assert _tenant(client, h)["plan"] == "complete", (
        "one declined charge cut off protection before Stripe had finished retrying"
    )
