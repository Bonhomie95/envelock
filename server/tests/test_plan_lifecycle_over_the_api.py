"""What a signed-in customer actually RECEIVES on each plan.

`test_plan_features` tests the gate functions. `test_billing` tests the price
arithmetic. Neither signs in and asks the API what it gets, so a gate that is
correct in isolation and never reached — or reached with the wrong tenant — was
covered by nothing.

This walks one company through the lifecycle a real customer has:

    register → trial (top plan) → trial lapses unpaid → pays for Essential
             → upgrades to Complete

and at every stop asserts the two things the customer can see: the `features`
block the dashboard reads to decide what to offer, and the mailbox capacity that
decides what they can connect. Getting those wrong is either giving away the
expensive plan or charging for something that does not turn on.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

PW = "correct horse battery staple 9"
SLUG = "lifecycle-co"


def _sign_up(client: TestClient) -> dict:
    email = f"owner@{SLUG}.example"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": SLUG},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": SLUG, "domain": f"{SLUG}.example"},
        headers=h,
    )
    return h


def _tenant(client: TestClient, h: dict) -> dict:
    r = client.get("/api/v1/tenant", headers=h)
    assert r.status_code == 200, r.text[:200]
    return r.json()


async def _set_plan(
    *, plan: str, paid: bool, trial_days: int | None
) -> None:
    """Move the tenant's billing state the way Stripe's webhook would."""
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Tenant

    with system_scope("test: drive the billing lifecycle"):
        async with get_sessionmaker()() as s:
            tenant = (
                await s.execute(select(Tenant).where(Tenant.name == SLUG))
            ).scalar_one()
            tenant.plan = plan
            tenant.payment_method_ok = paid
            tenant.trial_ends_at = (
                datetime.now(UTC) + timedelta(days=trial_days)
                if trial_days is not None
                else datetime.now(UTC) - timedelta(days=1)
            )
            await s.commit()


@pytest.mark.asyncio
async def test_a_company_gets_exactly_what_its_plan_says_at_every_stage(
    client: TestClient,
) -> None:
    h = _sign_up(client)

    # ── 1. Fresh signup: the trial runs on the TOP plan ─────────────────────
    # Deliberate product decision (see billing/pricing): someone evaluating the
    # product sees everything, so the thing they judge is the whole product.
    body = _tenant(client, h)
    features = body.get("features")
    assert features is not None, (
        "GET /tenant sent no `features` block — the dashboard uses it to decide "
        "what to offer, so without it every gated control is silently absent"
    )
    assert features == {
        "ai_on_links": True,
        "auto_remediation": True,
        "identity_detections": True,
    }, f"a trial should carry the top plan's features, got {features}"
    assert body["mailboxes"]["capacity"] >= 5, body["mailboxes"]

    # ── 2. The trial lapses unpaid: everything drops to Guard ───────────────
    await _set_plan(plan="complete", paid=False, trial_days=None)
    body = _tenant(client, h)
    assert body["plan"] == "guard", (
        f"an unpaid lapsed trial must fall back to Guard, got {body['plan']!r}"
    )
    assert body["features"] == {
        "ai_on_links": False,
        "auto_remediation": False,
        "identity_detections": False,
    }, "a lapsed trial kept paid features"
    assert body["mailboxes"]["capacity"] == 0, (
        "Guard protects domains, not mailboxes — capacity must be 0, got "
        f"{body['mailboxes']['capacity']}"
    )
    assert body["mailboxes"]["can_add"] is False

    # ── 3. They pay for Essential ───────────────────────────────────────────
    await _set_plan(plan="essential", paid=True, trial_days=None)
    body = _tenant(client, h)
    assert body["plan"] == "essential"
    assert body["features"] == {
        "ai_on_links": False,
        "auto_remediation": False,
        "identity_detections": False,
    }, (
        "Essential was served Complete's features — that is the whole plan "
        "given away for $2/mailbox less"
    )
    assert body["mailboxes"]["capacity"] == 5, body["mailboxes"]
    assert body["mailboxes"]["can_add"] is True

    # ── 4. They upgrade to Complete ─────────────────────────────────────────
    await _set_plan(plan="complete", paid=True, trial_days=None)
    body = _tenant(client, h)
    assert body["plan"] == "complete"
    assert body["features"] == {
        "ai_on_links": True,
        "auto_remediation": True,
        "identity_detections": True,
    }, "Complete did not get what it pays for"
    assert body["mailboxes"]["capacity"] == 5, body["mailboxes"]


@pytest.mark.asyncio
async def test_a_lapsed_tenant_cannot_connect_a_mailbox_through_the_api(
    client: TestClient,
) -> None:
    """The gate has to hold at the endpoint, not only in the payload.

    A dashboard that hides the button is not enforcement: the request can be
    made by hand. This is the half that actually stops a lapsed trial keeping
    live mail protection for free.
    """
    h = _sign_up(client)
    await _set_plan(plan="complete", paid=False, trial_days=None)

    r = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{SLUG}.example",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=h,
    )
    assert r.status_code == 402, (
        f"a lapsed unpaid tenant added a protected mailbox: {r.status_code} "
        f"{r.text[:200]}"
    )
