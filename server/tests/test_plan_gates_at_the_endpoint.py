"""The gates that were missing, at the endpoints that were missing them.

`test_plan_lifecycle_over_the_api` proves the `features` payload and the mailbox
seat cap are right. It does not prove that every OTHER door into live mail
protection is shut, and four of them were open:

* `POST /ingest` — a lapsed tenant could keep pushing mail through the whole
  pipeline. Nothing leaked (the plan filter empties the detection set), but we
  paid for the parse, the reputation lookups and the storage.
* `POST /mailboxes/{id}/connect/imap` — worse: it stored a credential and
  reported "connected" for a mailbox the poller will never read. A customer who
  believes they are protected and is not is the one outcome this product cannot
  produce.
* `POST /connect/oauth/{provider}/authorize` — the same, with a trip round
  Microsoft's consent screen first.
* `POST /sensor/pairings` — the sensor's only output is Channel 2, which is
  Complete's. On a smaller plan, pairing installs an extension on somebody's
  laptop that can never raise anything.

Each is asserted against a tenant whose trial has lapsed unpaid, which is the
state every trial reaches if nobody pays — so these are not edge cases, they are
the default ending.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

PW = "correct horse battery staple 9"
SLUG = "gatecheck-co"


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


async def _set_plan(*, plan: str, paid: bool, lapsed: bool) -> None:
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Tenant

    with system_scope("test: drive the billing state"):
        async with get_sessionmaker()() as s:
            tenant = (
                await s.execute(select(Tenant).where(Tenant.name == SLUG))
            ).scalar_one()
            tenant.plan = plan
            tenant.payment_method_ok = paid
            now = datetime.now(UTC)
            tenant.trial_ends_at = (
                now - timedelta(days=1) if lapsed else now + timedelta(days=5)
            )
            await s.commit()


def _add_mailbox(client: TestClient, h: dict) -> str:
    r = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{SLUG}.example",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=h,
    )
    assert r.status_code in (200, 201), r.text[:200]
    return r.json()["id"]


@pytest.mark.asyncio
async def test_a_lapsed_tenant_cannot_feed_the_pipeline_or_connect_anything(
    client: TestClient,
) -> None:
    h = _sign_up(client)
    # Added while the trial is live — the realistic shape. The mailbox survives
    # the trial, which is exactly why every one of these needs its own gate.
    mailbox_id = _add_mailbox(client, h)
    await _set_plan(plan="complete", paid=False, lapsed=True)

    ingest = client.post(
        "/api/v1/ingest",
        json={
            "raw_message": "From: a@b.example\nSubject: hi\n\nbody",
            "mailbox_address": f"pay@{SLUG}.example",
        },
        headers=h,
    )
    assert ingest.status_code == 402, (
        f"a lapsed tenant pushed mail through the pipeline: {ingest.status_code} "
        f"{ingest.text[:200]}"
    )

    imap = client.post(
        f"/api/v1/mailboxes/{mailbox_id}/connect/imap",
        json={
            "host": "imap.example.com",
            "port": 993,
            "username": f"pay@{SLUG}.example",
            "password": PW,
        },
        headers=h,
    )
    assert imap.status_code == 402, (
        "a lapsed tenant reached the IMAP credential store — it must be refused "
        f"before we can report 'connected' on a mailbox nothing will read: "
        f"{imap.status_code} {imap.text[:200]}"
    )

    oauth = client.post(
        "/api/v1/connect/oauth/google/authorize",
        json={"mailbox_address": f"pay@{SLUG}.example", "mode": "api"},
        headers=h,
    )
    # 503 when no OAuth client is configured in this environment, which is a
    # different refusal and equally not a grant; 402 once it is. Never a URL.
    assert oauth.status_code in (402, 503), oauth.text[:200]
    assert "authorize_url" not in oauth.text


@pytest.mark.asyncio
async def test_the_sensor_pairs_only_on_complete(client: TestClient) -> None:
    h = _sign_up(client)
    mailbox_id = _add_mailbox(client, h)

    # Essential pays for payment-fraud detection, not Channel 2.
    await _set_plan(plan="essential", paid=True, lapsed=True)
    r = client.post(
        "/api/v1/sensor/pairings", json={"mailbox_id": mailbox_id}, headers=h
    )
    assert r.status_code == 402, (
        "Essential was given a sensor pairing code — the sensor only feeds "
        f"Complete's detections, so this installs a no-op: {r.status_code} "
        f"{r.text[:200]}"
    )
    assert "code" not in r.json()

    # Complete does.
    await _set_plan(plan="complete", paid=True, lapsed=True)
    r = client.post(
        "/api/v1/sensor/pairings", json={"mailbox_id": mailbox_id}, headers=h
    )
    assert r.status_code == 201, r.text[:200]
    assert r.json()["code"]


@pytest.mark.asyncio
async def test_the_simulation_reports_what_this_plan_would_actually_catch(
    client: TestClient,
) -> None:
    """A demo that passes on detections the tenant has not bought is a lie in our
    favour — and the tenant reads it as "my mail is covered by this"."""
    h = _sign_up(client)
    _add_mailbox(client, h)
    body = {"protected_domain": f"{SLUG}.example", "vendor_domain": "gemini.example"}

    await _set_plan(plan="complete", paid=True, lapsed=True)
    full = client.post("/api/v1/simulate", json=body, headers=h).json()
    assert full["passed"] == full["total"], full
    assert full["plan_locked"] == 0, full

    # Lapsed to Guard: the A-series is not included, so the runs must not claim
    # to pass — and must say WHY, or it reads as a broken product.
    await _set_plan(plan="complete", paid=False, lapsed=True)
    guard = client.post("/api/v1/simulate", json=body, headers=h).json()
    assert guard["plan"] == "guard", guard
    assert guard["passed"] == 0, (
        "a Guard tenant was shown payment-fraud simulations passing while its "
        f"mail is not being checked at all: {guard}"
    )
    assert guard["plan_locked"] == guard["total"], (
        "the misses were not attributed to the plan, so they read as detection "
        f"failures: {guard}"
    )
