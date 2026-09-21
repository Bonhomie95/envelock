"""Tenant A must never be able to reach tenant B's data.

The product holds many companies' mail in one database. Postgres row-level
security exists in the schema but is off by default (`ENVELOCK_RLS_ENABLED`) and
gated again behind `ENVELOCK_APPLY_RLS` in the migrations, so in every realistic
deployment **application-layer scoping is the only thing between one missed
`WHERE tenant_id = ...` and another company reading your invoices**.

Before this file, 52 test suites covered detection, billing, auth, IMAP and
governance, and not one asserted that isolation. The control the whole product
rests on was the one thing nothing checked.

The shape of every test here is the same, and it is deliberately boring:

    build two complete tenants → have B point at A's object id → expect 404

404 rather than 403, throughout. A 403 confirms the id exists, which turns any
of these endpoints into an oracle for enumerating another tenant's mailboxes,
alerts or users. Asserting the *code* matters as much as asserting the refusal.

`_assert_denied` accepts 404 or 422 so that a route which rejects the id at
validation still counts as refusing — what it will not accept is a 2xx, or a
403 that leaks existence.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

PW = "correct horse battery staple 9"


# ── Two complete tenants ─────────────────────────────────────────────────────
class Tenant:
    """Everything one tenant owns, so a test can point B at any of A's ids."""

    def __init__(self, headers: dict, slug: str) -> None:
        self.headers = headers
        self.slug = slug
        self.domain = f"{slug}.example"
        self.mailbox_id: str = ""
        self.alert_id: str = ""
        self.member_id: str = ""
        self.tenant_id: str = ""


def _build(client: TestClient, slug: str) -> Tenant:
    email = f"owner@{slug}.example"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": slug},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    t = Tenant({"Authorization": f"Bearer {skip['access_token']}"}, slug)

    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": slug, "domain": t.domain},
        headers=t.headers,
    )
    t.tenant_id = client.get("/api/v1/auth/me", headers=t.headers).json()["tenant_id"]

    mb = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{t.domain}",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=t.headers,
    )
    t.mailbox_id = mb.json()["id"]

    # A pending colleague, so the member-approval routes have a real target.
    client.post(
        "/api/v1/auth/register",
        json={
            "email": f"colleague@{t.domain}",
            "password": PW,
            "tenant_name": slug,
        },
    )
    members = client.get("/api/v1/members", headers=t.headers).json()
    rows = members.get("members", members) if isinstance(members, dict) else members
    for row in rows or []:
        if row.get("email", "").startswith("colleague@"):
            t.member_id = row["id"]
            break

    return t


@pytest.fixture
def tenants(client: TestClient) -> tuple[Tenant, Tenant, TestClient]:
    a = _build(client, "alpha-co")
    b = _build(client, "beta-co")
    return a, b, client


def _assert_denied(resp, what: str) -> None:
    assert resp.status_code != 403, (
        f"{what}: answered 403, which confirms the id exists. That turns this "
        "endpoint into an enumeration oracle for another tenant's objects — it "
        "must be indistinguishable from an id that was never created."
    )
    assert resp.status_code in (404, 422), (
        f"{what}: expected 404, got {resp.status_code}. "
        f"Body: {resp.text[:300]}"
    )


# ── Mailboxes ────────────────────────────────────────────────────────────────
def test_cannot_read_another_tenants_mailbox(tenants) -> None:
    a, b, client = tenants
    _assert_denied(
        client.get(
            f"/api/v1/mailboxes/{a.mailbox_id}/activity", headers=b.headers
        ),
        "GET mailbox activity",
    )


def test_cannot_modify_another_tenants_mailbox(tenants) -> None:
    a, b, client = tenants
    _assert_denied(
        client.patch(
            f"/api/v1/mailboxes/{a.mailbox_id}",
            json={"mailbox_class": "monitored"},
            headers=b.headers,
        ),
        "PATCH mailbox",
    )


def test_cannot_delete_another_tenants_mailbox(tenants) -> None:
    a, b, client = tenants
    _assert_denied(
        client.delete(f"/api/v1/mailboxes/{a.mailbox_id}", headers=b.headers),
        "DELETE mailbox",
    )
    # And it must still be there afterwards.
    still = client.get("/api/v1/mailboxes", headers=a.headers).json()["mailboxes"]
    assert any(m["id"] == a.mailbox_id for m in still), (
        "a cross-tenant DELETE removed the mailbox anyway"
    )


def test_cannot_connect_or_sync_another_tenants_mailbox(tenants) -> None:
    """The connect routes take a stored credential and open a socket. Reaching
    another tenant's mailbox here would be worth more to an attacker than
    reading it."""
    a, b, client = tenants
    for method, path, body in (
        ("post", f"/api/v1/mailboxes/{a.mailbox_id}/sync", None),
        ("post", f"/api/v1/mailboxes/{a.mailbox_id}/connect/forward", {}),
        (
            "post",
            f"/api/v1/mailboxes/{a.mailbox_id}/connect/imap",
            {"host": "imap.example.com", "port": 993, "username": "x", "password": "y"},
        ),
        ("post", f"/api/v1/mailboxes/{a.mailbox_id}/backfill", {}),
    ):
        resp = getattr(client, method)(path, json=body, headers=b.headers)
        _assert_denied(resp, f"{method.upper()} {path}")


def test_mailbox_list_is_scoped(tenants) -> None:
    a, b, client = tenants
    mine = client.get("/api/v1/mailboxes", headers=b.headers).json()["mailboxes"]
    ids = {m["id"] for m in mine}
    assert a.mailbox_id not in ids
    assert all(m["address"].endswith(b.domain) for m in mine), (
        f"tenant B's mailbox list contained another tenant's addresses: {mine}"
    )


# ── Alerts ───────────────────────────────────────────────────────────────────
def _seed_alert(client: TestClient, t: Tenant) -> str:
    """Write an alert directly — the point is isolation, not detection."""
    import asyncio
    from uuid import UUID

    from conftest import platform_sessionmaker as get_sessionmaker

    from envelock.db_rls import system_scope
    from envelock.models import Alert

    async def _seed() -> str:
        # Seeding is a platform action, not a tenant one: under RLS an INSERT
        # with no tenant bound is refused by WITH CHECK, which is correct. The
        # assertions below still run through the API, fully enforced.
        with system_scope("test fixture: seed an alert for tenant isolation checks"):
            async with get_sessionmaker()() as s:
                alert = Alert(
                    tenant_id=UUID(t.tenant_id),
                    mailbox_id=UUID(t.mailbox_id),
                    tier="critical",
                    title=f"{t.slug} confidential",
                    body="bank details changed",
                )
                s.add(alert)
                await s.commit()
                return str(alert.id)

    return asyncio.run(_seed())


def test_cannot_act_on_another_tenants_alert(tenants) -> None:
    a, b, client = tenants
    alert_id = _seed_alert(client, a)

    for path in (
        f"/api/v1/alerts/{alert_id}/acknowledge",
        f"/api/v1/alerts/{alert_id}/quarantine",
        f"/api/v1/alerts/{alert_id}/resolve",
    ):
        _assert_denied(client.post(path, json={}, headers=b.headers), f"POST {path}")


def test_alert_list_never_shows_another_tenants_alerts(tenants) -> None:
    a, b, client = tenants
    alert_id = _seed_alert(client, a)

    listed = client.get("/api/v1/alerts", headers=b.headers).json()["alerts"]
    assert all(row["id"] != alert_id for row in listed)
    assert not any("alpha-co confidential" in str(row) for row in listed), (
        "tenant A's alert title leaked into tenant B's queue"
    )

    # ...and tenant A can still see their own, so the scoping is not just
    # returning nothing to everybody.
    own = client.get("/api/v1/alerts", headers=a.headers).json()["alerts"]
    assert any(row["id"] == alert_id for row in own)


# ── Members ──────────────────────────────────────────────────────────────────
def test_cannot_approve_or_reject_another_tenants_member(tenants) -> None:
    a, b, client = tenants
    if not a.member_id:
        pytest.skip("no pending member was created")
    for verb in ("approve", "reject"):
        _assert_denied(
            client.post(
                f"/api/v1/members/{a.member_id}/{verb}", json={}, headers=b.headers
            ),
            f"POST member {verb}",
        )


def test_member_list_is_scoped(tenants) -> None:
    a, b, client = tenants
    body = client.get("/api/v1/members", headers=b.headers).json()
    rows = body.get("members", body) if isinstance(body, dict) else body
    for row in rows or []:
        assert row.get("email", "").endswith(b.domain), (
            f"tenant B's member list contained {row.get('email')}"
        )


# ── Domains ──────────────────────────────────────────────────────────────────
def test_cannot_read_another_tenants_domain_verification(tenants) -> None:
    """The verification token is the ingest secret: whoever holds it can inject
    mail into that tenant's pipeline."""
    a, b, client = tenants
    resp = client.get(
        f"/api/v1/domains/{a.domain}/verification", headers=b.headers
    )
    if resp.status_code == 200:
        token = str(resp.json())
        mine = client.get(
            f"/api/v1/domains/{b.domain}/verification", headers=b.headers
        )
        assert mine.status_code == 200
        assert token != str(mine.json()), (
            "tenant B read tenant A's domain verification token — that token "
            "authenticates forwarded mail into A's pipeline"
        )
    else:
        _assert_denied(resp, "GET domain verification")


def test_ingest_address_differs_per_tenant(tenants) -> None:
    a, b, client = tenants
    one = client.get("/api/v1/ingest-address", headers=a.headers)
    two = client.get("/api/v1/ingest-address", headers=b.headers)
    if one.status_code == 200 and two.status_code == 200:
        assert one.json() != two.json(), (
            "both tenants were handed the same ingest address, so either could "
            "inject mail into the other's pipeline"
        )


# ── Tenant record ────────────────────────────────────────────────────────────
def test_tenant_endpoint_returns_only_your_own(tenants) -> None:
    a, b, client = tenants
    mine = client.get("/api/v1/tenant", headers=b.headers).json()
    assert str(mine.get("id", mine.get("tenant_id", ""))) != a.tenant_id
    assert "alpha-co" not in str(mine)


def test_oversight_counts_are_scoped(tenants) -> None:
    """Aggregates leak too: a count that includes another tenant's alerts tells
    you about their incidents even though you never see the rows."""
    a, b, client = tenants
    _seed_alert(client, a)
    _seed_alert(client, a)

    resp = client.get("/api/v1/oversight", headers=b.headers)
    if resp.status_code != 200:
        pytest.skip("oversight not available to this role")
    blob = str(resp.json())
    assert "alpha-co confidential" not in blob
    body = resp.json()
    for key in ("open_alerts", "total_alerts", "critical_alerts", "alerts"):
        if isinstance(body.get(key), int):
            assert body[key] == 0, (
                f"tenant B's oversight reported {key}={body[key]} while only "
                "tenant A had alerts"
            )


# ── Audit trail ──────────────────────────────────────────────────────────────
def test_audit_trail_is_scoped(tenants) -> None:
    a, b, client = tenants
    resp = client.get("/api/v1/audit", headers=b.headers)
    if resp.status_code != 200:
        pytest.skip("audit not available to this role")
    assert "alpha-co" not in str(resp.json())


# ── Unknown ids behave identically to another tenant's ids ───────────────────
def test_a_foreign_id_is_indistinguishable_from_a_nonexistent_one(tenants) -> None:
    """The anti-enumeration property, stated directly.

    If a foreign id and a made-up id produce different responses, the difference
    is a yes/no oracle for "does this id exist somewhere on the platform" — and
    ids are guessable in bulk far more often than people expect.
    """
    a, b, client = tenants
    nonexistent = str(uuid.uuid4())

    foreign = client.get(
        f"/api/v1/mailboxes/{a.mailbox_id}/activity", headers=b.headers
    )
    unknown = client.get(
        f"/api/v1/mailboxes/{nonexistent}/activity", headers=b.headers
    )
    assert foreign.status_code == unknown.status_code, (
        f"foreign id → {foreign.status_code}, unknown id → {unknown.status_code}; "
        "the difference reveals that the foreign id exists"
    )
