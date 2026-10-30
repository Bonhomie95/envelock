"""Plan entitlement gate, forwarding connect, per-mailbox activity, and full
account deletion that keeps the anti-abuse domain ledger."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.db import get_sessionmaker
from envelock.main import app
from envelock.models import DomainTrialLedger, Tenant

PW = "a-long-enough-passphrase"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _session(client: TestClient, email: str, domain: str) -> dict:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": domain},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": PW}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _tenant_id(client: TestClient, h: dict) -> str:
    return client.get("/api/v1/auth/me", headers=h).json()["tenant_id"]


def _add(client: TestClient, h: dict, address: str) -> str:
    return client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected", "sources": []},
        headers=h,
    ).json()["id"]


# ── Forwarding connect ────────────────────────────────────────────────────────
def test_forwarding_connect_marks_covered_alert_only(client: TestClient) -> None:
    h = _session(client, "it@fwd.example", "fwd.example")
    mid = _add(client, h, "ceo@fwd.example")

    out = client.post(f"/api/v1/mailboxes/{mid}/connect/forward", headers=h)
    assert out.status_code == 200
    body = out.json()
    assert "forward_ingest" in body["sources"]
    # Forwarding is post-delivery → alert-only → Limited is the honest ceiling.
    assert body["protection_level"] == "limited"


# ── Per-mailbox activity ──────────────────────────────────────────────────────
def test_mailbox_activity_shows_connection_events(client: TestClient) -> None:
    h = _session(client, "it@act.example", "act.example")
    mid = _add(client, h, "cfo@act.example")
    client.post(f"/api/v1/mailboxes/{mid}/connect/forward", headers=h)

    act = client.get(f"/api/v1/mailboxes/{mid}/activity", headers=h).json()
    assert act["connected"] is True
    assert act["messages_scanned"] == 0
    assert act["alerts_raised"] == 0
    actions = [e["action"] for e in act["events"]]
    assert "mailbox.connected" in actions  # both the add and the forward-connect


# ── Plan entitlement gate ─────────────────────────────────────────────────────
def test_mailbox_add_blocked_after_trial_lapses(client: TestClient) -> None:
    h = _session(client, "it@lapse.example", "lapse.example")
    tid = _tenant_id(client, h)

    async def _expire() -> None:
        async with get_sessionmaker()() as s:
            tenant = await s.get(Tenant, UUID(tid))
            assert tenant is not None
            tenant.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
            tenant.payment_method_ok = False
            await s.commit()

    asyncio.run(_expire())

    blocked = client.post(
        "/api/v1/mailboxes",
        json={"address": "new@lapse.example", "mailbox_class": "protected", "sources": []},
        headers=h,
    )
    assert blocked.status_code == 402  # add a payment method to protect mailboxes


# ── Full account deletion keeps the domain ledger ─────────────────────────────
def test_delete_account_keeps_domain_ledger_and_blocks_re_trial(client: TestClient) -> None:
    h = _session(client, "owner@delco.example", "delco.example")
    _add(client, h, "ceo@delco.example")

    # Wrong password is refused.
    bad = client.request(
        "DELETE", "/api/v1/tenant", json={"password": "wrong"}, headers=h
    )
    assert bad.status_code == 401

    ok = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
    assert ok.status_code == 200
    assert ok.json()["domain_ledger_retained"] is True

    # The ledger row survives deletion by design.
    async def _ledger_exists() -> bool:
        async with get_sessionmaker()() as s:
            return await s.get(DomainTrialLedger, "delco.example") is not None

    assert asyncio.run(_ledger_exists()) is True

    # A returning owner on the same domain gets NO fresh trial — paid from the start.
    h2 = _session(client, "owner2@delco.example", "delco.example")
    tenant = client.get("/api/v1/tenant", headers=h2).json()
    assert tenant["trial"]["active"] is False
    assert tenant["plan"] == "guard"


# ── Deleting a mailbox / account that has actually been used ──────────────────
def _use(tid: UUID, mid: UUID) -> UUID:
    """What a few days of real protection leaves behind: a message with a
    rewritten (and clicked) link, an alert the AI judged, a payment check, and a
    paired sensor. Every one of these references the mailbox or its messages."""
    from uuid import uuid4

    from envelock.models import (
        Alert,
        AttestedRead,
        LinkClick,
        LinkToken,
        LlmVerdictRecord,
        Message,
        PaymentVerification,
        SensorDevice,
        SensorPairing,
    )

    now = datetime.now(UTC)
    msg, alert, token = uuid4(), uuid4(), uuid4()

    async def _seed() -> None:
        async with get_sessionmaker()() as s:
            s.add(Message(id=msg, tenant_id=tid, mailbox_id=mid, direction="inbound",
                          sender_address="billing@vendor.example", received_at=now,
                          source="imap_idle"))
            s.add(Alert(id=alert, tenant_id=tid, mailbox_id=mid, tier="high",
                        title="Bank details changed", body="..."))
            await s.flush()
            s.add(LinkToken(id=token, tenant_id=tid, mailbox_id=mid, message_id=msg,
                            token=uuid4().hex, original_url="https://vendor.example/pay"))
            s.add(LlmVerdictRecord(tenant_id=tid, mailbox_id=mid, message_id=msg,
                                   alert_id=alert, verdict="fraud"))
            s.add(PaymentVerification(tenant_id=tid, alert_id=alert, channel="call"))
            s.add(SensorPairing(tenant_id=tid, user_id=uuid4(), mailbox_id=mid,
                                code_hash="h" * 64, expires_at=now))
            s.add(SensorDevice(tenant_id=tid, user_id=uuid4(), mailbox_id=mid, prefix="envs_x",
                               hashed="h" * 64, client="browser", device_fingerprint="fp"))
            s.add(AttestedRead(tenant_id=tid, mailbox_id=mid, message_ref="<m@x>", read_at=now))
            await s.flush()
            s.add(LinkClick(link_token_id=token, tenant_id=tid, action="allowed"))
            await s.commit()

    asyncio.run(_seed())
    return token


def test_a_used_mailbox_can_be_removed_and_its_links_keep_working(client: TestClient) -> None:
    from envelock.models import LinkToken

    h = _session(client, "it@usedmb.example", "usedmb.example")
    tid = UUID(_tenant_id(client, h))
    mid = UUID(_add(client, h, "ap@usedmb.example"))
    token = _use(tid, mid)

    out = client.request(
        "DELETE", f"/api/v1/mailboxes/{mid}", json={"current_password": PW}, headers=h
    )
    assert out.status_code == 200, out.text

    async def _token():  # noqa: ANN202
        async with get_sessionmaker()() as s:
            return await s.get(LinkToken, token)

    kept = asyncio.run(_token())
    assert kept is not None and kept.mailbox_id is None, "a delivered /r/ link must still resolve"


def test_a_used_account_can_be_deleted_and_nothing_is_left(client: TestClient) -> None:
    from sqlalchemy import func, select

    from envelock.models import Base

    h = _session(client, "owner@usedacct.example", "usedacct.example")
    tid = UUID(_tenant_id(client, h))
    _use(tid, UUID(_add(client, h, "ap@usedacct.example")))

    ok = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
    assert ok.status_code == 200, ok.text

    # Erasure is the promise: no tenant-keyed row survives except the ledger.
    async def _left() -> dict:
        found = {}
        async with get_sessionmaker()() as s:
            for table in Base.metadata.tables.values():
                if "tenant_id" in table.c and table.name != "staff_audit_events":
                    n = (await s.execute(
                        select(func.count()).select_from(table).where(table.c.tenant_id == tid)
                    )).scalar_one()
                    if n:
                        found[table.name] = n
        return found

    assert asyncio.run(_left()) == {}


def test_deleting_a_paying_account_cancels_its_subscription_first(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from envelock.billing import payments
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_STRIPE_SECRET_KEY", "sk_test_x")
    get_settings.cache_clear()
    calls: list[tuple[str, str]] = []

    class _Stripe:
        fail = True

        async def request(self, method, url, *, headers, json=None, data=None):  # noqa: A002, ANN001, ANN202, ARG002
            calls.append((method, url))
            if self.fail:
                raise payments.PaymentError("stripe is down", status_code=500)
            return {"id": "sub_paying", "status": "canceled"}

    fake = _Stripe()
    payments.set_default_transport(fake)
    try:
        h = _session(client, "owner@paying.example", "paying.example")
        tid = UUID(_tenant_id(client, h))

        async def _subscribe() -> None:
            async with get_sessionmaker()() as s:
                tenant = await s.get(Tenant, tid)
                tenant.stripe_subscription_id = "sub_paying"
                await s.commit()

        asyncio.run(_subscribe())

        # Stripe can't confirm the cancellation: nothing is deleted.
        refused = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
        assert refused.status_code == 502
        assert client.get("/api/v1/tenant", headers=h).status_code == 200

        fake.fail = False
        ok = client.request("DELETE", "/api/v1/tenant", json={"password": PW}, headers=h)
        assert ok.status_code == 200, ok.text
        assert ("DELETE", "https://api.stripe.com/v1/subscriptions/sub_paying") in calls
    finally:
        payments.set_default_transport(None)


def test_a_suspended_workspace_is_actually_suspended(client: TestClient) -> None:
    """SUSPEND in the operator console set a flag nothing read: the users kept
    working and their mailboxes kept being polled."""
    from envelock.billing.entitlement import mailbox_entitled

    h = _session(client, "owner@suspended.example", "suspended.example")
    tid = UUID(_tenant_id(client, h))
    assert client.get("/api/v1/mailboxes", headers=h).status_code == 200

    async def _suspend() -> Tenant:
        async with get_sessionmaker()() as s:
            tenant = await s.get(Tenant, tid)
            tenant.is_active = False
            tenant.payment_method_ok = True  # paying, yet suspended
            await s.commit()
            return tenant

    tenant = asyncio.run(_suspend())
    refused = client.get("/api/v1/mailboxes", headers=h)
    assert refused.status_code == 403 and "suspended" in refused.json()["detail"]
    assert mailbox_entitled(tenant) is False, "the pollers must skip it too"
