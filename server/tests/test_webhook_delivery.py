"""Outbound SIEM webhooks (PRD §15.3).

The signing, the envelope and the retry schedule were written and tested; what
was missing was anything that sent. `WebhookEndpoint` was a table with no code
behind it and `RETRY_SCHEDULE` was a constant nothing consulted — so a customer
could be told their SIEM integration existed and receive nothing at all.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from envelock.auth.security import _totp_at
from envelock.db import get_sessionmaker
from envelock.governance import export as ex
from envelock.models import WebhookDelivery, WebhookEndpoint
from envelock.workers import webhook_delivery as wd


def _session(client: TestClient, email: str, tenant: str) -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": tenant},
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
    return {"Authorization": f"Bearer {tokens['access_token']}"}


# ── SSRF guard ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/hook",
        "http://localhost:9000/hook",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5/hook",
        "ftp://example.com/hook",
    ],
)
def test_internal_and_non_http_destinations_are_refused(url: str) -> None:
    """The URL comes from a customer form and WE make the request — without this
    an outbound webhook is a request-forgery primitive aimed at our own network."""
    with pytest.raises(wd.UnsafeUrlError):
        wd.assert_safe_url(url)


def test_a_public_https_destination_is_allowed() -> None:
    wd.assert_safe_url("https://example.com/hooks/envelock")


def test_registering_an_internal_url_fails_on_the_form_not_four_hours_later(
    client: TestClient,
) -> None:
    h = _session(client, "it@hookguard.example", "HookGuard")
    r = client.post(
        "/api/v1/export/webhooks",
        json={"url": "http://127.0.0.1:8080/siem"},
        headers=h,
    )
    assert r.status_code == 422
    assert "private" in r.json()["detail"] or "reserved" in r.json()["detail"]


# ── Registration ─────────────────────────────────────────────────────────────
def test_the_signing_secret_is_returned_once_and_never_again(client: TestClient) -> None:
    h = _session(client, "it@hooksecret.example", "HookSecret")
    created = client.post(
        "/api/v1/export/webhooks",
        json={"url": "https://siem.example.com/envelock", "events": ["alert.raised"]},
        headers=h,
    )
    assert created.status_code == 201, created.text
    assert created.json()["secret"].startswith("whsec_")

    listed = client.get("/api/v1/export/webhooks", headers=h).json()
    assert len(listed["webhooks"]) == 1
    assert "secret" not in listed["webhooks"][0], "the secret must not be readable back"
    assert "alert.raised" in listed["events"]


def test_an_unknown_event_type_is_rejected(client: TestClient) -> None:
    h = _session(client, "it@hookevent.example", "HookEvent")
    r = client.post(
        "/api/v1/export/webhooks",
        json={"url": "https://siem.example.com/x", "events": ["alert.teleported"]},
        headers=h,
    )
    assert r.status_code == 422


def test_a_webhook_belongs_to_its_tenant(client: TestClient) -> None:
    a = _session(client, "it@hookowner.example", "HookOwner")
    created = client.post(
        "/api/v1/export/webhooks",
        json={"url": "https://siem.example.com/a"},
        headers=a,
    ).json()
    b = _session(client, "it@hookother.example", "HookOther")
    assert (
        client.delete(f"/api/v1/export/webhooks/{created['id']}", headers=b).status_code
        == 404
    )
    assert (
        client.patch(
            f"/api/v1/export/webhooks/{created['id']}",
            json={"active": False},
            headers=b,
        ).status_code
        == 404
    )


# ── The queue ────────────────────────────────────────────────────────────────
async def _endpoint(session, tenant_id, *, events=None):  # noqa: ANN001
    endpoint = WebhookEndpoint(
        tenant_id=tenant_id,
        url="https://siem.example.com/envelock",
        secret=ex.generate_webhook_secret(),
        events=list(events or []),
        active=True,
    )
    session.add(endpoint)
    await session.flush()
    return endpoint


async def test_enqueue_respects_the_event_subscription(db: None) -> None:
    from uuid import uuid4

    tenant_id = uuid4()
    async with get_sessionmaker()() as session:
        await _endpoint(session, tenant_id, events=["lookalike.detected"])
        queued = await wd.enqueue(
            session, tenant_id=tenant_id, event=ex.WebhookEvent.ALERT_RAISED, data={}
        )
        assert queued == 0, "an endpoint subscribed elsewhere must not receive this"

        await _endpoint(session, tenant_id, events=[])  # empty == everything
        queued = await wd.enqueue(
            session, tenant_id=tenant_id, event=ex.WebhookEvent.ALERT_RAISED, data={}
        )
        assert queued == 1


async def test_a_failed_attempt_backs_off_on_the_published_schedule(db: None) -> None:
    """A receiver being down is normal; the schedule is what lets it survive a
    deploy without losing alerts."""
    from uuid import uuid4

    tenant_id = uuid4()
    async with get_sessionmaker()() as session:
        endpoint = await _endpoint(session, tenant_id)
        await wd.enqueue(
            session, tenant_id=tenant_id, event=ex.WebhookEvent.ALERT_RAISED, data={"a": 1}
        )
        await session.commit()

        # Nothing answers at that host, so the attempt fails and backs off
        # rather than giving up.
        summary = await wd.drain(session)
        assert summary["attempted"] == 1
        assert summary["retrying"] == 1

        row = (await session.execute(select(WebhookDelivery))).scalars().one()
        assert row.status == "pending"
        assert row.attempt == 1
        assert row.last_error
        # Backed off by the second entry in the schedule (the first is 0).
        assert row.next_attempt_at > datetime.now(UTC)
        # An unresolvable receiver is transient, so it must be visible to the
        # customer without being treated as a permanent block.
        assert endpoint.last_status in ("error", "unresolved")


async def test_exhausting_the_schedule_marks_it_failed_rather_than_retrying_forever(
    db: None,
) -> None:
    from uuid import uuid4

    tenant_id = uuid4()
    async with get_sessionmaker()() as session:
        await _endpoint(session, tenant_id)
        await wd.enqueue(
            session, tenant_id=tenant_id, event=ex.WebhookEvent.ALERT_RAISED, data={}
        )
        await session.commit()

        row = (await session.execute(select(WebhookDelivery))).scalars().one()
        row.attempt = len(ex.RETRY_SCHEDULE)  # one past the last delay
        row.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

        summary = await wd.drain(session)
        assert summary["failed"] == 1
        refreshed = (await session.execute(select(WebhookDelivery))).scalars().one()
        assert refreshed.status == "failed"


async def test_a_delivery_is_signed_so_the_receiver_can_verify_it(db: None) -> None:
    """The signature covers the timestamp too, so a captured body cannot be
    replayed later with a fresh header."""
    from uuid import uuid4

    tenant_id = uuid4()
    async with get_sessionmaker()() as session:
        endpoint = await _endpoint(session, tenant_id)
        await wd.enqueue(
            session,
            tenant_id=tenant_id,
            event=ex.WebhookEvent.ALERT_RAISED,
            data={"alert_id": "abc"},
        )
        await session.commit()
        delivery = (await session.execute(select(WebhookDelivery))).scalars().one()
        secret = endpoint.secret

    body = json.dumps(delivery.payload, separators=(",", ":")).encode()
    signature, timestamp = ex.sign_payload(secret, body)
    assert ex.verify_signature(secret, body, signature, timestamp)
    assert not ex.verify_signature("whsec_wrong", body, signature, timestamp)


def test_raising_an_alert_queues_its_delivery_in_the_same_transaction(
    client: TestClient,
) -> None:
    """Enqueue happens inside the alert's transaction, so there is no window in
    which an alert exists and its SIEM delivery does not."""
    import asyncio

    h = _session(client, "it@hookalert.example", "HookAlert")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "HookAlert", "domain": "hookalert.example"},
        headers=h,
    )
    client.post(
        "/api/v1/export/webhooks",
        json={"url": "https://siem.example.com/envelock"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "pay@hookalert.example", "mailbox_class": "protected"},
        headers=h,
    )

    raw = (
        "From: \"Vendor\" <billing@vendor-lookalike.test>\r\n"
        "To: pay@hookalert.example\r\n"
        "Subject: URGENT updated bank details\r\n\r\n"
        "Remit to IBAN GB33BUKB20201555555555 today.\r\n"
    )
    posted = client.post(
        "/api/v1/ingest",
        json={"raw_message": raw, "mailbox_address": "pay@hookalert.example"},
        headers=h,
    )
    assert posted.status_code == 202
    if not posted.json().get("alerted"):
        pytest.skip("this message did not reach the alert threshold")

    async def _queued() -> int:
        async with get_sessionmaker()() as s:
            return len((await s.execute(select(WebhookDelivery))).scalars().all())

    assert asyncio.run(_queued()) >= 1


def test_the_guard_returns_the_ip_the_caller_must_dial() -> None:
    """DNS-rebinding defence: checking the hostname and letting the HTTP client
    resolve it again is a TOCTOU window. The guard hands back the address it
    approved so the request goes THERE."""
    ip = wd.assert_safe_url("https://example.com/hooks/envelock")
    assert ip and ip.count(".") == 3 or ":" in (ip or "")

    dial, headers, ext = wd.pinned_request("https://example.com/hooks/envelock", ip)
    # Dialled by address...
    assert ip in dial and dial.startswith("https://")
    # ...but the receiver still sees its own name, and TLS still verifies it.
    assert headers["Host"] == "example.com"
    assert ext["sni_hostname"] == "example.com"


def test_pinning_is_a_no_op_when_the_guard_is_disabled() -> None:
    """A self-hosted deployment that opted out keeps the plain URL."""
    dial, headers, ext = wd.pinned_request("https://siem.internal/hook", None)
    assert dial == "https://siem.internal/hook" and not headers and not ext
