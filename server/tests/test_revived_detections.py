"""Detections that were written correctly and could never fire.

C7, C9, C11, C13 and C14 were all implemented, registered and unit-tested
against synthetic contexts — and in production every one of them was dead,
because nothing ever supplied the input they read. `build_context` hardcoded
`latitude=None`, `mfa_enabled` was declared and never assigned, and the endpoint
that received read-attestations threw them away.

These tests pin the wiring, not the detection logic (which has its own tests):
the question here is "does the data actually reach the detection".
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from envelock.auth.security import _totp_at
from envelock.channels.identity import geo
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import AttestedRead, Domain, Mailbox, SensorSession, Tenant, User


@pytest.fixture(autouse=True)
def _clear_geo_cache():
    geo.reset_cache()
    yield
    geo.reset_cache()


# ── The geo lookup itself ────────────────────────────────────────────────────
async def test_private_addresses_are_never_sent_to_a_third_party() -> None:
    """A LAN address carries no location, and shipping a customer's internal
    addressing to an IP-intelligence vendor would be a needless disclosure."""
    for address in ("10.0.0.4", "192.168.1.10", "127.0.0.1", "169.254.169.254", "::1"):
        assert geo.is_public_ip(address) is False
        assert await geo.lookup(address) is geo.EMPTY
    assert geo.is_public_ip("8.8.8.8") is True


async def test_an_unconfigured_deployment_degrades_rather_than_errors(
    monkeypatch,
) -> None:
    """No provider configured must leave the detections off, not raise inside an
    ingest path. (The developer's own .env may carry a real IPinfo token — this
    test is about the UNCONFIGURED deployment, so clear it.)"""
    from envelock.config import get_settings

    # Patch the CACHED settings object: clearing the cache would just re-read
    # the .env file, token and all.
    monkeypatch.setattr(get_settings(), "ipinfo_token", None)
    facts = await geo.lookup("8.8.8.8")
    assert facts.located is False
    assert facts.anonymised is False


def test_ipinfo_shape_is_parsed_into_facts() -> None:
    facts = geo._parse_ipinfo(
        "1.2.3.4",
        {
            "country": "GB",
            "city": "London",
            "loc": "51.5074,-0.1278",
            "org": "AS15169 Google LLC",
            "privacy": {"vpn": True, "tor": False},
        },
    )
    assert (facts.country, facts.city) == ("GB", "London")
    assert facts.latitude == pytest.approx(51.5074)
    assert facts.longitude == pytest.approx(-0.1278)
    assert (facts.asn, facts.asn_name) == (15169, "Google LLC")
    assert facts.located and facts.anonymised


def test_a_malformed_location_does_not_break_the_parse() -> None:
    """A provider changing its response shape must degrade one field, not the
    whole enrichment."""
    facts = geo._parse_ipinfo("1.2.3.4", {"country": "GB", "loc": "not-coordinates"})
    assert facts.country == "GB"
    assert facts.located is False


# ── The wiring into the pipeline ─────────────────────────────────────────────
async def _seed(session, *, mfa: bool, slug: str = "geoco") -> tuple:  # noqa: ANN001
    """A tenant with one mailbox and the matching user account.

    `slug` varies the domain because `users.email` is globally unique — two
    cases seeding the same address collide.
    """
    tenant_id, mailbox_id = uuid4(), uuid4()
    session.add(Tenant(id=tenant_id, name="GeoCo"))
    await session.flush()
    session.add(
        Domain(
            id=uuid4(),
            tenant_id=tenant_id,
            name=f"{slug}.example",
            registrable_domain=f"{slug}.example",
            verification_token="tok",  # noqa: S106 — a DNS proof token
        )
    )
    session.add(
        Mailbox(
            id=mailbox_id,
            tenant_id=tenant_id,
            address=f"cfo@{slug}.example",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[SourceMechanism.CLIENT_SENSOR.value],
            is_active=True,
        )
    )
    session.add(
        User(
            id=uuid4(),
            tenant_id=tenant_id,
            email=f"cfo@{slug}.example",
            password_hash="scrypt$x",  # noqa: S106 — never verified in this test
            role="member",
            mfa_enabled=mfa,
        )
    )
    await session.commit()
    return tenant_id, mailbox_id


async def test_a_previous_session_now_carries_coordinates(db: None) -> None:
    """C7's haversine short-circuited on `latitude is None`, so impossible
    travel could never fire however far apart two sign-ins were."""
    from envelock.core.enums import IdentityEventKind
    from envelock.core.events import IdentityEvent, NetworkContext
    from envelock.platform.pipeline import build_context

    async with get_sessionmaker()() as session:
        tenant_id, mailbox_id = await _seed(session, mfa=True)
        session.add(
            SensorSession(
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                device_fingerprint="device-1",
                ip="8.8.8.8",
                country="US",
                latitude=37.4056,
                longitude=-122.0775,
                started_at=datetime.now(UTC) - timedelta(hours=1),
                last_seen_at=datetime.now(UTC) - timedelta(hours=1),
            )
        )
        await session.commit()

        now = datetime.now(UTC)
        ctx = await build_context(
            session,
            IdentityEvent(
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                occurred_at=now,
                ingested_at=now,
                source=SourceMechanism.CLIENT_SENSOR,
                kind=IdentityEventKind.SIGN_IN,
                network=NetworkContext(latitude=51.5, longitude=-0.12, country="GB"),
            ),
            tenant_id=tenant_id,
            owned_domains=frozenset({"geoco.example"}),
        )

    assert ctx.previous_session is not None
    assert ctx.previous_session.latitude == pytest.approx(37.4056)
    assert ctx.previous_session.longitude == pytest.approx(-122.0775)


async def test_impossible_travel_actually_fires_end_to_end(db: None) -> None:
    """The whole point: two located sign-ins an ocean apart, an hour apart."""
    from envelock.core.enums import IdentityEventKind
    from envelock.core.events import IdentityEvent, NetworkContext
    from envelock.detections.base import run_all
    from envelock.platform.pipeline import build_context

    async with get_sessionmaker()() as session:
        tenant_id, mailbox_id = await _seed(session, mfa=True)
        session.add(
            SensorSession(
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                device_fingerprint="device-1",
                ip="8.8.8.8",
                country="US",
                latitude=37.4056,   # California
                longitude=-122.0775,
                started_at=datetime.now(UTC) - timedelta(hours=1),
                last_seen_at=datetime.now(UTC) - timedelta(hours=1),
            )
        )
        await session.commit()

        now = datetime.now(UTC)
        ctx = await build_context(
            session,
            IdentityEvent(
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                occurred_at=now,
                ingested_at=now,
                source=SourceMechanism.CLIENT_SENSOR,
                kind=IdentityEventKind.SIGN_IN,
                network=NetworkContext(
                    latitude=51.5074, longitude=-0.1278, country="GB"  # London
                ),
            ),
            tenant_id=tenant_id,
            owned_domains=frozenset({"geoco.example"}),
        )

    services = {f.service for f in run_all(ctx)}
    assert "C7" in services, "impossible travel must fire on a located pair"


async def test_mfa_posture_is_read_from_the_account(db: None) -> None:
    """`mfa_enabled` was declared and never assigned, so C13 saw None forever."""
    from envelock.core.enums import IdentityEventKind
    from envelock.core.events import IdentityEvent, NetworkContext
    from envelock.platform.pipeline import build_context

    for mfa, expected, slug in ((True, True, "mfaon"), (False, False, "mfaoff")):
        async with get_sessionmaker()() as session:
            # A distinct domain per case: users.email is globally unique.
            tenant_id, mailbox_id = await _seed(session, mfa=mfa, slug=slug)
            now = datetime.now(UTC)
            ctx = await build_context(
                session,
                IdentityEvent(
                    tenant_id=tenant_id,
                    mailbox_id=mailbox_id,
                    occurred_at=now,
                    ingested_at=now,
                    source=SourceMechanism.CLIENT_SENSOR,
                    kind=IdentityEventKind.SIGN_IN,
                    network=NetworkContext(),
                ),
                tenant_id=tenant_id,
                owned_domains=frozenset({f"{slug}.example"}),
            )
        assert ctx.mfa_enabled is expected


# ── C11: attested reads ──────────────────────────────────────────────────────
def _session_headers(client: TestClient, email: str, tenant: str) -> dict[str, str]:
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


def test_an_attested_read_is_recorded_and_suppresses_c11(client: TestClient) -> None:
    """C11 fires when a message is read with nobody here. The endpoint that
    received the sensor's "I opened it" used to validate the mailbox and discard
    the attestation, so every legitimate read looked like an intrusion."""
    import asyncio

    h = _session_headers(client, "it@attest.example", "Attest")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Attest", "domain": "attest.example"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "cfo@attest.example", "mailbox_class": "protected"},
        headers=h,
    )

    body = {
        "mailbox_address": "cfo@attest.example",
        "device_fingerprint": "device-abc",
        "message_ref": "1001",
    }
    assert client.post("/api/v1/sensor/message-opened", json=body, headers=h).status_code == 200

    async def _count() -> int:
        async with get_sessionmaker()() as s:
            rows = (await s.execute(select(AttestedRead))).scalars().all()
            return len(rows)

    assert asyncio.run(_count()) == 1, "the attestation must actually be stored"

    # The flag change now finds it, so C11 stays quiet.
    flagged = client.post(
        "/api/v1/sensor/flag-changed",
        json={"mailbox_address": "cfo@attest.example", "message_ref": "1001", "flag": "seen"},
        headers=h,
    )
    assert flagged.status_code == 200
    assert "C11" not in {f["service"] for f in flagged.json()["findings"]}


def test_an_unattested_read_still_raises_c11(client: TestClient) -> None:
    """The detection must still work — suppressing it for everything would be
    worse than the false positives it used to produce."""
    h = _session_headers(client, "it@unattest.example", "Unattest")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Unattest", "domain": "unattest.example"},
        headers=h,
    )
    client.post(
        "/api/v1/mailboxes",
        json={"address": "cfo@unattest.example", "mailbox_class": "protected"},
        headers=h,
    )

    flagged = client.post(
        "/api/v1/sensor/flag-changed",
        json={
            "mailbox_address": "cfo@unattest.example",
            "message_ref": "2002",
            "flag": "seen",
        },
        headers=h,
    )
    assert flagged.status_code == 200
    assert "C11" in {f["service"] for f in flagged.json()["findings"]}


# ── E6 escalation must fire once per stage, not once per cycle ───────────────
async def test_each_escalation_stage_fires_exactly_once(db: None) -> None:
    """`escalated_at` is one timestamp overwritten by each step, so the
    60-minute rule matched on every subsequent cycle: the job re-escalated the
    same alert once a minute, forever — an SMS per minute to an admin until
    somebody acknowledged. Found by reading the audit trail of a running
    instance, which showed 590 escalations for three alerts."""
    from envelock.core.enums import AlertTier
    from envelock.models import Alert
    from envelock.platform.alerts import due_escalations, mark_escalated

    tenant_id = uuid4()
    async with get_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name="EscCo"))
        await session.flush()
        alert = Alert(
            id=uuid4(),
            tenant_id=tenant_id,
            mailbox_id=None,
            tier=AlertTier.CRITICAL.value,
            title="Wire to a new account",
            body="…",
            state="open",
        )
        session.add(alert)
        await session.flush()
        alert.created_at = datetime.now(UTC) - timedelta(minutes=20)
        await session.commit()
        alert_id = alert.id

        # 20 minutes old → the first stage, once.
        steps = await due_escalations(session, tenant_id=tenant_id)
        assert [s.to for s in steps] == ["it_admin"]
        await mark_escalated(session, alert_id=alert_id, tenant_id=tenant_id, to="it_admin")
        await session.commit()

        # Same cycle again: nothing new to do.
        assert await due_escalations(session, tenant_id=tenant_id) == []

        # Past an hour → the second stage, once.
        row = await session.get(Alert, alert_id)
        row.created_at = datetime.now(UTC) - timedelta(minutes=75)
        await session.commit()

        steps = await due_escalations(session, tenant_id=tenant_id)
        assert [s.to for s in steps] == ["all_admins"]
        await mark_escalated(session, alert_id=alert_id, tenant_id=tenant_id, to="all_admins")
        await session.commit()

        # And then it stops — this is the loop that was firing every 60 seconds.
        for _ in range(3):
            assert await due_escalations(session, tenant_id=tenant_id) == []
