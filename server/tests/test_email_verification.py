"""Email-ownership verification (ENVELOCK_REQUIRE_EMAIL_VERIFICATION) — the
anti-squatting control for one-company-one-tenant.

Both fixtures below set the flag explicitly rather than leaning on whatever the
ambient `.env` happens to say. `test_flag_off_...` used to assume the default
was off, so turning verification on for the real deployment broke a test that
was not about the deployment at all — a test that names a flag has to set it."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from envelock.models import Tenant, User


@pytest.fixture
def verification_on(monkeypatch):
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_REQUIRE_EMAIL_VERIFICATION", "true")
    get_settings.cache_clear()
    yield
    monkeypatch.delenv("ENVELOCK_REQUIRE_EMAIL_VERIFICATION", raising=False)
    get_settings.cache_clear()


@pytest.fixture
def verification_off(monkeypatch):
    """The relay-less deployment, asserted rather than assumed."""
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_REQUIRE_EMAIL_VERIFICATION", "false")
    get_settings.cache_clear()
    yield
    monkeypatch.delenv("ENVELOCK_REQUIRE_EMAIL_VERIFICATION", raising=False)
    get_settings.cache_clear()


def _register(client, email: str) -> dict:
    r = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "correct-horse-battery-9", "tenant_name": "Acme"},
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_unverified_account_cannot_sign_in_until_verified(client, verification_on) -> None:
    body = _register(client, "owner@acme-corp.com")
    assert body["verification_required"] is True
    # Development hands the link back (a relay-less dev box must stay usable).
    assert "verify_link" in body
    token = body["verify_link"].split("token=", 1)[1]

    login = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@acme-corp.com", "password": "correct-horse-battery-9"},
    )
    assert login.status_code == 403
    assert "confirm your email" in login.json()["detail"]

    verified = client.post("/api/v1/auth/verify-email", json={"token": token})
    assert verified.status_code == 200 and verified.json()["verified"] is True

    login2 = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@acme-corp.com", "password": "correct-horse-battery-9"},
    )
    assert login2.status_code == 200
    assert "mfa_token" in login2.json()


async def test_trial_starts_at_verification_not_registration(
    client, session, verification_on
) -> None:
    body = _register(client, "owner@trialco-example.com")
    token = body["verify_link"].split("token=", 1)[1]

    owner = (
        await session.execute(select(User).where(User.email == "owner@trialco-example.com"))
    ).scalar_one()
    tenant = await session.get(Tenant, owner.tenant_id)
    # A squatter who never verifies must not burn the domain's only trial.
    assert tenant.trial_started_at is None

    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 200
    await session.refresh(tenant)
    assert tenant.trial_started_at is not None


async def test_unverified_tenant_does_not_capture_real_colleagues(
    client, session, verification_on
) -> None:
    # The "squatter": registers first on the company domain, never verifies.
    _register(client, "fake@victim-company.com")
    # The real employee registers later.
    _register(client, "real@victim-company.com")

    fake = (
        await session.execute(select(User).where(User.email == "fake@victim-company.com"))
    ).scalar_one()
    real = (
        await session.execute(select(User).where(User.email == "real@victim-company.com"))
    ).scalar_one()
    # The employee did NOT land as a pending member of the squatter's tenant —
    # they got a fresh tenant of their own, as its owner.
    assert real.tenant_id != fake.tenant_id
    assert real.role == "owner"


def test_resend_never_enumerates(client, verification_on) -> None:
    _register(client, "someone@resend-example.com")
    known = client.post(
        "/api/v1/auth/verify-email/resend", json={"email": "someone@resend-example.com"}
    )
    unknown = client.post(
        "/api/v1/auth/verify-email/resend", json={"email": "nobody@resend-example.com"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.json()["status"] == unknown.json()["status"] == "sent"


def test_flag_off_keeps_registration_unchanged(client, verification_off) -> None:
    body = _register(client, "plain@flagoff-example.com")
    assert "verification_required" not in body
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "plain@flagoff-example.com", "password": "correct-horse-battery-9"},
    )
    assert login.status_code == 200


def test_a_provisioned_teammate_can_actually_sign_in(client, verification_on) -> None:
    """The regression that turning the flag on would otherwise have shipped.

    Only `/auth/register` sends a verification link. A colleague the owner
    provisions never goes through it, so without marking them verified at
    creation they are handed a temporary password and then refused at sign-in
    forever — with the error telling them to resend a link they were never sent.
    """
    domain = "provisioned-example.com"
    owner = f"owner@{domain}"
    pw = "correct-horse-battery-9"

    reg = _register(client, owner)
    client.post(
        "/api/v1/auth/verify-email",
        json={"token": reg["verify_link"].split("token=", 1)[1]},
    )
    login = client.post("/api/v1/auth/login", json={"email": owner, "password": pw}).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    headers = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=headers
    )
    # A seat only exists where a protected mailbox does.
    client.post(
        "/api/v1/mailboxes",
        json={"address": f"cfo@{domain}", "mailbox_class": "protected", "sources": []},
        headers=headers,
    )

    created = client.post(
        "/api/v1/members",
        json={"email": f"cfo@{domain}", "role": "member"},
        headers=headers,
    )
    assert created.status_code == 201, created.text

    member_login = client.post(
        "/api/v1/auth/login",
        json={"email": f"cfo@{domain}", "password": created.json()["temporary_password"]},
    )
    assert member_login.status_code == 200, member_login.text
    assert "confirm your email" not in member_login.text
