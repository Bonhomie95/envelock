"""F2 — the payment-fraud "known good" is verified ground truth.

Every write to it (the account A1 checks against, the number A2 tells people to
ring) must take a fresh re-authentication and leave an audit trail. A stolen
session that could silently point the known-good account or the callback number
at the attacker would defeat the one check the whole product rests on — and,
before this, two of these writes left no record that they had happened at all.

These run on a deferred-MFA (password-only) session, so the re-auth is the
current password; an MFA account additionally needs a fresh code, which the
shared `_verify_step_up` already enforces and the account-security tests cover.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.main import app

PW = "a-long-enough-passphrase"
DOMAIN = "supplier-truth.example"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    client.post(
        "/api/v1/auth/register",
        json={"email": f"owner@{DOMAIN}", "password": PW, "tenant_name": DOMAIN},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": f"owner@{DOMAIN}", "password": PW}
    ).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    return {"Authorization": f"Bearer {skip['access_token']}"}


def _audit_actions(client: TestClient, admin: dict) -> list[str]:
    body = client.get("/api/v1/audit", headers=admin).json()
    return [e["action"] for e in body["events"]]


# ── Bank record (A1 ground truth) ────────────────────────────────────────────
def test_adding_a_bank_record_needs_reauth_and_is_audited(
    client: TestClient, admin: dict
) -> None:
    body = {"scheme": "iban", "identifier": "GB33BUKB20201555555555"}

    # Session alone, no password → refused (422: the field is required).
    assert (
        client.post(
            f"/api/v1/counterparties/{DOMAIN}/bank-records", json=body, headers=admin
        ).status_code
        == 422
    )
    # Wrong password → 401.
    assert (
        client.post(
            f"/api/v1/counterparties/{DOMAIN}/bank-records",
            json={**body, "current_password": "not-the-password"},
            headers=admin,
        ).status_code
        == 401
    )
    # Correct password → recorded, and the write leaves an audit trail (it left
    # none before this fix — the parity bug with the retire path).
    ok = client.post(
        f"/api/v1/counterparties/{DOMAIN}/bank-records",
        json={**body, "current_password": PW},
        headers=admin,
    )
    assert ok.status_code == 201, ok.text
    assert "counterparty.bank_record_added" in _audit_actions(client, admin)


def test_retiring_a_bank_record_needs_reauth(client: TestClient, admin: dict) -> None:
    client.post(
        f"/api/v1/counterparties/{DOMAIN}/bank-records",
        json={"scheme": "iban", "identifier": "GB33BUKB20201555555555", "current_password": PW},
        headers=admin,
    )
    rid = client.get(
        f"/api/v1/counterparties/{DOMAIN}/bank-records", headers=admin
    ).json()["records"][0]["id"]

    # No re-auth body → refused (the owned record exists, so this is the step-up,
    # not a 404).
    refused = client.request(
        "DELETE", f"/api/v1/counterparties/{DOMAIN}/bank-records/{rid}", headers=admin
    )
    assert refused.status_code == 401, refused.text

    ok = client.request(
        "DELETE",
        f"/api/v1/counterparties/{DOMAIN}/bank-records/{rid}",
        json={"current_password": PW},
        headers=admin,
    )
    assert ok.status_code == 200, ok.text


# ── Callback number (A2 ground truth) ────────────────────────────────────────
def test_setting_the_callback_number_needs_reauth(client: TestClient, admin: dict) -> None:
    assert (
        client.post(
            f"/api/v1/counterparties/{DOMAIN}/phone",
            json={"phone": "+1 555 0100"},
            headers=admin,
        ).status_code
        == 422
    )
    ok = client.post(
        f"/api/v1/counterparties/{DOMAIN}/phone",
        json={"phone": "+1 555 0100", "current_password": PW},
        headers=admin,
    )
    assert ok.status_code == 200, ok.text


def test_upsert_needs_reauth_only_when_it_sets_the_phone_and_audits_it(
    client: TestClient, admin: dict
) -> None:
    # Display name alone is not verified ground truth → no re-auth required.
    plain = client.post(
        "/api/v1/counterparties",
        json={"domain": DOMAIN, "display_name": "Acme"},
        headers=admin,
    )
    assert plain.status_code == 201, plain.text

    # Setting the callback number through the same endpoint is, so it is refused
    # without re-auth…
    refused = client.post(
        "/api/v1/counterparties",
        json={"domain": DOMAIN, "verified_phone": "+1 555 0100"},
        headers=admin,
    )
    assert refused.status_code == 401, refused.text

    # …and with it, it is recorded and audited (it was silent before this fix).
    ok = client.post(
        "/api/v1/counterparties",
        json={"domain": DOMAIN, "verified_phone": "+1 555 0100", "current_password": PW},
        headers=admin,
    )
    assert ok.status_code == 201, ok.text
    assert "counterparty.callback_number_set" in _audit_actions(client, admin)


# ── Vendor-master import (the same ground truth, in bulk) ────────────────────
def test_importing_the_vendor_master_needs_reauth_but_the_preview_does_not(
    client: TestClient, admin: dict
) -> None:
    csv = "Supplier,Email,IBAN\nAcme Ltd,accounts@acme-import.example,GB33BUKB20201555555555\n"
    url = "/api/v1/counterparties/import"

    # The preview writes nothing, so it needs no password.
    preview = client.post(url, json={"csv": csv, "dry_run": True}, headers=admin)
    assert preview.status_code == 200
    assert preview.json()["bank_records_created"] == 1

    # A real import on the session alone, or with the wrong password, is refused.
    assert client.post(url, json={"csv": csv}, headers=admin).status_code == 401
    assert (
        client.post(
            url, json={"csv": csv, "current_password": "not-the-password"}, headers=admin
        ).status_code
        == 401
    )

    # With the password it writes — and the record is new, so neither refused
    # attempt slipped anything in first.
    ok = client.post(url, json={"csv": csv, "current_password": PW}, headers=admin)
    assert ok.status_code == 200
    assert ok.json()["bank_records_created"] == 1
    assert "counterparty.vendor_master_imported" in _audit_actions(client, admin)
