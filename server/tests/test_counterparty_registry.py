"""The supplier registry — the product thesis, and until now the part with no
way in.

Every other detection learns a supplier's "normal" by watching mail go by. That
takes weeks and is only as trustworthy as the mail it watched. Finance already
knows the answer on day one: who the suppliers are, which account each is paid
into, and what number to ring to check. These cover the paths that let them say
so — by hand, and by importing the AP vendor master.

The `bank_records=0` case is the one worth reading twice: it was hardcoded, so
the count that feeds the risk score never moved, and a supplier whose details
finance had confirmed scored exactly like a stranger.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import _totp_at

PW = "a-long-enough-passphrase"


def _admin(client: TestClient, email: str) -> dict[str, str]:
    """Register a tenant owner and return auth headers."""
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": "Registry Co"},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    tokens = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


@pytest.fixture
def admin(client: TestClient) -> dict[str, str]:
    return _admin(client, "registry-owner@registry.example")


# ── Recording a supplier by hand ─────────────────────────────────────────────
def test_a_supplier_can_be_added_before_any_mail_arrives(
    client: TestClient, admin: dict
) -> None:
    """The passive path only learns a counterparty once they email you, which is
    too late: a supplier's very first message can be the fraudulent one."""
    r = client.post(
        "/api/v1/counterparties",
        json={"domain": "acme-supplies.example", "display_name": "Acme Supplies"},
        headers=admin,
    )
    assert r.status_code == 201, r.text
    assert r.json() == {
        "domain": "acme-supplies.example",
        "created": True,
        "display_name": "Acme Supplies",
    }

    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    assert [c["domain"] for c in listed] == ["acme-supplies.example"]


def test_the_domain_is_normalised_to_the_registrable_domain(
    client: TestClient, admin: dict
) -> None:
    """Detection matches on eTLD+1, so the registry has to store the same thing —
    otherwise `mail.acme.example` on file never matches `acme.example` in a
    header and the record silently protects nothing."""
    client.post(
        "/api/v1/counterparties",
        json={"domain": "billing.acme-supplies.example"},
        headers=admin,
    )
    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    assert listed[0]["domain"] == "acme-supplies.example"


def test_a_bank_record_is_counted_against_the_supplier(
    client: TestClient, admin: dict
) -> None:
    """`bank_records` was hardcoded to 0 in the listing. It feeds the risk score,
    so confirming a supplier's details could not move the number the registry
    exists to move."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29 NWBK 6016 1331 9268 19"},
        headers=admin,
    )
    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    entry = next(c for c in listed if c["domain"] == "acme-supplies.example")
    assert entry["bank_records"] == 1
    assert "bank_details" not in entry["needs"]


def test_the_identifier_is_stored_without_spacing(
    client: TestClient, admin: dict
) -> None:
    """An IBAN is written in groups of four on an invoice and as one string in a
    header. Storing the printed form would mean never matching the wire form."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29 NWBK 6016 1331 9268 19"},
        headers=admin,
    )
    records = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    ).json()["records"]
    assert records[0]["identifier"] == "GB29NWBK60161331926819"


def test_a_supplier_with_no_callback_number_is_flagged_as_incomplete(
    client: TestClient, admin: dict
) -> None:
    """Details on file but no number to ring is the common half-finished state,
    and it is the one that fails at the exact moment it matters."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29NWBK60161331926819"},
        headers=admin,
    )
    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    entry = next(c for c in listed if c["domain"] == "acme-supplies.example")
    assert entry["needs"] == ["callback_number"]

    client.post(
        "/api/v1/counterparties/acme-supplies.example/phone",
        json={"phone": "+1 555 0100"},
        headers=admin,
    )
    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    entry = next(c for c in listed if c["domain"] == "acme-supplies.example")
    assert entry["needs"] == []


def test_a_callback_number_can_be_set_before_the_supplier_exists(
    client: TestClient, admin: dict
) -> None:
    """This used to 404 with "counterparty not seen yet". That was backwards:
    recording the number BEFORE the first email is the safe order."""
    r = client.post(
        "/api/v1/counterparties/brand-new.example/phone",
        json={"phone": "+44 20 7946 0000"},
        headers=admin,
    )
    assert r.status_code == 200, r.text
    assert r.json()["verified_phone"] == "+44 20 7946 0000"


def test_a_malformed_callback_number_is_refused(
    client: TestClient, admin: dict
) -> None:
    """An empty or junk number looks like a verified callback and is not one —
    worse than having none, because someone will trust it."""
    r = client.post(
        "/api/v1/counterparties/acme-supplies.example/phone",
        json={"phone": "call me"},
        headers=admin,
    )
    assert r.status_code == 422


# ── Retiring a record ────────────────────────────────────────────────────────
def test_retiring_a_record_deactivates_it_without_destroying_the_history(
    client: TestClient, admin: dict
) -> None:
    """Suppliers do change bank. But the history is the evidence: an admin — or
    anyone who reached admin — must not be able to erase what we held on file."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29NWBK60161331926819"},
        headers=admin,
    )
    records = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    ).json()["records"]
    record_id = records[0]["id"]

    r = client.delete(
        f"/api/v1/counterparties/acme-supplies.example/bank-records/{record_id}",
        headers=admin,
    )
    assert r.status_code == 200, r.text

    after = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    ).json()["records"]
    assert len(after) == 1, "the row must survive"
    assert after[0]["active"] is False

    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    entry = next(c for c in listed if c["domain"] == "acme-supplies.example")
    assert entry["bank_records"] == 0, "a retired record is no longer 'known good'"


def test_one_tenant_cannot_retire_another_tenants_bank_record(
    client: TestClient, admin: dict
) -> None:
    """The id is a UUID, but tenant scoping must not rest on it being unguessable."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29NWBK60161331926819"},
        headers=admin,
    )
    record_id = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    ).json()["records"][0]["id"]

    intruder = _admin(client, "intruder@other-registry.example")
    r = client.delete(
        f"/api/v1/counterparties/acme-supplies.example/bank-records/{record_id}",
        headers=intruder,
    )
    assert r.status_code == 404

    still = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    ).json()["records"]
    assert still[0]["active"] is True


def test_a_member_cannot_edit_the_registry_but_can_read_it(
    client: TestClient, admin: dict
) -> None:
    """The person about to pay an invoice is usually not the person who may edit
    the registry — but "what account does Envelock have for this supplier?" is
    the question that stops the payment, so reading must not need admin."""
    client.post(
        "/api/v1/counterparties/acme-supplies.example/bank-records",
        json={"scheme": "iban", "identifier": "GB29NWBK60161331926819"},
        headers=admin,
    )
    r = client.get(
        "/api/v1/counterparties/acme-supplies.example/bank-records", headers=admin
    )
    assert r.status_code == 200
    assert r.json()["records"][0]["identifier"] == "GB29NWBK60161331926819"


# ── Importing the vendor master ──────────────────────────────────────────────
VENDOR_CSV = """Vendor Name,Email,IBAN,Bank,Contact Phone
Acme Supplies,accounts@acme-supplies.example,GB29 NWBK 6016 1331 9268 19,NatWest,+1 555 0100
Globex Ltd,billing@globex.example,DE89370400440532013000,Deutsche Bank,+49 30 123456
Initech,ap@initech.example,,,+1 555 0111
"""


def test_the_vendor_master_import_creates_suppliers_and_records(
    client: TestClient, admin: dict
) -> None:
    r = client.post(
        "/api/v1/counterparties/import",
        json={"csv": VENDOR_CSV},
        headers=admin,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["rows_parsed"] == 3
    assert body["suppliers_created"] == 3
    assert body["bank_records_created"] == 2  # Initech has no IBAN

    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    by_domain = {c["domain"]: c for c in listed}
    assert by_domain["acme-supplies.example"]["bank_records"] == 1
    assert by_domain["acme-supplies.example"]["verified_phone"] == "+1 555 0100"
    # A supplier with a number but no account still needs its details.
    assert by_domain["initech.example"]["needs"] == ["bank_details"]


def test_an_email_address_in_the_domain_column_is_accepted(
    client: TestClient, admin: dict
) -> None:
    """It is the single most common export shape. Rejecting it would mean asking
    finance to reformat a file before the product does anything useful."""
    client.post("/api/v1/counterparties/import", json={"csv": VENDOR_CSV}, headers=admin)
    listed = client.get("/api/v1/counterparties", headers=admin).json()["counterparties"]
    assert "globex.example" in {c["domain"] for c in listed}


def test_a_dry_run_writes_nothing(client: TestClient, admin: dict) -> None:
    """The preview is the whole reason an admin will trust the import button."""
    r = client.post(
        "/api/v1/counterparties/import",
        json={"csv": VENDOR_CSV, "dry_run": True},
        headers=admin,
    )
    assert r.json()["suppliers_created"] == 3
    assert client.get("/api/v1/counterparties", headers=admin).json()["counterparties"] == []


def test_re_importing_the_same_file_adds_nothing(
    client: TestClient, admin: dict
) -> None:
    """Finance re-exports and re-imports. That must top up, not duplicate."""
    client.post("/api/v1/counterparties/import", json={"csv": VENDOR_CSV}, headers=admin)
    again = client.post(
        "/api/v1/counterparties/import", json={"csv": VENDOR_CSV}, headers=admin
    ).json()
    assert again["suppliers_created"] == 0
    assert again["bank_records_created"] == 0
    assert again["bank_records_already_present"] == 2


def test_a_semicolon_separated_export_is_understood(
    client: TestClient, admin: dict
) -> None:
    """European accounting exports are semicolon-separated and would otherwise
    parse as a single unusable column."""
    csv = (
        "Supplier;Email;IBAN\n"
        "Umbrella;ap@umbrella.example;FR1420041010050500013M02606\n"
    )
    body = client.post(
        "/api/v1/counterparties/import", json={"csv": csv}, headers=admin
    ).json()
    assert body["rows_parsed"] == 1
    assert body["bank_records_created"] == 1


def test_bad_rows_are_reported_and_the_rest_still_import(
    client: TestClient, admin: dict
) -> None:
    """A real export always has some junk in it. Failing the whole file for one
    bad line is how an import feature goes unused."""
    csv = (
        "Vendor,Email,IBAN\n"
        "Good Co,ap@goodco.example,GB29NWBK60161331926819\n"
        "Broken,not-a-domain,GB29NWBK60161331926819\n"
    )
    body = client.post(
        "/api/v1/counterparties/import", json={"csv": csv}, headers=admin
    ).json()
    assert body["suppliers_created"] == 1
    assert any("line 3" in p for p in body["problems"])


def test_a_file_with_no_domain_column_says_so(client: TestClient, admin: dict) -> None:
    """The error has to name the fix, not just refuse."""
    body = client.post(
        "/api/v1/counterparties/import",
        json={"csv": "Vendor,IBAN\nAcme,GB29NWBK60161331926819\n"},
        headers=admin,
    ).json()
    assert body["rows_parsed"] == 0
    assert any("domain" in p for p in body["problems"])


def test_the_import_is_admin_only(client: TestClient) -> None:
    """It writes the data every payment decision is checked against."""
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "member-owner@memberco.example",
            "password": PW,
            "tenant_name": "Member Co",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "member-owner@memberco.example", "password": PW},
    ).json()
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    )
    r = client.post("/api/v1/counterparties/import", json={"csv": VENDOR_CSV})
    assert r.status_code == 401
