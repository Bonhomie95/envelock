"""Confirming a bank-detail change with the supplier, and sharing what it proves.

The journey the product is sold on: a supplier we've paid before "changes" its
bank details → Critical alert → someone confirms through the number ON FILE
(never the email's) → a "that's not us" is confirmed fraud: the alert resolves,
and the account it asked for is flagged for every other customer.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from test_integration import FRAUD, LEGIT, auth, sign_in

from envelock.config import get_settings


def _db(fn):  # noqa: ANN001, ANN202
    """Run a small async DB step from a sync test (the suite's client pattern)."""

    async def _run():  # noqa: ANN202
        from conftest import platform_sessionmaker as get_sessionmaker

        from envelock.db import dispose

        async with get_sessionmaker()() as session:
            out = await fn(session)
            await session.commit()
        await dispose()
        return out

    return asyncio.run(_run())


def _workspace(client: TestClient, email: str, domain: str) -> dict:
    """Signed-in owner with a VERIFIED domain (only verified tenants may feed
    shared intelligence) and a protected mailbox that has seen the supplier."""
    h = auth(sign_in(client, email=email))
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)

    async def _verify(session):  # noqa: ANN001, ANN202
        from envelock.models import Domain

        await session.execute(
            update(Domain)
            .where(Domain.registrable_domain == domain)
            .values(verified_at=datetime.now(UTC))
        )

    _db(_verify)
    box = f"pay@{domain}"
    client.post("/api/v1/mailboxes", json={"address": box, "mailbox_class": "protected"},
                headers=h)
    return {"h": h, "box": box, "domain": domain}


def _ingest(client: TestClient, ws: dict, raw: str) -> None:
    raw = raw.replace("pay@acme.com", ws["box"])
    r = client.post("/api/v1/ingest", json={"raw_message": raw, "mailbox_address": ws["box"]},
                    headers=ws["h"])
    assert r.status_code == 202, r.text


def _bank_change_alert(client: TestClient, ws: dict) -> dict:
    for i in range(3):
        _ingest(client, ws, LEGIT.replace("9001", f"800{i}"))
    _ingest(client, ws, FRAUD)
    alerts = client.get("/api/v1/alerts", headers=ws["h"]).json()["alerts"]
    critical = [a for a in alerts if a["tier"] == "critical"]
    assert critical, alerts
    return critical[0]


def _set_supplier_phone(client: TestClient, ws: dict, phone: str = "+1 803 555 0100") -> None:
    r = client.post("/api/v1/counterparties/gemini.com/phone", json={"phone": phone},
                    headers=ws["h"])
    assert r.status_code in (200, 201), r.text


def test_the_panel_shows_the_number_on_file_and_the_masked_account(client) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    _set_supplier_phone(client, ws)

    v = client.get(f"/api/v1/alerts/{alert['id']}/verification", headers=ws["h"]).json()
    assert v["supplier"] == "gemini.com"
    assert v["phone_on_file"] == "+1 803 555 0100"
    assert v["account"] == "IBAN ••••5555"  # GB33BUKB20201555555555, masked
    assert v["attempts"] == []


def test_a_supplier_denial_on_the_phone_is_confirmed_fraud_everywhere(client) -> None:  # noqa: ANN001
    acme = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, acme)
    _set_supplier_phone(client, acme)

    r = client.post(f"/api/v1/alerts/{alert['id']}/verification/call",
                    json={"outcome": "denied", "note": "Accounts said they never changed banks"},
                    headers=acme["h"])
    assert r.status_code == 200, r.text
    assert r.json()["alert_state"] == "resolved"

    # A different customer, a different "supplier", the same mule account.
    other = _workspace(client, "it@globex.com", "globex.com")
    _ingest(client, other, (
        "From: <accounts@new-vendor.example>\nTo: pay@globex.com\nSubject: Invoice 55\n"
        "Content-Type: text/plain\n\nPlease pay invoice 55 by bank transfer to "
        "IBAN GB33BUKB20201555555555 today."
    ))
    alerts = client.get("/api/v1/alerts", headers=other["h"]).json()["alerts"]
    assert any(a["tier"] == "critical" and "another Envelock customer" in a["title"]
               for a in alerts), alerts


def test_a_confirmation_leaves_the_decision_to_a_person(client) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    _set_supplier_phone(client, ws)
    r = client.post(f"/api/v1/alerts/{alert['id']}/verification/call",
                    json={"outcome": "confirmed"}, headers=ws["h"])
    assert r.status_code == 200
    assert r.json()["alert_state"] == "open"
    attempts = client.get(f"/api/v1/alerts/{alert['id']}/verification",
                          headers=ws["h"]).json()["attempts"]
    assert [(a["channel"], a["status"]) for a in attempts] == [("call", "confirmed")]


@pytest.fixture
def sms(monkeypatch: pytest.MonkeyPatch):
    from envelock.notify.senders import SmsSender

    sent: list[tuple[str, str]] = []

    async def _deliver(self, to: str, text: str) -> None:  # noqa: ANN001, ARG001
        sent.append((to, text))

    monkeypatch.setattr(SmsSender, "_deliver_sms", _deliver)
    monkeypatch.setenv("ENVELOCK_SMS_ENABLED", "true")
    monkeypatch.setenv("ENVELOCK_SMS_PROVIDER", "twilio")
    monkeypatch.setenv("ENVELOCK_SMS_API_KEY", "test-key")
    get_settings.cache_clear()
    yield sent
    get_settings.cache_clear()


def test_the_supplier_answers_a_text_and_a_no_resolves_it(client, sms) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    _set_supplier_phone(client, ws)

    r = client.post(f"/api/v1/alerts/{alert['id']}/verification/sms", headers=ws["h"])
    assert r.status_code == 200, r.text
    to, text = sms[0]
    assert to == "+1 803 555 0100"
    assert "GB33" not in text and "5555" not in text  # nothing sensitive in a text
    token = re.search(r"/v/([A-Za-z0-9_-]+)", text).group(1)

    page = client.get(f"/api/v1/verify/{token}").json()
    assert page == {"company": "Acme", "account": "IBAN ••••5555", "status": "pending"}

    assert client.post(f"/api/v1/verify/{token}", json={"answer": "no"}).json() == {
        "status": "denied"
    }
    state = client.get("/api/v1/alerts", headers=ws["h"]).json()["alerts"]
    assert next(a for a in state if a["id"] == alert["id"])["state"] == "resolved"
    # Single use.
    assert client.post(f"/api/v1/verify/{token}", json={"answer": "yes"}).status_code == 409

    async def _hashes(session):  # noqa: ANN001, ANN202
        from envelock.models import PaymentVerification

        return (await session.execute(select(PaymentVerification.token_hash))).scalars().all()

    assert token not in _db(_hashes)  # only the hash is stored


def test_an_expired_link_says_so(client, sms) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    _set_supplier_phone(client, ws)
    client.post(f"/api/v1/alerts/{alert['id']}/verification/sms", headers=ws["h"])
    token = re.search(r"/v/([A-Za-z0-9_-]+)", sms[0][1]).group(1)

    async def _expire(session):  # noqa: ANN001, ANN202
        from datetime import UTC, datetime, timedelta

        from envelock.models import PaymentVerification

        await session.execute(update(PaymentVerification).values(
            expires_at=datetime.now(UTC) - timedelta(minutes=1)))

    _db(_expire)
    assert client.get(f"/api/v1/verify/{token}").json()["status"] == "expired"
    assert client.post(f"/api/v1/verify/{token}", json={"answer": "yes"}).status_code == 410


def test_no_number_on_file_means_no_text(client, sms) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    r = client.post(f"/api/v1/alerts/{alert['id']}/verification/sms", headers=ws["h"])
    assert r.status_code == 409 and "Suppliers page" in r.json()["detail"]
    assert sms == []


def test_an_unknown_link_is_a_404(client) -> None:  # noqa: ANN001
    assert client.get("/api/v1/verify/not-a-token").status_code == 404


def test_payment_requests_are_counted_for_the_monthly_headline(client) -> None:  # noqa: ANN001
    ws = _workspace(client, "it@acme.com", "acme.com")
    for n, amount in ((1, "12,500.00"), (2, "3,000")):
        _ingest(client, ws, (
            f"From: <billing@gemini.com>\nTo: pay@acme.com\nSubject: Invoice 70{n}\n"
            "Content-Type: text/plain\n\n"
            f"Please pay invoice 70{n} for ${amount} to our usual account."
        ))
    _ingest(client, ws, (  # not a payment request: must not count
        "From: <news@gemini.com>\nTo: pay@acme.com\nSubject: Our $5 anniversary sale\n"
        "Content-Type: text/plain\n\nCome to our party."
    ))

    async def _build(session):  # noqa: ANN001, ANN202
        from datetime import timedelta

        from envelock.models import Tenant
        from envelock.notify import digest as dg

        tenant = (await session.execute(select(Tenant))).scalars().first()
        return await dg.build_digest(
            session, tenant_id=tenant.id, since=datetime.now(UTC) - timedelta(days=1)
        )

    d = _db(_build)
    assert d.payment_requests == 2
    assert d.payments_checked_by_currency == [{"currency": "USD", "amount": 15500.0}]
    assert d.headline.startswith("$15,500 in payment requests checked")


def test_the_evidence_pack_is_a_pdf_with_the_verification_in_it(client) -> None:  # noqa: ANN001
    import io

    from pypdf import PdfReader

    ws = _workspace(client, "it@acme.com", "acme.com")
    alert = _bank_change_alert(client, ws)
    _set_supplier_phone(client, ws)
    client.post(f"/api/v1/alerts/{alert['id']}/verification/call",
                json={"outcome": "denied", "note": "Spoke to Dana in accounts"},
                headers=ws["h"])

    r = client.get(f"/api/v1/alerts/{alert['id']}/evidence.pdf", headers=ws["h"])
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    text = " ".join(page.extract_text() for page in PdfReader(io.BytesIO(r.content)).pages)
    text = " ".join(text.split())  # table cells wrap; compare the words
    for expected in ("FRAUD EVIDENCE RECORD", "billing@gemini.com", "GB33BUKB20201555555555",
                     "+1 803 555 0100", "did NOT make this change", "Spoke to Dana",
                     "Resolved as confirmed fraud", "Record fingerprint"):
        assert expected in text, expected

    # Another workspace can't pull it.
    other = _workspace(client, "it@globex.com", "globex.com")
    assert client.get(f"/api/v1/alerts/{alert['id']}/evidence.pdf",
                      headers=other["h"]).status_code == 404
