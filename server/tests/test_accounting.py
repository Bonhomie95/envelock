"""Xero and QuickBooks Online: supplier sync, and notes on bills when a
supplier's bank details "change".

Driven against a fake of each provider's API that records every call, so the
assertions are about what reached the customer's accounting system.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from test_integration import auth, sign_in

from envelock.config import get_settings
from envelock.integrations import accounting as acct


class FakeProviders:
    """Xero + QuickBooks, just enough of each."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, object]] = []
        self.token_n = 0

    async def request(self, method, url, *, headers, data=None, json=None):  # noqa: A002, ANN001, ANN201
        self.calls.append((method, url, data if data is not None else json))
        if "identity.xero.com/connect/token" in url or "oauth.platform.intuit.com" in url:
            self.token_n += 1
            return {"access_token": f"at-{self.token_n}", "refresh_token": f"rt-{self.token_n}",
                    "expires_in": 1800}
        if url == "https://api.xero.com/connections":
            return [{"tenantId": "xero-org-1", "tenantName": "Acme Ltd",
                     "tenantType": "ORGANISATION"}]
        if "/api.xro/2.0/Contacts" in url:
            return {"Contacts": [
                {"ContactID": "c-gemini", "Name": "Gemini Supplies", "IsSupplier": True,
                 "EmailAddress": "accounts@gemini.com",
                 "BankAccountDetails": "GB94BARC10201530093459",
                 "Phones": [{"PhoneType": "DEFAULT", "PhoneCountryCode": "1",
                             "PhoneAreaCode": "803", "PhoneNumber": "555 0100"}]},
                {"ContactID": "c-gmail", "Name": "Bob the Plumber",
                 "EmailAddress": "bob.plumber@gmail.com"},
                {"ContactID": "c-none", "Name": "Cash Supplier"},
            ]}
        if "/api.xro/2.0/Invoices?" in url:
            return {"Invoices": [
                {"InvoiceID": "inv-unpaid", "Status": "AUTHORISED", "AmountDue": 48250},
                {"InvoiceID": "inv-paid", "Status": "AUTHORISED", "AmountDue": 0},
                {"InvoiceID": "inv-draft", "Status": "DRAFT", "AmountDue": 900},
            ]}
        if "/api.xro/2.0/Invoices/" in url and url.endswith("/History"):
            return {}
        if "/companyinfo/" in url:
            return {"CompanyInfo": {"CompanyName": "Acme Inc"}}
        if "/query?" in url and "from Vendor" in parse_qs(urlparse(url).query)["query"][0]:
            return {"QueryResponse": {"Vendor": [
                {"Id": "57", "DisplayName": "Gemini Supplies",
                 "PrimaryEmailAddr": {"Address": "ap@gemini.com"},
                 "PrimaryPhone": {"FreeFormNumber": "(803) 555-0100"},
                 "VendorPaymentBankDetail": {"BankAccountNumber": "GB94BARC10201530093459"}},
            ]}}
        if "/query?" in url and "from Bill" in parse_qs(urlparse(url).query)["query"][0]:
            return {"QueryResponse": {"Bill": [
                {"Id": "301", "SyncToken": "4", "PrivateNote": "Net 30"},
            ]}}
        if "/bill?" in url:
            return {"Bill": {"Id": json["Id"]}}
        raise AssertionError(f"unexpected call {method} {url}")

    def to(self, fragment: str) -> list[tuple[str, str, object]]:
        return [c for c in self.calls if fragment in c[1]]


@pytest.fixture
def providers(monkeypatch: pytest.MonkeyPatch):
    for k, v in {
        "ENVELOCK_XERO_CLIENT_ID": "xero-id", "ENVELOCK_XERO_CLIENT_SECRET": "xero-secret",
        "ENVELOCK_XERO_REDIRECT_URI": "https://api.envelock.test/api/v1/accounting/xero/callback",
        "ENVELOCK_QUICKBOOKS_CLIENT_ID": "qb-id", "ENVELOCK_QUICKBOOKS_CLIENT_SECRET": "qb-secret",
        "ENVELOCK_QUICKBOOKS_REDIRECT_URI":
            "https://api.envelock.test/api/v1/accounting/quickbooks/callback",
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    fake = FakeProviders()
    acct.set_transport(fake)
    yield fake
    acct.set_transport(None)
    get_settings.cache_clear()


def _db(fn):  # noqa: ANN001, ANN202
    async def _run():  # noqa: ANN202
        from conftest import platform_sessionmaker as get_sessionmaker

        from envelock.db import dispose

        async with get_sessionmaker()() as session:
            out = await fn(session)
            await session.commit()
        await dispose()
        return out

    return asyncio.run(_run())


def _run(coro_factory):  # noqa: ANN001, ANN202
    async def _go():  # noqa: ANN202
        from envelock.db import dispose

        try:
            return await coro_factory()
        finally:
            await dispose()

    return asyncio.run(_go())


def _owner(client: TestClient, domain: str = "acme.com") -> dict:
    h = auth(sign_in(client, email=f"it@{domain}"))
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _connect(client: TestClient, h: dict, provider: str, realm: str | None = None) -> None:
    r = client.post(f"/api/v1/accounting/{provider}/connect", headers=h)
    assert r.status_code == 200, r.text
    state = parse_qs(urlparse(r.json()["url"]).query)["state"][0]
    q = f"code=auth-code&state={state}" + (f"&realmId={realm}" if realm else "")
    back = client.get(f"/api/v1/accounting/{provider}/callback?{q}", follow_redirects=False)
    assert back.status_code == 302
    assert back.headers["location"].endswith("/suppliers?accounting=connected")


def _sync_all() -> dict:
    from envelock.workers.accounting_sync import sync_due

    return _run(lambda: sync_due(requested_only=True))


def _suppliers(client: TestClient, h: dict) -> dict:
    return {s["domain"]: s for s in client.get("/api/v1/counterparties", headers=h).json()
            .get("counterparties", [])}


def test_xero_connects_seals_the_tokens_and_syncs_the_suppliers(client, providers) -> None:  # noqa: ANN001
    h = _owner(client)
    _connect(client, h, "xero")

    async def _row(session):  # noqa: ANN001, ANN202
        from envelock.models import AccountingConnection

        return (await session.execute(select(AccountingConnection))).scalars().one()

    conn = _db(_row)
    assert conn.external_org_id == "xero-org-1" and conn.org_name == "Acme Ltd"
    assert b"at-1" not in conn.ciphertext  # sealed, not stored in the clear
    assert conn.sync_requested_at is not None

    assert _sync_all() == {"connections": 1, "synced": 1}
    status = client.get("/api/v1/accounting", headers=h).json()
    summary = status["connections"][0]["summary"]
    assert summary["suppliers_seen"] == 3
    assert summary["suppliers_imported"] == 1  # gemini.com; gmail and no-email skipped
    assert summary["skipped_no_domain"] == 2
    assert summary["bank_records_created"] == 1

    async def _gemini(session):  # noqa: ANN001, ANN202
        from envelock.models import BankRecord, Counterparty

        cp = (await session.execute(select(Counterparty).where(
            Counterparty.registrable_domain == "gemini.com"))).scalars().one()
        banks = (await session.execute(select(BankRecord).where(
            BankRecord.counterparty_id == cp.id))).scalars().all()
        return cp.display_name, cp.verified_phone, [(b.scheme, b.identifier) for b in banks]

    name, phone, banks = _db(_gemini)
    assert name == "Gemini Supplies"
    assert phone == "+1 803 555 0100"  # becomes the callback number
    assert banks == [("iban", "GB94BARC10201530093459")]


def test_a_bank_change_notes_the_suppliers_unpaid_bills_once(client, providers) -> None:  # noqa: ANN001
    from test_integration import FRAUD

    h = _owner(client)
    _connect(client, h, "xero")
    _sync_all()
    client.post("/api/v1/mailboxes", json={"address": "pay@acme.com",
                                           "mailbox_class": "protected"}, headers=h)
    # The known account came from Xero — so the very first "we've changed banks"
    # email is Critical, without weeks of learning from mail.
    r = client.post("/api/v1/ingest", json={"raw_message": FRAUD,
                                            "mailbox_address": "pay@acme.com"}, headers=h)
    assert r.status_code == 202
    alerts = client.get("/api/v1/alerts", headers=h).json()["alerts"]
    assert any(a["tier"] == "critical" and a["counterparty_domain"] == "gemini.com"
               for a in alerts), alerts

    from envelock.workers.accounting_sync import flag_bills_for_new_alerts

    first = _run(flag_bills_for_new_alerts)
    assert first == {"alerts": 1, "bills_flagged": 2}  # unpaid + draft, not the paid one
    notes = providers.to("/History")
    assert {c[1].split("/Invoices/")[1].split("/")[0] for c in notes} == {"inv-unpaid", "inv-draft"}
    assert "Do not pay this bill to any new account" in notes[0][2]["HistoryRecords"][0]["Details"]

    assert _run(flag_bills_for_new_alerts) == {"alerts": 0, "bills_flagged": 0}


def test_quickbooks_syncs_and_notes_bills_without_losing_the_existing_note(
    client, providers  # noqa: ANN001
) -> None:
    h = _owner(client)
    _connect(client, h, "quickbooks", realm="9130")
    _sync_all()
    sup = _suppliers(client, h)
    assert "gemini.com" in sup

    from envelock.workers.accounting_sync import _note, flag_bills_for_new_alerts  # noqa: F401

    async def _alert(session):  # noqa: ANN001, ANN202
        from envelock.models import Alert, Finding, Tenant

        tenant = (await session.execute(select(Tenant))).scalars().first()
        a = Alert(tenant_id=tenant.id, tier="critical", title="Bank change", body="…",
                  counterparty_domain="gemini.com", state="open")
        session.add(a)
        await session.flush()
        session.add(Finding(tenant_id=tenant.id, alert_id=a.id, service="A1",
                            tier="critical", score=100, summary="changed", evidence={}))

    _db(_alert)
    assert _run(flag_bills_for_new_alerts)["bills_flagged"] == 1
    [(_, url, body)] = providers.to("/bill?")
    assert body["Id"] == "301" and body["SyncToken"] == "4" and body["sparse"] is True
    assert body["PrivateNote"].startswith("ENVELOCK WARNING")
    assert body["PrivateNote"].endswith("Net 30")  # their own note is kept


def test_an_expired_token_is_refreshed_and_the_new_refresh_token_kept(client, providers) -> None:  # noqa: ANN001
    h = _owner(client)
    _connect(client, h, "xero")

    async def _expire(session):  # noqa: ANN001, ANN202
        from envelock.models import AccountingConnection

        await session.execute(update(AccountingConnection).values(
            token_expires_at=datetime.now(UTC) - timedelta(minutes=1)))

    _db(_expire)
    _sync_all()
    refreshes = [c for c in providers.to("connect/token") if c[2]["grant_type"] == "refresh_token"]
    assert refreshes and refreshes[0][2]["refresh_token"] == "rt-1"  # noqa: S105 — fake token

    async def _stored(session):  # noqa: ANN001, ANN202
        from envelock.models import AccountingConnection
        from envelock.security.crypto import SealedSecret, open_secret
        from envelock.workers.accounting_sync import _aad

        c = (await session.execute(select(AccountingConnection))).scalars().one()
        return json.loads(open_secret(SealedSecret(c.ciphertext, c.wrapped_dek, c.key_id),
                                      aad=_aad(c)))

    assert _db(_stored)["refresh_token"] == "rt-2"  # noqa: S105 — fake token


def test_a_forged_or_foreign_callback_connects_nothing(client, providers) -> None:  # noqa: ANN001
    _owner(client)
    back = client.get("/api/v1/accounting/xero/callback?code=x&state=forged.state",
                      follow_redirects=False)
    assert back.headers["location"].endswith("accounting=failed")
    assert not providers.to("connect/token")


def test_members_cannot_connect_and_unconfigured_says_so(client, monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.delenv("ENVELOCK_XERO_CLIENT_ID", raising=False)
    get_settings.cache_clear()
    h = _owner(client)
    assert client.post("/api/v1/accounting/xero/connect", headers=h).status_code == 503
    assert client.get("/api/v1/accounting", headers=h).json()["available"] == []
