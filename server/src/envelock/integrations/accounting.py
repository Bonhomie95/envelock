"""Xero and QuickBooks Online — the customer's vendor master, live.

What this does, per connected company:

* **Sync** the supplier list into Envelock's ledger: who each supplier is (by
  the domain of their email or website), the phone number on file (which
  becomes the callback number), and the bank account where the system exposes
  one (Xero: `BankAccountDetails`; QuickBooks: `VendorPaymentBankDetail`, which
  only some regions populate). Same rules as the CSV import
  (services/suppliers.py).
* **Flag bills.** When a bank-change alert names a supplier, every unpaid bill
  from that supplier gets a note — Xero: a line in the bill's History; QuickBooks:
  the bill's private note — so whoever pays it sees the warning in the place they
  pay from. Neither API has a real "on hold" state for a bill, so this is a note,
  said as such; Envelock never changes an amount, a status or bank details.

Every HTTP call goes through an injectable transport, so the whole flow is
tested against fakes of both APIs.
"""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urlencode

from envelock.config import get_settings


class AccountingError(Exception):
    pass


class Transport(Protocol):
    async def request(
        self, method: str, url: str, *, headers: dict, data: dict | None = None,
        json: Any = None,
    ) -> Any: ...


class HttpxTransport:
    async def request(
        self, method: str, url: str, *, headers: dict, data: dict | None = None,
        json: Any = None,
    ) -> Any:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(method, url, headers=headers, data=data, json=json)
        if resp.status_code >= 400:
            raise AccountingError(
                f"{method} {url.split('?')[0]} → {resp.status_code}: {resp.text[:200]}"
            )
        return resp.json() if resp.content else {}


_TRANSPORT: Transport | None = None


def set_transport(transport: Transport | None) -> None:
    global _TRANSPORT
    _TRANSPORT = transport


def _t() -> Transport:
    return _TRANSPORT or HttpxTransport()


@dataclass(frozen=True, slots=True)
class Tokens:
    access_token: str
    refresh_token: str
    expires_at: float  # epoch seconds


@dataclass(frozen=True, slots=True)
class Supplier:
    external_id: str
    name: str | None
    email: str | None
    website: str | None
    phone: str | None
    bank_account: str | None
    bank_routing: str | None = None


def _basic(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def _tokens(body: dict) -> Tokens:
    if not body.get("access_token"):
        raise AccountingError("token endpoint returned no access token")
    return Tokens(
        access_token=body["access_token"],
        refresh_token=body.get("refresh_token", ""),
        expires_at=time.time() + int(body.get("expires_in") or 1800),
    )


# ── Xero ─────────────────────────────────────────────────────────────────────
class Xero:
    name = "xero"
    label = "Xero"
    AUTHORIZE = "https://login.xero.com/identity/connect/authorize"
    TOKEN = "https://identity.xero.com/connect/token"  # noqa: S105 — an endpoint URL
    CONNECTIONS = "https://api.xero.com/connections"
    API = "https://api.xero.com/api.xro/2.0"

    def _cfg(self) -> tuple[str | None, str | None, str | None]:
        s = get_settings()
        secret = s.xero_client_secret.get_secret_value() if s.xero_client_secret else None
        return s.xero_client_id, secret, s.xero_redirect_uri

    def configured(self) -> bool:
        return all(self._cfg())

    def authorize_url(self, state: str) -> str:
        cid, _, redirect = self._cfg()
        return self.AUTHORIZE + "?" + urlencode({
            "response_type": "code", "client_id": cid, "redirect_uri": redirect,
            "scope": get_settings().xero_scopes, "state": state,
        })

    async def _token(self, form: dict) -> Tokens:
        cid, secret, _ = self._cfg()
        return _tokens(await _t().request(
            "POST", self.TOKEN, headers={"Authorization": _basic(cid or "", secret or "")},
            data=form,
        ))

    async def exchange(self, code: str, realm_id: str | None = None) -> tuple[Tokens, str, str]:
        _, _, redirect = self._cfg()
        tokens = await self._token(
            {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect or ""}
        )
        conns = await _t().request(
            "GET", self.CONNECTIONS, headers={"Authorization": f"Bearer {tokens.access_token}"}
        )
        orgs = [c for c in conns or [] if c.get("tenantType", "ORGANISATION") == "ORGANISATION"]
        if not orgs:
            raise AccountingError("no Xero organisation was shared with Envelock")
        return tokens, orgs[0]["tenantId"], orgs[0].get("tenantName") or "Xero"

    async def refresh(self, refresh_token: str) -> Tokens:
        return await self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    def _h(self, token: str, org: str) -> dict:
        return {"Authorization": f"Bearer {token}", "xero-tenant-id": org,
                "Accept": "application/json"}

    @staticmethod
    def _phone(contact: dict) -> str | None:
        phones = {p.get("PhoneType"): p for p in contact.get("Phones") or []}
        for kind in ("DEFAULT", "DDI", "MOBILE"):
            p = phones.get(kind)
            if p and p.get("PhoneNumber"):
                parts = [p.get("PhoneCountryCode"), p.get("PhoneAreaCode"), p.get("PhoneNumber")]
                number = " ".join(x for x in parts if x)
                return ("+" + number) if p.get("PhoneCountryCode") else number
        return None

    async def suppliers(self, token: str, org: str) -> list[Supplier]:
        out: list[Supplier] = []
        page = 1
        while page <= 100:  # 10,000 suppliers is a ceiling, not a target
            body = await _t().request(
                "GET",
                f"{self.API}/Contacts?where={quote('IsSupplier==true')}&page={page}&pageSize=100",
                headers=self._h(token, org),
            )
            contacts = body.get("Contacts") or []
            for c in contacts:
                if c.get("ContactStatus", "ACTIVE") != "ACTIVE":
                    continue
                out.append(Supplier(
                    external_id=c["ContactID"], name=c.get("Name"),
                    email=c.get("EmailAddress"), website=c.get("Website"),
                    phone=self._phone(c), bank_account=c.get("BankAccountDetails"),
                ))
            if len(contacts) < 100:
                break
            page += 1
        return out

    async def flag_bills(self, token: str, org: str, supplier_id: str, note: str) -> int:
        where = quote(f'Type=="ACCPAY" AND Contact.ContactID==guid("{supplier_id}")')
        body = await _t().request(
            "GET", f"{self.API}/Invoices?where={where}&Statuses=DRAFT,SUBMITTED,AUTHORISED",
            headers=self._h(token, org),
        )
        flagged = 0
        for bill in body.get("Invoices") or []:
            if bill.get("Status") == "AUTHORISED" and not float(bill.get("AmountDue") or 0):
                continue
            await _t().request(
                "PUT", f"{self.API}/Invoices/{bill['InvoiceID']}/History",
                headers=self._h(token, org),
                json={"HistoryRecords": [{"Details": note[:2500]}]},
            )
            flagged += 1
        return flagged


# ── QuickBooks Online ────────────────────────────────────────────────────────
class QuickBooks:
    name = "quickbooks"
    label = "QuickBooks"
    AUTHORIZE = "https://appcenter.intuit.com/connect/oauth2"
    TOKEN = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"  # noqa: S105
    SCOPE = "com.intuit.quickbooks.accounting"
    MINOR = "minorversion=75"

    def _cfg(self) -> tuple[str | None, str | None, str | None]:
        s = get_settings()
        secret = (
            s.quickbooks_client_secret.get_secret_value() if s.quickbooks_client_secret else None
        )
        return s.quickbooks_client_id, secret, s.quickbooks_redirect_uri

    def _base(self) -> str:
        sandbox = get_settings().quickbooks_environment == "sandbox"
        host = "sandbox-quickbooks.api.intuit.com" if sandbox else "quickbooks.api.intuit.com"
        return f"https://{host}/v3/company"

    def configured(self) -> bool:
        return all(self._cfg())

    def authorize_url(self, state: str) -> str:
        cid, _, redirect = self._cfg()
        return self.AUTHORIZE + "?" + urlencode({
            "client_id": cid, "response_type": "code", "scope": self.SCOPE,
            "redirect_uri": redirect, "state": state,
        })

    async def _token(self, form: dict) -> Tokens:
        cid, secret, _ = self._cfg()
        return _tokens(await _t().request(
            "POST", self.TOKEN,
            headers={
                "Authorization": _basic(cid or "", secret or ""),
                "Accept": "application/json",
            },
            data=form,
        ))

    def _h(self, token: str) -> dict:
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    async def _query(self, token: str, realm: str, sql: str) -> dict:
        body = await _t().request(
            "GET", f"{self._base()}/{realm}/query?query={quote(sql)}&{self.MINOR}",
            headers=self._h(token),
        )
        return body.get("QueryResponse") or {}

    async def exchange(self, code: str, realm_id: str | None = None) -> tuple[Tokens, str, str]:
        if not realm_id:
            raise AccountingError("QuickBooks did not say which company was connected")
        _, _, redirect = self._cfg()
        tokens = await self._token(
            {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect or ""}
        )
        info = await _t().request(
            "GET", f"{self._base()}/{realm_id}/companyinfo/{realm_id}?{self.MINOR}",
            headers=self._h(tokens.access_token),
        )
        name = ((info or {}).get("CompanyInfo") or {}).get("CompanyName") or "QuickBooks"
        return tokens, realm_id, name

    async def refresh(self, refresh_token: str) -> Tokens:
        return await self._token({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def suppliers(self, token: str, org: str) -> list[Supplier]:
        out: list[Supplier] = []
        start = 1
        while start < 10_000:
            vendors = (await self._query(
                token, org,
                # QuickBooks' query language; `start` is our own integer.
                f"select * from Vendor where Active = true STARTPOSITION {start} MAXRESULTS 1000",  # noqa: S608, E501
            )).get("Vendor") or []
            for v in vendors:
                bank = v.get("VendorPaymentBankDetail") or {}
                out.append(Supplier(
                    external_id=str(v["Id"]),
                    name=v.get("DisplayName") or v.get("CompanyName"),
                    email=(v.get("PrimaryEmailAddr") or {}).get("Address"),
                    website=(v.get("WebAddr") or {}).get("URI"),
                    phone=(v.get("PrimaryPhone") or {}).get("FreeFormNumber"),
                    bank_account=bank.get("BankAccountNumber"),
                    bank_routing=bank.get("BankBranchIdentifier"),
                ))
            if len(vendors) < 1000:
                break
            start += 1000
        return out

    async def flag_bills(self, token: str, org: str, supplier_id: str, note: str) -> int:
        # QuickBooks' query language, not SQL — but still only ever a numeric id.
        if not supplier_id.isdigit():
            return 0
        bills = (await self._query(
            token, org,
            f"select * from Bill where VendorRef = '{supplier_id}' and Balance > '0'",  # noqa: S608
        )).get("Bill") or []
        flagged = 0
        for bill in bills:
            existing = bill.get("PrivateNote") or ""
            if note in existing:
                continue
            await _t().request(
                "POST", f"{self._base()}/{org}/bill?{self.MINOR}", headers=self._h(token),
                json={"Id": bill["Id"], "SyncToken": bill["SyncToken"], "sparse": True,
                      "PrivateNote": (note + ("\n\n" + existing if existing else ""))[:4000]},
            )
            flagged += 1
        return flagged


PROVIDERS: dict[str, Xero | QuickBooks] = {"xero": Xero(), "quickbooks": QuickBooks()}


def provider(name: str) -> Xero | QuickBooks | None:
    return PROVIDERS.get(name)


def supplier_row(s: Supplier) -> dict | None:
    """A supplier as a ledger row (services/suppliers.apply_supplier_rows), or
    None when it can't be keyed: Envelock identifies a supplier by the domain it
    emails from, so a vendor with no email/website, or on free mail, is skipped."""
    from envelock.util.domains import is_free_mail, registrable_domain
    from envelock.util.payments import extract_bank_identifiers

    domain = None
    for source in (s.email, s.website):
        if not source:
            continue
        host = source.rsplit("@", 1)[-1] if "@" in source else source
        host = host.split("://")[-1].split("/")[0].split(":")[0].strip().lower()
        reg = registrable_domain(host.removeprefix("www."))
        if reg and not is_free_mail(reg):
            domain = reg
            break
    if domain is None:
        return None
    row: dict[str, Any] = {"domain": domain, "name": s.name, "phone": s.phone}
    if s.bank_account:
        # Read through the same extractor that reads bank details out of mail,
        # so a stored account compares equal to the same account in an email.
        text = f"Bank account number {s.bank_account}"
        if s.bank_routing:
            text = f"Routing number {s.bank_routing}. " + text
        for ident in extract_bank_identifiers(text):
            row.setdefault(ident.scheme, ident.identifier)
    return row


__all__ = [
    "PROVIDERS",
    "AccountingError",
    "QuickBooks",
    "Supplier",
    "Tokens",
    "Xero",
    "provider",
    "set_transport",
    "supplier_row",
]
