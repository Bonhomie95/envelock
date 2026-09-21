"""The surfaces added for launch: money-at-risk, the monthly digest, the public
status page and the shared-network counts.

Each of these is customer-facing in a way that makes being *approximately* right
worse than being silent — a headline figure a customer can disprove from their
own ledger, a status page that leaks which dependency is down, a digest that
quotes a message back into a mail system we do not control. The tests below are
mostly about the refusals.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.core.enums import AlertTier
from envelock.main import app
from envelock.models import Alert
from envelock.notify import digest as dg
from envelock.platform.alerts import prevented_loss
from envelock.util.payments import largest_amount


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


# ── Amount extraction ────────────────────────────────────────────────────────
def test_largest_amount_picks_the_sum_being_asked_for() -> None:
    """A remittance mail carries several figures; the one that matters is the
    biggest, not the first one the regex happens to reach."""
    found = largest_amount(
        "Previous balance £120.00. VAT £9,650.00. Total now due £48,250.00."
    )
    assert found == (48250.0, "GBP")


def test_largest_amount_canonicalises_symbols() -> None:
    """'$1,000' and 'USD 2,000' in one thread must not land in two buckets."""
    assert largest_amount("$1,000 then USD 2,000") == (2000.0, "USD")


def test_largest_amount_never_mixes_currencies() -> None:
    """No conversion, ever — we hold no rate. The larger single figure wins and
    reports its own currency."""
    found = largest_amount("Invoice for £500 or NGN 900,000")
    assert found == (900000.0, "NGN")


def test_largest_amount_is_none_when_no_figure_is_named() -> None:
    """None, not zero. "No amount recorded" and "an amount of nothing" are
    different facts and the rollup depends on telling them apart."""
    assert largest_amount("Please confirm the bank details by phone.") is None


def test_largest_amount_sees_through_invisible_characters() -> None:
    """Same normalisation the payment identifiers get — a zero-width space in a
    figure is one keystroke for an attacker."""
    assert largest_amount("Total: £48​,250.00") == (48250.0, "GBP")


# ── Prevented loss ───────────────────────────────────────────────────────────
def _alert(**kw) -> Alert:
    base = {
        "id": uuid4(),
        "tenant_id": uuid4(),
        "mailbox_id": None,
        "tier": AlertTier.CRITICAL.value,
        "title": "Bank details changed",
        "body": "",
        "state": "resolved",
        "amount_at_risk": 1000.0,
        "amount_currency": "GBP",
    }
    base.update(kw)
    return Alert(**base)


def test_prevented_loss_counts_only_confirmed_fraud() -> None:
    """An open alert may still be dismissed tomorrow and a dismissed one was a
    false positive. Counting either produces a number the customer can disprove."""
    result = prevented_loss(
        [
            _alert(state="resolved", amount_at_risk=1000.0),
            _alert(state="open", amount_at_risk=9_000_000.0),
            _alert(state="dismissed", amount_at_risk=9_000_000.0),
            _alert(state="acked", amount_at_risk=9_000_000.0),
        ]
    )
    assert result["by_currency"] == [{"currency": "GBP", "amount": 1000.0}]
    assert result["incidents"] == 1


def test_prevented_loss_ignores_low_and_medium_tiers() -> None:
    result = prevented_loss(
        [
            _alert(tier=AlertTier.MEDIUM.value),
            _alert(tier=AlertTier.LOW.value),
        ]
    )
    assert result["by_currency"] == []
    assert result["incidents"] == 0


def test_prevented_loss_never_sums_across_currencies() -> None:
    """£ + ₦ is a number that is not true in either currency."""
    result = prevented_loss(
        [
            _alert(amount_at_risk=1000.0, amount_currency="GBP"),
            _alert(amount_at_risk=500.0, amount_currency="GBP"),
            _alert(amount_at_risk=2_000_000.0, amount_currency="NGN"),
        ]
    )
    assert result["by_currency"] == [
        {"currency": "NGN", "amount": 2_000_000.0},
        {"currency": "GBP", "amount": 1500.0},
    ]


def test_prevented_loss_reports_what_it_could_not_price() -> None:
    """Surfaced rather than hidden, so the UI can say "at least X, plus M we
    could not price" instead of implying the total is complete."""
    result = prevented_loss(
        [
            _alert(amount_at_risk=1000.0),
            _alert(amount_at_risk=None, amount_currency=None),
            _alert(amount_at_risk=None, amount_currency=None),
        ]
    )
    assert result["incidents"] == 1
    assert result["unpriced_incidents"] == 2


# ── Digest ───────────────────────────────────────────────────────────────────
def _digest(**kw) -> dg.Digest:
    now = datetime.now(UTC)
    base = {
        "tenant_name": "Acme",
        "period_start": now - timedelta(days=30),
        "period_end": now,
        "messages_analysed": 4120,
        "alerts_raised": 3,
        "critical": 1,
        "confirmed": 1,
        "prevented_by_currency": [{"currency": "GBP", "amount": 48250.0}],
        "unpriced_incidents": 0,
        "ai_consulted": 1,
        "items": [
            dg.DigestItem(
                tier=AlertTier.CRITICAL.value,
                title="Bank details changed mid-thread",
                counterparty="yoursuppler.com",
                reason="The account differs from the one used for 14 invoices.",
                amount=48250.0,
                currency="GBP",
                ai=True,
                at=now,
            )
        ],
    }
    base.update(kw)
    return dg.Digest(**base)


def test_an_empty_month_is_never_sent() -> None:
    """A digest with nothing in it is an advert, and it teaches the reader to
    filter the sender — which is how the next one, reporting a real fraud, lands
    in Junk."""
    assert not _digest(alerts_raised=0, items=[]).worth_sending
    assert _digest().worth_sending


def test_digest_text_and_html_carry_the_same_facts() -> None:
    d = _digest()
    text = dg.render_text(d)
    html_body = dg.render_html(d)
    for fragment in ("Acme", "48,250", "yoursuppler.com", "14 invoices"):
        assert fragment in text, fragment
        assert fragment in html_body, fragment


def test_digest_states_no_money_line_rather_than_a_zero() -> None:
    """"We saved you nothing" is not a sentence to put in front of a customer;
    an absent figure is the honest rendering."""
    d = _digest(prevented_by_currency=[], items=[])
    assert "0" not in dg.render_text(d).split("\n")[2]
    assert "wrong account" not in dg.render_text(d)


def test_digest_says_what_it_could_not_price() -> None:
    d = _digest(unpriced_incidents=2)
    assert "A further 2 confirmed incidents named no amount." in dg.render_text(d)


def test_digest_html_escapes_untrusted_fields() -> None:
    """Counterparty domains and alert titles are the only outside-influenced
    strings in the mail, and it renders in a client we do not control."""
    d = _digest(
        items=[
            dg.DigestItem(
                tier=AlertTier.HIGH.value,
                title="<script>alert(1)</script>",
                counterparty="<img src=x onerror=1>",
                reason="<b>not bold</b>",
                amount=None,
                currency=None,
                ai=False,
                at=datetime.now(UTC),
            )
        ]
    )
    out = dg.render_html(d)
    # The words may appear as inert text; what must never appear is a tag the
    # recipient's mail client would act on.
    assert "<script>" not in out
    assert "<img" not in out
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "&lt;img src=x onerror=1&gt;" in out
    # Escaped exactly once — "&amp;lt;" is safe but renders as gibberish.
    assert "&amp;lt;" not in out


# ── Public status ────────────────────────────────────────────────────────────
def test_public_status_is_anonymous_and_three_state(client: TestClient) -> None:
    body = client.get("/api/v1/status/public").json()
    assert body["state"] in ("operational", "degraded", "down")
    assert body["summary"]
    ids = {c["id"] for c in body["components"]}
    assert {"analysis", "alerts", "mail_flow", "dashboard"} <= ids
    for component in body["components"]:
        assert component["state"] in ("operational", "degraded", "down")


def test_public_status_never_names_a_dependency_or_an_exception(
    client: TestClient,
) -> None:
    """`/ready` names the failing exception class, which tells an attacker what we
    are built on. The public page must not become `/ready` with nicer wording."""
    raw = client.get("/api/v1/status/public").text.lower()
    for leak in ("postgres", "redis", "sqlalchemy", "traceback", "exception", "dsn"):
        assert leak not in raw, leak


def test_public_status_says_mail_delivery_is_unaffected(client: TestClient) -> None:
    """The single most useful line on the page during an incident."""
    body = client.get("/api/v1/status/public").json()
    flow = next(c for c in body["components"] if c["id"] == "mail_flow")
    assert flow["state"] == "operational"
    assert "delivery path" in flow["detail"]


# ── Shared network ───────────────────────────────────────────────────────────
def test_network_counts_are_public_but_name_no_domain(client: TestClient) -> None:
    """A domain name here is a ready-made target list, and a false positive
    published under our name is a defamation problem."""
    body = client.get("/api/v1/network").json()
    assert set(body) == {
        "domains_judged",
        "domains_confirmed_fraudulent",
        "actionable",
        "confirmations",
    }
    assert all(isinstance(v, int) for v in body.values())


# ── The alert payload carries the figure ─────────────────────────────────────
def _auth(client: TestClient, email: str = "growth@acme.com") -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": "Acme"},
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


def test_oversight_reports_prevented_loss(client: TestClient) -> None:
    body = client.get("/api/v1/oversight", headers=_auth(client)).json()
    assert "prevented_loss" in body
    assert body["prevented_loss"]["by_currency"] == []
    assert body["prevented_loss"]["incidents"] == 0
