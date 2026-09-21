"""Regression tests for the 2026-09 full-audit fix pass.

Each test pins a specific hole the audit found, so a future refactor that
reopens it fails here rather than in production.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import SourceMechanism
from envelock.detections.base import (
    CounterpartyState,
    DetectionContext,
    ThreadMessage,
    run_all,
)
from envelock.models import Domain, Tenant
from envelock.risk.engine import assess

pytestmark = pytest.mark.asyncio

OWNED = frozenset({"acme.com"})


def _ctx(raw: bytes, *, counterparty=None, thread=()):
    event = parse_message(
        raw, tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
    )
    return DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, counterparty=counterparty, thread_history=thread,
    )


# ── Detection coverage gaps the audit found ──────────────────────────────────
def test_gift_card_bec_now_fires_without_any_bank_identifier() -> None:
    """"buy gift cards, urgent, tell no one" carries no IBAN — every payment
    detection used to gate on has_payment_context and fire nothing."""
    raw = (
        b'From: "CEO" <ceo@gemini-invoices.com>\r\n'
        b"To: pay@acme.com\r\nSubject: urgent favour\r\n"
        b"Message-ID: <g@gemini-invoices.com>\r\nContent-Type: text/plain\r\n\r\n"
        b"Are you at your desk? I need you to buy five gift cards urgently and "
        b"send me the codes. Keep this confidential for now.\r\n"
    )
    findings = run_all(_ctx(raw))
    assert assess(findings) is not None  # something fired


def test_thread_hijack_reply_to_swap_fires_a8() -> None:
    """A reply inside a genuine thread that reroutes answers to a new address,
    about payment — the named attack A8 could not previously catch."""
    raw = (
        b'From: "Supplier" <ap@supplier.com>\r\n'
        b"To: pay@acme.com\r\nReply-To: ap@supplier-billing.com\r\n"
        b"Subject: Re: Invoice 88\r\nMessage-ID: <r@supplier.com>\r\n"
        b"References: <orig@supplier.com>\r\nContent-Type: text/plain\r\n\r\n"
        b"Please update the bank account for this payment and remit today.\r\n"
    )
    cp = CounterpartyState(registrable_domain="supplier.com", message_count=8)
    thread = (ThreadMessage(sender_address="ap@supplier.com",
                            reply_to_address="ap@supplier.com", dkim="pass"),)
    findings = run_all(_ctx(raw, counterparty=cp, thread=thread))
    assert any(f.service == "A8" for f in findings)


def test_html_only_bank_change_is_seen_by_a1_family() -> None:
    """An HTML-only message (no text/plain) hid a changed IBAN from A1."""
    raw = (
        b'From: "Supplier" <ap@supplier.com>\r\n'
        b"To: pay@acme.com\r\nSubject: bank update\r\n"
        b"Message-ID: <h@supplier.com>\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body>Our bank account changed. Remit to IBAN "
        b"GB33BUKB20201555555555 today.</body></html>\r\n"
    )
    cp = CounterpartyState(
        registrable_domain="supplier.com", message_count=6,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
    )
    findings = run_all(_ctx(raw, counterparty=cp))
    # A1 sees the (mismatched) IBAN in the HTML now.
    assert any(f.service == "A1" for f in findings)


# ── Billing gate lockdown ─────────────────────────────────────────────────────
async def test_stripe_verify_does_not_grant_entitlement(session) -> None:
    """A Stripe PaymentMethod object is mintable client-side — verifying it must
    not open the gate; only the paid webhook does."""
    from envelock.billing import payments

    assert payments._Stripe().grants_entitlement is False
    assert payments._Sandbox().grants_entitlement is True  # dev-only


# ── Domain uniqueness (one company = one tenant) ─────────────────────────────
async def test_two_tenants_cannot_own_the_same_domain(session) -> None:
    from sqlalchemy.exc import IntegrityError

    t1, t2 = uuid4(), uuid4()
    session.add_all([Tenant(id=t1, name="A"), Tenant(id=t2, name="B")])
    await session.flush()
    session.add(Domain(id=uuid4(), tenant_id=t1, name="acme.com", registrable_domain="acme.com"))
    await session.flush()
    session.add(Domain(id=uuid4(), tenant_id=t2, name="acme.com", registrable_domain="acme.com"))
    with pytest.raises(IntegrityError):
        await session.flush()


# ── Ingest listener must not run open in production ──────────────────────────
def test_smtp_ingest_refuses_to_run_open_in_production(monkeypatch) -> None:
    """Started as its own process the in-app boot check never fires, so the
    listener would accept forwarded mail from anywhere. The guard belongs where
    the socket opens."""
    import asyncio

    from envelock.config import get_settings
    from envelock.workers import smtp_ingest

    monkeypatch.setenv("ENVELOCK_ENV", "production")
    monkeypatch.setenv("ENVELOCK_INGEST_ALLOWED_IPS", "")
    # Isolate the ingest guard from the other production boot gates.
    monkeypatch.setenv("ENVELOCK_ALLOW_RLS_DISABLED", "true")
    monkeypatch.setenv("ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS", "true")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="INGEST_ALLOWED_IPS"):
            asyncio.run(smtp_ingest.run_forever())
    finally:
        get_settings.cache_clear()


def test_smtp_ingest_starts_when_sources_are_pinned(monkeypatch) -> None:
    from envelock.config import get_settings
    from envelock.workers import smtp_ingest

    monkeypatch.setenv("ENVELOCK_ENV", "production")
    monkeypatch.setenv("ENVELOCK_INGEST_ALLOWED_IPS", "203.0.113.0/24")
    # Same isolation as the test above: these are about the ingest guard only.
    monkeypatch.setenv("ENVELOCK_ALLOW_RLS_DISABLED", "true")
    monkeypatch.setenv("ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS", "true")
    get_settings.cache_clear()
    try:
        smtp_ingest._assert_ingest_is_pinned()  # must not raise
    finally:
        get_settings.cache_clear()
