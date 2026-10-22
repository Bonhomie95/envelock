"""Unit coverage for the detections that had none: A10, A11, B5, B6, B8, B9.

Each builds a MailEvent directly (no MIME parsing) so the detection logic is
exercised in isolation, and asserts the service fires on the shape it is meant
to catch. run_all is used so the registration wiring is covered too.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AuthResult, MailDirection, SourceMechanism
from envelock.core.events import (
    AttachmentRef,
    AuthenticationResults,
    EmailAddress,
    MailEvent,
)
from envelock.detections.base import CounterpartyState, DetectionContext, run_all

OWNED = frozenset({"acme.com"})
PAY = "Please update the bank account for your next invoice payment."
_CAPS = capabilities_for(frozenset({SourceMechanism.IMAP_IDLE}))


def _mail(**over) -> MailEvent:
    base = {
        "tenant_id": uuid4(),
        "mailbox_id": uuid4(),
        "occurred_at": datetime.now(UTC),
        "ingested_at": datetime.now(UTC),
        "source": SourceMechanism.IMAP_IDLE,
        "direction": MailDirection.INBOUND,
        "sender": EmailAddress(address="billing@supplier.com", display="Supplier"),
        "subject": "Invoice",
        "body_text": PAY,
    }
    base.update(over)
    return MailEvent(**base)


def _ctx(mail: MailEvent, **over) -> DetectionContext:
    kw = {
        "event": mail, "tenant_id": "t", "capabilities": _CAPS, "owned_domains": OWNED,
    }
    kw.update(over)
    return DetectionContext(**kw)


def _services(ctx: DetectionContext) -> set[str]:
    return {f.service for f in run_all(ctx)}


def test_b8_fires_when_sender_authentication_fails() -> None:
    mail = _mail(
        authentication=AuthenticationResults(
            spf=AuthResult.FAIL, dkim=AuthResult.FAIL, dmarc=AuthResult.FAIL
        )
    )
    assert "B8" in _services(_ctx(mail))


def test_b9_flags_a_freshly_registered_sender_domain() -> None:
    assert "B9" in _services(_ctx(_mail(), sender_domain_age_days=10))


def test_b9_silent_for_an_aged_domain() -> None:
    assert "B9" not in _services(_ctx(_mail(), sender_domain_age_days=400))


def test_b5_flags_a_password_protected_archive_with_the_password_in_body() -> None:
    att = AttachmentRef(
        filename="docs.zip", sha256="h", size_bytes=2048, is_archive=True, is_encrypted=True
    )
    mail = _mail(body_text="See attached. The password is Hunter2!", attachments=(att,))
    assert "B5" in _services(_ctx(mail))


def test_b6_flags_an_executable_disguised_as_an_image() -> None:
    att = AttachmentRef(
        filename="invoice.png", sha256="h", size_bytes=1024,
        declared_mime="image/png", detected_mime="application/x-dosexec",
    )
    assert "B6" in _services(_ctx(_mail(attachments=(att,))))


def test_a10_flags_a_counterparty_sending_from_new_infrastructure() -> None:
    cp = CounterpartyState(
        registrable_domain="supplier.com",
        message_count=12,
        known_dkim_domains=frozenset({"supplier.com"}),
    )
    mail = _mail(authentication=AuthenticationResults(dkim_domain="unknown-relay.net"))
    assert "A10" in _services(_ctx(mail, counterparty=cp))


def test_a11_flags_a_dormant_thread_revived_with_a_payment_request() -> None:
    cp = CounterpartyState(
        registrable_domain="supplier.com",
        last_seen_at=datetime.now(UTC) - timedelta(days=120),
    )
    mail = _mail(in_reply_to="<old-thread@supplier.com>")
    assert "A11" in _services(_ctx(mail, counterparty=cp))


def _sent(**over) -> MailEvent:
    over.setdefault("sent_at", datetime.now(UTC))
    return _mail(direction=MailDirection.OUTBOUND, **over)


def _away_ctx(mail: MailEvent, **over):
    kw = {"silent_access_armed": True, "has_sensor": True, "active_sessions": 0}
    kw.update(over)
    return _ctx(mail, **kw)


def test_c15_flags_a_send_while_no_device_was_present() -> None:
    assert "C15" in _services(_away_ctx(_sent()))


def test_c15_silent_when_a_device_is_present() -> None:
    assert "C15" not in _services(_away_ctx(_sent(), active_sessions=1))


def test_c15_silent_when_not_armed() -> None:
    assert "C15" not in _services(_away_ctx(_sent(), silent_access_armed=False))


def test_c15_silent_without_a_sensor() -> None:
    assert "C15" not in _services(_away_ctx(_sent(), has_sensor=False))


def test_c15_silent_on_the_historical_backfill() -> None:
    old = _sent(sent_at=datetime.now(UTC) - timedelta(days=3))
    assert "C15" not in _services(_away_ctx(old))
