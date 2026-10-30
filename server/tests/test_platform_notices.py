"""Platform notices: Envelock's own mail and big providers' mail (pure).

The 2026-10-23 demo recording showed a HIGH, AI-confirmed alert on Envelock's
own "Confirm your email for Envelock" message, and a MEDIUM on Google's
"Explore your Google Workspace trial". Both came from the counterparty checks:
"first email from envelock.org about payment" (the word "account"), and "no
verified phone number on file for google.com". The AI judge only ever saw them
because those rule findings opened its gate.

Mail whose mailbox provider stamps a DMARC pass for a platform domain now skips
those checks. A spoof still alerts, a bad link riding on a real platform's mail
still alerts, and a DMARC pass the sender wrote into the message is never read.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.message import EmailMessage
from types import SimpleNamespace
from uuid import uuid4

import pytest

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.llm.gate import should_escalate
from envelock.risk.engine import RiskAssessment, assess

OWNED = frozenset({"acme-widgets.com"})

#: Gmail's own stamp, which it prepends on delivery above everything the sender wrote.
_GMAIL = (
    "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; "
    "dmarc={dmarc} (p=REJECT sp=REJECT dis=NONE) header.from={d}"
)


def _delivered(raw: bytes, *stamps: str) -> bytes:
    """`raw` as the mailbox holds it, with each receiving-host header on top."""
    return "".join(f"Authentication-Results: {s}\n" for s in stamps).encode() + raw


def _assess(
    raw: bytes,
    counterparty: CounterpartyState | None = None,
    source: SourceMechanism = SourceMechanism.GMAIL_API,
) -> RiskAssessment | None:
    event = parse_message(
        raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source,
        owned_domains=OWNED, remediable=True,
    )
    ctx = DetectionContext(
        event=event,
        tenant_id="t",
        capabilities=capabilities_for(frozenset({source})),
        owned_domains=OWNED,
        counterparty=counterparty,
    )
    return assess(run_all(ctx))


def _quiet(assessment: RiskAssessment | None) -> bool:
    """No alert, and nothing for the AI judge to confirm."""
    return (assessment is None or not assessment.is_alertable) and not should_escalate(
        assessment
    )


@pytest.fixture
async def verify_email(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """The confirm-your-email message exactly as `send_mail` hands it to the relay."""
    from envelock.api.auth import _send_verification_email
    from envelock.notify import mail
    from envelock.notify.senders import EmailSender

    sent: list[EmailMessage] = []

    async def capture(self: EmailSender, message: EmailMessage) -> None:
        sent.append(message)

    monkeypatch.setattr(mail, "is_configured", lambda: True)
    monkeypatch.setattr(EmailSender, "_deliver", capture)
    user = SimpleNamespace(
        id=uuid4(), tenant_id=uuid4(), email="owner@acme-widgets.com", role="owner"
    )
    await _send_verification_email(user)  # type: ignore[arg-type]
    (message,) = sent
    return message.as_bytes()


def test_envelock_verify_email_raises_nothing(verify_email: bytes) -> None:
    raw = _delivered(verify_email, _GMAIL.format(d="envelock.org", dmarc="pass"))
    assessment = _assess(raw)
    assert _quiet(assessment), (
        f"Envelock's own confirm-your-email message alerted: {assessment}"
    )


def test_spoofed_envelock_mail_is_still_judged(verify_email: bytes) -> None:
    raw = _delivered(verify_email, _GMAIL.format(d="envelock.org", dmarc="fail"))
    assessment = _assess(raw)
    assert assessment is not None and assessment.is_alertable
    assert "A7" in assessment.services, "a spoof of our mail must keep the payee checks"


def test_envelock_alert_email_raises_nothing_after_a_baseline() -> None:
    """Our alert email prints the message date, which the payment extractor reads
    as a sort code. One learned in October made November's alert email an A1
    "bank details changed" CRITICAL."""
    from envelock.notify.report import AlertReport
    from envelock.notify.senders import EmailSender, Notification

    report = AlertReport(
        tier=AlertTier.HIGH,
        title="No verified phone number on file for vendor.example.",
        mailbox_address="owner@acme-widgets.com",
        findings=("Payment request uses urgency or secrecy pressure language.",),
        sender="billing@vendor.example",
        subject="Updated remittance details",
        received_at=datetime(2026, 11, 2, 9, 5, tzinfo=UTC),
    )
    message = EmailSender().build(
        Notification(
            alert_id=uuid4(), tenant_id=uuid4(), tier=report.tier,
            title=report.title, body="", report=report,
        ),
        to="owner@acme-widgets.com",
    )
    learned = CounterpartyState(
        registrable_domain="envelock.org",
        message_count=12,
        known_bank_ids=frozenset({"202610"}),
    )
    raw = _delivered(message.as_bytes(), _GMAIL.format(d="envelock.org", dmarc="pass"))
    assessment = _assess(raw, counterparty=learned)
    assert _quiet(assessment), f"Envelock's own alert email alerted: {assessment}"


GOOGLE_TRIAL = b"""\
From: Google Workspace <workspace-noreply@google.com>
To: owner@acme-widgets.com
Subject: Explore your Google Workspace trial
Message-ID: <trial-1@google.com>
Content-Type: text/plain

Your Google Workspace trial for acme-widgets.com is active.
Add a payment method before 2026-11-06 to keep your account and data.
Manage billing: https://admin.google.com/ac/billing
"""


def test_google_trial_mail_raises_nothing() -> None:
    raw = _delivered(GOOGLE_TRIAL, _GMAIL.format(d="google.com", dmarc="pass"))
    assessment = _assess(raw)
    assert _quiet(assessment), f"Google's own account mail alerted: {assessment}"


def test_platform_mail_still_gets_link_checks() -> None:
    """Drive, Docs and Forms carry attacker-written text on google.com's own
    DKIM, so a dangerous link there must still alert."""
    raw = _delivered(
        GOOGLE_TRIAL + b"Shared with you: http://203.0.113.10/login\n",
        _GMAIL.format(d="google.com", dmarc="pass"),
    )
    assessment = _assess(raw)
    assert assessment is not None and assessment.is_alertable
    assert "B1" in assessment.services


#: A fake Amazon invoice that writes its own DMARC pass into the header block.
FAKE_AMAZON_INVOICE = b"""\
From: Amazon Payments <payments@amazon.com>
To: owner@acme-widgets.com
Subject: Updated remittance details
Message-ID: <inv-1@amazon.com>
Authentication-Results: mx.google.com; dkim=pass header.i=@amazon.com;
 spf=pass smtp.mailfrom=amazon.com; dmarc=pass header.from=amazon.com
Content-Type: text/plain

Our bank account has changed. Please pay invoice INV-2026-1188 to
IBAN GB29 NWBK 6016 1331 9268 19 from today.
"""


@pytest.mark.parametrize(
    ("source", "stamps"),
    [
        pytest.param(SourceMechanism.IMAP_IDLE, (), id="imap-host-stamps-nothing"),
        pytest.param(
            SourceMechanism.IMAP_IDLE,
            ("mail.host.example; spf=pass smtp.mailfrom=amazon.com",),
            id="imap-host-stamp-without-dmarc",
        ),
        pytest.param(
            SourceMechanism.GMAIL_API,
            ("mx.google.com; spf=pass smtp.mailfrom=amazon.com",),
            id="gmail-stamp-without-dmarc",
        ),
        pytest.param(
            SourceMechanism.GRAPH_API,
            ("spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=amazon.com",),
            id="graph-stamp-without-dmarc",
        ),
    ],
)
def test_sender_written_dmarc_never_skips_the_payee_checks(
    source: SourceMechanism, stamps: tuple[str, ...]
) -> None:
    learned = CounterpartyState(
        registrable_domain="amazon.com",
        message_count=40,
        known_bank_ids=frozenset({"GB33BUKB20201555555555"}),
    )
    assessment = _assess(_delivered(FAKE_AMAZON_INVOICE, *stamps), learned, source)
    assert assessment is not None and "A1" in assessment.services, (
        f"a forged dmarc=pass skipped the bank-change check: {assessment}"
    )
    assert assessment.tier is AlertTier.CRITICAL
