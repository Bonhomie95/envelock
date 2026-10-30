"""Platform notices: Envelock's own mail and big providers' mail (pure).

The 2026-10-23 demo recording showed a HIGH, AI-confirmed alert on Envelock's
own "Confirm your email for Envelock" message, and a MEDIUM on Google's
"Explore your Google Workspace trial". Both came from the counterparty checks:
"first email from envelock.org about payment" (the word "account"), and "no
verified phone number on file for google.com". The AI judge only ever saw them
because those rule findings opened its gate. DMARC-authenticated mail from a
platform domain skips those checks. A spoof, or a bad link riding on a real
platform's mail, still alerts.
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

#: What the receiving mailbox provider stamps on delivery (Gmail's shape).
_AUTH = (
    "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; "
    "dmarc={dmarc} header.from={d}"
)


def _assess(
    raw: bytes, counterparty: CounterpartyState | None = None
) -> RiskAssessment | None:
    source = SourceMechanism.IMAP_IDLE
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
def verify_email(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    """The confirm-your-email message exactly as `send_mail` hands it to the relay."""
    from envelock.api.auth import _send_verification_email
    from envelock.notify import mail
    from envelock.notify.senders import EmailSender

    sent: list[EmailMessage] = []

    async def capture(self: EmailSender, message: EmailMessage) -> None:
        sent.append(message)

    monkeypatch.setattr(mail, "is_configured", lambda: True)
    monkeypatch.setattr(EmailSender, "_deliver", capture)

    async def build(dmarc: str) -> bytes:
        user = SimpleNamespace(
            id=uuid4(), tenant_id=uuid4(), email="owner@acme-widgets.com", role="owner"
        )
        await _send_verification_email(user)  # type: ignore[arg-type]
        message = sent.pop()
        message["Authentication-Results"] = _AUTH.format(d="envelock.org", dmarc=dmarc)
        return message.as_bytes()

    return build


async def test_envelock_verify_email_raises_nothing(verify_email) -> None:  # noqa: ANN001
    assessment = _assess(await verify_email("pass"))
    assert _quiet(assessment), (
        f"Envelock's own confirm-your-email message alerted: {assessment}"
    )


async def test_spoofed_envelock_mail_is_still_judged(verify_email) -> None:  # noqa: ANN001
    assessment = _assess(await verify_email("fail"))
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
    message["Authentication-Results"] = _AUTH.format(d="envelock.org", dmarc="pass")
    learned = CounterpartyState(
        registrable_domain="envelock.org",
        message_count=12,
        known_bank_ids=frozenset({"202610"}),
    )
    assessment = _assess(message.as_bytes(), counterparty=learned)
    assert _quiet(assessment), f"Envelock's own alert email alerted: {assessment}"


GOOGLE_TRIAL = """\
From: Google Workspace <workspace-noreply@google.com>
To: owner@acme-widgets.com
Subject: Explore your Google Workspace trial
Message-ID: <trial-1@google.com>
Authentication-Results: {auth}
Content-Type: text/plain

Your Google Workspace trial for acme-widgets.com is active.
Add a payment method before 2026-11-06 to keep your account and data.
Manage billing: https://admin.google.com/ac/billing
"""


def test_google_trial_mail_raises_nothing() -> None:
    raw = GOOGLE_TRIAL.format(auth=_AUTH.format(d="google.com", dmarc="pass"))
    assessment = _assess(raw.encode())
    assert _quiet(assessment), f"Google's own account mail alerted: {assessment}"


def test_platform_mail_still_gets_link_checks() -> None:
    """Drive, Docs and Forms carry attacker-written text on google.com's own
    DKIM, so a dangerous link there must still alert."""
    raw = (
        GOOGLE_TRIAL.format(auth=_AUTH.format(d="google.com", dmarc="pass"))
        + "Shared with you: http://203.0.113.10/login\n"
    )
    assessment = _assess(raw.encode())
    assert assessment is not None and assessment.is_alertable
    assert "B1" in assessment.services
