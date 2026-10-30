"""Payment-extractor precision: ordinary mail that read as a payment instruction.

`util/payments` gates A1, A2 and A6–A14 for every sender, so each of these made
routine mail alert, whoever sent it:

* an ISO date read as a UK sort code ("2026-10-23" → 202610);
* a token inside a link passed the IBAN checksum;
* the bare word "account" counted as payment language.
"""

from __future__ import annotations

from uuid import uuid4

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import SourceMechanism
from envelock.detections.base import DetectionContext, run_all
from envelock.llm.gate import should_escalate
from envelock.risk.engine import RiskAssessment, assess
from envelock.util.payments import extract_bank_identifiers, has_payment_context

IBAN = "GB29NWBK60161331926819"
#: Its token happens to contain DE89370400440532013000, a valid IBAN.
LINK = "https://portal.example/v?t=x7Kq-DE89370400440532013000Qz9wLm"


def _ids(text: str) -> set[tuple[str, str]]:
    return {(b.scheme, b.identifier) for b in extract_bank_identifiers(text)}


def _assess(content_type: str, body: str) -> RiskAssessment | None:
    """First contact from a sender we have no history with."""
    raw = (
        "From: Portal <noreply@portal.example>\r\nTo: pay@acme.com\r\n"
        f"Subject: Notice\r\nContent-Type: {content_type}; charset=utf-8\r\n\r\n{body}\r\n"
    ).encode()
    source = SourceMechanism.IMAP_IDLE
    event = parse_message(
        raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source,
        owned_domains=frozenset({"acme.com"}), remediable=True,
    )
    ctx = DetectionContext(
        event=event, tenant_id="t", capabilities=capabilities_for(frozenset({source})),
        owned_domains=frozenset({"acme.com"}),
    )
    return assess(run_all(ctx))


def test_a_date_or_colour_is_not_a_sort_code() -> None:
    """Envelock's alert emails print "Date 2026-10-23". Learned as the sender's
    sort code, the next month's (202611) was an A1 "bank details changed"
    CRITICAL — and any vendor that dates its invoices did the same. The same
    emails' HTML (which A2 reads) carries colours like #374151."""
    for text in (
        "Date 2026-10-23 09:05 UTC. Payment by bank transfer.",
        "Invoice dated 23-10-2026, payment by bank transfer.",
        '<p style="color:#374151">Payment by bank transfer &#128073;</p>',
    ):
        assert _ids(text) == set(), text
    for code in ("60-16-13", "601613", "60 16 13"):
        assert _ids(f"Bank sort code {code}, invoice dated 2026-10-23") == {
            ("sortcode", "601613")
        }, code


def test_a_token_in_a_link_is_not_an_iban() -> None:
    """1 in 300 of our own verify emails produced an "IBAN" from the uppercased
    JWT in the link."""
    assert _ids(f"Your invoice is ready: {LINK}") == set()
    # A2 hands the extractor raw HTML: the href goes, the IBAN printed right
    # beside it stays (a strip up to the next space would eat it too).
    assert _ids(f'<a href="{LINK}">View</a><br>IBAN:<b>{IBAN}</b>') == {("iban", IBAN)}
    assert _ids("Please remit to IBAN GB29 NWBK 6016 1331 9268 19") == {("iban", IBAN)}


def test_account_alone_is_not_payment_language() -> None:
    for text in ("Please confirm your account.", "Your account no longer has access."):
        assert not has_payment_context(text), text
    for text in (
        "Account number 31926819",
        "Pay into our bank account",
        "Account: 31926819",
        "Account No. 31926819",
    ):
        assert has_payment_context(text), text


def test_first_contact_notices_raise_no_payment_finding() -> None:
    """A7 and A2 at MEDIUM open the AI judge's gate, and the judge then promoted
    a sign-up email to HIGH."""
    verify = _assess("text/plain", f"Please confirm your account: {LINK}")
    assert verify is None or "A7" not in verify.services, verify
    assert not should_escalate(verify), verify

    # A2 reads the raw HTML, href and all.
    invoice = _assess("text/html", f'<p>Your invoice is ready.</p><a href="{LINK}">View</a>')
    assert invoice is None or "A2" not in invoice.services, invoice
