"""Everything the parser reads from a sender who is trying to be misread:
the From address, the body parts, and the links.

* #6 From: `accounts@vendor <attacker@evil>` authenticates as attacker, not the
  vendor the plain parser kept. And a display name with an invisible or Cyrillic
  character must not hide the brand/colleague it imitates (A5).
* #4 Body: an IBAN only in the HTML alternative, in a second inline text part, or
  under a bogus charset was invisible to A1 while every client rendered it.
* #5 Links: entity-encoded and backslashed hrefs were never collected or
  rewritten, and `#unsubscribe` opted a phishing link out of rewriting.
"""

from __future__ import annotations

from uuid import uuid4

from envelock.channels.mail.enforce import build_protected_copy
from envelock.channels.mail.parser import href_urls, normalise_href, parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.platform.links import rewritable_urls
from envelock.risk.engine import assess

OWNED = frozenset({"acme-widgets.com"})
KNOWN = frozenset({"gemini.com"})
_MBX = uuid4()


def _event(raw: bytes, source: SourceMechanism = SourceMechanism.IMAP_IDLE):
    return parse_message(
        raw, tenant_id=uuid4(), mailbox_id=_MBX, source=source,
        owned_domains=OWNED, remediable=True,
    )


# ── #6 From angle-address ────────────────────────────────────────────────────
def test_from_authenticates_the_bracketed_address() -> None:
    for header in (
        "accounts@gemini.com <attacker@evil.example>",
        '"accounts@gemini.com" <attacker@evil.example>',
    ):
        event = _event(
            f"From: {header}\nTo: ap@acme-widgets.com\nSubject: x\n"
            f"Message-ID: <{uuid4()}@x>\nContent-Type: text/plain\n\nhi\n".encode()
        )
        assert event.sender.address == "attacker@evil.example", header


def test_spoofed_vendor_in_front_text_still_alerts() -> None:
    # The vendor address up front (what a client shows as the name) must not make
    # the attacker's mail read as the vendor's — it was learned as them before.
    raw = (
        b"From: accounts@gemini.com <attacker@evil.example>\n"
        b"To: ap@acme-widgets.com\nSubject: Remittance\nMessage-ID: <s@evil.example>\n"
        b"Content-Type: text/plain\n\n"
        b"Our bank account has changed, pay IBAN GB29 NWBK 6016 1331 9268 19 now.\n"
    )
    event = _event(raw)
    # A vendor row exists for gemini.com, but this message is not from gemini.com.
    cp = None if event.sender.domain == "evil.example" else CounterpartyState("gemini.com")
    ctx = DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, known_counterparties=KNOWN, counterparty=cp,
    )
    assessment = assess(run_all(ctx))
    assert assessment is not None and assessment.tier is AlertTier.CRITICAL
    assert "A5" in assessment.services  # display name spoofs the vendor


def test_display_name_homoglyph_and_invisible_still_flag_a5() -> None:
    for display in (
        "=?utf-8?q?Gem=E2=80=8Bini_Accounts?=",  # zero-width space
        "=?utf-8?q?G=D0=B5mini_Accounts?=",  # Cyrillic e
    ):
        raw = (
            f"From: {display} <payouts@not-gemini.example>\n"
            "To: ap@acme-widgets.com\nSubject: Invoice\n"
            f"Message-ID: <{uuid4()}@x>\nContent-Type: text/plain\n\n"
            "Please pay our new account IBAN GB29 NWBK 6016 1331 9268 19.\n"
        ).encode()
        event = _event(raw)
        ctx = DetectionContext(
            event=event, tenant_id="t",
            capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
            owned_domains=OWNED, known_counterparties=KNOWN,
        )
        services = {f.service for f in run_all(ctx)}
        assert "A5" in services, display


# ── #4 body extraction ───────────────────────────────────────────────────────
_HDR = (
    "From: Gemini Accounts <accounts@gemini.com>\nTo: ap@acme-widgets.com\n"
    "Subject: Invoice INV-9\nMessage-ID: <{mid}@gemini.com>\nMIME-Version: 1.0\n"
)
_PAY = "Our bank account has changed. Pay INV-9 to IBAN GB29 NWBK 6016 1331 9268 19 today."
_CP = CounterpartyState(
    registrable_domain="gemini.com", message_count=40,
    known_bank_ids=frozenset({"GB33BUKB20201555555555"}), verified_phone="+1 555 0100",
)

_BODY_CASES = {
    "iban-only-in-html-alternative": _HDR + (
        "Content-Type: multipart/alternative; boundary=b\n\n"
        "--b\nContent-Type: text/plain\n\nPlease find the invoice below.\n"
        f"--b\nContent-Type: text/html\n\n<html><body><p>{_PAY}</p></body></html>\n--b--\n"
    ),
    "bogus-charset-single-part": _HDR + f'Content-Type: text/plain; charset="x-bogus"\n\n{_PAY}\n',
    "iban-in-second-inline-text-part": _HDR + (
        "Content-Type: multipart/mixed; boundary=b\n\n"
        "--b\nContent-Type: text/plain\n\nHello, see below.\n"
        f"--b\nContent-Type: text/plain\n\n{_PAY}\n--b--\n"
    ),
}


def test_a1_sees_the_changed_iban_whatever_part_it_is_in() -> None:
    for name, raw in _BODY_CASES.items():
        event = _event(raw.replace("{mid}", str(uuid4())).encode())
        ctx = DetectionContext(
            event=event, tenant_id="t",
            capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
            owned_domains=OWNED, counterparty=_CP,
        )
        assessment = assess(run_all(ctx))
        assert assessment is not None and "A1" in assessment.services, name
        assert assessment.tier is AlertTier.CRITICAL, name


def test_identical_text_and_html_does_not_double_count() -> None:
    # The HTML is only folded in when it ADDS payment content; a plain + html
    # alternative that says the same thing must read like the text alone.
    raw = _HDR.replace("{mid}", str(uuid4())) + (
        "Content-Type: multipart/alternative; boundary=b\n\n"
        "--b\nContent-Type: text/plain\n\nThanks for your order, regards.\n"
        "--b\nContent-Type: text/html\n\n"
        "<html><body>Thanks for your order, regards.</body></html>\n--b--\n"
    )
    from envelock.detections.impersonation import mail_text

    event = _event(raw.encode())
    assert mail_text(event).count("Thanks for your order") == 1


# ── #5 links ─────────────────────────────────────────────────────────────────
def test_normalise_href_resolves_browser_spellings() -> None:
    assert normalise_href("&#104;ttps://evil.example/x") == "https://evil.example/x"
    assert normalise_href("https:\\\\evil.example/x") == "https://evil.example/x"
    assert normalise_href("//evil.example/x") == "https://evil.example/x"
    assert normalise_href("ht\ttps://evil.example/x") == "https://evil.example/x"
    assert normalise_href("mailto:a@b.com") is None


def test_hrefs_are_collected_and_rewritten() -> None:
    html = (
        '<a href="&#104;ttps://evil.example/login">statement</a>'
        '<a href="https://evil.example/login#unsubscribe">pay</a>'
        '<a href="https:\\\\evil.example/login">now</a>'
    )
    raw = (
        "From: Gemini <billing@gemini.com>\nTo: ap@acme-widgets.com\nSubject: Invoice\n"
        f"Message-ID: <{uuid4()}@g>\nMIME-Version: 1.0\nContent-Type: text/html\n\n{html}\n"
    ).encode()
    event = _event(raw)
    assert "https://evil.example/login" in event.urls

    rw = rewritable_urls(list(event.urls), owned_domains=OWNED, redirect_base="https://app.envelock.org")
    assert "https://evil.example/login" in rw  # #unsubscribe no longer exempts it
    out = build_protected_copy(
        raw, link_map=dict.fromkeys(rw, "TOK"), redirect_base="https://app.envelock.org",
        mailbox_id=_MBX,
    )
    # Decode the rewritten part (transport may soft-wrap it) and read its hrefs.
    from email import message_from_bytes, policy

    rewritten = message_from_bytes(out, policy=policy.default).get_content()
    hrefs = href_urls(rewritten)
    assert hrefs == ["https://app.envelock.org/r/TOK"] * 3  # every spelling rewritten
    assert "evil.example" not in rewritten


def test_literal_unsubscribe_host_is_still_never_rewritten() -> None:
    urls = ["https://acme.us1.list-manage.com/unsubscribe?u=1", "https://evil.example/pay"]
    out = rewritable_urls(urls, owned_domains=OWNED, redirect_base="https://app.envelock.org")
    assert out == ["https://evil.example/pay"]
