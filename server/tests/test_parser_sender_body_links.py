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

import email.utils
from email import message_from_bytes
from uuid import uuid4

from envelock.channels.mail.enforce import build_protected_copy
from envelock.channels.mail.parser import POLICY, href_urls, normalise_href, parse_message
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
        remediable=True,
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


# ── Headers the stdlib cannot parse ──────────────────────────────────────────
# policy.default raised IndexError from inside the stdlib on each of these, which
# failed the whole message: a Microsoft 365 history scan stopped at the first
# one ("History scan failed — IndexError: list index out of range").
_UNPARSABLE = (
    b'From: "Billing" <billing@gemini.com>\r\n'
    b'Reply-To: "\r\n'
    b"To: ,\r\n :'\xc3\xa9,);\\[\r\n"
    b"Message-ID: <broken-headers@gemini.com>\r\n"
    b"Content-Type: multipart/mixed; boundary=B\r\n\r\n"
    b"--B\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
    b'<a href="https://evil.example/pay">Pay now</a>\r\n'
    b"--B\r\n"
    b"Content-Type: >x.example<@>=?utf-8?q?a?=[=?;.*\r\n"
    b'Content-Disposition: attachment; filename="invoice.pdf"\r\n\r\n'
    b"%PDF-1.4\r\n"
    b"--B--\r\n"
)


def test_headers_the_stdlib_cannot_parse_are_read_as_text() -> None:
    event = _event(_UNPARSABLE)
    assert event.sender.address == "billing@gemini.com"
    assert event.rfc_message_id == "<broken-headers@gemini.com>"
    assert "https://evil.example/pay" in event.urls
    assert [a.filename for a in event.attachments] == ["invoice.pdf"]

    out = build_protected_copy(
        _UNPARSABLE, link_map={"https://evil.example/pay": "TOK"},
        redirect_base="https://app.envelock.org", mailbox_id=_MBX,
    )
    assert out is not None
    assert b"https://app.envelock.org/r/TOK" in out.replace(b"=\r\n", b"")


def _rewritten_html(copy: bytes | None) -> bytes:
    assert copy is not None
    part = next(p for p in message_from_bytes(copy, policy=POLICY).walk()
                if p.get_content_type() == "text/html")
    payload = part.get_payload(decode=True)
    assert isinstance(payload, bytes)
    return payload


# ── Headers the stdlib cannot write back ─────────────────────────────────────
# The protected copy re-folded each delivered header on the way out and raised:
# UnicodeEncodeError, HeaderWriteError, IndexError. The copy failed, and the
# Gmail or IMAP sync holding the message failed with it on every poll. The utf-7
# part decodes to a lone surrogate, which set_content could not write either.
_UNFOLDABLE = (
    b"From: billing@gemini.com\r\n"
    b"MIME-Version: [filename*0*=[)charset=a\xc3\xa9=?utf-8?q?a?=)x.example?%=?utf-8?q?a?=\r\n"
    b"Reply-To: \xc3\xa9,filename*0*=\xc3\xa9*'filename*0*=\r\n"
    b"Message-ID: =?utf-8?b?\xc3\xa9\\,]filename*0*=);@>?=\r\n"
    b'To: bobboundary=x.example\xc3\xa9\\=?utf-8?b?\\;filename*0*=<@>""=?utf-8?q?a?="\r\n'
    b"Content-Type: multipart/mixed; boundary=B\r\n\r\n"
    b"--B\r\nContent-Type: text/html; charset=utf-7\r\n\r\n"
    b'+2AA-<a href="https://evil.example/pay">Pay now</a>\r\n'
    b"--B--\r\n"
)


def test_the_copy_writes_delivered_headers_back_as_they_arrived() -> None:
    out = build_protected_copy(
        _UNFOLDABLE, link_map={"https://evil.example/pay": "TOK"},
        redirect_base="https://app.envelock.org", mailbox_id=_MBX,
    )
    assert out is not None
    assert out.startswith(_UNFOLDABLE.split(b"\r\n\r\n", 1)[0] + b"\r\n")
    assert b"https://app.envelock.org/r/TOK" in _rewritten_html(out)


# ── RFC 2231 parameters the stdlib trips on ──────────────────────────────────
# Each in a header its structured parser gives up on, so it is kept as text. The
# part's `charset*=` reached the codec as a tuple: a TypeError that failed the
# message on any Python. The bare `boundary*` beside `boundary*0` is a TypeError
# on 3.12, the VPS's Python, from inside the parser; CI runs 3.13, so 3.12's
# decode_params is stood in for below.
_RFC2231 = (
    b"From: billing@gemini.com\r\n"
    b"Message-ID: <rfc2231@gemini.com>\r\n"
    b"Content-Type: multipart/mixed; boundary*=B; boundary*0=B;"
    b" >x.example<@>=?utf-8?q?a?=[=?;.*\r\n\r\n"
    b"--B\r\nContent-Type: text/html; charset*=utf-8''utf-8; y*\r\n\r\n"
    b'<a href="https://evil.example/pay">Pay now</a>\r\n'
    b"--B--\r\n"
)


def test_rfc2231_parameters_the_stdlib_trips_on_still_parse(monkeypatch) -> None:  # noqa: ANN001
    real = email.utils.decode_params

    def as_on_312(params):  # noqa: ANN001, ANN202 — sorts `boundary*` (None) against `boundary*0`
        if {"boundary*", "boundary*0"} <= {name for name, _ in params}:
            raise TypeError("'<' not supported between instances of 'int' and 'NoneType'")
        return real(params)

    monkeypatch.setattr(email.utils, "decode_params", as_on_312)
    assert "https://evil.example/pay" in _event(_RFC2231).urls
    out = build_protected_copy(
        _RFC2231, link_map={"https://evil.example/pay": "TOK"},
        redirect_base="https://app.envelock.org", mailbox_id=_MBX,
    )
    assert b"https://app.envelock.org/r/TOK" in _rewritten_html(out)
