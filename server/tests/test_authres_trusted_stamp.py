"""Authentication-Results is read per RFC 8601, from the topmost header only.

Both failures the old regex parser had, each with a test that fails on it:

* It scanned the whole header, comments and property values included. Gmail
  repeats the envelope sender in its spf comment and `smtp.mailfrom`, so an
  envelope sender shaped like `dmarc=pass.header.from=x.example@attacker` was
  read as a DMARC pass for x.example on Google's own stamp — and a spoofed
  platform domain then skipped the payee checks.
* It took the first match in ANY header, so a sender who wrote their own
  `Authentication-Results: ...; dmarc=pass` lower in the message was believed
  wherever the host stamped nothing for that method.
"""

from __future__ import annotations

from uuid import uuid4

from envelock.channels.mail.parser import _authres, parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, AuthResult, SourceMechanism
from envelock.detections.base import (
    CounterpartyState,
    DetectionContext,
    is_platform_notice,
    run_all,
)
from envelock.risk.engine import assess

OWNED = frozenset({"acme-widgets.com"})


def test_tokenizer_ignores_results_inside_comments_and_properties() -> None:
    # The envelope sender (a dmarc=pass string) appears in the spf comment and in
    # smtp.mailfrom; only the real dmarc clause counts.
    evil = "dmarc=pass.header.from=envelock.org@attacker.example"
    header = (
        "mx.google.com;"
        f" dkim=pass header.i=@attacker.example;"
        f" spf=pass (google.com: domain of {evil} designates 203.0.113.5 as"
        f" permitted sender) smtp.mailfrom={evil};"
        " dmarc=fail (p=NONE) header.from=envelock.org"
    )
    authserv, results = _authres(header)
    assert authserv == "mx.google.com"
    methods = {m: r for m, r, _ in results}
    assert methods == {"dkim": "pass", "spf": "pass", "dmarc": "fail"}


def test_tokenizer_keeps_quoted_semicolons_and_cfws_around_equals() -> None:
    authserv, results = _authres('mx.google.com; dmarc = pass header.from="a;b.com"')
    assert authserv == "mx.google.com"
    assert results == [("dmarc", "pass", {"header.from": "a;b.com"})]


def _event(raw: bytes, source: SourceMechanism):
    return parse_message(
        raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source,
        owned_domains=OWNED, remediable=True,
    )


_FAKE_PLATFORM = (
    "From: Envelock Alerts <alerts@envelock.org>\n"
    "To: owner@acme-widgets.com\n"
    "Subject: Verified new remittance account\n"
    "Message-ID: <x1@envelock.org>\n"
    "Content-Type: text/plain\n\n"
    "Please pay invoice INV-9 today to IBAN GB29 NWBK 6016 1331 9268 19. Urgent.\n"
)


def test_crafted_envelope_sender_does_not_forge_a_platform_pass() -> None:
    evil = "dmarc=pass.header.from=envelock.org@attacker.example"
    stamp = (
        "Authentication-Results: mx.google.com;"
        f" spf=pass (google.com: domain of {evil} designates 203.0.113.5 as"
        f" permitted sender) smtp.mailfrom={evil};"
        " dmarc=fail (p=NONE) header.from=envelock.org\n"
    )
    event = _event((stamp + _FAKE_PLATFORM).encode(), SourceMechanism.GMAIL_API)
    assert event.authentication.provider_dmarc is AuthResult.FAIL
    assert not is_platform_notice(event)
    ctx = DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.GMAIL_API})),
        owned_domains=OWNED,
    )
    assessment = assess(run_all(ctx))
    assert assessment is not None and assessment.tier is AlertTier.CRITICAL


def test_sender_written_results_below_the_stamp_are_never_read() -> None:
    # No host stamp on an IMAP poll: the only Authentication-Results header is one
    # the sender wrote, claiming every check passed. It is on top, so it is read as
    # the (sender's) stamp — but B8 still has nothing to fail here; what must hold
    # is that a LOWER sender header cannot override a real top stamp.
    raw = (
        "Authentication-Results: mail.host.example; dkim=fail header.d=evil.example;"
        " spf=fail smtp.mailfrom=evil.example; dmarc=fail header.from=gemini.com\n"
        "Authentication-Results: gemini.com; dkim=pass; spf=pass;"
        " dmarc=pass header.from=gemini.com\n"
        "From: Gemini <billing@gemini.com>\n"
        "To: owner@acme-widgets.com\nSubject: Invoice\nMessage-ID: <z@gemini.com>\n"
        "Content-Type: text/plain\n\nPay IBAN GB29 NWBK 6016 1331 9268 19.\n"
    )
    event = _event(raw.encode(), SourceMechanism.IMAP_IDLE)
    # The topmost (host) header won; the sender's all-pass header below is ignored.
    assert event.authentication.dkim is AuthResult.FAIL
    assert event.authentication.dmarc is AuthResult.FAIL


def test_gmail_requires_googles_authserv_id() -> None:
    # A stamp on top that is NOT Google's (an appended or POP-fetched copy) is not
    # trusted on the Gmail channel: no results, nothing skips.
    raw = (
        "Authentication-Results: someone.else; dmarc=pass header.from=envelock.org\n"
        + _FAKE_PLATFORM
    )
    event = _event(raw.encode(), SourceMechanism.GMAIL_API)
    assert event.authentication.stamped is False
    assert event.authentication.provider_dmarc is AuthResult.NONE
    assert not is_platform_notice(event)


def test_gmail_dkim_domain_from_header_i() -> None:
    # Gmail writes header.i, not header.d; A10's signing-domain baseline must come
    # from it or the detection has nothing on the Gmail channel.
    raw = (
        "Authentication-Results: mx.google.com; dkim=pass header.i=@mail.gemini.com;"
        " spf=pass smtp.mailfrom=gemini.com; dmarc=pass header.from=gemini.com\n"
        "From: Gemini <billing@gemini.com>\nTo: owner@acme-widgets.com\n"
        "Subject: Invoice\nMessage-ID: <q@gemini.com>\nContent-Type: text/plain\n\nHi.\n"
    )
    event = _event(raw.encode(), SourceMechanism.GMAIL_API)
    assert event.authentication.dkim_domain == "mail.gemini.com"


def test_graph_reads_the_top_header_without_an_authserv_id() -> None:
    # Exchange Online writes no authserv-id, so its first clause is a result.
    raw = (
        "Authentication-Results: spf=pass (sender IP is 10.0.0.1)"
        " smtp.mailfrom=gemini.com; dkim=pass header.d=gemini.com;"
        " dmarc=pass action=none header.from=gemini.com\n"
        "From: Gemini <billing@gemini.com>\nTo: owner@acme-widgets.com\n"
        "Subject: Invoice\nMessage-ID: <g@gemini.com>\nContent-Type: text/plain\n\nHi.\n"
    )
    event = _event(raw.encode(), SourceMechanism.GRAPH_API)
    assert event.authentication.dmarc is AuthResult.PASS
    assert event.authentication.dkim_domain == "gemini.com"
    assert event.authentication.provider_dmarc is AuthResult.PASS


def test_dmarc_about_a_different_domain_is_not_this_senders_pass() -> None:
    raw = (
        "Authentication-Results: mx.google.com; dmarc=pass header.from=someone-else.com\n"
        "From: Gemini <billing@gemini.com>\nTo: owner@acme-widgets.com\n"
        "Subject: Invoice\nMessage-ID: <d@gemini.com>\nContent-Type: text/plain\n\nHi.\n"
    )
    event = _event(raw.encode(), SourceMechanism.GMAIL_API)
    assert event.authentication.dmarc is AuthResult.NONE


FAKE_AMAZON = (
    b"From: Amazon Payments <payments@amazon.com>\n"
    b"To: owner@acme-widgets.com\nSubject: Updated remittance\n"
    b"Message-ID: <inv@amazon.com>\n"
    b"Authentication-Results: mx.google.com; dkim=pass header.i=@amazon.com;"
    b" spf=pass smtp.mailfrom=amazon.com; dmarc=pass header.from=amazon.com\n"
    b"Content-Type: text/plain\n\n"
    b"Our bank account has changed. Pay INV-1188 to IBAN GB29 NWBK 6016 1331 9268 19.\n"
)


def test_forged_dmarc_pass_still_does_not_skip_on_imap() -> None:
    learned = CounterpartyState(
        registrable_domain="amazon.com", message_count=40,
        known_bank_ids=frozenset({"GB33BUKB20201555555555"}),
    )
    event = _event(FAKE_AMAZON, SourceMechanism.IMAP_IDLE)
    ctx = DetectionContext(
        event=event, tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED, counterparty=learned,
    )
    assessment = assess(run_all(ctx))
    assert assessment is not None and "A1" in assessment.services
    assert assessment.tier is AlertTier.CRITICAL
