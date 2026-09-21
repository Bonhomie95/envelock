"""The alert as a person reads it.

The section that matters is "What should I do?". An alert whose reader has to
infer whether action is needed is worse than no alert: it costs attention and
teaches people that Envelock's mail can be skimmed. So every tier resolves to
either a concrete step or the word "Nothing", and these tests hold that line.

The other rule worth defending is honesty about what we did. "We already moved
it out of the inbox" and "this is still sitting in the inbox" are opposite
instructions, and the report derives which from the same tier rule the poller
uses — so the two can never drift into contradicting each other.
"""

from __future__ import annotations

from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest

from envelock.core.enums import AlertTier
from envelock.notify.report import AlertReport, render_html, render_text


def _report(**over) -> AlertReport:  # noqa: ANN003
    base = {
        "tier": AlertTier.MEDIUM,
        "title": "First email from examp1e-corp.com, and it's about payment",
        "mailbox_address": "joseph@bonhomieinc.dev",
        "sender": '"Finance Director" <accounts@examp1e-corp.com>',
        "subject": "Updated bank details",
        "received_at": datetime(2026, 8, 31, 18, 2, tzinfo=UTC),
        "findings": ("This is the first email from examp1e-corp.com.",),
    }
    return AlertReport(**(base | over))


# ── The five sections, always, in order ──────────────────────────────────────
SECTIONS = [
    "WHY AM I GETTING THIS ALERT?",
    "USER AFFECTED",
    "EMAIL DETAILS",
    "ANALYSIS",
    "WHAT SHOULD I DO?",
]


def test_every_section_appears_in_a_fixed_order() -> None:
    """Someone who gets these weekly should find the answer without reading.

    That only works if the layout never moves, so the order is asserted rather
    than merely the presence of each heading.
    """
    text = render_text(_report())
    positions = [text.index(s) for s in SECTIONS]
    assert positions == sorted(positions)


def test_the_reader_is_told_which_message_this_is_about() -> None:
    """An alert that does not identify its message cannot be acted on."""
    text = render_text(_report())
    assert "joseph@bonhomieinc.dev" in text
    assert "accounts@examp1e-corp.com" in text
    assert "Updated bank details" in text
    assert "2026-08-31 18:02 UTC" in text


# ── "What should I do?" — one unambiguous answer per situation ────────────────
def test_a_quarantined_message_says_nothing_is_needed() -> None:
    """The reader must not go hunting for a message we already removed."""
    action = _report(tier=AlertTier.CRITICAL, quarantined=True).action
    assert action.startswith("Nothing.")
    assert "moved this message out of the inbox" in action


def test_a_flagged_message_says_it_is_still_there() -> None:
    """The opposite instruction, and it must read as the opposite."""
    action = _report(tier=AlertTier.HIGH, flagged_in_place=True).action
    assert "still in the mailbox" in action
    assert "Nothing" not in action


def test_medium_asks_for_a_look_and_says_nothing_was_touched() -> None:
    """Your Medium alert. Silence about what we did would leave the reader
    wondering whether the message is safe to open."""
    action = _report().action
    assert "Nothing has been moved or changed" in action


def test_low_says_nothing_is_expected() -> None:
    assert _report(tier=AlertTier.LOW).action.startswith("Nothing.")


def test_a_callback_number_outranks_everything_else() -> None:
    """When money is at stake and there is a verified number, making that call
    is the whole instruction — and it must say to ignore the email's own number,
    which is the exact trick being defended against."""
    action = _report(
        tier=AlertTier.CRITICAL, quarantined=True, callback_phone="+18030000000"
    ).action
    assert action.startswith("Call +18030000000")
    assert "not use a number from the email" in action
    # Still tells them the message is out of reach, so nobody pays in the gap.
    assert "moved the message out of the inbox" in action


@pytest.mark.parametrize("tier", list(AlertTier))
def test_every_tier_produces_an_actionable_sentence(tier: AlertTier) -> None:
    """No tier may fall through to something vague.

    "You may wish to review this" is how alert fatigue starts, so the test is
    that each answer either names a step or says Nothing.
    """
    action = _report(tier=tier).action
    assert action, f"{tier} produced no action"
    assert action.startswith(("Nothing", "Call", "Check", "Take a look")), action


# ── Missing facts must degrade, not break ────────────────────────────────────
def test_a_missing_subject_is_omitted_rather_than_printed_as_none() -> None:
    """Metadata-only mode (E13) drops the subject deliberately. "Subject: None"
    would read as a bug and undermine a privacy feature that was sold as one."""
    text = render_text(_report(subject=None))
    assert "None" not in text
    assert "Subject" not in text
    assert "Sent to" in text  # the rest of the block still renders


def test_an_alert_with_no_message_behind_it_still_renders() -> None:
    """Identity-channel alerts have no single message. The report must still
    say whose mailbox and what to do."""
    text = render_text(_report(sender=None, subject=None, received_at=None, findings=()))
    assert "joseph@bonhomieinc.dev" in text
    assert "WHAT SHOULD I DO?" in text
    assert "ANALYSIS" not in text  # nothing to analyse; no empty heading


# ── HTML ─────────────────────────────────────────────────────────────────────
class _Balanced(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:  # noqa: ANN001, ARG002
        if tag not in ("br", "img", "meta", "hr"):
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        assert self.stack and self.stack[-1] == tag, f"mismatched </{tag}>"
        self.stack.pop()


def test_the_html_is_well_formed() -> None:
    parser = _Balanced()
    parser.feed(render_html(_report()))
    parser.close()
    assert not parser.stack, f"unclosed tags: {parser.stack}"


def test_content_from_the_email_cannot_inject_markup() -> None:
    """Subject and sender come from a message an attacker wrote. This report is
    read by the person the attack targeted, so unescaped content would let the
    attacker style the very warning about themselves."""
    hostile = _report(
        title="<script>alert(1)</script>",
        subject='"><b>URGENT</b>',
        sender="<img src=x onerror=alert(1)>",
    )
    out = render_html(hostile)
    # The property is that nothing becomes a TAG. Substring checks on payload
    # text ("onerror=") would fail on correctly-escaped output, which is how a
    # test like this ends up being "fixed" by weakening the escaping.
    assert "<script>" not in out
    assert "<b>URGENT</b>" not in out
    assert "<img" not in out
    # ...and that it survives visibly as text, so the reader sees what was sent.
    assert "&lt;script&gt;" in out
    assert "&lt;img" in out
    # Quotes escaped too: unescaped, the subject could break out of an
    # attribute even without an angle bracket.
    assert "&quot;" in out or "&#x27;" in out


def test_the_html_carries_the_same_sections_as_the_text() -> None:
    """A reader on a text-only client must not get a lesser alert."""
    out = render_html(_report())
    for heading in [
        "Why am I getting this alert?",
        "User affected",
        "Email details",
        "Analysis",
        "What should I do?",
    ]:
        assert heading in out
