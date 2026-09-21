"""Which tiers move a message out of the inbox.

The four tiers are *defined by required action* (PRD §8), not by how alarming
the finding sounds:

    Critical → money or access at risk now.   Auto-quarantine.
    High     → probable attack.               Flag it in place.
    Medium   → suspicious, needs a glance.    Dashboard only.
    Low      → context.                       Logged.

The poller used to quarantine on *any* alert for a Protected mailbox. That is
not a small over-reach: Medium's own example in the PRD is "first contact
discussing payment" — which is every new supplier a company ever emails. Pulling
those out of the inbox teaches people the product cannot be trusted, and then
the Critical alerts that genuinely matter get ignored too. The PRD names that
risk directly (calibration rule P5).

This was caught on a live deployment: a Medium "first email from this domain,
about payment" alert had already been moved to the Quarantine folder before
anyone was asked.
"""

from __future__ import annotations

import pytest

from envelock.core.enums import AlertTier


@pytest.mark.parametrize(
    ("tier", "quarantines", "why"),
    [
        (AlertTier.CRITICAL, True, "money or access at risk now"),
        (AlertTier.HIGH, False, "probable attack, but flagged in place — not moved"),
        (AlertTier.MEDIUM, False, "needs a human glance; moving it pre-empts the human"),
        (AlertTier.LOW, False, "logged for context only"),
    ],
)
def test_only_critical_moves_a_message(tier: AlertTier, quarantines: bool, why: str) -> None:
    """The rule, stated where a reader will find it.

    Kept as data rather than prose so that widening it later is a deliberate
    edit to this table, not a side effect of touching the poller.
    """
    assert (tier is AlertTier.CRITICAL) is quarantines, why


def test_the_poller_gates_quarantine_on_critical() -> None:
    """Guards the actual call site, since the table above cannot.

    Asserting on source is crude, but the alternative is standing up a mailbox,
    a tenant, an IMAP server and a detection result to observe one branch — and
    the failure being guarded against is precisely that someone edits this line
    without noticing the tier matters.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src/envelock/workers/imap_fetch.py"
    text = src.read_text()

    marker = "if protected and tier is AlertTier.CRITICAL:"
    assert marker in text, (
        "the quarantine call is no longer gated on Critical — a Medium alert "
        "would pull a legitimate first-contact email out of a customer's inbox"
    )

    # And every alerted tier BELOW Critical goes to the protected-copy path
    # (banner for High, protected links for Medium/Low) — never quarantine.
    high_branch = "elif protected:"
    assert high_branch in text, "sub-Critical alerts should flag/protect in place, not move"
    assert "banner_allowed=tier is AlertTier.HIGH" in text, (
        "only High carries the banner; Medium/Low get rewritten links without one"
    )


def test_high_is_flagged_in_place_rather_than_left_silent() -> None:
    """High is not "do nothing".

    A probable attack the reader never sees marked is barely better than no
    detection at all, so the banner path has to run even though the message
    stays where it is.
    """
    from pathlib import Path

    src = Path(__file__).resolve().parents[1] / "src/envelock/workers/imap_fetch.py"
    text = src.read_text()
    high_index = text.index("banner_allowed=tier is AlertTier.HIGH")
    surrounding = text[max(0, high_index - 900) : high_index + 200]
    assert "_enforce_copy" in surrounding, "High must still get the in-place banner"
    assert "quarantine_message" not in surrounding, "High must not move the message"
