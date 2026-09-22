"""The cascade gate — the single most important cost control.

An LLM call on *every* message would blow the margin (§12.11). This decides the
small fraction worth escalating: mail that already tripped a payment/impersonation
signal but sits in an ambiguous band where a human judgment call adds real value.
Clear-cut cases (a confirmed A1 bank change already Critical; plainly benign mail
with no signal) skip the LLM entirely.
"""

from __future__ import annotations

from envelock.core.enums import AlertTier
from envelock.risk.engine import RiskAssessment

#: Services whose presence marks a message as "about money/identity" — mail
#: where a BEC judge earns its cost. A9 (stylometry drift) belongs here: "the
#: writing doesn't sound like them" is precisely the ambiguity a judge resolves.
_PAYMENT_SIGNALS = frozenset(
    {"A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8", "A9", "A10", "A11", "A13", "A14", "A15"}
)

#: The URL/attachment-phishing family. These carried the OTHER half of the
#: product promise ("from URLs to…") and could never reach the judge — a pure
#: credential-phish, a quishing image or an HTML-smuggling lure produced only
#: B-codes, and the gate answered no. Same ambiguous band, same economics: the
#: B-family fires on a small fraction of mail, and MEDIUM/HIGH narrows further.
_PHISH_SIGNALS = frozenset({"B1", "B3", "B4", "B5", "B6", "B7", "B9"})


def should_escalate(assessment: RiskAssessment | None) -> bool:
    """True for the ambiguous middle: a payment/impersonation OR phishing signal
    fired, and the rule tier is Medium or High (not Low noise, not an
    already-certain Critical)."""
    if assessment is None:
        return False
    services = set(assessment.services)
    if not (services & (_PAYMENT_SIGNALS | _PHISH_SIGNALS)):
        return False
    # Low is logged, not alerted — not worth a call. Critical already interrupts a
    # human, so the confirmation adds little. The value is in the Medium/High band.
    return assessment.tier in (AlertTier.MEDIUM, AlertTier.HIGH)


__all__ = ["should_escalate"]
