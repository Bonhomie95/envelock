"""Every line on the pricing page, checked against what the product does.

The pricing page makes thirteen promises. Each one is either delivered by a
detection that fires, a feature gate that opens, or a worker that runs — and
until now nothing tied the sentence a customer reads to the code that has to
honour it. A promise nobody tests is a promise nobody keeps.

Each test below names the exact wording it defends, so when someone changes the
pricing copy the failure says which sentence is now a lie.

Two boundaries this file pins down, because both are easy to get backwards:

* **Link and attachment detection (B) is ESSENTIAL, not Complete.** Complete adds
  the AI *review* of phishing messages, not the detection of them. An Essential
  customer whose links stopped being inspected would be a broken product; an
  Essential customer without the AI second opinion on them is a smaller plan.
* **Guard runs no message detections at all.** Its promise is domain monitoring
  (Channel 3, the CT watcher), and it protects no mailbox — so a Guard tenant's
  message pipeline yielding nothing is correct, not a regression.
"""

from __future__ import annotations

import pytest

from envelock.billing.features import (
    ai_on_links,
    auto_remediation,
    detection_included,
    is_complete,
)
from envelock.core.capabilities import Capability
from envelock.detections.base import (
    active_for,
    ensure_loaded,
    plan_locked_detections,
    registry,
)

#: Everything a fully-capable connection can do, so these tests measure the PLAN
#: and never the connection.
ALL_CAPS = frozenset(Capability)

GUARD, SOLO, ESSENTIAL, COMPLETE = "guard", "solo", "essential", "complete"


def _services(plan: str) -> set[str]:
    return {d.service for d in active_for(ALL_CAPS, plan)}


def _family(plan: str, letter: str) -> set[str]:
    return {s for s in _services(plan) if s.startswith(letter)}


# ── The catalogue itself ─────────────────────────────────────────────────────
def test_the_detection_catalogue_is_the_size_we_think_it_is() -> None:
    """A promise check is worthless if the catalogue silently shrank."""
    ensure_loaded()
    by_family: dict[str, int] = {}
    for service in registry():
        by_family[service[0]] = by_family.get(service[0], 0) + 1
    assert by_family == {"A": 15, "B": 9, "C": 14}, by_family


# ── Guard: "Free · Domain monitoring" ────────────────────────────────────────
def test_guard_gets_domain_monitoring_and_no_mailbox_detections() -> None:
    """Pricing page, Guard: "Lookalike domain monitoring", "Domain impersonation
    warnings", "No mailbox connection required".

    Guard runs NO message detections — its entire promise is Channel 3, which
    lives in the CT watcher and the brand endpoints, not in this registry. The
    empty set here is the promise being kept, not broken.
    """
    assert _services(GUARD) == set(), (
        "Guard was given mailbox detections it does not pay for: "
        f"{sorted(_services(GUARD))}"
    )
    # And it is honest about why: everything is named as plan-locked, not as
    # unsupported by the connection.
    locked = set(plan_locked_detections(ALL_CAPS, GUARD))
    assert locked == set(registry()), "Guard's withheld detections are not all named"


def test_guard_is_free_forever_and_buys_no_mailbox_features() -> None:
    from envelock.billing.pricing import PLATFORM_CENTS, Plan, included_mailbox_seats

    assert PLATFORM_CENTS[Plan.GUARD] == 0
    assert included_mailbox_seats(GUARD) == 0


# ── Essential: "AI-assisted payment fraud detection" ─────────────────────────
def test_essential_delivers_payment_fraud_and_supplier_alerts() -> None:
    """Pricing page, Essential: "Bank-detail change & supplier fraud alerts".

    A1 is the bank-detail change itself; A2 is the supplier with no verified
    callback number; A15 is an account already confirmed as fraud. Those three
    ARE that sentence.
    """
    a = _family(ESSENTIAL, "A")
    for service, what in (
        ("A1", "a supplier changing bank details — the attack that takes the money"),
        ("A2", "a supplier with no verified callback number"),
        ("A15", "a bank account already confirmed as fraud"),
    ):
        assert service in a, f"Essential does not detect {what} ({service})"
    assert len(a) == 15, f"Essential is missing payment detections: {sorted(a)}"


def test_essential_delivers_impersonation_detection() -> None:
    """Landing page: "Get warnings about lookalike senders and people pretending
    to be trusted contacts." Sold under Essential, not held back for Complete."""
    a = _family(ESSENTIAL, "A")
    for service in ("A3", "A4", "A5", "A6"):
        assert service in a, f"impersonation detection {service} is not in Essential"


def test_essential_delivers_link_and_attachment_inspection() -> None:
    """Landing page: "Inspect links, attachments, and QR-code lures. Recheck
    rewritten links when they're clicked."

    The whole B family is Essential. Complete adds the AI review of those
    messages — a second opinion — not the inspection itself. Getting this
    backwards would leave an Essential customer's links uninspected while the
    page says otherwise.
    """
    b = _family(ESSENTIAL, "B")
    assert len(b) == 9, f"Essential lost link/attachment detections: {sorted(b)}"
    for service, what in (
        ("B1", "phishing URLs"),
        ("B2", "links weaponised after delivery (time-of-click)"),
        ("B3", "QR-code phishing"),
        ("B4", "malicious attachments"),
    ):
        assert service in b, f"Essential does not inspect {what} ({service})"


def test_essential_does_not_get_complete_only_identity_detection() -> None:
    """The whole Essential/Complete split. If this inverts, Complete is unsellable."""
    assert _family(ESSENTIAL, "C") == set(), (
        "Essential was given Channel 2 — that is Complete's entire premium: "
        f"{sorted(_family(ESSENTIAL, 'C'))}"
    )
    locked = set(plan_locked_detections(ALL_CAPS, ESSENTIAL))
    assert locked == {s for s in registry() if s.startswith("C")}, (
        "Essential's upgrade prompt does not name exactly the C family"
    )


# ── Complete: "Broader detection across email and identity" ──────────────────
def test_complete_delivers_account_takeover_detection() -> None:
    """Pricing page, Complete: "Account-takeover alerts with integrations".
    Landing page: "Surface unusual sign-ins, forwarding rules, and unexplained
    mailbox access with supported integrations."
    """
    c = _family(COMPLETE, "C")
    for service, what in (
        ("C1", "a forwarding rule to an external address"),
        ("C2", "mailbox rule tampering"),
        ("C4", "a rogue OAuth grant that survives a password reset"),
        ("C7", "impossible travel between sign-ins"),
        ("C10", "a sign-in from a device never seen before"),
        ("C11", "mail read while none of the tenant's devices were open"),
    ):
        assert service in c, f"Complete does not surface {what} ({service})"
    assert len(c) == 14, f"Complete is missing identity detections: {sorted(c)}"


def test_complete_is_a_strict_superset_of_essential() -> None:
    """"Everything in Essential" has to be literally true."""
    assert _services(ESSENTIAL) < _services(COMPLETE)


def test_essential_is_a_strict_superset_of_guard() -> None:
    """"Everything in Guard" — trivially true for detections, and asserted so a
    future Guard-only detection cannot be accidentally withheld from Essential."""
    assert _services(GUARD) <= _services(ESSENTIAL)


# ── The two feature gates that are not detections ────────────────────────────
class _Tenant:
    """Minimal stand-in: the gates read plan + entitlement, nothing else."""

    def __init__(self, plan: str, *, paid: bool = True) -> None:
        from datetime import UTC, datetime, timedelta

        self.plan = plan
        self.payment_method_ok = paid
        self.trial_ends_at = datetime.now(UTC) - timedelta(days=1)


def test_ai_review_of_phishing_is_complete_only() -> None:
    """Pricing page, Complete: "AI review of phishing messages".
    Essential's own line is "AI review of suspicious payment emails" — so the
    analyst runs for both, on different mail."""
    assert ai_on_links(_Tenant(COMPLETE)) is True
    assert ai_on_links(_Tenant(ESSENTIAL)) is False
    assert ai_on_links(_Tenant(GUARD)) is False
    assert ai_on_links(None) is False


def test_automatic_quarantine_is_complete_only() -> None:
    """Pricing page, Complete: "Automatic quarantine where supported".

    Essential still ALERTS on the same message and a human can quarantine by
    hand — what Complete buys is us doing it unasked.
    """
    assert auto_remediation(_Tenant(COMPLETE)) is True
    assert auto_remediation(_Tenant(ESSENTIAL)) is False
    assert auto_remediation(_Tenant(GUARD)) is False


def test_the_plan_a_lapsed_tenant_is_judged_on_is_guard_not_what_they_bought() -> None:
    """Every gate above has to read the EFFECTIVE plan. A lapsed Complete tenant
    is a Guard tenant, or the whole suspension story is decorative."""
    lapsed = _Tenant(COMPLETE, paid=False)
    assert is_complete(lapsed) is False
    assert ai_on_links(lapsed) is False
    assert auto_remediation(lapsed) is False


# ── Solo: the no-domain segment ──────────────────────────────────────────────
def test_solo_gets_payment_and_link_protection_but_not_identity() -> None:
    """PRD §12.6. Priced per mailbox with no domain, so it must not quietly be
    a cheaper Complete."""
    assert detection_included("A1", SOLO) is True
    assert detection_included("B1", SOLO) is True
    assert detection_included("C1", SOLO) is False


@pytest.mark.parametrize("plan", [GUARD, SOLO, ESSENTIAL, COMPLETE])
def test_no_plan_is_accidentally_given_an_unknown_service(plan: str) -> None:
    """A service id that matches no family must never be included by default."""
    assert detection_included("Z9", plan) is False
    assert detection_included("", plan) is False


def test_an_unknown_plan_buys_nothing() -> None:
    """A typo in a plan name must fail closed, not open."""
    for service in ("A1", "B1", "C1", "D1"):
        assert detection_included(service, "enterprise") is False
