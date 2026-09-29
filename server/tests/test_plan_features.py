"""The Essential / Complete split.

Until this existed nothing in the server read the plan outside billing, so a
paying Essential tenant got the whole Complete feature set for less money.
These pin the boundary in the place the work happens, because a gate that only
hides a button in the dashboard is not a gate.

    Essential — "Protects your mail from invoice fraud."
    Complete  — "Adds protection if a mailbox is broken into."
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from envelock.billing import features
from envelock.core.capabilities import Capability
from envelock.detections import base as det
from envelock.models import Tenant


def _tenant(plan: str, *, paid: bool = True) -> Tenant:
    t = Tenant(name="Acme", plan=plan)
    t.payment_method_ok = paid
    t.trial_ends_at = datetime.now(UTC) - timedelta(days=1)
    return t


def test_channel_two_is_what_complete_sells() -> None:
    """The C-series — unusual sign-in (C7/C8/C9/C10), silent access (C11), MFA
    posture (C13) and the tampering signals (C1-C6) — IS "adds protection if a
    mailbox is broken into". The whole channel moves together rather than only
    the four bullets that happen to be named on the pricing page."""
    for service in ("C1", "C7", "C10", "C11", "C13"):
        assert features.detection_included(service, "complete") is True
        assert features.detection_included(service, "essential") is False
        assert features.detection_included(service, "guard") is False

    # Everything else is Essential's subject and must never be gated — these are
    # the detections that stop the fraud the product exists for.
    for service in ("A1", "A13", "B3", "D4"):
        assert features.detection_included(service, "essential") is True
        assert features.detection_included(service, "complete") is True


def test_a_lapsed_trial_loses_complete_features_with_the_rest() -> None:
    """`effective_plan` drops to Guard when an unpaid trial ends, so the feature
    gates have to follow it — otherwise a lapsed tenant keeps the most expensive
    capabilities for free."""
    lapsed = _tenant("complete", paid=False)
    assert features.is_complete(lapsed) is False
    assert features.ai_on_links(lapsed) is False
    assert features.auto_remediation(lapsed) is False

    paying = _tenant("complete")
    assert features.is_complete(paying) is True
    assert features.ai_on_links(paying) is True
    assert features.auto_remediation(paying) is True


def test_a_trial_gets_complete_because_the_trial_is_on_the_top_plan() -> None:
    trial = Tenant(name="Acme", plan="complete")
    trial.payment_method_ok = False
    trial.trial_ends_at = datetime.now(UTC) + timedelta(days=5)
    assert features.is_complete(trial) is True


def test_the_registry_runs_only_what_the_plan_includes() -> None:
    """The real gate. `active_for` is the single door every detection goes
    through, so filtering there cannot be bypassed by a caller."""
    everything = frozenset(Capability)

    complete = {d.service for d in det.active_for(everything, "complete")}
    essential = {d.service for d in det.active_for(everything, "essential")}

    assert complete - essential, "Complete must run detections Essential does not"
    assert all(s.startswith("C") for s in complete - essential)
    assert not any(s.startswith("C") for s in essential)
    # Essential keeps everything that is not Channel 2.
    assert {s for s in complete if not s.startswith("C")} == essential


def test_no_plan_means_no_gating_so_coverage_can_describe_a_connection() -> None:
    """The coverage endpoints answer "what can this CONNECTION do", which is a
    different question from "what has this tenant bought"."""
    everything = frozenset(Capability)
    assert len(det.active_for(everything, None)) >= len(
        det.active_for(everything, "complete")
    )


def test_plan_locked_is_reported_separately_from_unsupported() -> None:
    """Two different facts, and the customer is told which. Folding the plan
    into `inactive_for` would tell someone their mailbox was incapable of
    something they had simply not bought."""
    everything = frozenset(Capability)

    locked = det.plan_locked_detections(everything, "essential")
    assert locked and all(s.startswith("C") for s in locked)

    # Nothing is unsupported when every capability is present — so anything
    # missing on Essential is missing for a billing reason, not a technical one.
    assert det.inactive_for(everything) == []
    assert det.plan_locked_detections(everything, "complete") == []


@pytest.mark.parametrize("plan", ["essential", "complete"])
def test_manual_quarantine_is_never_gated(plan: str) -> None:
    """Complete buys AUTOMATIC removal. Essential still raises the alert and a
    human can still act on it in one click — nobody is left less safe by not
    paying, which is what makes it fair to charge for."""
    from envelock.platform.remediation import can_remediate

    assert can_remediate(frozenset({Capability.MODIFY_MESSAGE})) is True


@pytest.mark.parametrize("service", ["A1", "B3", "C7"])
def test_guard_does_not_include_mailbox_detections(service: str) -> None:
    assert not features.detection_included(service, "guard")


def test_guard_keeps_domain_monitoring_only() -> None:
    assert features.detection_included("D1", "guard")
    assert not features.detection_included("A1", "unexpected-plan")


def test_free_plan_cannot_gain_mailbox_access_from_a_saved_card() -> None:
    from envelock.billing.entitlement import mailbox_capacity, mailbox_entitled
    guard = _tenant("guard", paid=True)
    assert not mailbox_entitled(guard)
    assert mailbox_capacity(guard) == 0
