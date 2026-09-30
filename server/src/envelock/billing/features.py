"""What each plan actually includes.

`entitlement.py` answers *how many* mailboxes a tenant may protect. This answers
*which capabilities* they get on them — the Essential/Complete split the pricing
page sells:

    Essential — "Protects your mail from invoice fraud."
    Complete  — "Adds protection if a mailbox is broken into."

Until this module existed nothing in the server read the plan outside billing,
so every paying tenant got the whole Complete feature set. That is the safe
direction to be wrong, but it made Complete unsellable: an Essential customer
had all of it for less money.

**One module, three questions, and the answers are used server-side where the
work happens** — not in the dashboard. A gate that only hides a button is not a
gate; the pipeline, the judge and the remediation planner each ask here.

A note on honesty, which the two "inactive" lists depend on: a detection that is
off because the connection cannot support it ("IMAP cannot read server-side
rules") and one that is off because the plan does not include it are different
facts, and the customer is told which. Folding the plan into `capabilities`
would have been less code and would have told people their mailbox was
incapable of something they simply had not bought.
"""

from __future__ import annotations

from envelock.billing.entitlement import effective_plan
from envelock.billing.pricing import Plan
from envelock.models import Tenant

#: Channel 2 — the identity/takeover suite. Every "C" detection: unusual
#: sign-in (C7, C8, C9, C10), silent access (C11), MFA posture (C13), and the
#: mailbox-tampering signals (C1–C6). Collectively this IS Complete's one-line
#: promise, "adds protection if a mailbox is broken into", so the whole channel
#: moves together rather than the four bullets that happen to be named.
_COMPLETE_ONLY_PREFIX = "C"

#: Which detection FAMILIES each plan includes, stated rather than inferred.
#:
#: A = payment and invoice fraud, B = links and attachments, C = identity and
#: takeover (Complete only), D = domain and brand (free, Channel 3).
#:
#: This was previously expressed as "included unless it starts with C", which is
#: correct for every family that exists and fails OPEN for any that does not: a
#: new family — or a typo in a service id — was silently granted to every paid
#: plan, with nobody deciding. Listing the families means adding one is a choice
#: someone has to make here, and the default for an unknown id is "not sold".
_PLAN_FAMILIES: dict[str, frozenset[str]] = {
    Plan.GUARD.value: frozenset({"D"}),
    Plan.SOLO.value: frozenset({"A", "B", "D"}),
    Plan.ESSENTIAL.value: frozenset({"A", "B", "D"}),
    Plan.COMPLETE.value: frozenset({"A", "B", "C", "D"}),
}


def _plan_of(tenant: Tenant | None) -> str:
    """The plan in force right now — Guard once an unpaid trial has lapsed."""
    if tenant is None:
        return Plan.GUARD.value
    return effective_plan(tenant)


def is_complete(tenant: Tenant | None) -> bool:
    return _plan_of(tenant) == Plan.COMPLETE.value


def detection_included(service: str, plan: str) -> bool:
    """Whether a detection's service id is covered by `plan`.

    Takes the plan string rather than the Tenant so the detection registry —
    which knows nothing about billing — can be filtered without importing the
    ORM into it.
    """
    families = _PLAN_FAMILIES.get(plan)
    if families is None:  # an unrecognised plan buys nothing
        return False
    family = service[:1].upper()
    return family in families


def ai_on_links(tenant: Tenant | None) -> bool:
    """Complete: "AI analyst on phishing links too".

    Essential buys the analyst on *payment* mail, which is that plan's whole
    subject. Credential phishing is takeover, which is Complete's.
    """
    return is_complete(tenant)


def auto_remediation(tenant: Tenant | None) -> bool:
    """Complete: "Remove dangerous mail automatically".

    Essential still ALERTS on the same message and a human can still quarantine
    it by hand from the dashboard — what Complete buys is us doing it without
    being asked. Nobody is left less safe by not having this; they are left
    doing one click.
    """
    return is_complete(tenant)


def upgrade_note(feature: str) -> str:
    """One sentence for the dashboard where a gate bites.

    Said plainly, because the alternative — a control that silently does
    nothing — is how a customer concludes the product is broken rather than
    that they are on a smaller plan.
    """
    return f"{feature} is included in the Complete plan."


__all__ = [
    "ai_on_links",
    "auto_remediation",
    "detection_included",
    "is_complete",
    "upgrade_note",
]
