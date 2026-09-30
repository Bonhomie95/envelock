"""The promises, fired on real messages, at each plan.

`test_every_plan_promise_is_delivered` proves which detections each plan RUNS.
This proves they actually fire, on real RFC822 mail, through the same
`run_all(DetectionContext)` the pipeline uses — and that the plan boundary holds
when the message would otherwise trip a Complete-only detection.

The payment attacks are the product's own canonical simulations, so what is
asserted here is exactly what the "run a simulation" feature reports.
"""

from __future__ import annotations

import asyncio

import pytest

from envelock.channels.mail.parser import parse_message_async
from envelock.core.capabilities import Capability
from envelock.core.enums import SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.platform.graph import simulations

PROTECTED = "acme.example"
VENDOR = "gemini.example"
ALL_CAPS = frozenset(Capability)

#: A vendor we already know, with an account on file — without this A1 has
#: nothing to diff a changed bank detail against and would correctly stay quiet.
KNOWN_VENDOR = CounterpartyState(
    registrable_domain=VENDOR,
    message_count=40,
    known_bank_ids=frozenset({"GB94BARC10201530093459"}),
    verified_phone="+1 555 0100",
)


async def _fire(raw: str, plan: str | None) -> set[str]:
    """Run one message through the real detection path on `plan`."""
    from uuid import uuid4

    event = await parse_message_async(
        raw.encode(),
        tenant_id=uuid4(),
        mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=frozenset({PROTECTED}),
        remediable=True,
    )
    ctx = DetectionContext(
        event=event,
        tenant_id="t",
        capabilities=ALL_CAPS,
        plan=plan,
        owned_domains=frozenset({PROTECTED}),
        known_counterparties=frozenset({VENDOR}),
        counterparty=KNOWN_VENDOR,
    )
    return {f.service for f in run_all(ctx)}


def fire(raw: str, plan: str | None) -> set[str]:
    return asyncio.run(_fire(raw, plan))


def _sims() -> dict[str, str]:
    return {
        s.expects: s.raw_message
        for s in simulations(protected_domain=PROTECTED, vendor_domain=VENDOR)
    }


# ── Essential's promise, on real mail ────────────────────────────────────────
@pytest.mark.parametrize(
    ("expects", "promise"),
    [
        ("A1", "Bank-detail change & supplier fraud alerts"),
        ("A3", "warnings about lookalike senders"),
        ("A6", "replies redirected somewhere else"),
        ("A8", "hijacked supplier conversations"),
    ],
)
def test_essential_catches_the_payment_attacks_it_sells(expects: str, promise: str) -> None:
    fired = fire(_sims()[expects], "essential")
    assert expects in fired, (
        f'Essential sells "{promise}" and {expects} did not fire on the attack '
        f"that is exactly it. Fired: {sorted(fired)}"
    )


@pytest.mark.parametrize("expects", ["A1", "A3", "A6", "A8"])
def test_complete_catches_everything_essential_does(expects: str) -> None:
    """"Everything in Essential", on live mail rather than on a feature list."""
    assert fire(_sims()[expects], "essential") <= fire(_sims()[expects], "complete")


@pytest.mark.parametrize("expects", ["A1", "A3", "A6", "A8"])
def test_guard_catches_none_of_them(expects: str) -> None:
    """Guard protects domains, not mailboxes. Silence here is the product
    working: these attacks arrive in a mailbox Guard does not cover."""
    assert fire(_sims()[expects], "guard") == set()


# ── The Essential/Complete boundary, on one message ──────────────────────────
_CREDENTIAL_PHISH = (
    "From: <it-support@acme-secure.example>\n"
    "To: pay@acme.example\n"
    "Subject: Action required: your mailbox password expires today\n"
    "Content-Type: text/plain\n\n"
    "Confirm your password here to avoid losing access:\n"
    "http://acme-secure.example/login?verify=1\n"
)


def test_link_inspection_is_essential_not_a_complete_upsell() -> None:
    """Landing page: "Inspect links, attachments, and QR-code lures."

    Sold at Essential. Complete adds the AI REVIEW of these messages, not the
    inspection — so an Essential customer must still get the B-family verdicts.
    Getting this backwards leaves links uninspected while the page says they are.
    """
    fired = fire(_CREDENTIAL_PHISH, "essential")
    assert {s for s in fired if s.startswith("B")}, (
        f"Essential inspected nothing on a credential-phishing message: {sorted(fired)}"
    )


def test_no_plan_below_complete_ever_yields_an_identity_finding() -> None:
    """Channel 2 is Complete's whole premium. Checked across every message in
    this file rather than on one, because one message proving it is luck."""
    messages = [*_sims().values(), _CREDENTIAL_PHISH]
    for plan in ("guard", "essential", "solo"):
        for raw in messages:
            leaked = {s for s in fire(raw, plan) if s.startswith("C")}
            assert not leaked, f"{plan} was given Channel 2 detections: {sorted(leaked)}"


def test_an_ordinary_email_produces_nothing_on_any_plan() -> None:
    """Silence is a feature. A product that cries wolf on ordinary mail gets
    turned off, and then it protects nobody."""
    ordinary = (
        f"From: <sara@{VENDOR}>\n"
        f"To: pay@{PROTECTED}\n"
        "Subject: Lunch Thursday?\n"
        "Content-Type: text/plain\n\n"
        "Are you free at 1pm?\n"
    )
    for plan in (None, "guard", "solo", "essential", "complete"):
        assert fire(ordinary, plan) == set(), (
            f"{plan}: ordinary mail raised {sorted(fire(ordinary, plan))}"
        )
