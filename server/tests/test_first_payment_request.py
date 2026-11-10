"""A7 on a known sender: their first payment request alerts, and only the first.

A7 used to key on the first email alone, so a sender who said hello first, or a
known contact whose mailbox was taken over, could ask for money unflagged. The
"first" also reads the Suppliers page's payment trail (an inbound payment mail
with an amount, alerted or not), because the baselines learn nothing from mail
flagged HIGH or CRITICAL: keyed on those alone, a webmail contact's every later
request would be "the first" again, at HIGH each time.
"""

from __future__ import annotations

from uuid import uuid4

from corpus.cases import msg

from envelock.channels.mail.parser import parse_message
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.detections.base import FindingResult
from envelock.models import Mailbox, Tenant
from envelock.platform.pipeline import analyse_event
from envelock.risk.engine import assess


async def _services(session, raws: list[bytes]) -> list[dict[str, AlertTier]]:
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="First pay", plan="essential", payment_method_ok=True))
    await session.flush()
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=MailboxClass.PROTECTED.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mailbox)
    await session.flush()
    out = []
    for raw in raws:
        event = parse_message(
            raw, tenant_id=tenant_id, mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE, remediable=True,
        )
        result = await analyse_event(
            session, event, tenant_id=tenant_id, owned_domains=frozenset({"acme.com"})
        )
        out.append({f.service: f.tier for f in result.findings})
    return out


async def test_a_known_senders_first_payment_request_alerts_once(session) -> None:
    hello, first, second = await _services(
        session,
        [
            msg("Thanks for the call today.", subject="Call"),
            msg("Here is our invoice INV-2001 for $3,000. Payment terms 30 days.", subject="2001"),
            msg("Here is our invoice INV-2002 for $3,100. Payment terms 30 days.", subject="2002"),
        ],
    )
    assert "A7" not in hello
    assert first.get("A7") is AlertTier.MEDIUM
    assert "A7" not in second, "a later invoice is not the first payment request"


def test_urgency_lifts_a_first_payment_request_and_says_so_once() -> None:
    def f(service: str, tier: AlertTier) -> FindingResult:
        return FindingResult(service=service, tier=tier, score=40, summary=service)

    pressured = assess([f("A7", AlertTier.MEDIUM), f("A14", AlertTier.LOW)])
    assert pressured is not None and pressured.tier is AlertTier.HIGH
    with_payee = assess(
        [f("A2", AlertTier.MEDIUM), f("A7", AlertTier.MEDIUM), f("A14", AlertTier.LOW)]
    )
    assert with_payee is not None and with_payee.tier is AlertTier.CRITICAL
    assert len(with_payee.rationale) == 1, with_payee.rationale


async def test_a_flagged_first_request_is_still_the_first(session) -> None:
    sender = {"sender": "j.doe.payments@gmail.com", "display": "John Doe"}
    ask = "Hi, please send $2,000 to my account 0123456789 at GTBank."
    hello, first, again = await _services(
        session,
        [
            msg("Hi, nice meeting you yesterday.", subject="Hi", **sender),
            msg(ask, subject="Hello", **sender),
            msg(f"{ask} Did you see my last email?", subject="Re: Hello", **sender),
        ],
    )
    assert "A7" not in hello
    # Webmail giving an account to pay: HIGH, so nothing about it is learned.
    assert first.get("A7") is AlertTier.HIGH
    assert "A7" not in again
