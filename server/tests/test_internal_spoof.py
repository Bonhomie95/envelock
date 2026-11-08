"""A forged own-domain sender: inbound, judged by A16, never learned.

Found 2026-11-08 by delivering forged mail through the forwarding ingest. The
parser filed every message whose From named a tenant domain as OUTBOUND, so a
CEO-fraud wire request "from" ceo@acme.com was stored as the tenant's own sent
mail with risk 0 and no alert, while the Detection lab rated the same mail HIGH.
Direction is now the channel's, and A16 asks whether the own-domain claim is
backed by a provider-stamped DMARC pass.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail.api_fetch import FetchedMessage
from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, MailDirection, SourceMechanism
from envelock.detections.base import DetectionContext, FindingResult, run_all
from envelock.models import Alert, Counterparty, Message, SenderProfile
from envelock.platform.pipeline import analyse_event
from envelock.risk.engine import assess
from envelock.workers.imap_fetch import sync_mailbox
from envelock.workers.outbound import process_outbound
from tests.test_link_safety import FakeImap, _factory, _protected_mailbox
from tests.test_pipeline import _mailbox

OWNED = frozenset({"acme.com"})

_WIRE = (
    "I need you to make an urgent payment of USD 24,500 to a new vendor today. "
    "I'm in back-to-back meetings, so reply by email only and don't call. "
    "Keep it between us for now."
)
_PRIVATE = "daniel.reyes.private@proton.me"


def _ceo(*, reply_to: str | None = _PRIVATE, body: str = _WIRE, stamp: str | None = None) -> bytes:
    """Mail "from" Acme's CEO, as the mailbox holds it (any host stamp on top)."""
    headers = [
        *([f"Authentication-Results: {stamp}"] if stamp else []),
        'From: "Daniel Reyes" <ceo@acme.com>',
        "To: finance@acme.com",
        *([f"Reply-To: {reply_to}"] if reply_to else []),
        "Subject: Quick favour",
        f"Message-ID: <{uuid4().hex}@acme.com>",
        "Content-Type: text/plain",
    ]
    return ("\n".join(headers) + "\n\n" + body + "\n").encode()


def _gmail(dmarc: str) -> str:
    return (
        "mx.google.com; dkim=pass header.i=@acme.com; spf=pass smtp.mailfrom=acme.com; "
        f"dmarc={dmarc} (p=REJECT) header.from=acme.com"
    )


def _graph(dmarc: str) -> str:
    """Exchange Online writes no authserv-id."""
    return (
        "spf=pass smtp.mailfrom=acme.com; dkim=pass header.d=acme.com; "
        f"dmarc={dmarc} action=none header.from=acme.com"
    )


def _findings(raw: bytes, source: SourceMechanism) -> list[FindingResult]:
    event = parse_message(raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source)
    assert event.direction is MailDirection.INBOUND
    return run_all(
        DetectionContext(
            event=event,
            tenant_id="t",
            capabilities=capabilities_for(frozenset({source})),
            owned_domains=OWNED,
        )
    )


@pytest.mark.parametrize(
    ("source", "stamp"),
    [
        (SourceMechanism.FORWARD_INGEST, None),
        (SourceMechanism.IMAP_IDLE, None),
        # Written by the sender: on IMAP nothing proves the host stamped it.
        (SourceMechanism.IMAP_POLL, "mx.acme.com; dmarc=pass header.from=acme.com"),
        (SourceMechanism.GMAIL_API, _gmail("fail")),
        (SourceMechanism.GRAPH_API, _graph("fail")),
    ],
)
def test_the_forged_ceo_wire_request_is_critical(source: SourceMechanism, stamp: str) -> None:
    assessment = assess(_findings(_ceo(stamp=stamp), source))
    assert assessment is not None, "the forged CEO raised nothing"
    assert assessment.tier is AlertTier.CRITICAL, assessment
    assert assessment.services == ("A16",)
    assert _PRIVATE in assessment.title


def test_a_redirect_or_payment_pressure_alone_is_high() -> None:
    redirected = _ceo(body="Are you at your desk? I need a quick favour.")
    pressured = _ceo(reply_to=None)
    for raw in (redirected, pressured):
        assessment = assess(_findings(raw, SourceMechanism.IMAP_IDLE))
        assert assessment is not None and assessment.tier is AlertTier.HIGH, assessment
        assert assessment.services == ("A16",)


@pytest.mark.parametrize(
    ("source", "stamp"),
    [(SourceMechanism.GMAIL_API, _gmail("pass")), (SourceMechanism.GRAPH_API, _graph("pass"))],
)
def test_internal_mail_the_provider_vouches_for_stays_quiet(
    source: SourceMechanism, stamp: str
) -> None:
    """The real CEO, really asking: Gmail or Exchange stamped DMARC pass for acme.com."""
    assert _findings(_ceo(reply_to=None, stamp=stamp), source) == []


def test_an_unproven_own_domain_claim_alone_stays_quiet() -> None:
    """IMAP and forwarding never carry a provider stamp, so every colleague's mail
    there is an unproven claim. With no redirect and no payment push, nothing."""
    raw = _ceo(reply_to="assistant@acme.com", body="Notes attached. Can we move the review to 3pm?")
    assert _findings(raw, SourceMechanism.IMAP_IDLE) == []


def test_our_own_sent_mail_is_never_a_spoof() -> None:
    event = parse_message(
        _ceo(), tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, direction=MailDirection.OUTBOUND,
    )
    caps = capabilities_for(frozenset({SourceMechanism.IMAP_IDLE}))
    ctx = DetectionContext(event=event, tenant_id="t", capabilities=caps, owned_domains=OWNED)
    assert run_all(ctx) == []


# ── Through the pipeline and the workers ──────────────────────────────────────
async def _learned_nothing(session, tenant_id) -> None:  # noqa: ANN001
    """The tenant's own domain is never a counterparty or a writing baseline."""
    assert (
        await session.execute(select(Counterparty).where(Counterparty.tenant_id == tenant_id))
    ).first() is None
    assert (
        await session.execute(select(SenderProfile).where(SenderProfile.tenant_id == tenant_id))
    ).first() is None


async def test_the_forwarded_spoof_alerts_and_teaches_nothing(session, tenant_id) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session, tenant_id, sources=[SourceMechanism.FORWARD_INGEST])
    event = parse_message(
        _ceo(), tenant_id=tenant_id, mailbox_id=mailbox.id, source=SourceMechanism.FORWARD_INGEST
    )
    result = await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert result.alerted and result.assessment is not None
    assert result.assessment.tier is AlertTier.CRITICAL
    alert = (await session.execute(select(Alert).where(Alert.tenant_id == tenant_id))).scalar_one()
    # Resolving it must never report the tenant's own domain to the shared graph.
    assert alert.counterparty_domain is None
    assert alert.amount_at_risk == 24500
    stored = (
        await session.execute(select(Message).where(Message.tenant_id == tenant_id))
    ).scalar_one()
    assert stored.direction == "inbound" and stored.risk_score > 0
    await _learned_nothing(session, tenant_id)


async def test_authenticated_internal_mail_is_quiet_and_teaches_nothing(session, tenant_id) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session, tenant_id, sources=[SourceMechanism.GMAIL_API])
    event = parse_message(
        _ceo(reply_to=None, stamp=_gmail("pass")),
        tenant_id=tenant_id, mailbox_id=mailbox.id, source=SourceMechanism.GMAIL_API,
    )
    result = await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert not result.alerted and result.findings == []
    await _learned_nothing(session, tenant_id)


async def test_the_imap_worker_flags_and_quarantines_the_forged_ceo(session) -> None:  # noqa: ANN001
    mailbox = await _protected_mailbox(session)  # acme.com, Complete, protected IMAP
    client = FakeImap({31: _ceo()})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory(client))

    assert summary["ok"] is True
    assert summary["alerted"] == 1
    assert summary["alerts"][0]["tier"] == "critical"
    assert summary["quarantined"] == 1


async def test_sent_mail_is_outbound_and_misfiled_mail_is_skipped(session, tenant_id) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session, tenant_id)
    sent = (
        b"From: pay@acme.com\nTo: ap@vendor.com\nSubject: Re: invoice 4471\n"
        b"Message-ID: <s1@acme.com>\nContent-Type: text/plain\n\n"
        b"Urgent: we are paying invoice 4471 today.\n"
    )
    misfiled = (
        b"From: ap@vendor.com\nTo: pay@acme.com\nSubject: invoice 4471\n"
        b"Message-ID: <v1@vendor.com>\nContent-Type: text/plain\n\nPlease pay invoice 4471.\n"
    )
    outcome = await process_outbound(
        session, mailbox,
        [FetchedMessage(ref="1", raw=sent), FetchedMessage(ref="2", raw=misfiled)],
        source=SourceMechanism.IMAP_IDLE, owned=OWNED,
    )
    await session.commit()

    assert outcome["outbound_ingested"] == 1
    rows = (
        await session.execute(
            select(Message.sender_address, Message.direction).where(Message.tenant_id == tenant_id)
        )
    ).all()
    assert [tuple(r) for r in rows] == [("pay@acme.com", "outbound")]
    alerts = await session.execute(select(Alert).where(Alert.tenant_id == tenant_id))
    assert alerts.first() is None
