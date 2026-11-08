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
from envelock.core.events import AttachmentRef
from envelock.detections.base import DetectionContext, FindingResult, run_all
from envelock.models import Alert, Counterparty, Message, SenderProfile
from envelock.platform import fraud_accounts
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


def _findings(
    raw: bytes,
    source: SourceMechanism,
    *,
    malicious: frozenset[str] = frozenset(),
    fraud: dict[str, dict] | None = None,
    attachments: tuple[AttachmentRef, ...] = (),
) -> list[FindingResult]:
    event = parse_message(raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source)
    assert event.direction is MailDirection.INBOUND
    if attachments:
        event = event.model_copy(update={"attachments": attachments})
    return run_all(
        DetectionContext(
            event=event,
            tenant_id="t",
            capabilities=capabilities_for(frozenset({source})),
            owned_domains=OWNED,
            malicious_domains=malicious,
            fraud_accounts=fraud or {},
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


# ── Links, QR codes and known fraud accounts on a forged colleague ────────────
_LISTED = "mailbox-quota-check.net"
_DRESSED = "microsoft-mailbox-verify.com"
_MULE = "GB82WEST12345698765432"


def _it_desk(lure: str, *, stamp: str | None = None) -> bytes:
    """A credential phish "from" Acme's IT desk. No Reply-To and no payment, so
    A16 has nothing to go on: only the link gives it away."""
    headers = [
        *([f"Authentication-Results: {stamp}"] if stamp else []),
        'From: "IT Service Desk" <it@acme.com>',
        "To: finance@acme.com",
        "Subject: Mailbox storage limit reached",
        f"Message-ID: <{uuid4().hex}@acme.com>",
        "Content-Type: text/plain",
    ]
    body = (
        "Your mailbox is over its storage limit and will stop receiving mail. "
        f"Sign in within 24 hours to keep it: {lure}"
    )
    return ("\n".join(headers) + "\n\n" + body + "\n").encode()


def _image(*qr_urls: str) -> AttachmentRef:
    return AttachmentRef(
        filename="scan.png", sha256="0" * 64, size_bytes=4096,
        declared_mime="image/png", detected_mime="image/png", qr_urls=qr_urls,
    )


@pytest.mark.parametrize("source", [SourceMechanism.IMAP_IDLE, SourceMechanism.FORWARD_INGEST])
@pytest.mark.parametrize(
    ("domain", "tier"), [(_LISTED, AlertTier.HIGH), (_DRESSED, AlertTier.MEDIUM)]
)
def test_a_forged_it_desk_phish_raises_b1(
    source: SourceMechanism, domain: str, tier: AlertTier
) -> None:
    """A blocklisted link alerts on its own; a domain dressed as Microsoft with "sign in"."""
    raw = _it_desk(f"https://{domain}/owa/login")
    assessment = assess(_findings(raw, source, malicious=frozenset({_LISTED})))
    assert assessment is not None, "the forged IT-desk phish raised nothing"
    assert assessment.services == ("B1",)
    assert assessment.tier is tier


@pytest.mark.parametrize(
    ("source", "stamp"),
    [(SourceMechanism.GMAIL_API, _gmail("pass")), (SourceMechanism.GRAPH_API, _graph("pass"))],
)
def test_the_same_links_from_a_colleague_the_provider_vouches_for_stay_quiet(
    source: SourceMechanism, stamp: str
) -> None:
    for domain in (_LISTED, _DRESSED):
        raw = _it_desk(f"https://{domain}/owa/login", stamp=stamp)
        assert _findings(raw, source, malicious=frozenset({_LISTED})) == []


def test_a_forged_qr_code_raises_b3_but_a_colleagues_screenshot_does_not() -> None:
    quishing = _it_desk("scan the attached code with your phone.")
    assessment = assess(
        _findings(
            quishing, SourceMechanism.IMAP_IDLE,
            malicious=frozenset({_LISTED}), attachments=(_image(f"https://{_LISTED}/owa"),),
        )
    )
    assert assessment is not None and "B3" in assessment.services
    assert assessment.tier is AlertTier.HIGH
    # Unproven too, with an image and payment words, which is ordinary between colleagues.
    screenshot = _ceo(reply_to=None, body="Screenshot of the supplier invoice. Can you pay it?")
    assert _findings(screenshot, SourceMechanism.IMAP_IDLE, attachments=(_image(),)) == []


_NEWSLETTER = (
    b'From: "Acme People Team" <people@acme.com>\n'
    b"To: all@acme.com\n"
    b"Subject: October at Acme\n"
    b"Message-ID: <october@acme.com>\n"
    b"Content-Type: text/plain\n\n"
    b"Expense invoices over $500 now need two approvers: https://acme.com/policies/expenses\n"
    b"Sign in to the policy library: https://acme.sharepoint.com/sites/policies\n"
    b"Town hall on Teams: https://teams.microsoft.com/l/meetup-join/19%3ameeting_abc\n"
    b"Benefits portal: https://nam02.safelinks.protection.outlook.com/"
    b"?url=https%3A%2F%2Facme.sharepoint.com%2Fsites%2Fhr&data=05\n"
    b"Survey: https://bit.ly/acme-october\n"
    b"Follow us: https://www.linkedin.com/company/acme\n"
)


def test_an_internal_newsletter_with_ordinary_links_stays_quiet() -> None:
    """Unproven, as all colleague mail on IMAP is, with payment and sign-in words, a
    short link and links to the brands Acme runs on. Even with acme.com on the shared
    graph (other tenants confirming forgeries of it), nothing fires."""
    poisoned = frozenset({"acme.com"})
    assert _findings(_NEWSLETTER, SourceMechanism.IMAP_IDLE, malicious=poisoned) == []


def test_a_forged_colleague_naming_a_known_fraud_account_is_critical() -> None:
    raw = _ceo(reply_to=None, body=f"Please pay invoice 4471 to IBAN {_MULE} this week.")
    fraud = {_MULE: {"scheme": "iban", "other_tenants": 2, "own": False}}
    assessment = assess(_findings(raw, SourceMechanism.IMAP_IDLE, fraud=fraud))
    assert assessment is not None and assessment.services == ("A15",)
    assert assessment.tier is AlertTier.CRITICAL


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


async def test_a_forged_colleagues_links_are_looked_up_but_never_our_own(  # noqa: ANN001
    session, tenant_id, monkeypatch
) -> None:
    """build_context runs link reputation on unproven internal mail, so B1 sees the
    feed hit. It never looks up the own domain, and nothing on vouched mail."""
    from envelock.channels.external import reputation
    from envelock.config import get_settings

    looked_up: list[str] = []

    async def fake_check(domain: str) -> reputation.ReputationResult:
        looked_up.append(domain)
        return reputation.ReputationResult(domain=domain, listed=domain == _LISTED)

    monkeypatch.setattr(reputation, "check_sender_domain", fake_check)
    monkeypatch.setenv("ENVELOCK_DOMAIN_REPUTATION_ENABLED", "true")
    get_settings.cache_clear()
    mailbox = await _mailbox(session, tenant_id, sources=[SourceMechanism.IMAP_IDLE])
    lure = f"https://{_LISTED}/owa/login (help: https://acme.com/it)"

    forged = parse_message(
        _it_desk(lure), tenant_id=tenant_id, mailbox_id=mailbox.id, source=SourceMechanism.IMAP_IDLE
    )
    result = await analyse_event(session, forged, tenant_id=tenant_id, owned_domains=OWNED)
    assert looked_up == [_LISTED]
    assert result.alerted and result.assessment is not None
    assert result.assessment.services == ("B1",) and result.assessment.tier is AlertTier.HIGH

    looked_up.clear()
    vouched = parse_message(
        _it_desk(lure, stamp=_gmail("pass")),
        tenant_id=tenant_id, mailbox_id=mailbox.id, source=SourceMechanism.GMAIL_API,
    )
    result = await analyse_event(session, vouched, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()
    assert looked_up == [] and result.findings == []
    await _learned_nothing(session, tenant_id)


async def test_a_known_fraud_account_from_a_forged_colleague_is_critical(  # noqa: ANN001
    session, tenant_id
) -> None:
    """End to end: another customer confirmed the account, the pipeline finds it."""
    mailbox = await _mailbox(session, tenant_id, sources=[SourceMechanism.FORWARD_INGEST])
    await fraud_accounts.report(
        session, tenant_id=uuid4(), identifiers=[{"scheme": "iban", "identifier": _MULE}]
    )
    event = parse_message(
        _ceo(reply_to=None, body=f"Please pay invoice 4471 to IBAN {_MULE} this week."),
        tenant_id=tenant_id, mailbox_id=mailbox.id, source=SourceMechanism.FORWARD_INGEST,
    )
    result = await analyse_event(session, event, tenant_id=tenant_id, owned_domains=OWNED)
    await session.commit()

    assert result.alerted and result.assessment is not None
    assert result.assessment.services == ("A15",)
    assert result.assessment.tier is AlertTier.CRITICAL
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
