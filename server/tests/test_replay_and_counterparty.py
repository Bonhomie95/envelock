"""Pipeline-level sender-control fixes that need stored state.

* #3 A reused Message-ID with DIFFERENT content is analysed, not dropped as a
  re-delivery; a genuine re-delivery (same id, same content) is still skipped;
  and our own protected copy is still skipped on every source.
* #7 Free-mail senders are keyed per address, so one gmail.com stranger's history
  is not inherited by the next.
* #8 The platform-notice skip no longer silences the payee checks — only A7/B9.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail import enforce
from envelock.channels.mail.parser import parse_message
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.models import Alert, Domain, Mailbox, Message, Tenant

pytestmark = pytest.mark.asyncio
OWNED = frozenset({"acme.com"})


async def _mailbox(session, *, cls=MailboxClass.PROTECTED) -> Mailbox:
    tid = uuid4()
    session.add(Tenant(id=tid, name="Acme", plan="complete", payment_method_ok=True))
    await session.flush()
    session.add(Domain(tenant_id=tid, name="acme.com", registrable_domain="acme.com"))
    mb = Mailbox(
        tenant_id=tid, address="pay@acme.com", mailbox_class=cls.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mb)
    await session.flush()
    return mb


def _raw(msg_id: str, subject: str, body: str) -> bytes:
    return (
        f'From: "AP" <billing@vendor.example>\r\nTo: pay@acme.com\r\n'
        f"Subject: {subject}\r\nMessage-ID: <{msg_id}@vendor.example>\r\n"
        f"Content-Type: text/plain\r\n\r\n{body}\r\n"
    ).encode()


async def test_reused_message_id_with_new_content_is_analysed(session) -> None:
    from envelock.platform.pipeline import analyse_event

    mb = await _mailbox(session)

    def event(raw):
        return parse_message(
            raw, tenant_id=mb.tenant_id, mailbox_id=mb.id,
            source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
        )

    # A benign message, then the phish reusing its Message-ID.
    decoy = _raw("reuse-1", "hello", "Good to meet you last week.")
    phish = _raw("reuse-1", "urgent payment", "Pay at http://203.0.113.9/login now.")
    first = await analyse_event(session, event(decoy), tenant_id=mb.tenant_id, owned_domains=OWNED)
    attack = await analyse_event(session, event(phish), tenant_id=mb.tenant_id, owned_domains=OWNED)
    await session.commit()

    assert first.duplicate is False
    assert attack.duplicate is False  # different content — NOT skipped
    assert attack.alerted is True
    stored = (
        await session.execute(select(Message).where(Message.mailbox_id == mb.id))
    ).scalars().all()
    assert len(stored) == 2


async def test_genuine_redelivery_is_still_skipped(session) -> None:
    from envelock.platform.pipeline import analyse_event

    mb = await _mailbox(session)
    raw = _raw("dup-1", "urgent payment", "Pay at http://203.0.113.9/login now.")

    def event(source):
        return parse_message(
            raw, tenant_id=mb.tenant_id, mailbox_id=mb.id, source=source,
            owned_domains=OWNED, remediable=True,
        )

    first = await analyse_event(
        session, event(SourceMechanism.IMAP_IDLE), tenant_id=mb.tenant_id, owned_domains=OWNED
    )
    second = await analyse_event(
        session, event(SourceMechanism.FORWARD_INGEST), tenant_id=mb.tenant_id, owned_domains=OWNED
    )
    await session.commit()

    assert first.alerted is True
    assert second.duplicate is True
    alerts = (
        await session.execute(select(Alert).where(Alert.tenant_id == mb.tenant_id))
    ).scalars().all()
    assert len(alerts) == 1


@pytest.mark.parametrize(
    "source",
    [
        SourceMechanism.IMAP_IDLE,
        SourceMechanism.GMAIL_API,
        SourceMechanism.GRAPH_API,
        SourceMechanism.FORWARD_INGEST,
    ],
)
async def test_our_own_protected_copy_is_skipped_on_every_source(session, source) -> None:
    from envelock.platform.pipeline import analyse_event

    mb = await _mailbox(session)
    original = _raw("copy-1", "urgent payment", "Pay at http://203.0.113.9/login now.")
    # The copy we wrote back carries our unforgeable stamp for this mailbox.
    copy = enforce.build_protected_copy(
        original, link_map={}, redirect_base="https://app.envelock.org",
        mailbox_id=mb.id, banner=None,
    )
    assert enforce.is_processed(copy, mb.id)
    event = parse_message(
        copy, tenant_id=mb.tenant_id, mailbox_id=mb.id, source=source,
        owned_domains=OWNED, remediable=True,
    )
    assert event.protected_copy is True
    result = await analyse_event(session, event, tenant_id=mb.tenant_id, owned_domains=OWNED)
    await session.commit()
    assert result.duplicate is True
    assert result.alerted is False


def _freemail(sender: str, body: str, msg_id: str) -> bytes:
    return (
        f"From: {sender}\r\nTo: pay@acme.com\r\nSubject: Wire request\r\n"
        f"Message-ID: <{msg_id}@gmail.com>\r\nContent-Type: text/plain\r\n\r\n{body}\r\n"
    ).encode()


async def test_free_mail_history_is_not_shared_between_senders(session) -> None:
    from envelock.platform.pipeline import analyse_event

    mb = await _mailbox(session)

    def run(raw):
        event = parse_message(
            raw, tenant_id=mb.tenant_id, mailbox_id=mb.id,
            source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
        )
        return analyse_event(session, event, tenant_id=mb.tenant_id, owned_domains=OWNED)

    # One gmail.com correspondent sends enough ordinary mail to build history.
    for i in range(3):
        await run(_freemail("Ada <ada.known@gmail.com>", "Thanks, talk soon.", f"ada-{i}"))
    await session.commit()

    # A different gmail.com address, first ever contact, asks for a wire. It must
    # still read as first contact (A7), not inherit ada's history.
    result = await run(
        _freemail(
            "Mark <mark.cfo.office@gmail.com>",
            "Please wire payment today to IBAN GB29 NWBK 6016 1331 9268 19. Urgent.",
            "mark-1",
        )
    )
    await session.commit()
    assert result.alerted
    assert "A7" in result.assessment.services  # first contact for THIS address


PLATFORM_SELLER = (
    b"From: \"Gemini - Marketplace\" <seller@amazon.com>\r\n"
    b"To: pay@acme.com\r\nSubject: Message from seller\r\n"
    b"Message-ID: <sell-1@amazon.com>\r\n"
    b"Authentication-Results: mx.google.com; dkim=pass header.i=@amazon.com;"
    b" spf=pass smtp.mailfrom=amazon.com; dmarc=pass header.from=amazon.com\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Our payout is frozen. Pay invoice INV-77 by bank transfer to IBAN"
    b" GB29 NWBK 6016 1331 9268 19 today or your order is cancelled.\r\n"
)


async def test_platform_skip_no_longer_silences_payee_checks(session) -> None:
    from envelock.platform.pipeline import analyse_event

    mb = await _mailbox(session)
    event = parse_message(
        PLATFORM_SELLER, tenant_id=mb.tenant_id, mailbox_id=mb.id,
        source=SourceMechanism.GMAIL_API, owned_domains=OWNED, remediable=True,
    )
    result = await analyse_event(session, event, tenant_id=mb.tenant_id, owned_domains=OWNED)
    await session.commit()
    # A2 (unverified payee) now fires on real platform mail carrying a payment ask;
    # A7 (first contact) stays skipped because the platform is not a counterparty.
    assert result.alerted
    assert "A2" in result.assessment.services
    assert "A7" not in result.assessment.services
