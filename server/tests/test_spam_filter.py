"""The spam filter: scored on every inbound message from outside, moved to the
mailbox's own Junk folder, never alerted on.

Gmail and Microsoft filter spam; a small or private host often does not, so this
runs on every mailbox whatever its provider. A customer who moves a message back
to the inbox has said "not spam", and that sender stays out of Junk.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from corpus.cases import CASES
from sqlalchemy import select, update
from test_api_writeback import FakeGmail, FakeGraph
from test_imap_live import FakeImapClient, _connected_mailbox, _factory_for

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.detections.base import DetectionContext, run_all
from envelock.detections.spam import connecting_ip, score_spam
from envelock.models import BankRecord, Mailbox, Message, Tenant
from envelock.platform.pipeline import analyse_event, mark_junked
from envelock.workers import oauth_fetch
from envelock.workers.imap_fetch import sync_mailbox

OWNED = frozenset({"acme.com"})
IMAP = SourceMechanism.IMAP_IDLE
LISTED = {"sending_ip_listed": ("zen.spamhaus.org",)}


def _raw(
    body: str,
    *,
    sender: str,
    subject: str,
    to: str = "pay@acme.com",
    mid: str | None = None,
    extra: str = "",
    ctype: str = "text/plain; charset=utf-8",
) -> bytes:
    lines = [f"From: {sender}", f"Subject: {subject}", f"Content-Type: {ctype}"]
    if to:
        lines.append(f"To: {to}")
    if mid:
        lines.append(f"Message-ID: <{mid}@spam.test>")
    return ("\r\n".join(lines) + "\r\n" + extra + "\r\n" + body + "\r\n").encode()


def _stamp(d: str, *, spf: str, dkim: str, dmarc: str) -> str:
    return (
        f"Authentication-Results: mx.acme.com; spf={spf} smtp.mailfrom={d}; "
        f"dkim={dkim} header.d={d}; dmarc={dmarc} header.from={d}\r\n"
    )


SPAM = {
    "advance-fee": _raw(
        "Dear Beneficiary, I am Barrister James. My late client died without a next of kin "
        "and left 15.5 million United States Dollars in a dormant account.",
        sender="james@lawchambers-intl.com", subject="Urgent",
        extra="Reply-To: barrister.james@gmail.com\r\n",
    ),
    "lottery": _raw(
        "Congratulations! You have won the Euro Millions online lottery. Claim your prize "
        "by sending your full name.",
        sender="claims@euro-lotto-board.net", subject="WINNING NOTIFICATION!!!", to="",
    ),
    "sextortion": _raw(
        "I have hacked your device and recorded you while you visited adult websites. Pay in "
        "bitcoin or I send the video to all your contacts.",
        sender="anon@mailcorp.xyz", subject="You have 48 hours",
    ),
    "pharma": _raw(
        "Cheap Viagra and Cialis from our online pharmacy.",
        sender="sales@pills-direct.biz", subject="Best prices",
    ),
    "seo-pitch": _raw(
        "Hi, I was checking your website and noticed it is not on the first page of Google. "
        "We offer SEO services at low cost. Reply STOP to opt out.",
        sender="rankpro.seo.team@gmail.com", subject="Quick question",
    ),
    "upstream-and-forged": _raw(
        "Exclusive deal just for you.", sender="deals@promo-mail.club", subject="Deal",
        extra="X-Spam-Flag: YES\r\n"
        + _stamp("promo-mail.club", spf="softfail", dkim="none", dmarc="fail"),
    ),
    "mailbox-full": _raw(
        "Your mailbox is almost full. Pending incoming messages are held. Verify your account: "
        "https://bit.ly/3xYz",
        sender="admin@mail-quota-check.com", subject="Re: Mailbox notice",
    ),
}
#: Blocklisted sending server plus one more sign.
SPAM_FROM_LISTED_IP = {
    "botnet": _raw(
        "Hello dear, see the offer for you.", sender="info@randomshop.top", subject="offer",
        extra=_stamp("randomshop.top", spf="fail", dkim="none", dmarc="fail"),
    ),
    "shouting": _raw("Act now", sender="news@bulkmailer.ru", subject="LIMITED OFFER FOR YOU TODAY"),
}
REAL = {
    "prospect": _raw(
        "Hi, I came across your website and would like a quote for 200 units.",
        sender="mary.jones1988@gmail.com", subject="Quote request",
    ),
    "loud-newsletter": _raw(
        '<html><body><img src="https://cdn.brand.com/hero.png">'
        '<a href="https://bit.ly/sale">Shop</a></body></html>',
        sender="news@brand.com", subject="BLACK FRIDAY STARTS NOW!!",
        ctype="text/html; charset=utf-8", extra="List-Unsubscribe: <https://brand.com/u>\r\n",
    ),
    "bank-notice": _raw(
        "Your account has been suspended after three failed sign-in attempts. Call us.",
        sender="alerts@chase.com", subject="Account notice",
    ),
    "funding-news": _raw(
        "This week Acme raised 10 million dollars in a Series A.",
        sender="digest@startupnews.com", subject="Weekly digest",
    ),
    "it-notice": _raw(
        "Your password will expire in 3 days. Please verify your account at the portal.",
        sender="it@managed-it.com", subject="Password expiry",
    ),
    "rescued-in-outlook": _raw(
        "Minutes from yesterday's meeting attached.", sender="kim@partnerco.com",
        subject="Minutes", extra="X-Forefront-Antispam-Report: CIP:1.2.3.4;SFV:SPM;\r\n",
    ),
    "exchange-notice": _raw(
        "A new bitcoin address was added to your account. Verify your identity if it wasn't you.",
        sender="no-reply@coinbase.com", subject="Security notice",
    ),
}
#: A real supplier on a blocklisted shared host, with nothing else wrong.
REAL_FROM_LISTED_IP = _raw(
    "Invoice 1182 attached, due in 30 days.", sender="billing@smallhost-supplier.com",
    subject="Invoice 1182",
)


def _verdict(raw: bytes, **ctx: tuple[str, ...]):  # noqa: ANN202
    event = parse_message(raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=IMAP, remediable=True)
    context = DetectionContext(
        event=event, tenant_id="t", capabilities=capabilities_for(frozenset({IMAP})),
        owned_domains=OWNED, **ctx,  # type: ignore[arg-type]
    )
    return score_spam(context, run_all(context))


@pytest.mark.parametrize("name", sorted(SPAM))
def test_spam_scores_as_spam(name: str) -> None:
    verdict = _verdict(SPAM[name])
    assert verdict.is_spam, (verdict.score, verdict.reasons)


@pytest.mark.parametrize("name", sorted(SPAM_FROM_LISTED_IP))
def test_a_blocklisted_server_and_one_more_sign_is_spam(name: str) -> None:
    verdict = _verdict(SPAM_FROM_LISTED_IP[name], **LISTED)
    assert verdict.is_spam and "ip_listed" in verdict.reasons, verdict


@pytest.mark.parametrize("name", sorted(REAL))
def test_real_mail_is_not_spam(name: str) -> None:
    verdict = _verdict(REAL[name])
    assert not verdict.is_spam, (verdict.score, verdict.reasons)


def test_a_blocklisted_server_alone_is_not_spam() -> None:
    verdict = _verdict(REAL_FROM_LISTED_IP, **LISTED)
    assert not verdict.is_spam and verdict.reasons == ("ip_listed",)


def test_nothing_in_the_detection_corpus_is_spam() -> None:
    """Fraud and real mail alike: none of it is junk to the customer."""
    called = [
        (case.id, i, v.score, v.reasons)
        for case in CASES
        for i, raw in enumerate(case.messages)
        if (v := _verdict(raw)).is_spam
    ]
    assert called == []


def test_the_sending_server_is_the_first_public_hop() -> None:
    received = (
        "by 2002:a05:7300:1234 with SMTP id x; Mon, 9 Nov 2026 10:00:01 +0000",
        "from localhost (localhost [127.0.0.1]) by mx.acme.com; Mon, 9 Nov 2026 10:00:00 +0000",
        "from relay.sender.com (relay.sender.com. [209.85.220.41]) by mx.acme.com with ESMTPS",
        # Below the host's own hop, so the sender's to write: never read.
        "from forged.example ([185.220.101.4]) by relay.sender.com",
    )
    assert connecting_ip(received) == "209.85.220.41"
    # Exchange writes the address in parentheses.
    assert connecting_ip((
        "from mail-ej1-f43.google.com (209.85.218.43) by BN8NAM11FT0.outlook.com (10.13.177.10)",
    )) == "209.85.218.43"
    assert connecting_ip(("from EXCH01 (10.0.0.4) by EXCH02 (10.0.0.5)",)) is None


@pytest.mark.parametrize(
    ("header", "spam"),
    [
        ("X-Spam-Flag: YES", True),
        ("X-Spam-Status: Yes, score=7.2 required=5.0", True),
        ("X-Spam: Yes", True),
        ("X-MS-Exchange-Organization-SCL: 6", True),
        ("X-Forefront-Antispam-Report: CIP:1.2.3.4;SFV:SPM;", True),
        ("X-Spam-Status: No, score=1.1", False),
        ("X-MS-Exchange-Organization-SCL: -1", False),
        ("X-Forefront-Antispam-Report: CIP:1.2.3.4;SFV:NSPM;", False),
    ],
)
def test_another_filters_verdict_only_ever_adds(header: str, spam: bool) -> None:
    raw = _raw("Hello.", sender="a@b.example", subject="Hi", extra=f"{header}\r\n")
    event = parse_message(raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=IMAP)
    assert event.upstream_spam is spam


# ── The pipeline: who gets moved, and what it learns ─────────────────────────
async def _mailbox(session, *, cls: MailboxClass = MailboxClass.PROTECTED) -> Mailbox:  # noqa: ANN001
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="Spam", plan="complete", payment_method_ok=True))
    await session.flush()
    mailbox = Mailbox(
        tenant_id=tenant_id, address="pay@acme.com", mailbox_class=cls.value,
        sources=[IMAP.value],
    )
    session.add(mailbox)
    await session.flush()
    return mailbox


async def _analyse(
    session, mailbox: Mailbox, raw: bytes, *, source: SourceMechanism = IMAP,  # noqa: ANN001
    remediable: bool = True,
):  # noqa: ANN202
    event = parse_message(
        raw, tenant_id=mailbox.tenant_id, mailbox_id=mailbox.id, source=source,
        remediable=remediable,
    )
    return await analyse_event(session, event, tenant_id=mailbox.tenant_id, owned_domains=OWNED)


def _pharma(mid: str) -> bytes:
    return _raw(
        "Cheap Viagra and Cialis from our online pharmacy.", sender="sales@pills-direct.biz",
        subject="Best prices", mid=mid,
    )


async def _stored(session, message_id) -> Message:  # noqa: ANN001
    row = await session.get(Message, message_id)
    assert row is not None
    await session.refresh(row)
    return row


async def test_spam_is_moved_without_an_alert(session) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session)
    pr = await _analyse(session, mailbox, _pharma("p1"))
    assert pr.junk and pr.alert_id is None
    stored = await _stored(session, pr.message_id)
    assert stored.spam_score is not None and stored.spam_score >= 5
    assert stored.spam_reasons == ["pharma_adult"]


async def test_spam_teaches_nothing_about_its_sender(session) -> None:  # noqa: ANN001
    """A 419 naming an account: learned, the account would be the "supplier's"
    baseline, and its fee would count toward the payment requests checked."""
    mailbox = await _mailbox(session)
    pr = await _analyse(session, mailbox, _raw(
        "Dear Beneficiary, my late client left 15.5 million United States Dollars. Next of "
        "kin required. Pay the release fee of $450 to account 0123456789 at Zenith Bank.",
        sender="james@lawchambers-intl.com", subject="Release", to="", mid="f1",
    ))
    assert pr.junk, pr.assessment
    stored = await _stored(session, pr.message_id)
    assert stored.payment_amount is None
    banks = (await session.execute(
        select(BankRecord).where(BankRecord.tenant_id == mailbox.tenant_id)
    )).scalars().all()
    assert banks == []


async def test_a_correspondent_is_never_junked(session) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session)
    hello = await _analyse(session, mailbox, _raw(
        "Thanks for the order.", sender="sales@pills-direct.biz", subject="Thanks", mid="c0",
    ))
    assert not hello.junk
    pr = await _analyse(session, mailbox, _pharma("c1"))
    assert not pr.junk
    stored = await _stored(session, pr.message_id)
    assert stored.spam_reasons is not None and "known_sender" in stored.spam_reasons


async def test_moving_it_back_is_not_spam(session) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session)
    pr = await _analyse(session, mailbox, _pharma("r1"))
    assert pr.junk
    await mark_junked(session, pr.message_id)
    # Ten minutes on, the customer drags it back to the inbox.
    await session.execute(
        update(Message).where(Message.id == pr.message_id)
        .values(junked_at=datetime.now(UTC) - timedelta(minutes=10))
    )
    back = await _analyse(session, mailbox, _pharma("r1"))
    assert back.duplicate and not back.junk
    assert (await _stored(session, pr.message_id)).spam_rescued_at is not None
    # And the sender's next one stays where it lands.
    assert not (await _analyse(session, mailbox, _pharma("r2"))).junk


async def test_the_same_spam_twice_follows_the_first_copy(session) -> None:  # noqa: ANN001
    mailbox = await _mailbox(session)
    pr = await _analyse(session, mailbox, _pharma("d1"))
    await mark_junked(session, pr.message_id)
    twin = await _analyse(session, mailbox, _pharma("d1"))
    assert twin.duplicate and twin.junk
    assert (await _stored(session, pr.message_id)).spam_rescued_at is None


async def test_mail_we_may_not_move_is_scored_and_stays(session) -> None:  # noqa: ANN001
    monitored = await _mailbox(session, cls=MailboxClass.MONITORED)
    pr = await _analyse(
        session, monitored, _pharma("m1"), source=SourceMechanism.IMAP_POLL, remediable=False
    )
    assert not pr.junk
    assert (await _stored(session, pr.message_id)).spam_score >= 5
    forwarded = await _analyse(
        session, await _mailbox(session), _pharma("m2"), source=SourceMechanism.FORWARD_INGEST
    )
    assert not forwarded.junk


async def test_a_high_alert_keeps_its_own_action(session) -> None:  # noqa: ANN001
    """Webmail giving an account to pay is A7 HIGH: flagged in place, not junked."""
    mailbox = await _mailbox(session)
    pr = await _analyse(session, mailbox, _raw(
        "Dear Beneficiary, my late client left 15.5 million United States Dollars. Next of "
        "kin required. Send the $450 fee to account 0123456789 at Zenith Bank.",
        sender="barrister.james@gmail.com", subject="Release", to="", mid="h1",
    ))
    assert pr.assessment is not None and pr.assessment.tier in (AlertTier.HIGH, AlertTier.CRITICAL)
    assert not pr.junk
    assert (await _stored(session, pr.message_id)).spam_score >= 5


# ── The workers: where it goes ───────────────────────────────────────────────
class _SpecialUseImap(FakeImapClient):
    """A server that marks its Junk folder (RFC 6154), under a namespace prefix."""

    def __init__(self, **kw) -> None:  # noqa: ANN003
        super().__init__(**kw)
        self.folders.add("INBOX.Junk")

    def find_special_folder(self, folder_flag: bytes) -> str | None:
        return "INBOX.Junk" if folder_flag == b"\\Junk" else None


@pytest.mark.parametrize(("client_cls", "folder"), [(_SpecialUseImap, "INBOX.Junk"),
                                                    (FakeImapClient, "Junk")])
async def test_imap_spam_lands_in_the_servers_junk_folder(
    session, client_cls: type[FakeImapClient], folder: str  # noqa: ANN001
) -> None:
    mailbox = await _connected_mailbox(session)
    client = client_cls(messages={201: _pharma("i1")})
    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    assert summary["junked"] == 1 and summary["alerted"] == 0
    assert client.moved == [(201, folder)]
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id)
    )).scalars().one()
    assert stored.junked_at is not None


@pytest.fixture
def oauth_token(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    def _use(provider: str) -> None:
        async def _tok(session, mailbox_id):  # noqa: ANN001, ANN202, ARG001
            return ("access-token", provider)

        monkeypatch.setattr(oauth_fetch, "current_access_token", _tok)

    return _use


async def _oauth_mailbox(session, provider: str) -> Mailbox:  # noqa: ANN001
    mailbox = await _mailbox(session)
    src = SourceMechanism.GMAIL_API if provider == "google" else SourceMechanism.GRAPH_API
    mailbox.sources = [src.value]
    await session.commit()
    return mailbox


async def test_gmail_spam_gets_the_spam_label_and_a_rescue_registers(
    session, oauth_token  # noqa: ANN001
) -> None:
    oauth_token("google")
    mailbox = await _oauth_mailbox(session, "google")
    gmail = FakeGmail({"g1": _pharma("g1")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert summary["junked"] == 1
    assert "SPAM" in gmail.msgs["g1"]["labelIds"] and "INBOX" not in gmail.msgs["g1"]["labelIds"]
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id)
    )).scalars().one()
    assert stored.junked_at is not None

    # "Not spam" in Gmail, ten minutes later: back in the inbox under the same id.
    stored.junked_at = datetime.now(UTC) - timedelta(minutes=10)
    await session.commit()
    gmail.msgs["g1"]["labelIds"] = ["INBOX"]
    again = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert again["junked"] == 0
    assert (await _stored(session, stored.id)).spam_rescued_at is not None
    assert gmail.msgs["g1"]["labelIds"] == ["INBOX"]


async def test_graph_spam_moves_to_junk_email(session, oauth_token) -> None:  # noqa: ANN001
    oauth_token("microsoft")
    mailbox = await _oauth_mailbox(session, "microsoft")
    graph = FakeGraph({"o1": _pharma("o1")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=graph, write_transport=graph
    )
    assert summary["junked"] == 1
    assert graph.folder_of["o1"] == "junkemail"


# ── Junked spam keeps protected links, and moving its copy back is "not spam" ──
def _pharma_link(mid: str) -> bytes:
    return _raw(
        "Cheap Viagra and Cialis from our online pharmacy: https://pills-direct.biz/order",
        sender="sales@pills-direct.biz", subject="Best prices", mid=mid,
    )


class _AppendingImap(_SpecialUseImap):
    def __init__(self, **kw) -> None:  # noqa: ANN003
        super().__init__(**kw)
        self.appended: list[tuple[str, bytes]] = []

    def append(self, folder: str, msg: bytes, flags=(), msg_time=None) -> None:  # noqa: ANN001
        self.appended.append((folder, msg))


async def test_imap_spam_goes_to_junk_as_its_protected_copy(session) -> None:  # noqa: ANN001
    from envelock.config import get_settings

    mailbox = await _connected_mailbox(session)
    client = _AppendingImap(messages={201: _pharma_link("j1")})
    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    assert summary["junked"] == 1 and client.moved == []
    [(folder, copy)] = client.appended
    assert folder == "INBOX.Junk" and 201 not in client.messages
    assert get_settings().redirect_base.encode() in copy

    # The customer drags the copy back to the inbox.
    client.messages[202] = copy
    again = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))
    assert again["junked"] == 0
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id)
    )).scalars().one()
    await session.refresh(stored)
    assert stored.junked_at is not None and stored.spam_rescued_at is not None


async def test_gmail_spam_copy_goes_in_under_spam_and_back_counts(
    session, oauth_token  # noqa: ANN001
) -> None:
    oauth_token("google")
    mailbox = await _oauth_mailbox(session, "google")
    gmail = FakeGmail({"g2": _pharma_link("g2")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert summary["junked"] == 1 and gmail.trashed == ["g2"]
    [copy_id] = [m for m in gmail.msgs if m != "g2"]
    assert "SPAM" in gmail.msgs[copy_id]["labelIds"]
    assert "INBOX" not in gmail.msgs[copy_id]["labelIds"]

    gmail.msgs[copy_id]["labelIds"] = ["INBOX"]  # "Not spam"
    await oauth_fetch.sync_oauth_mailbox(session, mailbox, transport=gmail, write_transport=gmail)
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id)
    )).scalars().one()
    await session.refresh(stored)
    assert stored.spam_rescued_at is not None


class _GraphFolders(FakeGraph):
    created_in: str | None = None

    async def request(self, method: str, url: str, *, headers: dict, json=None):  # noqa: A002, ANN001, ANN201
        if "/mailFolders/" in url and url.endswith("/messages") and method == "POST":
            self.created_in = url.split("/mailFolders/")[1].split("/")[0]
        return await super().request(method, url, headers=headers, json=json)


async def test_graph_spam_copy_is_made_in_junk_email(session, oauth_token) -> None:  # noqa: ANN001
    oauth_token("microsoft")
    mailbox = await _oauth_mailbox(session, "microsoft")
    graph = _GraphFolders({"o2": _pharma_link("o2")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=graph, write_transport=graph
    )
    assert summary["junked"] == 1
    assert graph.created_in == "junkemail" and graph.deleted == ["o2"]


# ── Blocklists: IPv6, the Spamhaus DQS key, and lists that refuse ────────────
@pytest.fixture
def dnsbl(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    """Answer DNSBL queries from `table` (zone suffix → codes); record each name asked."""
    from envelock.channels.external import reputation
    from envelock.config import get_settings

    asked: list[str] = []
    table: dict[str, list[str]] = {}

    def answers(name: str, *, lifetime: float = 5.0) -> list[str]:  # noqa: ARG001
        asked.append(name)
        return next((codes for suffix, codes in table.items() if name.endswith(suffix)), [])

    monkeypatch.setattr(reputation, "_answers", answers)
    monkeypatch.setenv("ENVELOCK_DOMAIN_REPUTATION_ENABLED", "true")
    get_settings.cache_clear()
    yield asked, table
    get_settings.cache_clear()


def test_a_list_that_refuses_is_never_a_listing(dnsbl) -> None:  # noqa: ANN001
    from envelock.channels.external.reputation import DomainReputation

    _, table = dnsbl
    table.update({
        ".zen.spamhaus.org": ["127.255.255.254"], ".bl.spamcop.net": ["127.0.0.1"],
        ".dbl.spamhaus.org": ["127.255.255.255"], ".multi.surbl.org": ["127.0.0.1"],
    })
    assert not DomainReputation().check_ip("185.220.101.4").listed
    assert not DomainReputation().check("random-sender.com").listed
    table[".bl.spamcop.net"] = ["127.0.0.2"]
    listed = DomainReputation().check_ip("185.220.101.4")
    assert listed.listed and listed.sources == ("bl.spamcop.net",)


def test_ipv6_senders_are_looked_up(dnsbl) -> None:  # noqa: ANN001
    import ipaddress

    from envelock.channels.external.reputation import DomainReputation

    asked, table = dnsbl
    nibbles = ipaddress.ip_address("2a01:111:f400::1").reverse_pointer.removesuffix(".ip6.arpa")
    table[f"{nibbles}.zen.spamhaus.org"] = ["127.0.0.3"]
    assert DomainReputation().check_ip("2a01:111:f400::1").listed
    assert f"{nibbles}.zen.spamhaus.org" in asked


def test_a_dqs_key_asks_spamhaus_privately(dnsbl, monkeypatch) -> None:  # noqa: ANN001
    from envelock.channels.external.reputation import DomainReputation
    from envelock.config import get_settings

    asked, table = dnsbl
    monkeypatch.setenv("ENVELOCK_SPAMHAUS_DQS_KEY", "k3y")
    get_settings.cache_clear()
    table[".k3y.zen.dq.spamhaus.net"] = ["127.0.0.4"]
    result = DomainReputation().check_ip("185.220.101.4")
    assert result.listed and result.sources == ("zen.spamhaus.org",)  # the key stays private
    assert asked == ["4.101.220.185.k3y.zen.dq.spamhaus.net", "4.101.220.185.bl.spamcop.net"]


def test_the_status_page_says_which_list_refuses(dnsbl) -> None:  # noqa: ANN001
    from envelock.channels.external.reputation import probe

    _, table = dnsbl
    table.update({".zen.spamhaus.org": ["127.255.255.254"], ".bl.spamcop.net": ["127.0.0.2"]})
    ok, detail = probe()
    assert not ok
    assert "zen.spamhaus.org: refuses queries sent through a public DNS resolver" in detail
    assert "bl.spamcop.net: answering" in detail and "no Spamhaus DQS key" in detail
