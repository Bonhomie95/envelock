"""The live IMAP path, end to end, with a fake server.

This is the test that reproduces the user's exact complaint: connect a mailbox
over IMAP, a sketchy message arrives, and it must be fetched, flagged, an alert
raised, and (for a Protected mailbox) moved out of the inbox. The IMAP client is
faked so the whole path runs without a real server — the fake speaks the same
slice of the `imapclient.IMAPClient` API the worker uses.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail import imap_sync
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.models import Alert, Domain, Mailbox, MailboxCredential, Message, Tenant
from envelock.security.crypto import seal
from envelock.workers.imap_fetch import run_imap_poll_cycle, sync_mailbox

pytestmark = pytest.mark.asyncio

OWNED = "acme.com"


def _phishing_raw(uid_hint: str = "1") -> bytes:
    # A bare-IP link and a link shortener — B1 flags this at MEDIUM, which is
    # alertable. Deterministic: needs no threat feed or brand list.
    return (
        b'From: "Accounts Payable" <billing@evil-invoices.com>\r\n'
        b"To: pay@acme.com\r\n"
        b"Subject: URGENT: update your payment details\r\n"
        b"Message-ID: <" + uid_hint.encode() + b"@evil-invoices.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Please confirm at http://203.0.113.9/login and http://bit.ly/pay-now now.\r\n"
    )


def _benign_raw() -> bytes:
    return (
        b'From: "Jane" <jane@partner.com>\r\n'
        b"To: pay@acme.com\r\n"
        b"Subject: lunch next week?\r\n"
        b"Message-ID: <benign@partner.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Great seeing you. Lunch Tuesday?\r\n"
    )


class FakeImapClient:
    """In-memory IMAP server good enough for the worker's use of it."""

    def __init__(self, *, messages: dict[int, bytes], uidvalidity: int = 42) -> None:
        self.messages = dict(messages)  # uid -> raw
        self.uidvalidity = uidvalidity
        self.moved: list[tuple[int, str]] = []
        self.folders: set[str] = {"INBOX"}
        self.logged_in = False

    # connection
    def login(self, username: str, password: str) -> None:
        self.logged_in = True

    def starttls(self) -> None:  # pragma: no cover - not exercised here
        pass

    def logout(self) -> None:
        pass

    # folder + search
    def select_folder(self, folder: str, readonly: bool = False) -> dict:
        return {b"UIDVALIDITY": self.uidvalidity, b"EXISTS": len(self.messages)}

    def search(self, criteria):
        uids = sorted(self.messages)
        if criteria and criteria[0] == "UID":
            lo = int(str(criteria[1]).split(":", 1)[0])
            hits = [u for u in uids if u >= lo]
            # ``lo:*`` always yields at least the highest message (IMAP quirk).
            if not hits and uids:
                hits = [uids[-1]]
            return hits
        return uids

    def fetch(self, messages, data):
        # Answer the way a server answers BODY.PEEK[] — under the name BODY[].
        # The poller must never request RFC822, which sets \Seen.
        assert "RFC822" not in data, "the poller asked for RFC822, which marks mail read"
        return {uid: {b"BODY[]": self.messages[uid]} for uid in messages if uid in self.messages}

    # quarantine
    def folder_exists(self, folder: str) -> bool:
        return folder in self.folders

    def create_folder(self, folder: str) -> None:
        self.folders.add(folder)

    def capabilities(self):
        return (b"IMAP4REV1", b"MOVE", b"UIDPLUS")

    def move(self, messages, folder: str) -> None:
        for uid in messages:
            if uid in self.messages:
                self.moved.append((uid, folder))
                del self.messages[uid]

    def copy(self, messages, folder: str) -> None:  # pragma: no cover - MOVE path used
        for uid in messages:
            self.moved.append((uid, folder))

    def delete_messages(self, messages) -> None:  # pragma: no cover
        for uid in messages:
            self.messages.pop(uid, None)

    def expunge(self, messages=None) -> None:  # pragma: no cover
        pass


def _factory_for(client: FakeImapClient):
    def factory(*, host, port, security, timeout):
        return client

    return factory


async def _connected_mailbox(
    session, *, cls=MailboxClass.PROTECTED, source=SourceMechanism.IMAP_IDLE
) -> Mailbox:
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="Acme", plan="complete", payment_method_ok=True))
    await session.flush()
    session.add(Domain(tenant_id=tenant_id, name=OWNED, registrable_domain=OWNED))
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=cls.value,
        sources=[source.value],
    )
    session.add(mailbox)
    await session.flush()
    sealed = seal(b"hunter2-app-password", aad=str(mailbox.id).encode())
    session.add(
        MailboxCredential(
            mailbox_id=mailbox.id,
            tenant_id=tenant_id,
            kind="imap_password",
            imap_host="imap.acme.com",
            imap_port=993,
            imap_security="ssl",
            imap_username=None,
            ciphertext=sealed.ciphertext,
            wrapped_dek=sealed.wrapped_dek,
            key_id=sealed.key_id,
        )
    )
    await session.flush()
    return mailbox


async def test_sketchy_mail_is_fetched_flagged_and_quarantined(session):
    """The headline scenario: connect IMAP, a phishing message is waiting, one
    sync must fetch it, flag it, raise an alert, and move it out of the inbox."""
    mailbox = await _connected_mailbox(session)
    client = FakeImapClient(messages={101: _phishing_raw("101")})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    assert summary["ok"] is True
    assert summary["fetched"] == 1
    assert summary["alerted"] == 1
    # NOT quarantined. `_phishing_raw` scores MEDIUM (its own comment says so),
    # and Medium means "suspicious, needs a human glance" — dashboard only.
    # This assertion used to read `== 1`, which encoded a real bug rather than
    # the requirement: every Medium alert was pulled out of the inbox, and
    # Medium's canonical example is "first contact discussing payment" — every
    # new supplier a company ever emails. See test_quarantine_tiers.py.
    assert summary["quarantined"] == 0

    # An alert and a message were actually persisted for this tenant.
    alerts = (
        (await session.execute(select(Alert).where(Alert.tenant_id == mailbox.tenant_id)))
        .scalars()
        .all()
    )
    assert len(alerts) == 1
    messages = (
        (await session.execute(select(Message).where(Message.mailbox_id == mailbox.id)))
        .scalars()
        .all()
    )
    assert len(messages) == 1

    # The message stays where the reader expects it. A Medium finding is
    # information, not a verdict — moving it makes the decision for them.
    assert client.moved == []
    assert 101 in client.messages

    # The cursor advanced so the next poll does not re-fetch it.
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    assert cred.imap_last_uid == 101
    assert cred.imap_uidvalidity == 42


async def test_second_sync_only_sees_new_mail(session):
    """After the cursor advances, a benign follow-up is fetched but nothing
    re-fires on the already-seen phishing message."""
    mailbox = await _connected_mailbox(session)
    client = FakeImapClient(messages={101: _phishing_raw("101")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    # A new benign message arrives at a higher UID.
    client.messages[102] = _benign_raw()
    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    assert summary["fetched"] == 1  # only the new one
    assert summary["alerted"] == 0  # benign
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    assert cred.imap_last_uid == 102


async def test_monitored_mailbox_alerts_but_does_not_quarantine(session):
    """A Monitored (poll) mailbox is alert-only — it must flag but never move
    mail, because polling arrives post-hoc and remediation isn't guaranteed."""
    mailbox = await _connected_mailbox(
        session, cls=MailboxClass.MONITORED, source=SourceMechanism.IMAP_POLL
    )
    client = FakeImapClient(messages={7: _phishing_raw("7")})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    assert summary["alerted"] == 1
    assert summary["quarantined"] == 0
    assert client.moved == []


async def test_unreachable_server_is_reported_not_raised(session):
    """One broken mailbox must not crash the poll — a connection failure comes
    back as ok=False with a reason."""
    mailbox = await _connected_mailbox(session)

    def exploding_factory(*, host, port, security, timeout):
        raise OSError("connection refused")

    summary = await sync_mailbox(session, mailbox, client_factory=exploding_factory)
    assert summary["ok"] is False
    assert "connection refused" in summary["reason"]


async def test_uidvalidity_change_resets_the_cursor(session):
    """If the server renumbers the folder (UIDVALIDITY changes), the stored UID
    is meaningless and we must not silently skip mail."""
    result = imap_sync.fetch_new(
        host="h",
        port=993,
        security="ssl",
        username="u",
        password="p",  # noqa: S106 — test credential, not a secret
        since_uid=500,  # stale cursor from the old epoch
        uidvalidity=1,  # old epoch
        client_factory=_factory_for(
            FakeImapClient(messages={1: _benign_raw()}, uidvalidity=2)  # new epoch
        ),
    )
    assert result.ok is True
    # Despite since_uid=500, the low-UID message under the new epoch is fetched.
    assert [m.uid for m in result.messages] == [1]
    assert result.uidvalidity == 2


async def test_undecryptable_credential_flags_reconnect(session):
    """If the stored password can't be decrypted (master key rotated), the
    mailbox must be flagged needs_reconnect — not left looking healthy."""
    mailbox = await _connected_mailbox(session)
    # Corrupt the wrapped DEK so open_secret fails, simulating a rotated key.
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    cred.wrapped_dek = b"\x00" * len(cred.wrapped_dek)
    await session.flush()

    summary = await sync_mailbox(
        session, mailbox, client_factory=_factory_for(FakeImapClient(messages={}))
    )
    assert summary["ok"] is False
    assert summary["needs_reconnect"] is True

    refreshed = await session.get(Mailbox, mailbox.id)
    assert refreshed.needs_reconnect is True
    assert "reconnect" in (refreshed.connection_error or "")


async def test_login_rejection_flags_reconnect(session):
    """A server rejecting the password is a reconnect prompt, not a transient error."""
    mailbox = await _connected_mailbox(session)

    class LoginError(Exception):
        pass

    class RejectingClient(FakeImapClient):
        def login(self, username, password):
            raise LoginError("authentication failed")

    def factory(*, host, port, security, timeout):
        return RejectingClient(messages={})

    summary = await sync_mailbox(session, mailbox, client_factory=factory)
    assert summary["ok"] is False
    assert summary["needs_reconnect"] is True
    refreshed = await session.get(Mailbox, mailbox.id)
    assert refreshed.needs_reconnect is True


async def test_successful_sync_clears_reconnect_flag(session):
    """Once a good sync succeeds, the reconnect flag is cleared."""
    mailbox = await _connected_mailbox(session)
    mailbox.needs_reconnect = True
    mailbox.connection_error = "old error"
    await session.flush()

    await sync_mailbox(
        session, mailbox, client_factory=_factory_for(FakeImapClient(messages={5: _benign_raw()}))
    )
    refreshed = await session.get(Mailbox, mailbox.id)
    assert refreshed.needs_reconnect is False
    assert refreshed.connection_error is None


async def test_poll_cycle_covers_all_connected_imap_mailboxes(session):
    """The background cycle discovers connected IMAP mailboxes and polls them.
    (Uses the default real client factory, so with no fake it simply reports the
    mailbox as an errored poll — the point here is that it is *discovered*.)"""
    await _connected_mailbox(session)
    await session.commit()
    totals = await run_imap_poll_cycle(
        client_factory=_factory_for(FakeImapClient(messages={9: _phishing_raw("9")}))
    )
    assert totals["mailboxes"] == 1
    assert totals["alerted"] == 1
    assert totals["quarantined"] == 0  # MEDIUM — alerted, not moved


async def test_backfill_analyses_recent_history(session):
    """E11 onboarding backfill actually pulls history and runs it through the
    pipeline (seeding A9/A12 baselines), and never quarantines old mail."""
    from envelock.workers.imap_fetch import backfill_mailbox

    mailbox = await _connected_mailbox(
        session, cls=MailboxClass.PROTECTED, source=SourceMechanism.IMAP_POLL
    )
    # Two historical messages waiting in the mailbox.
    client = FakeImapClient(messages={5: _benign_raw(), 9: _phishing_raw("9")})

    result = await backfill_mailbox(
        session, mailbox, days=30, client_factory=_factory_for(client)
    )
    assert result["ok"] is True
    assert result["analysed"] == 2

    # Messages were persisted (baselines seeded) and the mailbox is marked.
    msgs = (
        await session.execute(select(Message).where(Message.mailbox_id == mailbox.id))
    ).scalars().all()
    assert len(msgs) == 2
    await session.refresh(mailbox)
    assert mailbox.backfilled_at is not None

    # Backfill never quarantines historical mail, even the phishing one.
    assert client.moved == []
    assert 9 in client.messages


def _bank_change_raw(uid_hint: str = "500") -> bytes:
    """A known supplier announcing new payment details — A1, always Critical.

    "Any change to a previously-seen vendor's details is Critical, always"
    (models.BankRecord). This is the case the whole product exists for, so it is
    also the one case that should move a message out of the inbox on its own.
    """
    return (
        b'From: "Gemini Accounts" <billing@gemini.com>\r\n'
        b"To: pay@acme.com\r\n"
        b"Subject: Updated remittance details for invoice 8891\r\n"
        b"Message-ID: <" + uid_hint.encode() + b"@gemini.com>\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Our bank has changed. Please remit to IBAN GB33BUKB20201555555555\r\n"
        b"from now on. Same-day payment please.\r\n"
    )


async def _known_supplier(session, tenant_id) -> None:  # noqa: ANN001
    """Give the tenant a history with gemini.com, including its real account.

    Without this the message is merely a first contact about payment (Medium).
    The history is what turns it into "the supplier we have paid 40 times just
    changed its bank details" — which is Critical.
    """
    from datetime import UTC, datetime, timedelta

    from envelock.models import BankRecord, Counterparty

    now = datetime.now(UTC)
    cp = Counterparty(
        tenant_id=tenant_id,
        registrable_domain="gemini.com",
        display_name="Gemini",
        first_seen_at=now - timedelta(days=400),
        last_seen_at=now - timedelta(days=1),
        message_count=40,
        verified_phone="+18030000000",
    )
    session.add(cp)
    await session.flush()
    session.add(
        BankRecord(
            tenant_id=tenant_id,
            counterparty_id=cp.id,
            scheme="iban",
            identifier="GB94BARC10201530093459",  # the account we know
            first_seen_at=now - timedelta(days=300),
            verified_at=now - timedelta(days=300),
        )
    )
    await session.flush()


async def test_a_critical_bank_change_is_quarantined(session):
    """The other half of the tier rule, and the reason quarantine exists.

    Medium must stay put; Critical must not. Testing only the first would let
    someone "fix" over-quarantining by disabling it entirely and still see green.
    """
    mailbox = await _connected_mailbox(session)
    await _known_supplier(session, mailbox.tenant_id)
    client = FakeImapClient(messages={500: _bank_change_raw("500")})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory_for(client))

    assert summary["ok"] is True
    assert summary["alerted"] == 1
    assert summary["quarantined"] == 1, "a Critical bank change must leave the inbox"
    assert client.moved == [(500, imap_sync.QUARANTINE_FOLDER)]
    assert 500 not in client.messages

    alert = (
        (await session.execute(select(Alert).where(Alert.tenant_id == mailbox.tenant_id)))
        .scalars()
        .one()
    )
    assert alert.tier == "critical"


async def _mailboxes_on_one_server(session, count: int) -> list[Mailbox]:  # noqa: ANN001
    """`count` mailboxes in separate workspaces, all on the same IMAP server."""
    boxes = []
    for n in range(count):
        tenant_id = uuid4()
        domain = f"co{n}-{uuid4().hex[:6]}.example"
        session.add(Tenant(id=tenant_id, name=domain, plan="complete", payment_method_ok=True))
        await session.flush()
        session.add(Domain(tenant_id=tenant_id, name=domain, registrable_domain=domain))
        mailbox = Mailbox(
            tenant_id=tenant_id,
            address=f"pay@{domain}",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[SourceMechanism.IMAP_IDLE.value],
        )
        session.add(mailbox)
        await session.flush()
        sealed = seal(b"app-password", aad=str(mailbox.id).encode())
        session.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=tenant_id,
                kind="imap_password",
                imap_host="imap.shared-provider.example",
                imap_port=993,
                imap_security="ssl",
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
        boxes.append(mailbox)
    await session.flush()
    return boxes


class _SlowServer:
    """Shared by every connection in a cycle: counts how many are open at once.

    Each login sleeps on the calling thread, the way a real provider's TLS
    handshake and LOGIN round trip do, so the cycle's wall time shows whether
    mailboxes were polled one after another or side by side."""

    def __init__(self, *, delay: float) -> None:
        import threading

        self.delay = delay
        self.lock = threading.Lock()
        self.open = 0
        self.peak = 0

    def factory(self):  # noqa: ANN201
        server = self

        class _Client(FakeImapClient):
            def login(self, username: str, password: str) -> None:
                import time

                with server.lock:
                    server.open += 1
                    server.peak = max(server.peak, server.open)
                time.sleep(server.delay)
                with server.lock:
                    server.open -= 1
                self.logged_in = True

        def make(*, host, port, security, timeout):  # noqa: ANN001, ANN202
            return _Client(messages={})

        return make


@pytest.fixture
def poll_settings(monkeypatch):  # noqa: ANN001, ANN201
    from envelock.config import get_settings

    def apply(**values: str) -> None:
        for key, value in values.items():
            monkeypatch.setenv(f"ENVELOCK_{key.upper()}", value)
        get_settings.cache_clear()

    yield apply
    get_settings.cache_clear()


async def test_a_cycle_polls_mailboxes_side_by_side(session, poll_settings) -> None:  # noqa: ANN001
    """One at a time, a cycle cost the SUM of every server's round trip, so the
    60-second cadence quietly became minutes once there were a few dozen
    mailboxes. Eight mailboxes at 0.3 s each: ~2.4 s in series, ~0.6 s at four
    wide."""
    import time

    poll_settings(imap_poll_concurrency="4", imap_max_connections_per_egress_ip="15")
    await _mailboxes_on_one_server(session, 8)
    await session.commit()

    server = _SlowServer(delay=0.3)
    started = time.monotonic()
    totals = await run_imap_poll_cycle(client_factory=server.factory())
    elapsed = time.monotonic() - started

    assert totals["mailboxes"] == 8
    assert totals["errors"] == 0
    assert server.peak > 1, "mailboxes were still polled one at a time"
    assert server.peak <= 4, "the overall concurrency limit was exceeded"
    assert elapsed < 1.8, f"cycle took {elapsed:.2f}s — not running in parallel"


async def test_one_mail_server_never_gets_more_than_its_cap(session, poll_settings) -> None:  # noqa: ANN001
    """Providers cap simultaneous connections per source IP and answer a burst
    by refusing all of them — so every mailbox on that provider fails at once.
    Every mailbox here is on the same server; the per-server cap must hold even
    though the overall limit is higher."""
    poll_settings(imap_poll_concurrency="8", imap_max_connections_per_egress_ip="2")
    await _mailboxes_on_one_server(session, 6)
    await session.commit()

    server = _SlowServer(delay=0.15)
    totals = await run_imap_poll_cycle(client_factory=server.factory())

    assert totals["mailboxes"] == 6
    assert server.peak <= 2


async def test_one_broken_mailbox_does_not_stop_the_others(  # noqa: ANN001
    session, poll_settings, monkeypatch
) -> None:
    """Run side by side, a crash in one poll must still be isolated: the rest of
    the cycle completes and the crash is counted, not raised."""
    from envelock.workers import imap_fetch

    poll_settings(imap_poll_concurrency="4")
    boxes = await _mailboxes_on_one_server(session, 4)
    await session.commit()
    doomed = boxes[1].id
    real_sync = imap_fetch.sync_mailbox

    async def sometimes_crash(session, mailbox, **kwargs):  # noqa: ANN001, ANN202
        if mailbox.id == doomed:
            raise RuntimeError("boom")
        return await real_sync(session, mailbox, **kwargs)

    monkeypatch.setattr(imap_fetch, "sync_mailbox", sometimes_crash)
    totals = await run_imap_poll_cycle(client_factory=_SlowServer(delay=0.01).factory())

    assert totals["mailboxes"] == 3
    assert totals["errors"] == 1
