"""IMAP: the poll's real cadence, IDLE's recovery, and the limits around both.

A cycle used to wait for its slowest mailbox and then sleep the full interval;
IDLE's backoff only reset after a session survived 25 minutes, and nothing
synced after a reconnect; IDLE wakes bypassed every budget; a pool timeout
escaped `_sync_one`; the Sent scan re-downloaded twenty messages every poll; and
an IMAP-over-OAuth token was never refreshed. One test per failure.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import platform_sessionmaker
from test_imap_idle import FRAUD, IdleImapServer, _alert_count, _seed

from envelock.channels.mail import imap_sync
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.workers import imap_fetch


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "true"
    os.environ["ENVELOCK_IMAP_ALLOW_PLAINTEXT"] = "true"
    from envelock.config import get_settings

    get_settings.cache_clear()
    monkeypatch.setattr(imap_sync, "IDLE_CHECK_SECONDS", 0.3)
    srv = IdleImapServer()
    srv.start()
    yield srv
    srv.stop()
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "false"
    os.environ["ENVELOCK_IMAP_ALLOW_PLAINTEXT"] = "false"
    get_settings.cache_clear()


async def _another_mailbox(port: int, *, mailbox_class: str) -> object:
    """`_seed` for a second, third... tenant: domains are unique platform-wide."""
    from envelock.models import Domain, Mailbox, MailboxCredential, Tenant
    from envelock.security.crypto import seal

    tenant_id, mailbox_id, domain = uuid4(), uuid4(), f"co-{uuid4().hex[:8]}.example"
    async with platform_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name=domain, plan="complete", payment_method_ok=True))
        await session.flush()
        session.add(Domain(id=uuid4(), tenant_id=tenant_id, name=domain,
                           registrable_domain=domain, verification_token="tok"))  # noqa: S106
        session.add(Mailbox(id=mailbox_id, tenant_id=tenant_id, address=f"pay@{domain}",
                            mailbox_class=mailbox_class, is_active=True,
                            sources=[SourceMechanism.IMAP_IDLE.value]))
        sealed = seal(b"p", aad=str(mailbox_id).encode())
        session.add(MailboxCredential(
            mailbox_id=mailbox_id, tenant_id=tenant_id, kind="imap_password",
            imap_host="127.0.0.1", imap_port=port, imap_security="none",
            imap_last_uid=1000, imap_uidvalidity=7, ciphertext=sealed.ciphertext,
            wrapped_dek=sealed.wrapped_dek, key_id=sealed.key_id,
        ))
        await session.commit()
    return mailbox_id


def _env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    from envelock.config import get_settings

    for k, v in values.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()


# ── The poll's cadence ───────────────────────────────────────────────────────
async def test_cycles_start_an_interval_apart_not_an_interval_after_each_other(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, ENVELOCK_IMAP_IDLE_ENABLED="false")
    starts: list[float] = []
    stop = asyncio.Event()

    async def cycle(*, client_factory=None, deadline=None):  # noqa: ANN001, ANN202, ARG001
        starts.append(time.monotonic())
        if len(starts) == 3:
            stop.set()
        await asyncio.sleep(0.4)  # a cycle that takes 40% of the interval
        return {"mailboxes": 0}

    monkeypatch.setattr(imap_fetch, "run_imap_poll_cycle", cycle)
    await asyncio.wait_for(imap_fetch.imap_poll_loop(stop, interval_seconds=1), timeout=10)

    gaps = [b - a for a, b in zip(starts, starts[1:], strict=False)]
    assert all(g < 1.25 for g in gaps), f"cycle starts {gaps} apart, interval 1 s"


async def test_one_slow_mailbox_no_longer_holds_up_the_cycle(
    db: None, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    slow = await _another_mailbox(1, mailbox_class=MailboxClass.MONITORED.value)
    fast = await _another_mailbox(2, mailbox_class=MailboxClass.MONITORED.value)
    synced: list = []

    async def sync_one(mailbox_id, *, client_factory=None, light=False):  # noqa: ANN001, ANN202, ARG001
        async with imap_fetch._SYNC_LOCKS.setdefault(mailbox_id, asyncio.Lock()):
            synced.append(mailbox_id)
            await asyncio.sleep(1.5 if mailbox_id == slow else 0)
        return {"ok": True, "fetched": 0}

    monkeypatch.setattr(imap_fetch, "_sync_one", sync_one)
    began = time.monotonic()
    first = await imap_fetch.run_imap_poll_cycle(deadline=0.3)
    assert time.monotonic() - began < 1.0, "the cycle waited for the slow server"
    assert first["mailboxes"] == 1 and first["running"] == 1

    # The next cycle skips the mailbox still syncing instead of queueing a second.
    second = await imap_fetch.run_imap_poll_cycle(deadline=0.3)
    assert second["busy"] == 1 and second["mailboxes"] == 1
    assert synced.count(slow) == 1 and synced.count(fast) == 2
    await asyncio.gather(*imap_fetch._STRAGGLERS)


class _SentImap:
    """A Sent folder that honours `UID n:*` searches and records each FETCH."""

    def __init__(self) -> None:
        self.messages = {1: self._raw(1), 2: self._raw(2)}
        self.fetched: list[list[int]] = []

    @staticmethod
    def _raw(n: int) -> bytes:
        return (f"From: ap@idleco.example\r\nTo: v@vendor.example\r\nSubject: re {n}\r\n"
                f"Message-ID: <sent-{n}@idleco.example>\r\n\r\nThanks {n}\r\n").encode()

    def login(self, username, password) -> None:  # noqa: ANN001
        pass

    def logout(self) -> None:
        pass

    def folder_exists(self, folder: str) -> bool:
        return folder == "Sent"

    def select_folder(self, folder: str, readonly: bool = False) -> dict:  # noqa: ARG002
        return {b"UIDVALIDITY": 5}

    def search(self, criteria):  # noqa: ANN001, ANN201
        if criteria[0] == "UID":
            low = int(criteria[1].split(":")[0])
            return [u for u in self.messages if u >= low] or [max(self.messages)]
        return sorted(self.messages)

    def fetch(self, messages, data):  # noqa: ANN001, ANN201, ARG002
        self.fetched.append(list(messages))
        return {uid: {b"BODY[]": self.messages[uid]} for uid in messages}


async def test_the_sent_scan_downloads_only_new_sent_mail(db: None) -> None:  # noqa: ARG001
    from envelock.models import Mailbox

    _, mailbox_id = await _seed(3, mailbox_class=MailboxClass.MONITORED.value)
    fake = _SentImap()

    def factory(*, host, port, security, timeout):  # noqa: ANN001, ANN202, ARG001
        return fake

    async def scan() -> None:
        async with platform_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mailbox_id)
            await imap_fetch._scan_sent(
                session, mailbox, owned=frozenset({"idleco.example"}), recipients=[],
                client_factory=factory, host="h", port=993, security="ssl",
                username="u", password="p", access_token=None, pin_sha256=None,  # noqa: S106
            )
            await session.commit()

    await scan()
    await scan()
    fake.messages[3] = fake._raw(3)
    await scan()
    assert fake.fetched == [[1, 2], [3]], fake.fetched


# ── IDLE recovery ────────────────────────────────────────────────────────────
async def _run_idle_watch(monkeypatch, *, session_seconds: float, logged) -> list[float]:  # noqa: ANN001
    """Drive `_idle_watch` through four dropped sessions; the delays it chose."""
    monkeypatch.setattr(imap_fetch, "IDLE_HEALTHY_SECONDS", 0.05)
    monkeypatch.setattr(imap_fetch, "IDLE_BACKOFF_SECONDS", 0.001)
    calls = 0

    async def connection(mailbox_id):  # noqa: ANN001, ANN202, ARG001
        return {"host": "h"}

    def watch(**_):  # noqa: ANN003, ANN202
        nonlocal calls
        calls += 1
        time.sleep(session_seconds)
        raise ConnectionError("the mail server closed the IDLE connection")

    monkeypatch.setattr(imap_fetch, "_idle_connection", connection)
    monkeypatch.setattr(imap_sync, "idle_watch", watch)
    capture = logged("envelock.imap")
    release = threading.Event()
    task = asyncio.create_task(imap_fetch._idle_watch(uuid4(), release))
    for _ in range(300):
        if calls >= 4:
            break
        await asyncio.sleep(0.01)
    release.set()
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    return [float(m) for m in re.findall(r"retrying in ([\d.e-]+)s", capture.text)]


async def test_a_session_that_held_idle_resets_the_backoff(monkeypatch, logged) -> None:  # noqa: ANN001
    delays = await _run_idle_watch(monkeypatch, session_seconds=0.1, logged=logged)
    assert len(delays) >= 3, delays
    assert set(delays) == {0.002}, f"backoff grew across healthy sessions: {delays}"


async def test_failures_in_a_row_still_back_off(monkeypatch, logged) -> None:  # noqa: ANN001
    delays = await _run_idle_watch(monkeypatch, session_seconds=0.0, logged=logged)
    assert delays[:3] == [0.002, 0.004, 0.008], delays


def test_idle_announces_mail_that_landed_while_nobody_listened(server: IdleImapServer) -> None:
    server.deliver(FRAUD)  # UID 1001, before the session exists
    for since_uid, expect in ((1000, True), (1001, False)):
        stop, woke = threading.Event(), threading.Event()
        thread = threading.Thread(
            target=imap_sync.idle_watch, daemon=True,
            kwargs={"host": "127.0.0.1", "port": server.port, "security": "none",
                    "username": "u", "password": "p",  # noqa: S106
                    "on_new_mail": woke.set, "max_seconds": 30, "stop": stop,
                    "since_uid": since_uid},
        )
        thread.start()
        assert woke.wait(1.0) is expect, f"since_uid={since_uid}"
        stop.set()
        thread.join(3)


async def test_mail_from_before_the_watcher_started_is_alerted_without_a_poll(
    db: None, server: IdleImapServer  # noqa: ARG001
) -> None:
    _, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    server.deliver(FRAUD)  # lands while nothing listens (cursor is 1000)
    try:
        await imap_fetch._reconcile_idle()
        landed = time.monotonic()
        while await _alert_count(mailbox_id) == 0:
            assert time.monotonic() - landed < 5, "only the next poll would have seen it"
            await asyncio.sleep(0.05)
    finally:
        imap_fetch._release_idle()
        await asyncio.sleep(0.5)


# ── Limits ───────────────────────────────────────────────────────────────────
async def test_a_database_failure_while_loading_is_reported_not_raised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Session:
        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, *exc) -> None:  # noqa: ANN002
            return None

        async def get(self, *_):  # noqa: ANN002, ANN202
            raise TimeoutError("QueuePool limit of size 20 overflow 10 reached")

    monkeypatch.setattr(imap_fetch, "get_sessionmaker", lambda: _Session)
    assert await imap_fetch._sync_one(uuid4()) == {"crashed": True}


async def test_idle_wakes_run_light_and_inside_their_own_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _env(monkeypatch, ENVELOCK_IMAP_IDLE_SYNC_CONCURRENCY="2")
    running = peak = 0
    lights: list[bool] = []

    async def sync_one(mailbox_id, *, client_factory=None, light=False):  # noqa: ANN001, ANN202, ARG001
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        lights.append(light)
        await asyncio.sleep(0.05)
        running -= 1
        return {"ok": True}

    monkeypatch.setattr(imap_fetch, "_sync_one", sync_one)
    await asyncio.gather(*(imap_fetch._wake_sync(uuid4()) for _ in range(5)))
    assert peak == 2, f"{peak} IDLE syncs at once, budget 2"
    assert all(lights), "an IDLE wake ran the full read-watch + Sent scan"


async def test_a_light_sync_skips_the_read_watch_and_the_sent_scan(
    db: None, server: IdleImapServer, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    _, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    ran: list[str] = []

    async def reads(*_, **__):  # noqa: ANN002, ANN003, ANN202
        ran.append("reads")
        return {"observed": 0, "alerted": 0}

    async def sent(*_, **__):  # noqa: ANN002, ANN003, ANN202
        ran.append("sent")
        return {"outbound_ingested": 0, "signature_alert": False}

    monkeypatch.setattr(imap_fetch, "_watch_reads", reads)
    monkeypatch.setattr(imap_fetch, "_scan_sent", sent)
    assert (await imap_fetch._sync_one(mailbox_id, light=True))["ok"]
    assert ran == []
    assert (await imap_fetch._sync_one(mailbox_id))["ok"]
    assert ran == ["reads", "sent"]


async def test_the_idle_cap_is_its_own_setting_and_says_who_it_left_out(
    db: None, monkeypatch: pytest.MonkeyPatch, logged  # noqa: ANN001, ARG001
) -> None:
    _env(monkeypatch, ENVELOCK_IMAP_IDLE_MAX_PER_HOST="2",
         ENVELOCK_IMAP_MAX_CONNECTIONS_PER_EGRESS_IP="15")
    for port in (11, 12, 13):  # three Protected mailboxes, one mail server
        await _another_mailbox(port, mailbox_class=MailboxClass.PROTECTED.value)

    async def hold(mailbox_id, release):  # noqa: ANN001, ANN202, ARG001
        await asyncio.Event().wait()

    monkeypatch.setattr(imap_fetch, "_idle_watch", hold)
    capture = logged("envelock.imap")
    try:
        await imap_fetch._reconcile_idle()
        assert len(imap_fetch._IDLE) == 2
        assert imap_fetch.worker_health()["idle_capped"] == 1
        assert "left on the poll" in capture.text
    finally:
        imap_fetch._release_idle()
        imap_fetch._IDLE_CAPPED.clear()


# ── IMAP over OAuth ──────────────────────────────────────────────────────────
async def test_an_imap_oauth_token_is_refreshed_before_it_is_used(
    db: None, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    """Such a mailbox carries only IMAP sources, so its provider was unknown and
    its token never refreshed: logins failed an hour after connecting."""
    from envelock.channels.mail import oauth, oauth_refresh
    from envelock.models import Mailbox, MailboxCredential, Tenant
    from envelock.security.crypto import seal

    _env(monkeypatch, ENVELOCK_MS_CLIENT_ID="cid",
         ENVELOCK_MS_CLIENT_SECRET="secret",  # noqa: S106 — a fake app registration
         ENVELOCK_MS_REDIRECT_URI="https://app.example/callback")

    class _TokenEndpoint:
        async def post_form(self, url, data):  # noqa: ANN001, ANN202, ARG002
            return {"access_token": "fresh-access", "expires_in": 3600}

    tenant_id, mailbox_id = uuid4(), uuid4()
    async with platform_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name="M365 Co", plan="complete",
                           payment_method_ok=True))
        await session.flush()
        session.add(Mailbox(id=mailbox_id, tenant_id=tenant_id, address="ap@m365co.example",
                            mailbox_class="monitored", is_active=True,
                            sources=[SourceMechanism.IMAP_POLL.value]))
        await session.flush()
        sealed = seal(json.dumps({"access_token": "stale", "refresh_token": "rt"}).encode(),
                      aad=str(mailbox_id).encode())
        session.add(MailboxCredential(
            mailbox_id=mailbox_id, tenant_id=tenant_id, kind="oauth_token",
            ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek,
            key_id=sealed.key_id, imap_host="outlook.office365.com", imap_port=993,
            imap_security="ssl", token_expires_at=datetime.now(UTC) - timedelta(minutes=5),
        ))
        await session.commit()

    logins: list[str] = []

    class _Imap:
        def oauth2_login(self, username, token) -> None:  # noqa: ANN001
            logins.append(token)

        def select_folder(self, folder, readonly=False) -> dict:  # noqa: ANN001, ARG002
            return {b"UIDVALIDITY": 1}

        def search(self, criteria):  # noqa: ANN001, ANN201, ARG002
            return []

        def logout(self) -> None:
            pass

    def factory(*, host, port, security, timeout):  # noqa: ANN001, ANN202, ARG001
        return _Imap()

    oauth.set_default_transport(_TokenEndpoint())
    try:
        async with platform_sessionmaker()() as session:
            assert await oauth_refresh.refresh_due_tokens(session) == 1
        async with platform_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, mailbox_id)
            summary = await imap_fetch.sync_mailbox(session, mailbox, client_factory=factory)
    finally:
        oauth.set_default_transport(None)
    assert summary["ok"], summary
    assert logins and set(logins) == {"fresh-access"}, logins
