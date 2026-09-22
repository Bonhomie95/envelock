"""Split key custody — the API seals, only the worker can decrypt.

That is the intended production shape (deploy/README.md), and three things broke
the moment the API stopped holding the decryption key:

* "Sync now" ran in the API, hit the missing key as an ordinary decryption
  failure — the same error a dead credential raises — and marked a healthy
  mailbox "reconnect required";
* "Scan my history", the first thing every new customer does, failed outright;
* the OAuth refresh/fetch jobs shared the scheduler's leader lock, so they ran
  in whichever process booted first — and nowhere at all when that was the API.

These tests stand the API up as seal-only and check each one now hands its work
to the process that can do it.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from conftest import platform_sessionmaker as get_sessionmaker
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.core.enums import SourceMechanism
from envelock.main import app
from envelock.models import Mailbox

DOMAIN = "splitco.example"


def _seal_only(monkeypatch) -> None:  # noqa: ANN001
    """This process holds the sealing key and nothing else."""
    import envelock.security.keys as keys

    def summary() -> dict:
        return {"ok": True, "can_decrypt": False, "separated": True, "key_id": "x25519:test"}

    monkeypatch.setattr(keys, "custody_summary", summary)


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _imap_mailbox(client: TestClient) -> tuple[dict, str]:
    email = f"it@{DOMAIN}"
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register", json={"email": email, "password": pw, "tenant_name": DOMAIN}
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": DOMAIN, "domain": DOMAIN}, headers=h)
    created = client.post(
        "/api/v1/mailboxes",
        json={"address": f"pay@{DOMAIN}", "mailbox_class": "protected"},
        headers=h,
    )
    assert created.status_code == 201, created.text
    mailbox_id = created.json()["id"]

    async def connect():  # noqa: ANN202
        async with get_sessionmaker()() as s:
            await s.execute(
                update(Mailbox)
                .where(Mailbox.address == f"pay@{DOMAIN}")
                .values(sources=[SourceMechanism.IMAP_IDLE.value])
            )
            await s.commit()

    asyncio.run(connect())
    return h, mailbox_id


def _mailbox_row(address: str) -> Mailbox:
    async def fetch():  # noqa: ANN202
        async with get_sessionmaker()() as s:
            return (await s.execute(select(Mailbox).where(Mailbox.address == address))).scalar_one()

    return asyncio.run(fetch())


# ── Sync now ─────────────────────────────────────────────────────────────────
def test_sync_now_is_queued_not_reported_as_a_broken_password(
    client: TestClient, monkeypatch
) -> None:
    h, mailbox_id = _imap_mailbox(client)
    _seal_only(monkeypatch)

    r = client.post(f"/api/v1/mailboxes/{mailbox_id}/sync", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["queued"] is True

    row = _mailbox_row(f"pay@{DOMAIN}")
    assert row.needs_reconnect is False, "a healthy mailbox must not be told to reconnect"
    assert row.connection_error is None
    assert row.sync_requested_at is not None


def test_the_mailbox_shows_a_sync_is_pending(client: TestClient, monkeypatch) -> None:
    h, mailbox_id = _imap_mailbox(client)
    _seal_only(monkeypatch)
    client.post(f"/api/v1/mailboxes/{mailbox_id}/sync", headers=h)
    boxes = client.get("/api/v1/mailboxes", headers=h).json()["mailboxes"]
    assert next(b for b in boxes if b["id"] == mailbox_id)["sync_pending"] is True


# ── Scan my history ──────────────────────────────────────────────────────────
def test_a_history_scan_is_queued_for_the_worker(client: TestClient, monkeypatch) -> None:
    h, mailbox_id = _imap_mailbox(client)
    _seal_only(monkeypatch)

    r = client.post(f"/api/v1/mailboxes/{mailbox_id}/backfill", headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["queued"] is True and body["job"] is None

    row = _mailbox_row(f"pay@{DOMAIN}")
    assert row.backfill_requested_at is not None
    assert row.backfill_requested_days == body["days"]
    assert row.backfill_state["status"] == "queued"


# ── The worker picks both up ─────────────────────────────────────────────────
from tests.test_imap_live import (  # noqa: E402
    FakeImapClient,
    _benign_raw,
    _connected_mailbox,
    _factory_for,
)


@pytest.mark.asyncio
async def test_the_worker_runs_a_queued_scan_exactly_once(session) -> None:
    from envelock.workers import imap_fetch

    mailbox = await _connected_mailbox(session)
    mailbox.backfill_requested_at = datetime.now(UTC)
    mailbox.backfill_requested_days = 30
    mailbox.backfill_state = {"status": "queued"}
    await session.commit()

    imap = FakeImapClient(messages={301: _benign_raw()})
    tasks = await imap_fetch.start_requested_backfills(client_factory=_factory_for(imap))
    assert len(tasks) == 1
    # A second look before the first finishes must not start it again.
    assert await imap_fetch.start_requested_backfills(client_factory=_factory_for(imap)) == []
    await asyncio.gather(*tasks)

    await session.refresh(mailbox)
    assert mailbox.backfill_requested_at is None
    assert mailbox.backfill_state["status"] == "done", mailbox.backfill_state
    assert mailbox.backfill_state["analysed"] == 1
    assert mailbox.backfilled_at is not None


@pytest.mark.asyncio
async def test_a_poll_clears_a_queued_sync(session) -> None:
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _connected_mailbox(session)
    mailbox.sync_requested_at = datetime.now(UTC)
    await session.commit()
    summary = await sync_mailbox(
        session, mailbox, client_factory=_factory_for(FakeImapClient(messages={}))
    )
    assert summary["ok"]
    await session.refresh(mailbox)
    assert mailbox.sync_requested_at is None


# ── OAuth jobs ───────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_the_shared_scheduler_no_longer_runs_the_oauth_jobs() -> None:
    """They need the decryption key, so they must not depend on which process
    happened to win the scheduler's lock."""
    from envelock.workers import scheduler

    stop = asyncio.Event()
    tasks = scheduler.start(stop)
    try:
        names = {
            t.get_coro().cr_frame.f_locals.get("name")
            for t in tasks
            if t.get_coro().cr_frame is not None
        }
    finally:
        stop.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert "oauth_refresh" not in names and "oauth_fetch" not in names
    assert {"escalation", "retention", "monthly_digest"} <= names


@pytest.mark.asyncio
async def test_the_oauth_jobs_have_a_starter_of_their_own() -> None:
    from envelock.workers import scheduler
    from envelock.workers.leader import LOCK_OAUTH, LOCK_SCHEDULER

    assert LOCK_OAUTH != LOCK_SCHEDULER
    stop = asyncio.Event()
    tasks = scheduler.start_oauth_jobs(stop)
    try:
        names = {t.get_coro().cr_frame.f_locals.get("name") for t in tasks}
    finally:
        stop.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    # Everything that opens a stored token: mailbox OAuth, push subscriptions,
    # and the accounting connections (sealed the same way).
    assert names == {
        "oauth_refresh", "oauth_fetch", "oauth_push_drain", "push_subscriptions",
        "accounting_requested", "accounting_sync", "accounting_bills",
    }
