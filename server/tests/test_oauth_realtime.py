"""Gmail / Microsoft 365: how fast a pushed message becomes an alert.

Every sync — each push drain, each 60-second fallback poll — used to download
the fifty newest inbox messages in full before analysing any of them, one HTTP
client per request, one mailbox at a time. A push flag set while a sync ran was
then wiped by it. These tests pin the cheaper, parallel, race-free version.
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from conftest import platform_sessionmaker

from envelock.core.enums import SourceMechanism
from envelock.security.crypto import seal


def _mail(n: int) -> bytes:
    return (
        f"From: Supplier <news@supplier-{n}.example>\r\n"
        f"To: ap@acme.example\r\n"
        f"Subject: Weekly update {n}\r\n"
        f"Date: Mon, 1 Sep 2025 09:00:00 +0000\r\n"
        f"Message-ID: <weekly-{n}@supplier-{n}.example>\r\n"
        f"\r\nNothing to see here, update {n}.\r\n"
    ).encode()


class _Graph:
    """Graph as far as a sync reads it: an inbox listing and `$value` bodies."""

    def __init__(self, inbox: dict[str, bytes]) -> None:
        self.inbox = dict(inbox)
        self.downloads: list[str] = []
        self.on_list = None

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        if "/mailFolders/inbox/messages" in url:
            if self.on_list is not None:
                await self.on_list()
            return {"value": [{"id": mid} for mid in self.inbox]}
        return {"value": []}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        mid = url.split("/messages/")[1].split("/$value")[0]
        self.downloads.append(mid)
        return self.inbox[mid]


async def _oauth_mailbox(
    *, source: SourceMechanism = SourceMechanism.GRAPH_API,
    connected_address: str | None = None,
    sync_requested_at: datetime | None = None,
) -> tuple[UUID, UUID]:
    from envelock.models import Mailbox, MailboxCredential, Tenant

    tenant_id, mailbox_id = uuid4(), uuid4()
    async with platform_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name="Push Co", plan="complete",
                           payment_method_ok=True,
                           trial_ends_at=datetime.now(UTC) + timedelta(days=30)))
        await session.flush()
        session.add(Mailbox(
            id=mailbox_id, tenant_id=tenant_id, address="ap@acme.example",
            mailbox_class="monitored", sources=[source.value], is_active=True,
            connected_address=connected_address, sync_requested_at=sync_requested_at,
        ))
        await session.flush()
        sealed = seal(
            json.dumps({"access_token": "fake", "refresh_token": "r"}).encode(),
            aad=str(mailbox_id).encode(),
        )
        session.add(MailboxCredential(
            mailbox_id=mailbox_id, tenant_id=tenant_id, kind="oauth_token",
            ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek,
            key_id=sealed.key_id, token_expires_at=datetime.now(UTC) + timedelta(hours=1),
        ))
        await session.commit()
    return tenant_id, mailbox_id


async def _sync(mailbox_id: UUID, transport) -> dict:  # noqa: ANN001
    from envelock.models import Mailbox
    from envelock.workers import oauth_fetch

    async with platform_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        return await oauth_fetch.sync_oauth_mailbox(session, mailbox, transport=transport)


async def _mailbox(mailbox_id: UUID):  # noqa: ANN202
    from envelock.models import Mailbox

    async with platform_sessionmaker()() as session:
        return await session.get(Mailbox, mailbox_id)


async def test_a_sync_downloads_only_mail_it_has_not_analysed(client) -> None:  # noqa: ANN001, ARG001
    _, mailbox_id = await _oauth_mailbox()
    graph = _Graph({f"m{n}": _mail(n) for n in range(5)})

    first = await _sync(mailbox_id, graph)
    assert first["ok"] and first["fetched"] == 5
    assert len(graph.downloads) == 5

    graph.downloads.clear()
    assert (await _sync(mailbox_id, graph))["fetched"] == 0
    assert graph.downloads == [], "every sync re-downloaded the whole listing"

    graph.inbox = {"m-new": _mail(99), **graph.inbox}
    assert (await _sync(mailbox_id, graph))["fetched"] == 1
    assert graph.downloads == ["m-new"]


async def test_one_sync_uses_one_http_client(client, monkeypatch) -> None:  # noqa: ANN001, ARG001
    """Each provider call built its own client — a fresh TLS handshake and CA
    bundle load, dozens of times per sync."""
    import httpx

    made: list[object] = []

    class _Response:
        def __init__(self, url: str) -> None:
            self._url = url
            self.content = _mail(1) if "/$value" in url else b""

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            if "/mailFolders/inbox/messages" in self._url:
                return {"value": [{"id": "m1"}, {"id": "m2"}]}
            return {"value": []}

    class _Client:
        def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003, ARG002
            made.append(self)

        async def __aenter__(self):  # noqa: ANN204
            return self

        async def __aexit__(self, *exc) -> None:  # noqa: ANN002
            return None

        async def get(self, url: str, **_) -> _Response:  # noqa: ANN003
            return _Response(url)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    _, mailbox_id = await _oauth_mailbox()

    from envelock.models import Mailbox
    from envelock.workers import oauth_fetch

    async with platform_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        summary = await oauth_fetch.sync_oauth_mailbox(session, mailbox)
    assert summary["ok"] and summary["fetched"] == 2, summary
    assert len(made) == 1, f"{len(made)} HTTP clients for one sync"


async def test_mailboxes_sync_side_by_side_within_the_budget(
    client, monkeypatch  # noqa: ANN001, ARG001
) -> None:
    """One at a time, a push for one mailbox waited behind every other flagged
    mailbox's sync, and the fallback cycle took the sum of them all."""
    from envelock.config import get_settings
    from envelock.workers import oauth_fetch

    monkeypatch.setenv("ENVELOCK_OAUTH_SYNC_CONCURRENCY", "2")
    get_settings.cache_clear()
    ids = [(await _oauth_mailbox())[1] for _ in range(4)]

    running = peak = 0

    async def _sync_slowly(session, mailbox, *, transport=None, write_transport=None):  # noqa: ANN001, ARG001
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.1)
        running -= 1
        return {"ok": True, "fetched": 1}

    monkeypatch.setattr(oauth_fetch, "sync_oauth_mailbox", _sync_slowly)
    totals = await oauth_fetch._sync_ids(ids)

    assert totals["mailboxes"] == 4 and totals["fetched"] == 4
    assert peak == 2, f"peak concurrency {peak}, budget 2"


async def test_a_push_during_a_sync_is_not_wiped_by_it(client) -> None:  # noqa: ANN001, ARG001
    """The flag was stamped only when empty and cleared unconditionally when a
    sync ended — so a notification landing mid-sync was erased, and the message
    it announced waited for the fallback poll."""
    from envelock.api import webhooks
    from envelock.db_rls import system_scope

    stamped = datetime.now(UTC) - timedelta(seconds=5)
    tenant_id, mailbox_id = await _oauth_mailbox(sync_requested_at=stamped)
    graph = _Graph({"m1": _mail(1)})

    async def push_arrives() -> None:
        graph.on_list = None
        with system_scope("test: the API receives a Graph notification"):
            assert await webhooks._fetch_mailbox(str(mailbox_id), tenant_id=tenant_id)

    graph.on_list = push_arrives
    assert (await _sync(mailbox_id, graph))["ok"]

    after = (await _mailbox(mailbox_id)).sync_requested_at
    assert after is not None, "the mid-sync notification was erased"
    assert after > stamped

    # With nothing new arriving, the next drain answers it for good.
    assert (await _sync(mailbox_id, graph))["ok"]
    assert (await _mailbox(mailbox_id)).sync_requested_at is None


async def test_gmail_push_finds_a_mailbox_by_the_account_it_reads(client) -> None:  # noqa: ANN001
    """Gmail names the account the token reads. When that differs from the label
    the mailbox was added under, push matched nothing — for good."""
    from envelock.security.webhook_auth import push_token

    _, mailbox_id = await _oauth_mailbox(
        source=SourceMechanism.GMAIL_API, connected_address="John.Doe@acme.example"
    )
    data = base64.b64encode(
        json.dumps({"emailAddress": "john.doe@acme.example", "historyId": 9}).encode()
    ).decode()
    r = client.post(f"/api/v1/webhooks/gmail?token={push_token()}",
                    json={"message": {"data": data}})
    assert r.status_code == 202
    assert (await _mailbox(mailbox_id)).sync_requested_at is not None


async def test_a_graph_lifecycle_event_renews_push_and_syncs(client) -> None:  # noqa: ANN001
    from envelock.security.webhook_auth import client_state

    tenant_id, mailbox_id = await _oauth_mailbox()
    from envelock.models import Mailbox

    async with platform_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        mailbox.push_subscription_id = "sub-1"
        mailbox.push_expires_at = datetime.now(UTC) + timedelta(days=2)
        await session.commit()

    note = {
        "subscriptionId": "sub-1",
        "lifecycleEvent": "subscriptionRemoved",
        "clientState": client_state(tenant_id=tenant_id, mailbox=str(mailbox_id)),
    }
    assert client.post("/api/v1/webhooks/graph", json={"value": [note]}).status_code == 202
    mailbox = await _mailbox(mailbox_id)
    assert mailbox.push_expires_at is None, "the removed subscription was not marked for renewal"
    assert mailbox.sync_requested_at is not None


class _Subscriptions:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []

    async def request(self, method: str, url: str, *, headers: dict, json=None):  # noqa: A002, ANN001, ANN201, ARG002
        self.calls.append((method, url, json))
        return {"id": "sub-1", "expirationDateTime": json["expirationDateTime"]}


async def test_graph_subscriptions_are_checked_well_before_they_expire(
    client, monkeypatch  # noqa: ANN001, ARG001
) -> None:
    """Renewed only once under a day was left, a subscription Microsoft dropped
    sat unnoticed for up to two days. The renewal is the check."""
    from envelock.config import get_settings
    from envelock.models import Mailbox
    from envelock.workers import push_subscriptions

    hook = "https://api.envelock.test/api/v1/webhooks/graph"
    monkeypatch.setenv("ENVELOCK_MS_WEBHOOK_URL", hook)
    get_settings.cache_clear()

    async def _token(session, mailbox_id):  # noqa: ANN001, ANN202, ARG001
        return ("access", "microsoft")

    monkeypatch.setattr(push_subscriptions, "current_access_token", _token)
    _, mailbox_id = await _oauth_mailbox()
    graph = _Subscriptions()
    async with platform_sessionmaker()() as session:
        mailbox = await session.get(Mailbox, mailbox_id)
        assert await push_subscriptions.ensure_push(session, mailbox, transport=graph)
        created = graph.calls[-1]
        assert created[0] == "POST"
        assert created[2]["lifecycleNotificationUrl"] == hook

        later = datetime.now(UTC) + timedelta(hours=7)
        assert await push_subscriptions.ensure_push(
            session, mailbox, transport=graph, now=later
        ), "a 7-hour-old subscription was not checked"
        assert graph.calls[-1][0] == "PATCH"


async def test_a_push_never_queues_behind_the_fallback_poll(client, monkeypatch) -> None:  # noqa: ANN001, ARG001
    """The drain and the fallback poll each have a budget. Sharing one, a push
    flagged mid-cycle waited behind every mailbox the poll had queued."""
    import time

    from envelock.config import get_settings
    from envelock.workers import oauth_fetch

    monkeypatch.setenv("ENVELOCK_OAUTH_SYNC_CONCURRENCY", "1")
    get_settings.cache_clear()
    ids = [(await _oauth_mailbox())[1] for _ in range(4)]
    ids.append((await _oauth_mailbox(sync_requested_at=datetime.now(UTC)))[1])
    started: dict = {}
    began = time.monotonic()

    async def _sync_slowly(session, mailbox, *, transport=None, write_transport=None):  # noqa: ANN001, ARG001
        started.setdefault(mailbox.id, time.monotonic() - began)
        await asyncio.sleep(0.2)
        return {"ok": True, "fetched": 0}

    monkeypatch.setattr(oauth_fetch, "sync_oauth_mailbox", _sync_slowly)
    poll = asyncio.create_task(oauth_fetch._sync_ids(ids))  # the fallback cycle
    await asyncio.sleep(0.05)
    await oauth_fetch.drain_requested()  # the last one was flagged by a push
    await poll

    assert started[ids[-1]] < 0.4, f"the pushed mailbox waited {started[ids[-1]]:.2f}s"
