"""Alert delivery while syncs and the scheduler run side by side.

Committing the alert before notifying (so whoever opens the push finds it) made
the delivery rows visible as `pending` while the sync was still sending them —
and the scheduler's escalation tick sends every pending row it can see. Both
sent: two emails, two SMS. These tests pin the claim, the commit right after
delivery, the order notify → enforce, and pruning only on a push service's 410.
"""

from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from conftest import platform_sessionmaker
from sqlalchemy import func, select
from test_imap_idle import FRAUD, IdleImapServer, _seed

from envelock.channels.mail import imap_sync
from envelock.core.enums import AlertTier, MailboxClass
from envelock.models import NotificationDelivery, PushSubscription, Tenant, User
from envelock.notify.dispatch import deliver_pending
from envelock.notify.ladder import Recipient, Rung
from envelock.notify.senders import Dispatcher, SendResult
from envelock.platform import alerts as alert_svc
from envelock.risk.engine import RiskAssessment


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


def _assessment(tier: AlertTier) -> RiskAssessment:
    return RiskAssessment(
        tier=tier, score=60, title="First contact discussing payment", body="",
        services=("A1",), requires_callback=False, callback_phone=None, rationale=(),
    )


async def _alert_with_one_pending_delivery():  # noqa: ANN202
    async with platform_sessionmaker()() as session:
        tenant = Tenant(id=uuid4(), name="Claim Co")
        session.add(tenant)
        await session.flush()
        admin = User(id=uuid4(), tenant_id=tenant.id, email="it@claimco.example",
                     role="owner", is_admin=True)
        session.add(admin)
        await session.flush()
        alert = await alert_svc.raise_alert(
            session, tenant_id=tenant.id, mailbox_id=None,
            assessment=_assessment(AlertTier.MEDIUM), findings=[],
            recipients=[Recipient(
                user_id=str(admin.id), is_admin=True, has_push_subscription=False,
                out_of_band_email=None, phone=None, has_sensor=False,
            )],
        )
        # Committed and pending — exactly what the sync now leaves for a moment.
        await session.commit()
        return tenant.id, alert.id


class _InApp:
    rung = Rung.L0_IN_APP
    configured = True

    def __init__(self, during=None) -> None:  # noqa: ANN001
        self.sent = 0
        self._during = during

    async def send(self, note, *, to):  # noqa: ANN001, ANN202, ARG002
        self.sent += 1
        if self._during is not None:
            during, self._during = self._during, None
            await during()
        return SendResult(Rung.L0_IN_APP, True, "queued in app")


async def test_the_scheduler_never_sends_a_row_the_sync_is_sending(db: None) -> None:  # noqa: ARG001
    """The race itself: the scheduler's sweep runs while the sync is mid-send.
    Before the claim both read the row as pending and both sent it."""
    _, alert_id = await _alert_with_one_pending_delivery()
    scheduler = Dispatcher()
    scheduler.in_app = _InApp()  # type: ignore[assignment]

    async def scheduler_tick() -> None:
        async with platform_sessionmaker()() as other:
            await deliver_pending(other, dispatcher=scheduler)
            await other.commit()

    sync = Dispatcher()
    sync.in_app = _InApp(during=scheduler_tick)  # type: ignore[assignment]
    async with platform_sessionmaker()() as session:
        await deliver_pending(session, alert_id=alert_id, dispatcher=sync)
        await session.commit()

    assert sync.in_app.sent + scheduler.in_app.sent == 1, (  # type: ignore[attr-defined]
        "one delivery row was sent by both drains"
    )


async def test_a_network_error_never_deletes_a_live_subscription(
    db: None, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    """Pruning used to search the error text for '410'/'404'/'gone'. A network
    error carries the endpoint URL, and a random token containing '410' was
    enough to delete a working subscription."""
    import base64

    import pywebpush
    import requests
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    raw = key.private_numbers().private_value.to_bytes(32, "big")
    monkeypatch.setenv(
        "ENVELOCK_VAPID_PRIVATE_KEY", base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    )
    monkeypatch.setenv("ENVELOCK_VAPID_PUBLIC_KEY", "configured")
    from envelock.config import get_settings

    get_settings.cache_clear()

    endpoint = "https://fcm.googleapis.com/fcm/send/dGhp410cyBp:APA91bH404gone"
    failures = {
        endpoint: requests.exceptions.ConnectionError(
            f"Max retries exceeded with url: {endpoint.split('.com', 1)[1]}"
        ),
    }

    def fake_webpush(*, subscription_info, **_):  # noqa: ANN001, ANN003, ANN202
        exc = failures.get(subscription_info["endpoint"])
        if exc is not None:
            raise exc
        response = type("R", (), {"status_code": 410, "reason": "Gone", "text": ""})()
        raise pywebpush.WebPushException("Push failed: 410 Gone", response=response)

    monkeypatch.setattr(pywebpush, "webpush", fake_webpush)

    async with platform_sessionmaker()() as session:
        tenant = Tenant(id=uuid4(), name="Prune Co")
        session.add(tenant)
        await session.flush()
        user = User(id=uuid4(), tenant_id=tenant.id, email="u@pruneco.example", role="owner")
        session.add(user)
        await session.flush()
        for ep in (endpoint, "https://updates.push.services.mozilla.com/wpush/v2/dead"):
            session.add(PushSubscription(tenant_id=tenant.id, user_id=user.id,
                                         endpoint=ep, p256dh="p" * 20, auth="a" * 20))
        await session.commit()

        from envelock.notify.dispatch import _push_to_all
        from envelock.notify.senders import Notification

        note = Notification(alert_id=uuid4(), tenant_id=tenant.id, tier=AlertTier.HIGH,
                            title="t", body="")
        result = await _push_to_all(session, Dispatcher(), note, user.id)
        await session.commit()
        left = (await session.execute(select(PushSubscription.endpoint))).scalars().all()

    assert result.delivered is False
    # The network blip kept its subscription; the push service's 410 lost its.
    assert left == [endpoint]


async def _pending_for(tenant_id) -> int:  # noqa: ANN001
    async with platform_sessionmaker()() as session:
        return int(
            (
                await session.execute(
                    select(func.count()).select_from(NotificationDelivery).where(
                        NotificationDelivery.tenant_id == tenant_id,
                        NotificationDelivery.status == "pending",
                    )
                )
            ).scalar_one()
        )


async def _deliveries_for(tenant_id) -> int:  # noqa: ANN001
    async with platform_sessionmaker()() as session:
        return int(
            (
                await session.execute(
                    select(func.count()).select_from(NotificationDelivery).where(
                        NotificationDelivery.tenant_id == tenant_id
                    )
                )
            ).scalar_one()
        )


async def _admin_for(tenant_id) -> None:  # noqa: ANN001
    async with platform_sessionmaker()() as session:
        session.add(User(id=uuid4(), tenant_id=tenant_id, email="it@idleco.example",
                         role="owner", is_admin=True, status="active"))
        await session.commit()


async def test_deliveries_are_committed_before_the_rest_of_the_sync(
    db: None, server: IdleImapServer, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    """The sync goes on to the read-watch and the Sent scan — seconds of IMAP.
    Sent-but-uncommitted rows read as pending to everyone else all that time,
    which is the window the scheduler double-sent in."""
    from envelock.workers import imap_fetch

    tenant_id, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    await _admin_for(tenant_id)
    server.deliver(FRAUD)

    seen_during_scan: list[int] = []

    async def scan_sent(session, mailbox, **_):  # noqa: ANN001, ANN003, ANN202, ARG001
        seen_during_scan.append(await _pending_for(tenant_id))
        return {"outbound_ingested": 0, "signature_alert": False}

    monkeypatch.setattr(imap_fetch, "_scan_sent", scan_sent)
    summary = await imap_fetch._sync_one(mailbox_id)

    assert summary and summary["alerted"] == 1, summary
    assert await _deliveries_for(tenant_id) > 0, "the alert queued no delivery to check"
    assert seen_during_scan == [0], "deliveries were still pending while the sync went on"


async def test_the_alert_is_delivered_before_the_quarantine_move(
    db: None, server: IdleImapServer, monkeypatch: pytest.MonkeyPatch  # noqa: ARG001
) -> None:
    """A quarantine is a fresh login and a MOVE (a rewrite, an APPEND of the
    whole message). The notification must not wait behind either."""
    from envelock.workers import imap_fetch

    tenant_id, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    await _admin_for(tenant_id)
    server.deliver(FRAUD)

    order: list[str] = []
    real_deliver, real_move = imap_fetch.deliver_pending, imap_sync.quarantine_message

    async def deliver(session, **kw):  # noqa: ANN001, ANN003, ANN202
        order.append("notify")
        return await real_deliver(session, **kw)

    def move(**kw):  # noqa: ANN003, ANN202
        order.append("quarantine")
        return real_move(**kw)

    monkeypatch.setattr(imap_fetch, "deliver_pending", deliver)
    monkeypatch.setattr(imap_sync, "quarantine_message", move)
    summary = await imap_fetch._sync_one(mailbox_id)

    assert summary and summary["quarantined"] == 1, summary
    assert order == ["notify", "quarantine"]
    assert server.moved == [1001]


async def test_measure_arrival_to_notification_over_idle(
    db: None, server: IdleImapServer  # noqa: ARG001
) -> None:
    """The number the owner asked about: mail lands → the notification row is
    sent, through the real IDLE watcher. Printed for the record."""
    import time

    from envelock.workers import imap_fetch

    tenant_id, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    await _admin_for(tenant_id)
    try:
        await imap_fetch._reconcile_idle()
        for _ in range(250):
            if server.idling:
                break
            await asyncio.sleep(0.02)
        assert server.idling
        landed = time.monotonic()
        server.deliver(FRAUD)
        while not (await _deliveries_for(tenant_id) and await _pending_for(tenant_id) == 0):
            assert time.monotonic() - landed < 10, "nothing delivered 10 s after arrival"
            await asyncio.sleep(0.02)
        print(f"\nIDLE arrival -> notification sent: {time.monotonic() - landed:.2f}s")  # noqa: T201
    finally:
        imap_fetch._release_idle()
        await asyncio.sleep(0.5)
