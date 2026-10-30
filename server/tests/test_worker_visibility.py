"""A dead worker must not show green.

Mail is read and alerts escalated by the worker process; the status pages are
served by the API process, which under split custody runs neither. The public
page used to equate "the database answers" with "mail is being analysed", and
the operator console read the API's own memory, where the poller and scheduler
are disabled by design — so both reported green while the worker was dead,
crash-looping, or never started. Both now ask Postgres which leader locks are
held (workers/leader.py), which is the same answer from every process.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest


@contextlib.asynccontextmanager
async def _leading(*keys: int):  # noqa: ANN202
    """Hold leader locks the way a running worker does."""
    from envelock.workers.leader import hold

    async with contextlib.AsyncExitStack() as stack:
        for key in keys:
            assert await stack.enter_async_context(hold(key, name=f"test {key:x}")) is not None
        yield


def _component(body, ident: str):  # noqa: ANN001, ANN202
    return next(c for c in body.components if c.id == ident)


@pytest.mark.asyncio
async def test_public_status_says_analysis_is_down_when_no_worker_is_running() -> None:
    from envelock.api.health import public_status

    body = await public_status()
    assert _component(body, "analysis").state == "down"
    assert _component(body, "alerts").state == "down"
    assert body.state == "down"
    # Still honest about the part that is structurally fine.
    assert _component(body, "mail_flow").state == "operational"
    assert _component(body, "dashboard").state == "operational"


@pytest.mark.asyncio
async def test_public_status_is_operational_while_the_worker_leads() -> None:
    from envelock.api.health import public_status
    from envelock.workers.leader import LOCK_IMAP_POLLER, LOCK_OAUTH, LOCK_SCHEDULER

    async with _leading(LOCK_IMAP_POLLER, LOCK_OAUTH, LOCK_SCHEDULER):
        body = await public_status()
    assert _component(body, "analysis").state == "operational"
    assert _component(body, "alerts").state == "operational"


@pytest.mark.asyncio
async def test_alerts_are_degraded_when_only_escalation_is_missing() -> None:
    from envelock.api.health import public_status
    from envelock.workers.leader import LOCK_IMAP_POLLER

    async with _leading(LOCK_IMAP_POLLER):
        body = await public_status()
    assert _component(body, "analysis").state == "operational"
    assert _component(body, "alerts").state == "degraded"


@pytest.mark.asyncio
async def test_operator_console_reports_a_missing_worker_as_down() -> None:
    from envelock.api.admin import system_status
    from envelock.workers.leader import LOCK_IMAP_POLLER, LOCK_OAUTH, LOCK_SCHEDULER

    body = await system_status(actor=None)
    worker = next(c for c in body["checks"] if c["component"] == "worker")
    assert worker["state"] == "down" and worker["critical"] is True
    assert "scheduler" in worker["detail"]
    assert body["overall"] == "down"

    async with _leading(LOCK_IMAP_POLLER, LOCK_OAUTH, LOCK_SCHEDULER):
        body = await system_status(actor=None)
    worker = next(c for c in body["checks"] if c["component"] == "worker")
    assert worker["state"] == "up"


@pytest.mark.asyncio
async def test_operator_console_flags_stalled_mailbox_syncing(session) -> None:  # noqa: ANN001
    from envelock.api.admin import system_status
    from envelock.models import Mailbox, Tenant

    tenant = Tenant(id=uuid4(), name="stall co", plan="complete")
    session.add(tenant)
    await session.flush()
    session.add(
        Mailbox(
            id=uuid4(),
            tenant_id=tenant.id,
            address="ap@stall.example",
            sources=[],
            last_sync_at=datetime.now(UTC) - timedelta(hours=2),
        )
    )
    await session.commit()

    body = await system_status(actor=None)
    sync = next(c for c in body["checks"] if c["component"] == "mail_sync")
    assert sync["state"] == "degraded"
    assert "stalled" in sync["detail"]


@pytest.mark.asyncio
async def test_operator_console_lists_production_warnings(monkeypatch) -> None:  # noqa: ANN001
    from envelock.api.admin import system_status
    from envelock.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(
        type(settings), "production_warnings", lambda self: ["Stripe is in TEST mode"]
    )
    body = await system_status(actor=None)
    config = next(c for c in body["checks"] if c["component"] == "configuration")
    assert config["state"] == "degraded"
    assert "TEST mode" in config["detail"]
