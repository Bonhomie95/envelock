"""Leader election stands down when its lock connection dies.

The advisory lock belongs to one connection. Every Postgres restart kills that
connection while the process lives, and the lock is released at the server —
but the loop it guarded used to keep running here, unguarded, forever. With a
second contender (a second worker, `--workers 2`, a debugging run against the
live database) that is two pollers and two escalation schedulers: the exact
double-alerting the lock exists to prevent.

These run against the test Postgres, because the behaviour under test is the
server releasing a lock when a backend is terminated.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import text

#: Distinct from the real keys so nothing else in the suite can collide.
_KEY = 0x454E56_00F1


async def _lock_holder_pid() -> int | None:
    from envelock.db import get_engine

    async with get_engine().connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted "
                    "AND objsubid = 1 AND (classid::bigint << 32) | objid::bigint = :k"
                ),
                {"k": _KEY},
            )
        ).first()
    return row[0] if row else None


async def _wait_for(predicate, timeout: float = 10.0) -> None:  # noqa: ANN001, ASYNC109
    async with asyncio.timeout(timeout):
        # Polling is the point: the state being waited on lives in Postgres.
        while not await predicate():  # noqa: ASYNC110
            await asyncio.sleep(0.05)


@pytest.mark.asyncio
async def test_a_leader_whose_lock_connection_dies_stops_its_loop_and_re_elects() -> None:
    from envelock.db import get_engine
    from envelock.workers.leader import run_as_leader

    started = 0
    cancelled = 0

    async def body(stop: asyncio.Event) -> None:
        nonlocal started, cancelled
        started += 1
        try:
            await stop.wait()
        except asyncio.CancelledError:
            cancelled += 1
            raise

    stop = asyncio.Event()
    leader = asyncio.create_task(
        run_as_leader(
            _KEY, name="test loop", body=body, stop=stop,
            retry_seconds=0.1, check_seconds=0.1,
        )
    )
    try:
        async def has_lock() -> bool:
            return started == 1 and await _lock_holder_pid() is not None

        await _wait_for(has_lock)
        first_pid = await _lock_holder_pid()

        # What a Postgres restart does to the lock connection.
        async with get_engine().connect() as admin:
            await admin.execute(text("SELECT pg_terminate_backend(:p)"), {"p": first_pid})
            await admin.commit()

        async def re_elected() -> bool:
            pid = await _lock_holder_pid()
            return cancelled == 1 and started == 2 and pid not in (None, first_pid)

        # The unguarded loop is stopped, and a new one runs under a new lock.
        await _wait_for(re_elected)
    finally:
        stop.set()
        await asyncio.wait_for(leader, timeout=10)
    assert started == cancelled + 1  # exactly one loop alive at any moment


@pytest.mark.asyncio
async def test_running_leaders_reports_locks_held_by_any_session() -> None:
    """The status pages are served by the API process, which runs no leader
    loop under split custody — so they have to ask Postgres, not memory."""
    from envelock.db import get_engine
    from envelock.workers.leader import LOCK_SCHEDULER, hold, running_leaders

    async with get_engine().connect() as conn:
        assert "scheduler" not in await running_leaders(conn)

    async with hold(LOCK_SCHEDULER, name="scheduler") as lock:
        assert lock is not None
        async with get_engine().connect() as other:
            assert "scheduler" in await running_leaders(other)

    async with get_engine().connect() as conn:
        assert "scheduler" not in await running_leaders(conn)


@pytest.mark.asyncio
async def test_a_second_contender_waits_as_follower() -> None:
    from envelock.workers.leader import hold

    async with hold(_KEY, name="first") as first:
        assert first is not None
        async with hold(_KEY, name="second") as second:
            assert second is None
