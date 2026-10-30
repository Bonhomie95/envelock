"""Single-writer election for the background workers.

The IMAP poller and the periodic scheduler must run on exactly one process. Two
pollers fetch the same mail twice; two schedulers escalate the same alert twice,
which in the E6 ladder means the customer's phone rings twice per cycle. Until
now the only protection was a comment telling the operator to set
`ENVELOCK_SCHEDULER_ENABLED=false` on every replica but one — a config invariant
no deploy enforces and nobody remembers during an incident.

The lock is a Postgres **session-level advisory lock**, chosen over Redis for
three reasons:

* Postgres is already a hard dependency; Redis is optional (`rate_limit_backend`
  can be "memory"), so a Redis lock would silently not exist on some deployments.
* An advisory lock is released automatically when the holder's connection dies.
  There is no lease to renew and no TTL to tune, so a hard-killed process cannot
  leave the workers wedged until a timeout expires — the failure mode that makes
  hand-rolled Redis locks worse than no lock at all.
* It is genuinely atomic across replicas, which an in-process flag is not.

A process that does not win the lock is not an error: it serves HTTP and leaves
the background work to the holder. It retries, so killing the leader promotes a
follower within one retry interval.

The flip side of "released when the connection dies" is that the connection can
die while the process lives — every Postgres restart does it. The lock is then
free at the server while the loop it guarded keeps running here, unguarded, and
a second contender would start a second copy. So a leader re-proves its lock
connection every `CHECK_SECONDS` and stands down the moment it cannot.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger("envelock.leader")

#: Advisory lock keys. Arbitrary but fixed 64-bit ints, namespaced by a constant
#: high word so they cannot collide with an application lock someone adds later.
LOCK_SCHEDULER = 0x454E56_0001  # "ENV" + 1
LOCK_IMAP_POLLER = 0x454E56_0002
#: The OAuth token refresh/fetch loop. Separate from the scheduler's lock on
#: purpose: those jobs need the credential decryption key, and under split
#: custody only the worker has it. Sharing the scheduler lock meant whichever
#: process booted first won it — and when that was the API, OAuth tokens were
#: refreshed nowhere and every Microsoft/Google mailbox went dark within an hour.
LOCK_OAUTH = 0x454E56_0003

#: Every leader lock, by the name the status pages report it under.
LEADER_LOCKS: dict[str, int] = {
    "scheduler": LOCK_SCHEDULER,
    "imap poller": LOCK_IMAP_POLLER,
    "oauth jobs": LOCK_OAUTH,
}

#: How often a follower re-attempts. Short enough that a leader dying is a brief
#: gap in background work, long enough not to hammer the pool.
RETRY_SECONDS = 30.0

#: How often a leader re-proves its lock connection is alive. A dead one means
#: the lock is already free at the server, so this bounds how long two copies of
#: a loop could ever overlap.
CHECK_SECONDS = 30.0


@contextlib.asynccontextmanager
async def hold(key: int, *, name: str) -> AsyncIterator[AsyncConnection | None]:
    """Try to take `key` for the life of the block.

    Yields the connection that holds the lock — that connection IS the lock, so
    it is kept out of the pool for the whole time and must not be recycled
    underneath us — or None when another process holds it.
    """
    from envelock.db import get_engine

    conn = None
    acquired = False
    try:
        conn = await get_engine().connect()
        result = await conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key})
        acquired = bool(result.scalar())
        # A session-level lock outlives the transaction. Ending it here keeps a
        # lock held for days from sitting "idle in transaction", where an
        # idle-transaction timeout would kill it.
        await conn.commit()
        if acquired:
            logger.info("acquired %s leadership", name)
        yield conn if acquired else None
    except Exception as exc:  # noqa: BLE001
        # A database that cannot hand out a lock is a database the workers could
        # not do anything with anyway. Report and stand down rather than run
        # unsynchronised, which is the outcome the lock exists to prevent.
        logger.warning("%s leadership unavailable (%s) — not running here", name, exc)
        yield None
    finally:
        if conn is not None:
            if acquired:
                with contextlib.suppress(Exception):
                    await conn.execute(
                        text("SELECT pg_advisory_unlock(:k)"), {"k": key}
                    )
            with contextlib.suppress(Exception):
                await conn.close()


async def _still_holds(conn: AsyncConnection, *, timeout: float) -> bool:  # noqa: ASYNC109
    """Whether the lock connection still answers. While it does, the session —
    and with it the session-level lock — is alive."""
    try:
        async with asyncio.timeout(timeout):
            await conn.execute(text("SELECT 1"))
            await conn.commit()
        return True
    except Exception:  # noqa: BLE001 — any failure means the lock may be gone
        return False


async def _lead(
    conn: AsyncConnection,
    *,
    name: str,
    body,  # noqa: ANN001 — async callable taking (stop_event)
    stop: asyncio.Event,
    check_seconds: float,
) -> None:
    """Run `body(stop)` for exactly as long as `conn` holds the lock."""
    task = asyncio.create_task(body(stop))
    try:
        while not task.done():
            await asyncio.wait({task}, timeout=check_seconds)
            if task.done():
                break
            if not await _still_holds(conn, timeout=check_seconds):
                logger.error(
                    "%s lost its lock connection — standing down so leadership "
                    "is re-elected rather than run twice",
                    name,
                )
                return
        task.result()  # the body's own exception, if it raised one
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def run_as_leader(
    key: int,
    *,
    name: str,
    body,  # noqa: ANN001 — async callable taking (stop_event)
    stop: asyncio.Event,
    retry_seconds: float = RETRY_SECONDS,
    check_seconds: float = CHECK_SECONDS,
) -> None:
    """Run `body(stop)` for as long as we hold `key`, retrying if we do not.

    A follower loops quietly until the leader releases — on a clean shutdown, or
    when its connection dies — and then takes over. A leader whose own lock
    connection dies cancels `body` and goes back to being a candidate.
    """
    announced_follower = False
    while not stop.is_set():
        async with hold(key, name=name) as lock:
            if lock is not None:
                announced_follower = False
                try:
                    await _lead(
                        lock, name=name, body=body, stop=stop, check_seconds=check_seconds
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception("%s leader loop failed; will re-elect", name)
            elif not announced_follower:
                # Once, not every 30 seconds: a follower is the normal state for
                # every replica but one, and it should not fill the log.
                logger.info(
                    "%s is running elsewhere — standing by as follower", name
                )
                announced_follower = True
        if stop.is_set():
            return
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=retry_seconds)


async def running_leaders(conn: AsyncConnection) -> set[str]:
    """Which leader loops are running right now, in ANY process on this database.

    Asked of Postgres rather than of this process's memory: under split custody
    the API that serves the status pages runs none of these loops, so its own
    state says nothing about the worker. A loop is running exactly when some
    live session holds its lock (and a leader whose session dies stands down,
    see `_lead`). Bigint advisory keys appear in `pg_locks` split across
    classid/objid with objsubid = 1; pg_locks is readable by every role.
    """
    rows = await conn.execute(
        text(
            "SELECT (classid::bigint << 32) | objid::bigint FROM pg_locks "
            "WHERE locktype = 'advisory' AND granted AND objsubid = 1 "
            "AND database = (SELECT oid FROM pg_database "
            "WHERE datname = current_database())"
        )
    )
    held = {int(key) for (key,) in rows}
    return {name for name, key in LEADER_LOCKS.items() if key in held}


__all__ = [
    "LEADER_LOCKS",
    "LOCK_IMAP_POLLER",
    "LOCK_OAUTH",
    "LOCK_SCHEDULER",
    "hold",
    "run_as_leader",
    "running_leaders",
]
