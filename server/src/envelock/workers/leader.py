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
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator

from sqlalchemy import text

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

#: How often a follower re-attempts. Short enough that a leader dying is a brief
#: gap in background work, long enough not to hammer the pool.
RETRY_SECONDS = 30.0


@contextlib.asynccontextmanager
async def hold(key: int, *, name: str) -> AsyncIterator[bool]:
    """Try to take `key` for the life of the block. Yields whether we got it.

    Holds one dedicated connection outside the pool for the whole time — that
    connection IS the lock, so it must not be recycled underneath us.
    """
    from envelock.db import get_engine

    conn = None
    acquired = False
    try:
        conn = await get_engine().connect()
        result = await conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key})
        acquired = bool(result.scalar())
        if acquired:
            logger.info("acquired %s leadership", name)
        yield acquired
    except Exception as exc:  # noqa: BLE001
        # A database that cannot hand out a lock is a database the workers could
        # not do anything with anyway. Report and stand down rather than run
        # unsynchronised, which is the outcome the lock exists to prevent.
        logger.warning("%s leadership unavailable (%s) — not running here", name, exc)
        yield False
    finally:
        if conn is not None:
            if acquired:
                with contextlib.suppress(Exception):
                    await conn.execute(
                        text("SELECT pg_advisory_unlock(:k)"), {"k": key}
                    )
            with contextlib.suppress(Exception):
                await conn.close()


async def run_as_leader(
    key: int,
    *,
    name: str,
    body,  # noqa: ANN001 — async callable taking (stop_event)
    stop: asyncio.Event,
    retry_seconds: float = RETRY_SECONDS,
) -> None:
    """Run `body(stop)` for as long as we hold `key`, retrying if we do not.

    A follower loops quietly until the leader releases — on a clean shutdown, or
    when its connection dies — and then takes over.
    """
    announced_follower = False
    while not stop.is_set():
        async with hold(key, name=name) as leading:
            if leading:
                announced_follower = False
                try:
                    await body(stop)
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


__all__ = ["LOCK_IMAP_POLLER", "LOCK_OAUTH", "LOCK_SCHEDULER", "hold", "run_as_leader"]
