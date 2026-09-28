"""In-process fan-out for live operator notifications.

The operator console used to load its tenant list once and never again, so a
signup that happened while someone was looking at the page stayed invisible
until they reloaded. The alternative most reached for — poll every N seconds —
spends a request per operator per interval forever to discover that, almost
always, nothing has changed.

This is the other shape: publishers call `publish()` when something actually
happens, and each connected operator holds one queue that a Server-Sent Events
response drains. Nothing is sent when nothing occurs.

**Deliberately in-process, and correct here because of the deployment.** The
API runs as a single uvicorn process (`deploy/envelock-api.service`, no
`--workers`), and the events published here are raised by request handlers in
that same process, so every subscriber sees every event.

ponytail: in-process fan-out, because one process publishes and one process
subscribes. The day the API runs more than one worker, a second worker's
subscribers would miss events raised by the first — swap `publish` for a Redis
PUBLISH and have `subscribe` consume a Redis subscription. Redis is already a
dependency, so that change is confined to this file.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from typing import Any

logger = logging.getLogger("envelock.events")

#: Per-subscriber buffer. Small on purpose: a browser tab that has been
#: suspended for an hour should not be able to pin an hour of events in memory.
#: When it overflows the OLDEST are dropped and the client is told to refetch,
#: which is cheap and correct — these events are hints to reload, not a ledger.
_QUEUE_SIZE = 64

_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()


def publish(event: str, data: dict[str, Any] | None = None) -> None:
    """Announce that something happened. Never raises, never blocks.

    Called from request handlers on the success path, so it must not be able to
    fail the operation it is reporting: a signup that worked must not 500
    because the operator console's plumbing had a bad day.
    """
    if not _subscribers:
        return
    payload = {"event": event, "data": data or {}}
    for queue in list(_subscribers):
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            # Drop the oldest to make room. A subscriber that cannot keep up
            # gets a gap, and the `stale` flag tells it to do a full refetch.
            with contextlib.suppress(asyncio.QueueEmpty):
                queue.get_nowait()
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait({"event": "stale", "data": {}})
        except Exception as exc:  # noqa: BLE001 — see docstring
            logger.warning("event publish to a subscriber failed: %s", exc)


@contextlib.asynccontextmanager
async def subscribe() -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
    """One queue for the life of a connection, removed on the way out.

    The context manager is what stops a leak: a browser tab closing, a network
    drop or an nginx timeout all unwind the generator, and the subscriber goes
    with it. Without that the set grows for every connection ever made and
    `publish` slows down forever.
    """
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_SIZE)
    _subscribers.add(queue)
    try:
        yield queue
    finally:
        _subscribers.discard(queue)


def subscriber_count() -> int:
    """For the status endpoint and tests."""
    return len(_subscribers)


__all__ = ["publish", "subscribe", "subscriber_count"]
