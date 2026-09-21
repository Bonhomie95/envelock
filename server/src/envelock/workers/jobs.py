"""A tiny in-process job registry for work that cannot run inside a request.

Onboarding backfill is the case that forced this. It pulls up to
`backfill_max_messages` (5,000) messages over IMAP, and parses, extracts and
analyses each one. It was `await`ed directly inside
`POST /mailboxes/{id}/backfill`, so the proxy timed out long before it finished:
the customer saw a failure, the work carried on invisibly, and there was nothing
to report progress to. It is also the first thing every new customer does.

Deliberately not a broker. `arq` is already a dependency and a Redis queue is the
right answer once there is a separate worker deployment — but adding one now
would mean a second process to deploy, monitor and get right before launch, to
solve a problem that is one background task and a status row. What this does
provide is the part that matters to the customer: the request returns
immediately, the job reports progress, and a failure is visible rather than
silent.

Jobs live in memory, so a restart loses their status (not their effect — the
pipeline commits as it goes, and re-running a backfill is idempotent by
`rfc_message_id`). `GET /jobs/{id}` says so rather than pretending otherwise.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

logger = logging.getLogger("envelock.jobs")

#: Completed jobs kept for status lookups before the oldest is dropped. A person
#: polls a job for a few minutes; nothing needs an hour of history in memory.
_MAX_RETAINED = 200


@dataclass
class Job:
    id: UUID
    kind: str
    tenant_id: UUID
    #: queued | running | done | failed
    status: str = "queued"
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    #: Free-form, job-defined progress — e.g. messages processed so far.
    progress: dict[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "kind": self.kind,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "progress": self.progress,
            "result": self.result,
            "error": self.error,
        }


_jobs: OrderedDict[UUID, Job] = OrderedDict()
_tasks: dict[UUID, asyncio.Task] = {}


def get(job_id: UUID, *, tenant_id: UUID) -> Job | None:
    """Look up a job, scoped to its owning tenant.

    The tenant check is here rather than at the call site because a job id is a
    bearer-ish handle: without it, knowing an id would be enough to read another
    tenant's onboarding progress.
    """
    job = _jobs.get(job_id)
    if job is None or job.tenant_id != tenant_id:
        return None
    return job


def running_for(*, tenant_id: UUID, kind: str, key: str | None = None) -> Job | None:
    """An unfinished job of this kind for this tenant, if one exists.

    Used to make starting a job idempotent: a customer double-clicking "scan my
    history" should join the run in progress, not start a second one competing
    for the same IMAP connection.
    """
    for job in reversed(_jobs.values()):
        if (
            job.tenant_id == tenant_id
            and job.kind == kind
            and job.status in ("queued", "running")
            and (key is None or job.progress.get("key") == key)
        ):
            return job
    return None


def submit(*, kind: str, tenant_id: UUID, body, key: str | None = None) -> Job:  # noqa: ANN001
    """Start `body(job)` in the background and return its handle immediately."""
    job = Job(id=uuid4(), kind=kind, tenant_id=tenant_id)
    if key is not None:
        job.progress["key"] = key
    _jobs[job.id] = job
    while len(_jobs) > _MAX_RETAINED:
        # Never evict something still running, however old it is.
        oldest_id, oldest = next(iter(_jobs.items()))
        if oldest.status in ("queued", "running"):
            break
        _jobs.pop(oldest_id, None)

    async def _run() -> None:
        job.status = "running"
        job.started_at = datetime.now(UTC)
        try:
            job.result = await body(job)
            job.status = "done"
        except asyncio.CancelledError:
            job.status = "failed"
            job.error = "cancelled"
            raise
        except Exception as exc:  # noqa: BLE001
            # The whole point is that a failure is *visible*. Log it with the
            # stack for the operator and keep a short reason for the customer.
            logger.exception("background job %s (%s) failed", job.id, kind)
            job.status = "failed"
            job.error = f"{type(exc).__name__}: {exc}"[:500]
        finally:
            job.finished_at = datetime.now(UTC)
            _tasks.pop(job.id, None)

    _tasks[job.id] = asyncio.create_task(_run())
    return job


async def drain(seconds: float = 30.0) -> None:  # noqa: ASYNC109
    """Wait for in-flight jobs — used at shutdown and by tests.

    Named `seconds` rather than `timeout` so it is clear this is a shutdown
    budget, not a cancellation contract the caller can compose with.
    """
    pending = [t for t in _tasks.values() if not t.done()]
    if not pending:
        return
    # `asyncio.wait` with a timeout is deprecated in favour of a timeout context;
    # suppressing here (rather than letting it propagate) is deliberate: a job
    # that outruns the shutdown budget is abandoned, not allowed to hang the
    # process. Its work is committed incrementally and safe to re-run.
    with contextlib.suppress(TimeoutError):
        async with asyncio.timeout(seconds):
            await asyncio.wait(pending)


def reset() -> None:
    """Test hook."""
    _jobs.clear()
    _tasks.clear()


__all__ = ["Job", "drain", "get", "reset", "running_for", "submit"]
