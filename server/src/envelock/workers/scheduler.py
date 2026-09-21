"""The in-process periodic scheduler (PRD §8.1 E6, §15.2, §17).

Everything that must run on a timer lives here. Before this module the only
background task was the IMAP poller, which meant E6 escalation never fired,
retention never purged, OAuth tokens never refreshed, and the Channel-3 domain
watchers — the free Guard tier and the pre-signup demo — never ran. Each job is a
plain async function so it stays unit-testable; the scheduler only owns the loop,
the interval, and the "one crash never kills the others" isolation.

A single leader runs everything: main.py wraps the scheduler in a Postgres
advisory-lock leader election (`run_as_leader`), so a multi-instance deployment
elects exactly one scheduler on its own.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from envelock.config import get_settings
from envelock.db import get_sessionmaker

logger = logging.getLogger(__name__)

#: The live CT watcher, when the scheduler starts one — /status/channels reads
#: it so the stats shown are the REAL stream's, not a fresh instance's zeros.
LIVE_CT_WATCHER = None

Job = Callable[[], Awaitable[dict | list | None]]

#: Per-job last-run heartbeat, read by GET /status/system so a stalled or failing
#: scheduler job is visible rather than only in logs. {name: {ran_at, ok, error}}.
_HEARTBEAT: dict[str, dict] = {}


def _now_iso() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def scheduler_health() -> dict:
    """Snapshot of every scheduler job's last run (for the ops status endpoint)."""
    return {k: dict(v) for k, v in _HEARTBEAT.items()}


def _did_something(result: dict | list | None) -> bool:
    """Whether a job actually did work worth a log line.

    `if result:` was wrong here: every job returns a dict like
    `{"escalated": 0, "delivered": 0}`, and a non-empty dict is truthy however
    many zeros are in it. So each job logged on every tick forever — several
    lines every 30 seconds, which on a small host is tens of thousands of daily
    entries that bury the ones that matter.
    """
    if not result:
        return False
    values = result.values() if isinstance(result, dict) else result
    return any(_did_something(v) if isinstance(v, dict | list) else bool(v) for v in values)


async def _run_forever(name: str, job: Job, *, interval: float, stop: asyncio.Event) -> None:
    """Run `job` every `interval` seconds until `stop` is set. A job that raises is
    logged and retried next tick — one failing job never stops the others."""
    import contextlib

    # Small initial stagger so all jobs don't fire in the same instant at boot.
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stop.wait(), timeout=min(interval, 5.0))
    from envelock.db_rls import system_scope

    while not stop.is_set():
        try:
            # Every scheduler job is platform-wide by definition: escalate across
            # all tenants, purge expired data everywhere, refresh every OAuth
            # token, re-verify every domain. Under RLS a job runs with no tenant
            # bound, so without this it would see zero rows and report a cheerful
            # "nothing to do" forever — retention silently stopping is exactly
            # the failure mode that is hardest to notice.
            with system_scope(f"scheduler job {name}"):
                result = await job()
            _HEARTBEAT[name] = {
                "ran_at": _now_iso(),
                "ok": True,
                "error": None,
            }
            if _did_something(result):
                # Interpolated, not `extra=`: the default formatter that
                # `basicConfig` installs never renders extras, so this used to
                # print a bare "scheduler job ran" with no job name in
                # production — useless for working out which job did what.
                logger.info("scheduler job %s ran: %s", name, result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            # Same reason, and worse here: without the name you knew a job had
            # failed but not which one.
            logger.warning("scheduler job %s failed: %s", name, exc)
            _HEARTBEAT[name] = {
                "ran_at": _now_iso(),
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}"[:200],
            }
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            continue


# ── Individual jobs ───────────────────────────────────────────────────────────
async def escalation_job() -> dict:
    """E6 — escalate unacknowledged Criticals across every tenant."""
    from envelock.notify.dispatch import deliver_pending, run_escalation_cycle

    async with get_sessionmaker()() as session:
        escalated = await run_escalation_cycle(session)
        # Also flush any pending ladder deliveries (L1/L2) that the raise path
        # queued but a same-request dispatch didn't complete.
        delivered = await deliver_pending(session)
        await session.commit()
    return {"escalated": len(escalated), "delivered": len(delivered)}


async def retention_job() -> dict:
    """§15.2 — actually delete expired data. Demonstrable, on a timer."""
    from envelock.governance.retention import purge_expired

    async with get_sessionmaker()() as session:
        counts = await purge_expired(session)
    return {"purged": counts}


async def webhook_delivery_job() -> dict:
    """Attempt every outbound SIEM delivery that is due (PRD §15.3)."""
    from envelock.workers.webhook_delivery import webhook_delivery_job as run

    return await run()


async def oauth_refresh_job() -> dict:
    """Keep Tier-1 (Graph/Gmail) access tokens alive. Without this, OAuth
    mailboxes go dark ~1h after connection."""
    from envelock.channels.mail.oauth_refresh import refresh_due_tokens

    async with get_sessionmaker()() as session:
        refreshed = await refresh_due_tokens(session)
    return {"refreshed": refreshed}


async def oauth_fetch_job() -> dict:
    """Pull new mail for connected Tier-1 mailboxes (the API/webhook-less fetch
    path). A webhook receiver short-circuits this when configured, but polling is
    the always-correct fallback."""
    from envelock.workers.oauth_fetch import fetch_all_oauth_mailboxes

    return await fetch_all_oauth_mailboxes()


async def domain_reverify_job() -> dict:
    """Revoke a domain's verification if its DNS proof was deleted — so a domain we
    once trusted can't stay trusted after the customer loses control of it. Only a
    conclusive 'record absent' revokes; transient DNS failures are ignored."""
    from envelock.services.domains import revalidate_verified_domains

    async with get_sessionmaker()() as session:
        return await revalidate_verified_domains(session)


async def monthly_digest_job() -> dict:
    """Send each workspace its month, to the admins who run it.

    Runs on a short cycle and decides per tenant, rather than on a monthly timer:
    a monthly timer means a restart or a deploy on the wrong day silently skips a
    month for everyone, and nobody notices until a customer asks why they stopped
    getting them. Here the due date lives in the row, so a missed cycle is caught
    on the next one.

    Deliberately conservative about who gets mail:

    * only tenants whose month actually contained something (see
      `Digest.worth_sending`) — an empty digest trains people to filter us;
    * only admins and owners, who are the people with a dashboard to act in;
    * `last_digest_at` is stamped even when nothing was worth sending, so a quiet
      workspace is reconsidered next month rather than re-evaluated every cycle.
    """
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from envelock.models import Tenant, User
    from envelock.notify import digest as dg
    from envelock.notify.mail import is_configured, send_mail

    if not is_configured():
        return {"digests": 0, "skipped": "no smtp relay"}

    now = datetime.now(UTC)
    period = timedelta(days=30)
    sent = 0
    considered = 0

    async with get_sessionmaker()() as session:
        tenants = (
            (await session.execute(select(Tenant).where(Tenant.is_active.is_(True))))
            .scalars()
            .all()
        )
        for tenant in tenants:
            last = tenant.last_digest_at
            if last is not None and last.tzinfo is None:
                last = last.replace(tzinfo=UTC)
            created = tenant.created_at
            if created is not None and created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            # A tenant that has not existed for a month has no month to report.
            since = last or created or now
            if now - since < period:
                continue
            considered += 1

            built = await dg.build_digest(session, tenant_id=tenant.id, since=since, until=now)
            tenant.last_digest_at = now
            if built is None or not built.worth_sending:
                continue

            recipients = (
                (
                    await session.execute(
                        select(User.email).where(
                            User.tenant_id == tenant.id,
                            User.is_admin.is_(True),
                            User.status == "active",
                        )
                    )
                )
                .scalars()
                .all()
            )
            subject = f"Envelock — {built.alerts_raised} caught this month"
            text = dg.render_text(built)
            html_body = dg.render_html(built)
            for address in recipients:
                result = await send_mail(
                    to=address, subject=subject, body=text, html_body=html_body
                )
                if result.sent:
                    sent += 1
        await session.commit()

    return {"digests": sent, "tenants_due": considered}


# ── Channel-3 CT-log watcher ──────────────────────────────────────────────────
async def _load_protected_domains() -> frozenset[str]:
    from sqlalchemy import select

    from envelock.db_rls import system_scope
    from envelock.models import Domain

    # Every tenant's domains, by definition. Unscoped under row-level security
    # this returned an empty set, and the watcher protected nothing.
    with system_scope("ct watcher: load every protected domain"):
        async with get_sessionmaker()() as session:
            rows = (await session.execute(select(Domain.registrable_domain))).scalars().all()
    return frozenset(r for r in rows if r)


async def _persist_ct_observation(obs) -> int:  # noqa: ANN001
    """Record one lookalike certificate against every tenant it imitates.

    One certificate can be a lookalike of several tenants' domains, so this
    spans tenants and runs in system scope.
    """
    from envelock.db_rls import system_scope
    from envelock.workers.ct_persist import persist_observation

    with system_scope("ct watcher: persist a lookalike"):
        async with get_sessionmaker()() as session:
            return await persist_observation(session, obs)


async def run_ct_watcher(stop: asyncio.Event) -> None:
    """D2 — the primary Channel-3 sensor. Persists every lookalike match and
    raises a weaponisation-scored alert. Resilient: a certstream outage reconnects
    with backoff and the protected-domain set refreshes periodically."""
    from envelock.workers.watchers import CertTransparencyWatcher

    settings = get_settings()
    queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    def on_match(obs) -> None:  # noqa: ANN001
        import contextlib

        # Drop under flood rather than block the hot CT loop.
        with contextlib.suppress(asyncio.QueueFull):
            queue.put_nowait(obs)

    protected = await _load_protected_domains()
    watcher = CertTransparencyWatcher(protected_domains=protected, on_match=on_match)
    global LIVE_CT_WATCHER  # noqa: PLW0603 — status endpoint reads the live instance
    LIVE_CT_WATCHER = watcher

    async def refresh_domains() -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(
                    stop.wait(), timeout=settings.watcher_domain_refresh_seconds
                )
            except TimeoutError:
                watcher.protected = set(await _load_protected_domains())

    async def drain() -> None:
        while not stop.is_set():
            try:
                obs = await asyncio.wait_for(queue.get(), timeout=2.0)
            except TimeoutError:
                continue
            try:
                await _persist_ct_observation(obs)
            except Exception as exc:  # noqa: BLE001
                logger.warning("ct persist failed: %s", exc)

    watch_task = asyncio.create_task(watcher.run())
    refresh_task = asyncio.create_task(refresh_domains())
    drain_task = asyncio.create_task(drain())
    await stop.wait()
    watcher.stop()
    for t in (watch_task, refresh_task, drain_task):
        t.cancel()
    import contextlib

    for t in (watch_task, refresh_task, drain_task):
        with contextlib.suppress(asyncio.CancelledError):
            await t


# ── Scheduler entrypoint ──────────────────────────────────────────────────────
def start_oauth_jobs(stop: asyncio.Event) -> list[asyncio.Task]:
    """The Tier-1 OAuth token refresh and fetch loops.

    Started by main.py only in a process that can decrypt stored credentials,
    under `LOCK_OAUTH` — so the process that holds the key is the one that runs
    them, whatever order the replicas booted in.
    """
    settings = get_settings()
    return [
        asyncio.create_task(
            _run_forever(
                "oauth_refresh", oauth_refresh_job,
                interval=settings.oauth_refresh_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "oauth_fetch", oauth_fetch_job,
                interval=settings.oauth_refresh_seconds, stop=stop,
            )
        ),
    ]


def start(stop: asyncio.Event) -> list[asyncio.Task]:
    """Launch every scheduled job as a background task. Returns the tasks so the
    lifespan can cancel them on shutdown."""
    settings = get_settings()
    tasks: list[asyncio.Task] = [
        asyncio.create_task(
            _run_forever(
                "escalation", escalation_job,
                interval=settings.escalation_cycle_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "retention", retention_job,
                interval=settings.retention_purge_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "domain_reverify", domain_reverify_job,
                interval=settings.domain_reverify_seconds, stop=stop,
            )
        ),
        # The monthly "what we caught and why" digest. Cheap when nothing is due
        # (one indexed scan), and the only thing in the product that tells a
        # customer on a quiet month what they are paying for.
        asyncio.create_task(
            _run_forever(
                "monthly_digest", monthly_digest_job,
                interval=settings.digest_cycle_seconds, stop=stop,
            )
        ),
    ]

    # Drains the outbound SIEM webhook queue — ALWAYS. This was parked under
    # focus mode on the belief that "nothing enqueues deliveries while
    # governance is unmounted", but the governance router is mounted
    # unconditionally (main.py mounts it with a comment explaining why) and
    # `raise_alert` enqueues a delivery row on EVERY alert. The result under the
    # focus default was a queue that grew forever while a customer who
    # registered a SIEM endpoint — and saw the test delivery succeed — received
    # nothing, silently. A drain with an empty queue costs one indexed query per
    # cycle; a queue with no drain costs the customer their integration.
    tasks.append(
        asyncio.create_task(
            _run_forever(
                "webhook_delivery", webhook_delivery_job,
                interval=settings.webhook_delivery_seconds, stop=stop,
            )
        )
    )

    # The OAuth refresh/fetch jobs are NOT started here any more. They need the
    # credential decryption key, and this scheduler runs in whichever process
    # wins its leader lock — under split custody that is sometimes the API,
    # which cannot decrypt, so the jobs silently ran nowhere. They now run from
    # `start_oauth_jobs`, which main.py starts only where decryption is possible,
    # under a lock of their own.
    # The CT-log lookalike watcher is Channel 3 (brand protection). It is what
    # makes the free Guard tier's advertised "lookalike domain monitoring"
    # actually happen, so a deployment that has asked for it and is not getting
    # it must say so out loud: `focus_core` silently overriding an explicit
    # CT_WATCHER_ENABLED=true is how the pricing page ended up promising a
    # service that was not running.
    if settings.ct_watcher_enabled and not settings.focus_core:
        tasks.append(asyncio.create_task(run_ct_watcher(stop)))
    elif settings.ct_watcher_enabled:
        logger.warning(
            "CT lookalike watcher NOT started: ENVELOCK_CT_WATCHER_ENABLED=true "
            "is overridden by ENVELOCK_FOCUS_CORE=true. The free Guard tier "
            "advertises lookalike monitoring and will not be doing any. Set "
            "ENVELOCK_FOCUS_CORE=false, or remove the claim from the pricing page."
        )
    logger.info("scheduler started (%d jobs)", len(tasks))
    return tasks
