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

#: The live CT watcher, when the scheduler starts one — held module-level so the
#: stats read are the REAL stream's and not a fresh instance's zeros.
#:
#: Read by the operator console's overview (`api/admin._ct_watcher_health`) to
#: answer the one question the product previously could not: is the free tier's
#: advertised lookalike monitoring actually receiving anything. Customer-facing
#: status deliberately does not show it — platform internals belong in staff
#: tools.
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


async def oauth_push_drain_job() -> dict:
    """Act on push notifications within seconds (see oauth_fetch.drain_requested)."""
    from envelock.workers.oauth_fetch import drain_requested

    return await drain_requested()


async def push_subscription_job() -> dict:
    """Create and renew Graph subscriptions / Gmail watches before they lapse."""
    from envelock.workers.push_subscriptions import ensure_all

    return await ensure_all()


async def accounting_requested_job() -> dict:
    """Connections just made or with "Sync now" pressed — within seconds."""
    from envelock.workers.accounting_sync import sync_due

    return await sync_due(requested_only=True)


async def accounting_sync_job() -> dict:
    """Re-read every connected accounting system on its cadence."""
    from envelock.workers.accounting_sync import sync_due

    return await sync_due()


async def accounting_bills_job() -> dict:
    """Note the unpaid bills of suppliers named by new bank-change alerts."""
    from envelock.workers.accounting_sync import flag_bills_for_new_alerts

    return await flag_bills_for_new_alerts()


async def domain_reverify_job() -> dict:
    """Revoke a domain's verification if its DNS proof was deleted — so a domain we
    once trusted can't stay trusted after the customer loses control of it. Only a
    conclusive 'record absent' revokes; transient DNS failures are ignored."""
    from envelock.services.domains import revalidate_verified_domains

    async with get_sessionmaker()() as session:
        return await revalidate_verified_domains(session)


#: Days-remaining marks we warn on. The job sends the SMALLEST milestone the
#: tenant has reached but not yet been told about, so a server that was down for
#: the 7- and 3-day marks sends "2 days left" once on the way back up — not a
#: burst of three stale warnings.
RENEWAL_REMINDER_DAYS = (7, 3, 2, 1, 0)


def _due_mark(days_left: int) -> int | None:
    """The closest mark `days_left` has reached, or None if it is still further
    out than the first warning. Ascending, so two days left picks the "2 days"
    warning rather than the "7 days" one it also technically satisfies."""
    return next((d for d in sorted(RENEWAL_REMINDER_DAYS) if days_left <= d), None)


async def renewal_reminder_job() -> dict:
    """Warn before access changes — at 7, 3, 2 and 1 days, and on the day.

    Three different deadlines, one mechanism, because to the customer they are
    the same event ("when does my protection change?"):

    * **Trial ending, no card.** Counts down; protection drops to Guard.
    * **Paid plan set to cancel.** Counts down; same outcome, and the more
      important of the two because they are already a paying customer.
    * **Paid plan renewing normally.** ONE notice at the first mark, not a
      countdown. A card that is simply going to be charged is not an emergency,
      and four escalating warnings about it would train people to ignore the
      ones that are.

    Idempotent by construction: `renewal_reminder_days` holds the smallest mark
    already sent for the current period, so re-running the job — on the same
    tick, after a restart, or twice in a day — cannot repeat a warning. Every
    place that starts a new period (activation, renewal, downgrade) clears it.
    """
    from datetime import UTC, datetime

    from sqlalchemy import or_, select

    from envelock.models import Tenant
    from envelock.notify.account import app_url, notify_admins, plan_title
    from envelock.notify.mail import is_configured

    if not is_configured():
        return {"renewal_reminders": 0, "skipped": "no smtp relay"}

    now = datetime.now(UTC)
    sent = 0

    async with get_sessionmaker()() as session:
        tenants = (
            (
                await session.execute(
                    select(Tenant).where(
                        Tenant.is_active.is_(True),
                        or_(
                            Tenant.trial_ends_at.is_not(None),
                            Tenant.subscription_period_end.is_not(None),
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        for tenant in tenants:
            paid = bool(tenant.payment_method_ok)
            deadline = tenant.subscription_period_end if paid else tenant.trial_ends_at
            if deadline is None:
                continue
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=UTC)

            days_left = (deadline - now).days
            if days_left < 0:
                continue  # already past; the webhook's own email covers the drop
            due = _due_mark(days_left)
            if due is None:
                continue  # further out than the first warning
            already = tenant.renewal_reminder_days
            if already is not None and already <= due:
                continue  # this mark, or a closer one, has already gone

            ending = (not paid) or tenant.subscription_cancel_at_period_end
            # A plan that will simply renew gets its one notice and then goes
            # quiet: the mark is set straight to 0 so no later tick fires again.
            if not ending and already is not None:
                continue

            when = (
                "today"
                if days_left <= 0
                else "tomorrow"
                if days_left == 1
                else f"in {days_left} days"
            )
            tenant.renewal_reminder_days = due if ending else 0

            if ending and not paid:
                subject = f"Your Envelock trial ends {when}"
                heading = f"Your trial ends {when}"
                paragraphs = [
                    f"Your Envelock trial ends {when}.",
                    "Add a payment method to keep your mailboxes protected.",
                ]
                cta_label = "Add a payment method"
                footnote = (
                    "If you don't, your workspace drops to Guard (free) — domain and "
                    "brand monitoring continue, mailbox protection stops. You are never "
                    "locked out, and you can add a card at any time."
                )
            elif ending:
                subject = f"Your Envelock plan ends {when}"
                heading = f"Your plan ends {when}"
                paragraphs = [
                    f"Your Envelock plan is set to cancel and ends {when}.",
                    "Resume it to keep your mailboxes protected.",
                ]
                cta_label = "Resume my plan"
                footnote = (
                    "When it ends, your workspace drops to Guard (free) — domain and "
                    "brand monitoring continue, mailbox protection stops. Your data "
                    "and settings are kept."
                )
            else:
                subject = f"Envelock renews {when}"
                heading = f"{plan_title(tenant.plan)} renews {when}"
                paragraphs = [
                    f"{plan_title(tenant.plan)} renews {when} and your card will be "
                    "charged automatically.",
                    "Nothing for you to do — this is just so the charge isn't a "
                    "surprise.",
                ]
                cta_label = "Review my billing"
                footnote = (
                    "Change plan, seats or card at any time before then in Billing."
                )

            body = "\n\n".join(paragraphs)
            sent += await notify_admins(
                session,
                tenant.id,
                subject=subject,
                heading=heading,
                preheader=paragraphs[0],
                paragraphs=paragraphs,
                text=f"{body}\n\n{app_url('/billing')}",
                cta_label=cta_label,
                cta_url=app_url("/billing"),
                footnote=footnote,
            )
        await session.commit()

    return {"renewal_reminders": sent}


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
            subject = f"Envelock: {built.headline}"
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
                interval=settings.oauth_poll_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "oauth_push_drain", oauth_push_drain_job,
                interval=settings.oauth_push_drain_seconds, stop=stop,
            )
        ),
        asyncio.create_task(
            _run_forever(
                "push_subscriptions", push_subscription_job,
                interval=settings.push_subscription_seconds, stop=stop,
            )
        ),
        # Accounting systems: their tokens are sealed the same way, so their jobs
        # live here with the other credential-holding work.
        asyncio.create_task(
            _run_forever("accounting_requested", accounting_requested_job, interval=15, stop=stop)
        ),
        asyncio.create_task(
            _run_forever("accounting_sync", accounting_sync_job, interval=1800, stop=stop)
        ),
        asyncio.create_task(
            _run_forever("accounting_bills", accounting_bills_job, interval=60, stop=stop)
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
        # Trial and plan expiry warnings at 7/3/2/1/0 days. Shares the digest cadence:
        # both are "scan tenants, decide per row, send rarely", and the milestone
        # column makes a duplicate run a no-op, so the interval only has to be
        # comfortably shorter than a day.
        asyncio.create_task(
            _run_forever(
                "renewal_reminder", renewal_reminder_job,
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
