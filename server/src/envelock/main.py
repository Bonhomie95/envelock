"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from envelock import __version__
from envelock.api import (
    admin,
    auth,
    billing,
    channels,
    governance,
    health,
    redirect,
    security_posture,
    sensor,
    staff,
    staff_auth,
    tenants,
    v1,
    webhooks,
)
from envelock.config import get_settings
from envelock.detections import (  # noqa: F401  (registers detections)
    content,
    identity,
    impersonation,
    sessions,
)
from envelock.obs.middleware import ObservabilityMiddleware
from envelock.security.middleware import (
    RequestGuardMiddleware,
    SecurityHeadersMiddleware,
)

logger = logging.getLogger(__name__)



@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    # Structured logging before anything else logs, so no line escapes unstructured.
    # JSON in production (shipped and queried by machine), console off-prod (read
    # by a person). Every line from here on carries the request and tenant ids.
    from envelock.obs import configure_logging
    from envelock.obs.metrics import set_build_info

    configure_logging(
        level=settings.log_level,
        json_output=(
            settings.log_json if settings.log_json is not None else settings.is_production
        ),
    )
    set_build_info(version=__version__, env=settings.env)
    logger.info("envelock starting (env=%s)", settings.env)

    # Card billing half-configured fails quietly in front of a paying customer:
    # no webhook secret → they pay and the plan never activates; a missing
    # price → checkout or extra mailboxes answer "not available". Not a boot
    # refusal (that would take protection down for everyone) — a loud line.
    if settings.stripe_secret_key:
        missing_billing = [
            name
            for name, value in (
                ("ENVELOCK_STRIPE_WEBHOOK_SECRET", settings.stripe_webhook_secret),
                ("ENVELOCK_STRIPE_PRICE_ESSENTIAL", settings.stripe_price_essential),
                ("ENVELOCK_STRIPE_PRICE_COMPLETE", settings.stripe_price_complete),
                (
                    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_ESSENTIAL",
                    settings.stripe_price_extra_mailbox_essential,
                ),
                (
                    "ENVELOCK_STRIPE_PRICE_EXTRA_MAILBOX_COMPLETE",
                    settings.stripe_price_extra_mailbox_complete,
                ),
            )
            if not value
        ]
        if missing_billing:
            logger.error(
                "Stripe is on but billing is incomplete — missing %s "
                "(see LAUNCH-GUIDE step 11)",
                ", ".join(missing_billing),
            )

    # Say out loud what custody this process actually has over stored mailbox
    # credentials (PRD §5.2). "We use a KMS" has to be checkable in a log line,
    # not just claimed in a doc — and a seal-only process needs to know it is one
    # before it starts workers that would fail every poll.
    from envelock.security.keys import custody_summary

    custody = custody_summary()
    can_decrypt_credentials = bool(custody.get("can_decrypt"))
    if not custody.get("ok"):
        logger.error("credential key custody NOT configured: %s", custody.get("error"))
    elif custody.get("separated"):
        logger.info(
            "credential key custody: %s (seal-only — this process cannot decrypt "
            "stored credentials, which is the intended production split)",
            custody["key_id"],
        )
    else:
        logger.info(
            "credential key custody: %s (this process CAN decrypt stored credentials)",
            custody["key_id"],
        )

    # Ensure the schema exists on the configured Postgres. Idempotent, so moving
    # from a local DB to a production one is only a change of ENVELOCK_POSTGRES_DSN.
    from envelock.db import create_all

    # One-time schema rebuild for a DRIFTED database (e.g. a pre-launch Render DB
    # whose `users` table predates `tenant_id`). `create_all` only creates missing
    # tables, never alters existing ones, so a drifted schema keeps 500-ing. Set
    # ENVELOCK_RESET_SCHEMA_ON_STARTUP=true, redeploy once, then set it back to
    # false. DANGER: this WIPES ALL DATA — only for a pre-launch/throwaway DB.
    if settings.reset_schema_on_startup:
        from sqlalchemy import text

        from envelock.db import get_engine

        logger.warning(
            "ENVELOCK_RESET_SCHEMA_ON_STARTUP=true — DROPPING AND REBUILDING THE "
            "SCHEMA. ALL DATA IN THIS DATABASE IS BEING ERASED. Set this back to "
            "false immediately after this deploy, or every restart will wipe it."
        )
        engine = get_engine()
        async with engine.begin() as conn:
            await conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            await conn.execute(text("CREATE SCHEMA public"))

    await create_all()

    # Hydrate the E8 counterparty graph from its durable store so the moat — one
    # tenant's confirmation protecting every other tenant — survives restarts and
    # is shared across instances, not reset on every deploy.
    try:
        from envelock.db import get_sessionmaker
        from envelock.db_rls import system_scope
        from envelock.platform import graph_store

        # The counterparty graph is cross-tenant by design (E8) and this runs at
        # boot with no tenant bound.
        with system_scope("startup: hydrate counterparty graph"):
            async with get_sessionmaker()() as session:
                loaded = await graph_store.hydrate(session)
        logger.info("counterparty graph hydrated (%s verdicts)", loaded)
    except Exception as exc:  # noqa: BLE001
        logger.warning("counterparty graph hydrate skipped: %s", exc)

    # Cross-instance shared state (PRD §17.3). A single instance stays fully
    # in-process; a redis-backed deployment shares the rate-limit window AND the
    # auth-security stores (login lockout, TOTP replay guard, token revocations),
    # so those protections hold across replicas. Any failure logs and falls back
    # to per-instance rather than blocking startup.
    if settings.rate_limit_backend == "redis":
        try:
            import redis.asyncio as aioredis

            from envelock.security import limits

            client = aioredis.from_url(settings.redis_dsn, socket_timeout=2)
            await client.ping()
            limits.use_backend(limits.RedisRateLimiter(client, fallback=limits.limiter))
            limits.use_auth_backends(
                lockout=limits.RedisAccountLockout(client, fallback=limits.lockout),
                replay=limits.RedisReplayGuard(client, fallback=limits.totp_replay),
                revocations=limits.RedisTokenRevocations(client, fallback=limits.revocations),
            )
            logger.info("shared state: redis backend active (rate limit + auth stores)")
        except Exception as exc:  # noqa: BLE001
            logger.warning("shared state: redis unavailable (%s) — using in-process", exc)

    # Live IMAP worker (PRD §5.3). This is what actually *reads* a connected
    # mailbox: without it, connect_imap stores a credential but no mail is ever
    # fetched or analysed. Runs as a background task in-process; a redis-backed
    # multi-instance deployment would elect a single poller, but a single instance
    # is correct as-is. Disabled in tests (they drive the worker directly).
    import asyncio

    imap_stop = asyncio.Event()
    imap_task: asyncio.Task | None = None
    if settings.imap_poll_worker_enabled and not can_decrypt_credentials:
        # Deliberate, not a failure: in the split deployment the API pod holds only
        # the sealing key, so a poller here could never open a credential. Starting
        # it anyway would log an authentication error every 60 seconds and look
        # exactly like broken customer credentials.
        logger.info(
            "imap poll worker not started in this process — it holds no credential "
            "decryption key. Run the worker deployment (with the private key) to poll."
        )
    elif settings.imap_poll_worker_enabled:
        from envelock.workers.imap_fetch import imap_poll_loop
        from envelock.workers.leader import LOCK_IMAP_POLLER, run_as_leader

        # Guarded by a Postgres advisory lock so exactly one process polls,
        # however many replicas are running. Two pollers fetch — and enforce on —
        # the same message twice.
        imap_task = asyncio.create_task(
            run_as_leader(
                LOCK_IMAP_POLLER,
                name="imap poller",
                body=lambda stop: imap_poll_loop(
                    stop, interval_seconds=settings.imap_poll_worker_seconds
                ),
                stop=imap_stop,
            )
        )
        logger.info("imap poll worker enabled (%ss)", settings.imap_poll_worker_seconds)

    # The periodic scheduler (PRD §8.1 E6, §15.2 retention, §17 watchers). This is
    # what makes escalation fire, data actually get purged, OAuth tokens stay alive,
    # and the free Guard tier's CT-log watcher run. One instance owns it.
    scheduler_stop = asyncio.Event()
    scheduler_tasks: list[asyncio.Task] = []
    if settings.scheduler_enabled:
        from envelock.workers import scheduler as sched
        from envelock.workers.leader import LOCK_SCHEDULER, run_as_leader

        # Same reasoning as the poller: two schedulers escalate the same
        # unacknowledged Critical twice, which in the E6 ladder is the customer's
        # phone ringing twice a cycle.
        async def _run_scheduler(stop: asyncio.Event) -> None:
            tasks = sched.start(stop)
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()

        scheduler_tasks = [
            asyncio.create_task(
                run_as_leader(
                    LOCK_SCHEDULER,
                    name="scheduler",
                    body=_run_scheduler,
                    stop=scheduler_stop,
                )
            )
        ]

    # Tier-1 OAuth token refresh + fetch. Needs the credential decryption key,
    # so — like the IMAP poller — it starts only where that key is held, under a
    # lock of its own. It used to ride on the scheduler's lock, so under split
    # custody it ran in whichever process booted first; when that was the API,
    # OAuth tokens were refreshed nowhere and those mailboxes went dark.
    oauth_stop = asyncio.Event()
    oauth_task: asyncio.Task | None = None
    if settings.scheduler_enabled and can_decrypt_credentials:
        from envelock.workers import scheduler as sched_oauth
        from envelock.workers.leader import LOCK_OAUTH, run_as_leader

        async def _run_oauth(stop: asyncio.Event) -> None:
            tasks = sched_oauth.start_oauth_jobs(stop)
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()

        oauth_task = asyncio.create_task(
            run_as_leader(LOCK_OAUTH, name="oauth jobs", body=_run_oauth, stop=oauth_stop)
        )
    elif settings.scheduler_enabled:
        logger.info(
            "oauth refresh/fetch not started in this process — it holds no "
            "credential decryption key. The worker deployment runs them."
        )

    # Tier-4 forwarding ingest (SMTP). Optional in-app listener so forwarding works
    # without a separate process; production may instead point MX at a dedicated host.
    smtp_stop = asyncio.Event()
    smtp_task: asyncio.Task | None = None
    if settings.ingest_smtp_in_app:
        from envelock.workers.smtp_ingest import run_forever as smtp_run

        smtp_task = asyncio.create_task(smtp_run(smtp_stop))
        logger.info(
            "smtp forwarding ingest enabled in-app (%s:%s)",
            settings.ingest_smtp_host, settings.ingest_smtp_port,
        )

    yield

    smtp_stop.set()
    oauth_stop.set()

    scheduler_stop.set()
    if imap_task is not None:
        imap_stop.set()
        imap_task.cancel()
    import contextlib

    for task in [imap_task, smtp_task, oauth_task, *scheduler_tasks]:
        if task is None:
            continue
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    logger.info("envelock stopped")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Envelock",
        description="Email fraud and account-takeover protection",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url=None,
    )

    # Order matters, and Starlette applies these outermost-last: the
    # observability layer is added LAST so it wraps everything and therefore
    # measures the whole request — including one the rate limiter rejects with
    # 429 or the size guard rejects with 413. A middleware that only sees
    # requests which reached a handler hides exactly the traffic you need.
    app.add_middleware(SecurityHeadersMiddleware, production=settings.is_production)
    app.add_middleware(RequestGuardMiddleware)
    app.add_middleware(ObservabilityMiddleware)

    # CORS is required in production too: the web client is served from a
    # different origin (e.g. Vercel) than this API (e.g. Render), so its origin
    # must be allow-listed or the browser blocks every call. Origins come from
    # ENVELOCK_CORS_ORIGINS (plus localhost dev). Explicit list rather than "*":
    # a wildcard with credentials is a cross-origin credential leak waiting to
    # happen.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )

    # Outermost: a hard byte ceiling on every request body, counted as received.
    # The Content-Length check inside RequestGuardMiddleware is advisory only —
    # a chunked request carries no Content-Length and walked straight past it.
    from envelock.security.middleware import BodySizeLimitMiddleware

    app.add_middleware(BodySizeLimitMiddleware)

    # A 500 raised inside a handler is turned into a response by Starlette's
    # ServerErrorMiddleware, which sits *outside* the CORS layer — so that error
    # never gets an Access-Control-Allow-Origin header, and the browser reports it
    # as a misleading "CORS policy" block instead of the real error. Attaching the
    # CORS header here means a real 500 surfaces as a real 500 the client can read.
    from fastapi import Request
    from fastapi.responses import JSONResponse

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:  # noqa: ANN001
        logger.exception(
            "unhandled error on %s %s", request.method, request.url.path
        )
        resp = JSONResponse(
            status_code=500,
            content={"detail": "internal server error", "path": request.url.path},
        )
        # This handler runs in Starlette's ServerErrorMiddleware, OUTSIDE the
        # middleware stack — so 500s would otherwise be the only responses that
        # skip the security headers. Apply the ones that matter on an error page.
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
        )
        if settings.env == "production":
            resp.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )
        origin = request.headers.get("origin")
        if origin and origin in settings.cors_origin_list:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Vary"] = "Origin"
        return resp

    # ── Core: everything the two launch features need ────────────────────────
    # (1) link safety, (2) payment safety — plus auth, domain verification,
    # mailbox connect, alerts and their delivery. This is the whole v1 product.
    app.include_router(health.router, tags=["health"])
    app.include_router(v1.router, tags=["v1"])
    app.include_router(auth.router)
    app.include_router(tenants.router)
    app.include_router(channels.router)
    #: Enrolling, listing and revoking client sensors (the heartbeats and read
    #: attestations themselves live in channels). Core: without it the Group-C
    #: account-takeover detections the Complete plan sells have no data at all.
    app.include_router(sensor.router)
    app.include_router(webhooks.router)
    #: The click-time redirector — the enforcement half of link safety.
    app.include_router(redirect.router)

    # Billing is CORE, not an extra. It was parked behind `focus_core` while the
    # client's /billing route was also commented out — so the default deployment
    # had no route by which a customer could pay. A trial starts at registration
    # on the top plan and drops to Guard after fifteen days, which meant every
    # signup hit a dead end on day sixteen: the upgrade handler receives 402 and
    # sends them to a page that did not exist. A product that cannot take money
    # is not a shipped product, whatever else is switched on.
    app.include_router(billing.router)

    # Governance/SIEM export is core too, and for a smaller but real reason: the
    # dashboard reads `/api/v1/metrics/quality` from this router, so with it
    # unmounted the quality panel silently 404'd and rendered nothing on every
    # production deployment.
    app.include_router(governance.router)

    # ── Everything else, parked behind ENVELOCK_FOCUS_CORE=false ────────────
    # The staff/admin console is genuinely separable: it is a different app on a
    # different hostname, for Envelock's own operators, and a v1 without it costs
    # a customer nothing.
    if not settings.focus_core:
        # Order matters: the staff routers declare `/admin/staff…` and
        # `/admin/auth/…`, which must be matched before `admin.router`'s
        # `/admin/tenants/{tenant_id}`-style paths get a chance to swallow them.
        app.include_router(staff_auth.router)
        app.include_router(staff.router)
        app.include_router(security_posture.router)
        app.include_router(admin.router)
    return app


app = create_app()
