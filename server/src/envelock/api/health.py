"""Liveness and readiness.

These are two different questions and they need two different answers, which is
why they are two endpoints.

* **Liveness** (`/health`) — "is this process still running its event loop?" It
  must touch nothing external. A liveness probe that fails on a database blip
  gets the container *killed and restarted*, which cannot fix a database blip and
  turns a brief dependency outage into a restart loop across every replica.

* **Readiness** (`/ready`) — "can this process actually serve a request?" It
  checks the dependencies whose absence makes every real endpoint fail. This is
  what a load balancer, a deploy gate and a container healthcheck should read.

Before this split there was only `/health`, and it returned 200 unconditionally
without touching a single dependency — while `deploy/deploy.sh` gated the deploy
on it and the Dockerfile's HEALTHCHECK trusted it. A release that could not reach
Postgres was reported as a successful deploy and a healthy container.
"""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import text

from envelock import __version__
from envelock.config import get_settings

logger = logging.getLogger("envelock.health")
router = APIRouter()

#: A readiness probe must fail fast. Hanging until the client gives up looks
#: identical to "healthy but slow" to most orchestrators.
_PROBE_TIMEOUT_SECONDS = 3.0


class HealthResponse(BaseModel):
    status: str
    version: str
    env: str


class ReadyResponse(BaseModel):
    status: str
    version: str
    env: str
    checks: dict[str, str]


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness only. Deliberately touches nothing — see the module docstring."""
    settings = get_settings()
    return HealthResponse(status="ok", version=__version__, env=settings.env)


async def _check_database() -> str:
    from envelock.db import get_sessionmaker

    async with get_sessionmaker()() as session:
        await session.execute(text("SELECT 1"))
    return "ok"


async def _check_redis() -> str:
    settings = get_settings()
    if settings.rate_limit_backend != "redis":
        return "not_configured"
    import redis.asyncio as aioredis

    client = aioredis.from_url(settings.redis_dsn, socket_timeout=2)
    try:
        await client.ping()
        return "ok"
    finally:
        await client.aclose()


@router.get("/ready", response_model=ReadyResponse)
async def ready(response: Response) -> ReadyResponse:
    """Readiness: 200 only when this process can actually serve traffic.

    Redis being down degrades rate limiting to per-instance rather than breaking
    the product (`main.py` falls back deliberately), so it is reported but does
    not fail the probe. Postgres is not optional: without it every authenticated
    endpoint 500s, and a replica in that state should be taken out of rotation
    rather than left serving errors.
    """
    settings = get_settings()
    checks: dict[str, str] = {}

    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            checks["database"] = await _check_database()
    except Exception as exc:  # noqa: BLE001 — any failure means "not ready"
        logger.warning("readiness: database check failed: %s", exc)
        checks["database"] = f"failed: {type(exc).__name__}"

    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            checks["redis"] = await _check_redis()
    except Exception as exc:  # noqa: BLE001
        logger.warning("readiness: redis check failed: %s", exc)
        checks["redis"] = f"degraded: {type(exc).__name__}"

    ok = checks["database"] == "ok"
    if not ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadyResponse(
        status="ready" if ok else "not_ready",
        version=__version__,
        env=settings.env,
        checks=checks,
    )


# ── Public status ────────────────────────────────────────────────────────────
class StatusComponent(BaseModel):
    id: str
    name: str
    #: operational | degraded | down. Three states, not five: a status page whose
    #: vocabulary is finer than the customer's decision ("do I need to do
    #: something?") is decoration.
    state: str
    detail: str


class PublicStatusResponse(BaseModel):
    state: str
    summary: str
    components: list[StatusComponent]
    checked_at: str


@router.get("/api/v1/status/public", response_model=PublicStatusResponse)
async def public_status() -> PublicStatusResponse:
    """The status page's source of truth. Unauthenticated, and deliberately thin.

    Under `/api/v1/` rather than a bare `/status`, even though it is a
    root-level concern like `/health`: the web app owns the route `/status` for
    the page itself, and in development both are served through one origin, so a
    bare `/status` on the API made the dev proxy shadow the page with its own
    JSON. Production splits the hosts and would not have shown this — which is
    exactly the kind of difference that ships.

    We ask businesses to hand us access to their mail. The minimum we owe them in
    return is somewhere to look that is not our marketing site when something
    feels wrong — and somewhere that keeps answering when the product itself is
    the thing that is broken.

    What this must never become is `/ready` with a nicer name. `/ready` names the
    exception class on failure, which tells an attacker which dependency is down
    and what it is built on; this reports three states and a sentence a customer
    can act on. It also reports the two things a customer actually experiences —
    can mail be analysed, and do alerts still go out — rather than the names of
    our internal services.
    """
    from datetime import UTC, datetime

    components: list[StatusComponent] = []

    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            await _check_database()
        db_ok = True
    except Exception as exc:  # noqa: BLE001
        logger.warning("status: database check failed: %s", exc)
        db_ok = False

    try:
        async with asyncio.timeout(_PROBE_TIMEOUT_SECONDS):
            redis_state = await _check_redis()
    except Exception as exc:  # noqa: BLE001
        logger.warning("status: redis check failed: %s", exc)
        redis_state = "degraded"

    components.append(
        StatusComponent(
            id="analysis",
            name="Mail analysis",
            state="operational" if db_ok else "down",
            detail=(
                "Messages are being analysed as they arrive."
                if db_ok
                else "Analysis is interrupted. Your mail is unaffected — Envelock is "
                "never in the delivery path — but new messages are not being checked."
            ),
        )
    )
    components.append(
        StatusComponent(
            id="alerts",
            name="Alerts and escalation",
            state="operational" if db_ok else "down",
            detail=(
                "Alerts are being raised and escalated normally."
                if db_ok
                else "New alerts cannot be raised while analysis is interrupted."
            ),
        )
    )
    components.append(
        StatusComponent(
            id="mail_flow",
            name="Your email delivery",
            # Structurally true, not measured: Envelock sits alongside mail, never
            # in the delivery path, so there is no failure of ours that can hold
            # up a message. Saying so on the page is the single most useful line
            # on it during an incident.
            state="operational",
            detail=(
                "Unaffected by definition — Envelock is never in your mail's "
                "delivery path, so nothing here can delay or lose a message."
            ),
        )
    )
    components.append(
        StatusComponent(
            id="dashboard",
            name="Dashboard and API",
            state="operational" if db_ok else "degraded",
            detail=(
                "Signing in and the API are responding."
                if db_ok
                else "The dashboard may be slow or unavailable."
            ),
        )
    )
    if redis_state not in ("ok", "not_configured"):
        components.append(
            StatusComponent(
                id="throttling",
                name="Rate limiting",
                state="degraded",
                detail=(
                    "Running per-instance rather than shared. No customer-visible "
                    "effect; noted for transparency."
                ),
            )
        )

    worst = "operational"
    if any(c.state == "down" for c in components):
        worst = "down"
    elif any(c.state == "degraded" for c in components):
        worst = "degraded"

    summary = {
        "operational": "All systems operational.",
        "degraded": "Running with reduced capability.",
        "down": "We have a problem and we are on it. Your mail is still flowing.",
    }[worst]

    return PublicStatusResponse(
        state=worst,
        summary=summary,
        components=components,
        checked_at=datetime.now(UTC).isoformat(),
    )


# ── Metrics ──────────────────────────────────────────────────────────────────
def _peer_is_local(request: Request) -> bool:
    """Whether the immediate peer is on this host or in this private network.

    The standard deployment has nginx proxying from 127.0.0.1 and Prometheus
    scraping over the private network, so this covers the real cases without a
    shared secret. It deliberately does NOT consult `X-Forwarded-For`: that
    header is caller-controlled, and trusting it here would make the whole check
    a formality.
    """
    import ipaddress

    host = request.client.host if request.client else None
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    """Prometheus exposition.

    Closed by default, two ways to open it. `ENVELOCK_METRICS_TOKEN` is the
    explicit one — a bearer the scraper presents, compared in constant time. With
    no token set, the endpoint serves only local/private peers, which is the
    nginx-and-Prometheus-on-the-same-VPC case. A public, unauthenticated
    `/metrics` would publish alert volumes, mailbox counts and error rates to
    anyone who asked, which is competitive intelligence at best and a target list
    at worst.
    """
    import hmac

    from envelock.obs.metrics import render_latest

    settings = get_settings()
    configured = settings.metrics_token.get_secret_value() if settings.metrics_token else ""

    if configured:
        presented = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(presented, configured):
            return Response(status_code=status.HTTP_404_NOT_FOUND)
    elif not _peer_is_local(request):
        return Response(status_code=status.HTTP_404_NOT_FOUND)

    payload, content_type = render_latest()
    return Response(content=payload, media_type=content_type)
