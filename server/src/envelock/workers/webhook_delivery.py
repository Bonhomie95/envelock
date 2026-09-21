"""Deliver signed events to a customer's SIEM (PRD §15.3).

The signing, the envelope and the retry schedule were all written and tested;
what was missing was anything that actually sent. `WebhookEndpoint` was a table
with no code behind it and `RETRY_SCHEDULE` was a constant nothing consulted, so
a customer could be told their SIEM integration existed and receive nothing.

The delivery model is deliberately simple and durable:

* A row in `webhook_deliveries` is the queue. Enqueue is a database insert inside
  the same transaction that raised the alert, so an alert can never be raised
  without its delivery being queued, and a crash between the two is impossible.
* The scheduler drains it. Each attempt either succeeds, or schedules the next
  one from `RETRY_SCHEDULE` — roughly four hours of backoff, enough for a
  customer to survive a deploy without losing alerts.
* Exhausting the schedule marks the delivery failed and deactivates nothing: a
  receiver that is down for a day should not silently unsubscribe itself.

SSRF matters here too. The URL is customer-supplied and we make the request, so
the same guard the IMAP connector uses applies: no loopback, no private ranges,
no cloud metadata.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.governance import export as ex
from envelock.models import WebhookDelivery, WebhookEndpoint

logger = logging.getLogger("envelock.webhooks.out")

#: Delivered bodies are small; a slow receiver must not hold a worker.
REQUEST_TIMEOUT = 10.0

#: How many due deliveries one drain pass will attempt. Bounded so a backlog
#: cannot monopolise the scheduler tick.
BATCH = 50


class UnsafeUrlError(Exception):
    """The destination is one we will never POST to. Permanent — do not retry."""


class UnresolvableUrlError(Exception):
    """We could not resolve the host *right now*.

    Deliberately distinct from `UnsafeUrlError`: a receiver's DNS being briefly
    unavailable, or a record not yet propagated after registration, is exactly
    what the retry schedule exists for. Treating it as permanent would throw away
    a customer's alerts for a blip.
    """


def assert_safe_url(url: str) -> str | None:
    """Refuse to make a customer-supplied request against our own network.

    Same reasoning as the IMAP connector's guard: the URL comes from a form, so
    without this an outbound webhook is a request-forgery primitive pointed at
    whatever the API can reach — including the cloud metadata endpoint.

    Returns the **validated IP address** the caller must dial, or None when the
    guard is disabled. Returning it is the point: checking the hostname here and
    then letting the HTTP client resolve the name again is a TOCTOU window — a
    record with a one-second TTL can answer with a public address for this check
    and 169.254.169.254 for the request that follows. The caller connects to the
    address we approved, carrying the original Host and TLS SNI so the request
    and its certificate check are otherwise unchanged.

    Raises `UnsafeUrlError` for something we will never call, and
    `UnresolvableUrlError` for something we merely cannot call yet.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise UnsafeUrlError("a webhook URL must be http(s)")
    if not parsed.hostname:
        raise UnsafeUrlError("that URL has no host")

    from envelock.config import get_settings

    # A dedicated flag: `imap_allow_private_hosts` exists so a self-hosted mail
    # server on a private IP can be polled — reusing it here silently disabled
    # the SSRF guard on customer-supplied webhook URLs whenever that unrelated
    # IMAP convenience was on.
    if get_settings().webhook_allow_private_hosts:
        return None  # self-hosted SIEM on a private network — opt in explicitly

    try:
        infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise UnresolvableUrlError(
            f"could not resolve {parsed.hostname} right now"
        ) from exc

    chosen: str | None = None
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
        except ValueError:
            continue
        if (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_private
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            # EVERY address the name resolves to must be safe. Accepting the
            # name because one record is public would let a dual-A-record host
            # hand the client the private one.
            raise UnsafeUrlError(
                f"{parsed.hostname} resolves to a private or reserved address; "
                "a webhook must point at a publicly reachable receiver"
            )
        if chosen is None:
            chosen = str(ip)
    if chosen is None:
        raise UnresolvableUrlError(f"no usable address for {parsed.hostname}")
    return chosen


def pinned_request(url: str, ip: str | None) -> tuple[str, dict, dict]:
    """`(dial_url, extra_headers, extensions)` for a request pinned to `ip`.

    The URL we dial carries the approved address, the Host header carries the
    name the customer registered, and `sni_hostname` keeps TLS negotiating — and
    verifying — against that same name. So the certificate check is exactly as
    strict as before while the address can no longer change under us between the
    guard and the request.
    """
    if ip is None:
        return url, {}, {}
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Bracket IPv6 literals for the authority component.
    host_part = f"[{ip}]" if ":" in ip else ip
    rest = parsed.path or "/"
    if parsed.query:
        rest = f"{rest}?{parsed.query}"
    dial = f"{parsed.scheme}://{host_part}:{port}{rest}"
    return dial, {"Host": parsed.netloc}, {"sni_hostname": parsed.hostname}


async def enqueue(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    event: ex.WebhookEvent,
    data: dict,
) -> int:
    """Queue this event for every endpoint of `tenant_id` subscribed to it.

    Called inside the alert transaction, so a queued delivery and the alert it
    describes commit together or not at all. Returns how many were queued.
    """
    endpoints = (
        (
            await session.execute(
                select(WebhookEndpoint).where(
                    WebhookEndpoint.tenant_id == tenant_id,
                    WebhookEndpoint.active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    queued = 0
    for endpoint in endpoints:
        # An empty subscription list means "everything" — the least surprising
        # reading of a customer who registered a URL and chose nothing.
        wanted = list(endpoint.events or [])
        if wanted and event.value not in wanted:
            continue
        session.add(
            WebhookDelivery(
                tenant_id=tenant_id,
                endpoint_id=endpoint.id,
                event_type=event.value,
                payload=ex.webhook_envelope(event, str(tenant_id), data),
                attempt=0,
                next_attempt_at=datetime.now(UTC),
                status="pending",
            )
        )
        queued += 1
    return queued


async def _attempt(session: AsyncSession, delivery: WebhookDelivery) -> bool:
    """One POST. Returns True on a 2xx."""
    endpoint = await session.get(WebhookEndpoint, delivery.endpoint_id)
    if endpoint is None or not endpoint.active:
        delivery.status = "cancelled"
        delivery.last_error = "endpoint removed or disabled"
        return False

    import json

    body = json.dumps(delivery.payload, separators=(",", ":")).encode()
    signature, timestamp = ex.sign_payload(endpoint.secret, body)

    try:
        # Resolve + validate ONCE, then dial the address we approved.
        safe_ip = assert_safe_url(endpoint.url)
        dial_url, pin_headers, extensions = pinned_request(endpoint.url, safe_ip)
        import httpx

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            response = await client.post(
                dial_url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Envelock-Signature": signature,
                    "X-Envelock-Timestamp": str(timestamp),
                    "X-Envelock-Event": delivery.event_type,
                    "User-Agent": "Envelock-Webhooks/1",
                    **pin_headers,
                },
                extensions=extensions,
            )
        ok = 200 <= response.status_code < 300
        endpoint.last_delivery_at = datetime.now(UTC)
        endpoint.last_status = str(response.status_code)
        if not ok:
            delivery.last_error = f"receiver returned {response.status_code}"
        return ok
    except UnsafeUrlError as exc:
        # Not retryable and not the receiver's fault — stop immediately rather
        # than spending four hours of backoff on a URL we will never call.
        delivery.status = "failed"
        delivery.last_error = str(exc)
        endpoint.last_status = "blocked"
        logger.warning("webhook endpoint %s blocked: %s", endpoint.id, exc)
        return False
    except UnresolvableUrlError as exc:
        # Transient by definition — fall through to the normal backoff.
        delivery.last_error = str(exc)
        endpoint.last_status = "unresolved"
        return False
    except Exception as exc:  # noqa: BLE001 — a receiver being down is normal
        delivery.last_error = f"{type(exc).__name__}: {exc}"[:400]
        endpoint.last_status = "error"
        return False


async def drain(session: AsyncSession, *, now: datetime | None = None) -> dict:
    """Attempt every delivery that is due. Returns a summary for the scheduler."""
    now = now or datetime.now(UTC)
    due = (
        (
            await session.execute(
                select(WebhookDelivery)
                .where(
                    WebhookDelivery.status == "pending",
                    WebhookDelivery.next_attempt_at <= now,
                )
                .order_by(WebhookDelivery.next_attempt_at.asc())
                .limit(BATCH)
            )
        )
        .scalars()
        .all()
    )

    summary = {"attempted": 0, "delivered": 0, "retrying": 0, "failed": 0}
    for delivery in due:
        summary["attempted"] += 1
        delivered = await _attempt(session, delivery)
        delivery.attempt += 1
        delivery.last_attempt_at = now

        if delivered:
            delivery.status = "delivered"
            delivery.delivered_at = now
            summary["delivered"] += 1
            continue
        if delivery.status in ("failed", "cancelled"):
            summary["failed"] += 1
            continue

        delay = ex.next_retry_delay(delivery.attempt)
        if delay is None:
            delivery.status = "failed"
            summary["failed"] += 1
        else:
            delivery.next_attempt_at = now + timedelta(seconds=delay)
            summary["retrying"] += 1

    await session.commit()
    return summary


async def webhook_delivery_job() -> dict:
    """Scheduler entry point."""
    from envelock.db import get_sessionmaker

    async with get_sessionmaker()() as session:
        return await drain(session)


__all__ = [
    "UnresolvableUrlError",
    "UnsafeUrlError",
    "assert_safe_url",
    "pinned_request",
    "drain",
    "enqueue",
    "webhook_delivery_job",
]
