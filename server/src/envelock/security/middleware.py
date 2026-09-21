"""Security headers, request limits and rate-limit enforcement."""

from __future__ import annotations

import ipaddress
from collections.abc import Awaitable, Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from envelock.config import get_settings
from envelock.security.limits import MAX_RAW_MESSAGE_BYTES, active_limiter

#: Route prefix → rate-limit bucket. Most specific match wins.
_BUCKETS: tuple[tuple[str, str], ...] = (
    # Redeeming a pairing code is the one sensor call with no credential at
    # all, and the tight limit is what makes an 8-character code safe to use.
    # Listed before the general sensor prefix so it matches first.
    ("/api/v1/sensor/enroll", "sensor.enroll"),
    # Heartbeats and read attestations. Keyed by address, so it has to be sized
    # for a whole office behind one NAT, each device beating once a minute.
    ("/api/v1/sensor/", "sensor"),
    ("/api/v1/auth/login", "auth.login"),
    ("/api/v1/auth/register", "auth.register"),
    ("/api/v1/auth/mfa", "auth.mfa"),
    ("/api/v1/auth/phone", "auth.phone"),
    # Password reset SENDS EMAIL to an address the caller names. It matched no
    # prefix here and fell through to the 120-per-minute default, which made it
    # an email bomb aimed at any address an attacker knew — and a fast way to
    # burn our sending reputation. `/password` covers forgot, reset,
    # reset-with-code and the authenticated change.
    ("/api/v1/auth/password", "auth.password"),
    ("/api/v1/auth/recovery", "auth.recovery"),
    # Verification resend SENDS EMAIL to a caller-named address — same bombing
    # shape as password reset, same tight bucket.
    ("/api/v1/auth/verify-email", "auth.password"),
    ("/api/v1/auth/refresh", "auth.refresh"),
    ("/api/v1/analyse", "analyse"),
    ("/api/v1/domains", "scan.domain"),
    ("/api/v1/export", "export"),
    # The click-time redirector. Unauthenticated by design — the person
    # clicking is reading their mail, not signed into us — and every hit does a
    # live reputation evaluation plus a click-ledger insert. Anyone holding one
    # valid token (i.e. the recipient of any protected message) could otherwise
    # drive unbounded Safe Browsing lookups and database writes. Generous, so a
    # mail client prefetching links in a thread is never throttled.
    ("/r/", "redirect"),
    # Unauthenticated (or cheap-to-call) surfaces that each drive real work —
    # provider sync, DNS/RDAP lookups, or a full pipeline run — previously fell
    # through to the generous default bucket.
    ("/api/v1/webhooks/", "webhooks"),
    ("/api/v1/brand/", "brand"),
    ("/api/v1/simulate", "simulate"),
    ("/api/v1/ingest", "ingest"),
    # Unauthenticated, and it probes Postgres and Redis on every call — see the
    # rule's note in security/limits.py.
    ("/api/v1/status/public", "status"),
)


def _subject_of(token: str) -> str | None:
    """The `sub` claim of a token whose signature we have verified.

    This used to read the claim straight out of the unverified payload, on the
    reasoning that "a forged subject can only throttle itself". That reasoning
    is wrong, and it cost us every rate limit in the product.

    The buckets that matter most — `auth.login`, `auth.register`,
    `auth.password`, `auth.phone`, `analyse` — sit on endpoints that take no
    authentication at all. Nothing downstream ever looks at the header, so an
    attacker could attach a *random* unsigned bearer to each request, land in a
    fresh empty sliding window every time, and send unlimited password-reset
    mail to any address, unlimited SMS at our cost, or unlimited 25 MB bodies
    into the synchronous parsers. A forged subject did not throttle itself; it
    escaped the throttle entirely.

    Verifying costs one HMAC-SHA256 over a few hundred bytes — far less than the
    Redis round-trip the limiter is about to make. An unsigned, expired or
    malformed token yields None and the caller falls back to the peer address,
    which is the correct bucket for an anonymous request.
    """
    from envelock.auth.security import TokenError, decode_token

    try:
        # No `expect`: refresh tokens hit /auth/refresh and staff tokens hit the
        # console, and both should bucket by subject like anything else.
        claims = decode_token(token)
    except TokenError:
        return None
    return str(claims.sub)


def _bucket_for(path: str) -> str:
    for prefix, bucket in _BUCKETS:
        if path.startswith(prefix):
            return bucket
    return "default"


def _is_local_peer(host: str | None) -> bool:
    """Whether the immediate peer is a reverse proxy on our own network.

    A request arriving from loopback or a private range did not come from the
    internet: something on this host or in this VPC forwarded it. That is the
    only situation in which `X-Forwarded-For` is worth anything.
    """
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local


def client_identity(request: Request) -> str:
    """Who to charge this request to: the authenticated subject, else the client
    address.

    Getting the address wrong is not a small problem. In the standard deployment
    — nginx terminating TLS on the same box and proxying to 127.0.0.1 — the peer
    address is the PROXY for every request on the platform. Every customer then
    lands in one bucket, so "10 sign-ins per 5 minutes" becomes ten sign-ins for
    the entire product, and the second customer of the day is told to come back
    later. It presents to the customer as the feature being broken.

    So `X-Forwarded-For` is honoured when, and only when, the immediate peer is
    local: a request forwarded by our own proxy. A request arriving directly from
    a public address carries an attacker-controlled header, and it is ignored.
    `ENVELOCK_TRUST_FORWARDED_FOR` still forces the header on for a proxy that is
    genuinely remote (a CDN), where the peer is public and this heuristic cannot
    tell the difference on its own.
    """
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        # Bucket by the *subject*, not the token string. Hashing the token meant
        # every rotation produced a fresh bucket, so anyone holding a refresh
        # token could reset their own limit at will. The subject is taken only
        # from a token whose signature verifies — see `_subject_of`; trusting the
        # unverified payload here made every limit in the product bypassable.
        subject = _subject_of(auth[7:].strip())
        if subject:
            return f"sub:{subject}"

    peer = request.client.host if request.client else None
    if get_settings().trust_forwarded_for or _is_local_peer(peer):
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            # The left-most entry is the original client the proxy saw.
            client = forwarded.split(",")[0].strip()
            if client:
                return f"ip:{client}"
    if peer:
        return f"ip:{peer}"
    return "ip:unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Defence-in-depth headers on every response."""

    def __init__(self, app, *, production: bool) -> None:  # noqa: ANN001
        super().__init__(app)
        self.production = production

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=()"
        # The API returns JSON only — except the click-time redirector, whose
        # block/interstitial pages are real HTML shown to a person mid-click.
        # They use inline styles only (no scripts, no external loads), so
        # style-src 'unsafe-inline' is the whole allowance.
        if request.url.path.startswith("/r/"):
            h["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'unsafe-inline'; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            )
        else:
            h["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
            )
        h["Cache-Control"] = "no-store"
        if self.production:
            h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        # Do not advertise the stack. MutableHeaders has no pop().
        if "server" in h:
            del h["server"]
        return response


class RequestGuardMiddleware(BaseHTTPMiddleware):
    """Body-size ceiling and rate limiting, applied before routing work."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > MAX_RAW_MESSAGE_BYTES:
            return JSONResponse(
                {"detail": "request body too large"},
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            )

        path = request.url.path
        if path.startswith(("/api/", "/r/")):
            bucket = _bucket_for(path)
            allowed, retry_after = await active_limiter().acheck(
                bucket, client_identity(request)
            )
            if not allowed:
                return JSONResponse(
                    {"detail": "rate limit exceeded", "retry_after": retry_after},
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(retry_after)},
                )

        return await call_next(request)


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Pure-ASGI body ceiling that counts the bytes actually received.

    The Content-Length check in RequestGuardMiddleware is advisory: a request
    with `Transfer-Encoding: chunked` carries no Content-Length at all, so it
    sailed past the ceiling and was buffered whole by the endpoint — no limit on
    any route, /auth/login included. This wraps `receive` itself, so the cap
    holds no matter what the headers claim. Pure ASGI (not BaseHTTPMiddleware)
    so it sits outside the buffering stack.
    """

    def __init__(self, app, max_bytes: int = MAX_RAW_MESSAGE_BYTES) -> None:  # noqa: ANN001
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):  # noqa: ANN001
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        received = 0
        response_started = False

        async def wrapped_send(message):  # noqa: ANN001
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        async def wrapped_receive():  # noqa: ANN001
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        try:
            await self.app(scope, wrapped_receive, wrapped_send)
        except _BodyTooLargeError:
            if not response_started:
                await send(
                    {
                        "type": "http.response.start",
                        "status": 413,
                        "headers": [(b"content-type", b"application/json")],
                    }
                )
                await send(
                    {
                        "type": "http.response.body",
                        "body": b'{"detail": "request body too large"}',
                    }
                )
