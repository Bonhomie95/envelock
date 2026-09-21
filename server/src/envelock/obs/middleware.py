"""Request correlation and HTTP metrics, as one middleware.

Sits outermost so it measures the whole request — including time spent in the
rate limiter and in the security-header layer — and so a request rejected with
429 or 413 still gets an id and still lands in the counters. A middleware that
only measures the requests that reached a handler hides exactly the traffic you
most want to see.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from envelock.obs.context import bind_request, current_request_id, reset_request
from envelock.obs.metrics import observe_http

#: Header a proxy or a caller may set to continue an existing trace. Accepted
#: only as a correlation hint — it is echoed and logged, never trusted for
#: anything that matters — and length-capped so it cannot be used to write
#: unbounded attacker text into the log index.
_INBOUND_HEADER = "x-request-id"
_MAX_INBOUND_ID = 64


def _route_template(request: Request) -> str:
    """The matched route pattern, not the raw path.

    This is the difference between one `/r/{token}` series and one series per
    link ever issued. An unmatched path (404) collapses to a single bucket for
    the same reason: scanners would otherwise mint a metric series per probe.
    """
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return str(path)
    return "<unmatched>"


class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        inbound = (request.headers.get(_INBOUND_HEADER) or "").strip()
        # Alphanumerics, dashes and underscores only: this string is written into
        # structured log output and read back by an operator.
        if inbound and (
            len(inbound) > _MAX_INBOUND_ID
            or not all(c.isalnum() or c in "-_" for c in inbound)
        ):
            inbound = ""

        token = bind_request(inbound or None)
        request_id = current_request_id() or ""
        started = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            # Echo the id so a customer reporting a failure can quote it and an
            # operator can find the exact request in the log index.
            response.headers["X-Request-Id"] = request_id
            return response
        finally:
            observe_http(
                method=request.method,
                route=_route_template(request),
                status=status,
                seconds=time.perf_counter() - started,
            )
            reset_request(token)


__all__ = ["ObservabilityMiddleware"]
