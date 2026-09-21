"""Observability: structured logs, request correlation, and metrics.

Three separate things a running system needs, kept in one package because they
share the same request-scoped context:

* `logs`    — JSON to stdout in production, human-readable off-prod, with the
              request id and tenant id attached to every line automatically.
* `context` — the contextvars that carry those ids across `await` boundaries.
* `metrics` — Prometheus counters/histograms and the `/metrics` endpoint.

Before this package the product had `structlog` and `prometheus-client` as
declared dependencies and imported neither: no metrics, no structured logs, no
traces, no request ids. For a product whose promise is "we saw what your mail
provider missed", the operator could not answer how many messages were analysed
yesterday, how many alerts fired, or whether the IMAP poller had been dead since
Tuesday.
"""

from envelock.obs.context import (
    bind_request,
    bind_tenant,
    current_request_id,
    current_tenant_id,
)
from envelock.obs.logs import configure_logging, get_logger
from envelock.obs.metrics import (
    observe_alert,
    observe_analysis,
    observe_delivery,
    observe_link_click,
    observe_poll_cycle,
    render_latest,
    set_worker_up,
)

__all__ = [
    "bind_request",
    "bind_tenant",
    "configure_logging",
    "current_request_id",
    "current_tenant_id",
    "get_logger",
    "observe_alert",
    "observe_analysis",
    "observe_delivery",
    "observe_link_click",
    "observe_poll_cycle",
    "render_latest",
    "set_worker_up",
]
