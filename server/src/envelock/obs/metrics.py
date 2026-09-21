"""Prometheus metrics.

The metric set is chosen to answer the questions an operator actually asks at
3am, in the order they ask them:

  1. Is it up and serving?            → http request rate, error rate, latency
  2. Is it *reading mail*?            → poll cycles, mailboxes polled, fetch count
  3. Is it *finding* anything?        → messages analysed, findings, alerts by tier
  4. Did the customer hear about it?  → notification deliveries by rung and status
  5. What is it costing?              → cascade fall-through, LLM judge calls

Label cardinality is the one way a metrics endpoint becomes an outage of its own,
so every label here is drawn from a closed set: a route *template* rather than a
path (`/r/{token}` is one series, not one per link ever issued), a tier, a rung,
an outcome. Nothing takes a tenant id, a mailbox address or a domain.
"""

from __future__ import annotations

import contextlib

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

#: Our own registry rather than the global default. The default registry also
#: carries the process and GC collectors, which are useful — they are registered
#: explicitly below so the set is deliberate rather than whatever happens to have
#: imported prometheus_client.
REGISTRY = CollectorRegistry(auto_describe=True)

with contextlib.suppress(Exception):  # pragma: no cover — platform dependent
    # Process RSS/FDs, Python version and GC stats. Registered explicitly so the
    # exported set is a deliberate choice rather than whatever imported the
    # library first. Never allowed to block startup.
    from prometheus_client import GC_COLLECTOR, PLATFORM_COLLECTOR, PROCESS_COLLECTOR

    REGISTRY.register(PROCESS_COLLECTOR)
    REGISTRY.register(PLATFORM_COLLECTOR)
    REGISTRY.register(GC_COLLECTOR)


BUILD = Gauge(
    "envelock_build_info",
    "Build and deployment identity. Always 1; the labels carry the information.",
    ["version", "env"],
    registry=REGISTRY,
)

# ── 1. Serving ───────────────────────────────────────────────────────────────
HTTP_REQUESTS = Counter(
    "envelock_http_requests_total",
    "HTTP requests by route template, method and status class.",
    ["method", "route", "status"],
    registry=REGISTRY,
)

HTTP_LATENCY = Histogram(
    "envelock_http_request_duration_seconds",
    "Request latency by route template.",
    ["method", "route"],
    # Tuned for this app: most calls are a few DB round-trips, but the IMAP
    # connect probe and the analyse endpoint legitimately take seconds.
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
    registry=REGISTRY,
)

# ── 2. Reading mail ──────────────────────────────────────────────────────────
POLL_CYCLES = Counter(
    "envelock_imap_poll_cycles_total",
    "IMAP poll cycles completed, by outcome.",
    ["outcome"],
    registry=REGISTRY,
)

POLL_MAILBOXES = Gauge(
    "envelock_imap_last_cycle_mailboxes",
    "Mailboxes visited in the most recent poll cycle.",
    registry=REGISTRY,
)

POLL_FETCHED = Counter(
    "envelock_imap_messages_fetched_total",
    "Messages fetched from customer mailboxes.",
    registry=REGISTRY,
)

POLL_ERRORS = Counter(
    "envelock_imap_poll_errors_total",
    "Per-mailbox poll failures. A mailbox erroring every cycle is a customer "
    "whose protection is silently off.",
    registry=REGISTRY,
)

WORKER_UP = Gauge(
    "envelock_worker_up",
    "1 when a background worker completed its most recent cycle without dying.",
    ["worker"],
    registry=REGISTRY,
)

WORKER_LAST_RUN = Gauge(
    "envelock_worker_last_success_timestamp_seconds",
    "Unix time of the last successful cycle. Alert on `time() - this` — a poller "
    "that stopped is indistinguishable from a quiet inbox without it.",
    ["worker"],
    registry=REGISTRY,
)

# ── 3. Finding things ────────────────────────────────────────────────────────
MESSAGES_ANALYSED = Counter(
    "envelock_messages_analysed_total",
    "Messages put through the detection pipeline, by ingest source.",
    ["source"],
    registry=REGISTRY,
)

ANALYSIS_LATENCY = Histogram(
    "envelock_analysis_duration_seconds",
    "End-to-end pipeline latency per message.",
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0),
    registry=REGISTRY,
)

FINDINGS = Counter(
    "envelock_findings_total",
    "Detections that fired, by PRD service id (A1, C4, D4…).",
    ["service"],
    registry=REGISTRY,
)

ALERTS = Counter(
    "envelock_alerts_raised_total",
    "Alerts raised, by tier.",
    ["tier"],
    registry=REGISTRY,
)

QUARANTINES = Counter(
    "envelock_quarantines_total",
    "Messages moved out of a customer inbox — the enforcement action.",
    registry=REGISTRY,
)

REWRITES = Counter(
    "envelock_protected_copies_written_total",
    "Messages rewritten in place with safe links and/or a warning banner.",
    registry=REGISTRY,
)

LINK_CLICKS = Counter(
    "envelock_link_clicks_total",
    "Rewritten-link clicks by what the redirector did.",
    ["action"],
    registry=REGISTRY,
)

# ── 4. Telling the customer ──────────────────────────────────────────────────
DELIVERIES = Counter(
    "envelock_notification_deliveries_total",
    "Notification ladder attempts by rung and status. A rung failing silently is "
    "the failure mode that loses the customer money.",
    ["rung", "status"],
    registry=REGISTRY,
)

# ── 5. Cost ──────────────────────────────────────────────────────────────────
LLM_CALLS = Counter(
    "envelock_llm_judge_calls_total",
    "LLM judge invocations by outcome — the metered last rung of the cascade.",
    ["outcome"],
    registry=REGISTRY,
)

CASCADE_LAYER = Counter(
    "envelock_cascade_resolutions_total",
    "Which cascade layer resolved an artefact. Fall-through to the paid layers is "
    "the number that predicts COGS.",
    ["kind", "layer"],
    registry=REGISTRY,
)


# ── Recording helpers ────────────────────────────────────────────────────────
# Thin wrappers so call sites never import prometheus_client directly and a
# metric rename stays a one-file change. Every one swallows its own errors:
# instrumentation must never be able to fail the thing it measures.


def _safe(fn) -> None:  # noqa: ANN001
    # Instrumentation must never be able to fail the thing it measures: a metric
    # that raises would turn an observability bug into a customer-facing 500.
    with contextlib.suppress(Exception):
        fn()


def set_build_info(*, version: str, env: str) -> None:
    _safe(lambda: BUILD.labels(version=version, env=env).set(1))


def observe_http(*, method: str, route: str, status: int, seconds: float) -> None:
    _safe(lambda: HTTP_REQUESTS.labels(method, route, str(status)).inc())
    _safe(lambda: HTTP_LATENCY.labels(method, route).observe(seconds))


def observe_analysis(
    *,
    source: str,
    seconds: float,
    findings: list[str] | None = None,
    tier: str | None = None,
) -> None:
    _safe(lambda: MESSAGES_ANALYSED.labels(source).inc())
    _safe(lambda: ANALYSIS_LATENCY.observe(seconds))
    for service in findings or []:
        _safe(lambda s=service: FINDINGS.labels(s).inc())
    if tier:
        _safe(lambda: ALERTS.labels(tier).inc())


def observe_alert(tier: str) -> None:
    _safe(lambda: ALERTS.labels(tier).inc())


def observe_delivery(*, rung: str, status: str) -> None:
    _safe(lambda: DELIVERIES.labels(rung, status).inc())


def observe_link_click(action: str) -> None:
    _safe(lambda: LINK_CLICKS.labels(action).inc())


def observe_poll_cycle(
    *,
    outcome: str,
    mailboxes: int = 0,
    fetched: int = 0,
    errors: int = 0,
    quarantined: int = 0,
    rewritten: int = 0,
) -> None:
    _safe(lambda: POLL_CYCLES.labels(outcome).inc())
    _safe(lambda: POLL_MAILBOXES.set(mailboxes))
    if fetched:
        _safe(lambda: POLL_FETCHED.inc(fetched))
    if errors:
        _safe(lambda: POLL_ERRORS.inc(errors))
    if quarantined:
        _safe(lambda: QUARANTINES.inc(quarantined))
    if rewritten:
        _safe(lambda: REWRITES.inc(rewritten))


def set_worker_up(worker: str, *, up: bool, at: float | None = None) -> None:
    import time as _time

    _safe(lambda: WORKER_UP.labels(worker).set(1 if up else 0))
    if up:
        _safe(lambda: WORKER_LAST_RUN.labels(worker).set(at or _time.time()))


def observe_llm(outcome: str) -> None:
    _safe(lambda: LLM_CALLS.labels(outcome).inc())


def observe_cascade(*, kind: str, layer: str) -> None:
    _safe(lambda: CASCADE_LAYER.labels(kind, layer).inc())


def render_latest() -> tuple[bytes, str]:
    """The exposition payload and its content type."""
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


__all__ = [
    "REGISTRY",
    "observe_alert",
    "observe_analysis",
    "observe_cascade",
    "observe_delivery",
    "observe_http",
    "observe_link_click",
    "observe_llm",
    "observe_poll_cycle",
    "render_latest",
    "set_build_info",
    "set_worker_up",
]
