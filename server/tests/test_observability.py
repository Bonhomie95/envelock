"""Telemetry, and the session revocation it took a metric to notice.

`structlog` and `prometheus-client` were declared dependencies that nothing
imported: no metrics, no structured logs, no request ids. An operator could not
answer how many messages were analysed yesterday, how many alerts fired, or
whether the IMAP poller had been dead since Tuesday.

These pin the parts that would otherwise rot silently — a metrics endpoint is
exactly the kind of thing that keeps returning 200 while measuring nothing.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

#: TestClient reports a peer of "testclient", which is not an IP address, so the
#: local-peer path cannot apply — the tests therefore use the bearer-token path.
#: The peer check is covered directly in `test_peer_check` below.
SCRAPER_TOKEN = "scraper-secret"  # noqa: S105 — a test fixture, not a credential
SCRAPER = {"Authorization": f"Bearer {SCRAPER_TOKEN}"}


@pytest.fixture
def scrapeable(monkeypatch):  # noqa: ANN001, ANN201
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_METRICS_TOKEN", SCRAPER_TOKEN)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── The endpoint itself ──────────────────────────────────────────────────────
def test_metrics_are_served_to_an_authorised_scraper(
    client: TestClient, scrapeable: None
) -> None:
    r = client.get("/metrics", headers=SCRAPER)
    assert r.status_code == 200
    assert "envelock_build_info" in r.text
    assert "envelock_http_requests_total" in r.text


def test_metrics_are_closed_by_default_to_a_non_local_caller(
    client: TestClient,
) -> None:
    """With no token set, only a local/private peer may scrape. A TestClient is
    neither, so this is the internet-facing case."""
    assert client.get("/metrics").status_code == 404


def test_peer_check_accepts_a_proxy_and_refuses_the_internet() -> None:
    """The standard deployment has nginx proxying from 127.0.0.1 and Prometheus
    on the private network. `X-Forwarded-For` is deliberately NOT consulted:
    trusting a caller-supplied header here would make the check a formality."""
    from types import SimpleNamespace

    from envelock.api.health import _peer_is_local

    def peer(host: str | None):  # noqa: ANN202
        return SimpleNamespace(
            client=SimpleNamespace(host=host) if host else None, headers={}
        )

    assert _peer_is_local(peer("127.0.0.1"))
    assert _peer_is_local(peer("10.0.3.7"))
    assert _peer_is_local(peer("192.168.1.20"))
    # 8.8.8.8, not a 203.0.113.x documentation address: Python classifies the
    # RFC 5737 documentation ranges as `is_private`, so using one here would
    # assert the opposite of what it looks like.
    assert not _peer_is_local(peer("8.8.8.8"))
    assert not _peer_is_local(peer("testclient"))
    assert not _peer_is_local(peer(None))


def test_metrics_are_not_in_the_public_api_schema(client: TestClient) -> None:
    """An operational endpoint has no business in the customer-facing schema."""
    assert "/metrics" not in client.get("/openapi.json").json()["paths"]


def test_a_wrong_token_gets_the_same_answer_as_no_token(
    client: TestClient, scrapeable: None
) -> None:
    """A public /metrics publishes alert volumes, mailbox counts and error rates
    to anyone who asks. 404 rather than 401, both times: we do not advertise that
    the endpoint exists."""
    assert client.get("/metrics").status_code == 404
    assert client.get(
        "/metrics", headers={"Authorization": "Bearer wrong"}
    ).status_code == 404


# ── Request correlation ──────────────────────────────────────────────────────
def test_every_response_carries_a_request_id(client: TestClient) -> None:
    """A customer reporting a failure can quote this and an operator can find the
    exact request in the log index."""
    r = client.get("/health")
    assert r.headers.get("X-Request-Id")


def test_an_inbound_request_id_is_honoured_so_a_trace_continues(
    client: TestClient,
) -> None:
    r = client.get("/health", headers={"X-Request-Id": "abc123-def"})
    assert r.headers["X-Request-Id"] == "abc123-def"


@pytest.mark.parametrize(
    "hostile",
    ["a" * 200, "id with spaces", "<script>", "id\nInjected: header"],
)
def test_a_hostile_inbound_request_id_is_replaced_not_echoed(
    client: TestClient, hostile: str
) -> None:
    """This string is written into structured log output and read back by a
    person. It must not be attacker-controlled text of arbitrary length."""
    r = client.get("/health", headers={"X-Request-Id": hostile})
    assert r.headers["X-Request-Id"] != hostile
    assert r.headers["X-Request-Id"].isalnum()


# ── Cardinality: the way a metrics endpoint becomes its own outage ───────────
def test_the_redirector_is_one_series_not_one_per_link(
    client: TestClient, scrapeable: None
) -> None:
    """`/r/{token}` labelled by raw path would mint a metric series per link ever
    issued, which is unbounded memory in the scraper and in us."""
    for token in ("aaa", "bbb", "ccc"):
        client.get(f"/r/{token}")
    body = client.get("/metrics", headers=SCRAPER).text
    assert 'route="/r/{token}"' in body
    for token in ("aaa", "bbb", "ccc"):
        assert f'route="/r/{token}"' not in body


def test_unmatched_paths_collapse_into_one_bucket(
    client: TestClient, scrapeable: None
) -> None:
    """Otherwise a scanner mints a series per probe."""
    for path in ("/wp-login.php", "/.env", "/admin.php"):
        client.get(path)
    body = client.get("/metrics", headers=SCRAPER).text
    assert 'route="<unmatched>"' in body
    assert "wp-login" not in body


def test_a_throttled_request_is_still_measured(
    client: TestClient, scrapeable: None
) -> None:
    """The observability layer wraps the rate limiter deliberately: a middleware
    that only sees requests reaching a handler hides exactly the traffic an
    operator needs to look at."""
    from envelock.security import limits

    limits.reset_all()
    for _ in range(30):
        client.post("/api/v1/auth/login", json={"email": "x@y.com", "password": "z"})
    body = client.get("/metrics", headers=SCRAPER).text
    assert 'status="429"' in body
    limits.reset_all()


# ── Recording helpers never break the thing they measure ─────────────────────
def test_a_broken_metric_cannot_fail_a_request(monkeypatch) -> None:  # noqa: ANN001
    """Instrumentation that raises turns an observability bug into a customer
    facing 500."""
    from envelock.obs import metrics

    def _boom(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("collector exploded")

    monkeypatch.setattr(metrics.HTTP_REQUESTS, "labels", _boom)
    # Must not raise.
    metrics.observe_http(method="GET", route="/health", status=200, seconds=0.01)


def test_worker_liveness_records_a_timestamp_to_alert_on() -> None:
    """A poller that stopped is indistinguishable from a set of quiet inboxes
    without this gauge."""
    from envelock.obs.metrics import REGISTRY, set_worker_up

    set_worker_up("imap_poller", up=True, at=1_700_000_000.0)
    value = REGISTRY.get_sample_value(
        "envelock_worker_last_success_timestamp_seconds",
        {"worker": "imap_poller"},
    )
    assert value == 1_700_000_000.0
