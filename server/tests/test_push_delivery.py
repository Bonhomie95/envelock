"""Browser alerts end to end: a real, encrypted Web Push leaves the server.

The push service is a local HTTP endpoint standing in for FCM / Mozilla, so the
sender runs for real — VAPID signing, payload encryption, headers — and the test
decrypts what went over the wire exactly as the browser would.
"""

from __future__ import annotations

import base64
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import http_ece
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from test_api import _auth_header


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _public(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


class PushService(threading.Thread):
    """Records each push and answers with `status` (201 accepted, 410 gone)."""

    daemon = True

    def __init__(self, status: int = 201) -> None:
        super().__init__()
        self.received: list[tuple[dict, bytes]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 — http.server's naming
                body = self.rfile.read(int(self.headers["Content-Length"]))
                # Header names are case-insensitive on the wire; compare lowered.
                sent = {k.lower(): v for k, v in self.headers.items()}
                outer.received.append((sent, body))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args) -> None:  # noqa: ANN002
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.httpd.server_port}/push/device-1"

    def run(self) -> None:
        self.httpd.serve_forever()


@pytest.fixture
def vapid(monkeypatch: pytest.MonkeyPatch) -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setenv(
        "ENVELOCK_VAPID_PRIVATE_KEY", _b64(key.private_numbers().private_value.to_bytes(32, "big"))
    )
    monkeypatch.setenv("ENVELOCK_VAPID_PUBLIC_KEY", _b64(_public(key)))
    from envelock.config import get_settings

    get_settings.cache_clear()


def _subscribe(client, headers: dict, endpoint: str) -> tuple:  # noqa: ANN001
    browser = ec.generate_private_key(ec.SECP256R1())
    secret = os.urandom(16)
    r = client.post(
        "/api/v1/push/subscribe",
        json={"endpoint": endpoint, "p256dh": _b64(_public(browser)), "auth": _b64(secret)},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    return browser, secret


def test_a_test_push_is_delivered_encrypted_and_urgent(client, vapid) -> None:  # noqa: ANN001
    service = PushService()
    service.start()
    try:
        headers = _auth_header(client, email="push-ok@acme.com")
        browser, secret = _subscribe(client, headers, service.endpoint)

        r = client.post("/api/v1/push/test", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["delivered"] is True, r.json()

        assert len(service.received) == 1
        sent, body = service.received[0]
        assert sent["urgency"] == "high", "alerts must not be batched for a sleeping device"
        assert sent["content-encoding"] == "aes128gcm"
        assert sent["authorization"].startswith("vapid ")
        # Decrypt as the browser does: only the subscriber's keys can read it.
        payload = json.loads(
            http_ece.decrypt(body, private_key=browser, auth_secret=secret, version="aes128gcm")
        )
        assert payload["body"].startswith("Test notification")
    finally:
        service.httpd.shutdown()


def test_a_gone_subscription_is_reported_and_pruned(client, vapid) -> None:  # noqa: ANN001
    from conftest import platform_sessionmaker as get_sessionmaker
    from sqlalchemy import func, select

    from envelock.models import PushSubscription

    service = PushService(status=410)
    service.start()
    try:
        headers = _auth_header(client, email="push-gone@acme.com")
        _subscribe(client, headers, service.endpoint)

        r = client.post("/api/v1/push/test", headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["delivered"] is False
        assert "410" in r.json()["detail"]
    finally:
        service.httpd.shutdown()

    import asyncio

    async def remaining() -> int:
        async with get_sessionmaker()() as session:
            return int(
                (
                    await session.execute(select(func.count()).select_from(PushSubscription))
                ).scalar_one()
            )

    assert asyncio.run(remaining()) == 0, "a 410 subscription must be deleted"
