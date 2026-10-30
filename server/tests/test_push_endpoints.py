"""Registering a browser for push, across workspaces and across rotations.

The endpoint is unique platform-wide but was looked up under the caller's tenant
scope, so a browser last registered from another workspace hit the unique index
(500) and the toggle read "off" — and pressing Enable then unsubscribed the
browser, ending the other workspace's alerts too. The cross-tenant cases only
fail with row-level security on (ENVELOCK_TEST_RLS=1), which is how production
runs.

When the browser itself replaces a subscription, the service worker reports it
to /push/rotate, proving possession with the old subscription's auth secret.
"""

from __future__ import annotations

import asyncio

from conftest import platform_sessionmaker
from sqlalchemy import select
from test_api import _auth_header

from envelock.models import PushSubscription, User

ENDPOINT = "https://fcm.googleapis.com/fcm/send/browser-one"


def _keys(tag: str) -> dict:
    return {"p256dh": f"p256dh-{tag}-xxxxxxxx", "auth": f"auth-{tag}-xxxxxxxx"}


def _rows() -> list[tuple[str, str, str]]:
    async def read() -> list[tuple[str, str, str]]:
        async with platform_sessionmaker()() as session:
            rows = await session.execute(
                select(PushSubscription.endpoint, User.email, PushSubscription.auth)
                .join(User, User.id == PushSubscription.user_id)
            )
            return [tuple(r) for r in rows.all()]

    return asyncio.run(read())


def test_a_browser_moves_to_whoever_in_any_workspace_holds_its_keys(client) -> None:  # noqa: ANN001
    first = _auth_header(client, email="owner@acme.com")
    other_workspace = _auth_header(client, email="owner@globex.com")

    r = client.post("/api/v1/push/subscribe", json={"endpoint": ENDPOINT, **_keys("b1")},
                    headers=first)
    assert r.status_code == 200, r.text
    # Same browser (same keys), now signed in to a different workspace.
    r = client.post("/api/v1/push/subscribe", json={"endpoint": ENDPOINT, **_keys("b1")},
                    headers=other_workspace)
    assert r.status_code == 200, r.text
    assert _rows() == [(ENDPOINT, "owner@globex.com", _keys("b1")["auth"])]


def test_a_leaked_endpoint_cannot_be_claimed_from_another_workspace(client) -> None:  # noqa: ANN001
    victim = _auth_header(client, email="owner@acme.com")
    attacker = _auth_header(client, email="owner@globex.com")
    client.post("/api/v1/push/subscribe", json={"endpoint": ENDPOINT, **_keys("victim")},
                headers=victim)

    r = client.post("/api/v1/push/subscribe", json={"endpoint": ENDPOINT, **_keys("evil")},
                    headers=attacker)
    assert r.status_code == 409, r.text
    assert _rows() == [(ENDPOINT, "owner@acme.com", _keys("victim")["auth"])]


def test_the_worker_rotates_a_subscription_with_the_old_auth_secret(client) -> None:  # noqa: ANN001
    headers = _auth_header(client, email="owner@acme.com")
    client.post("/api/v1/push/subscribe", json={"endpoint": ENDPOINT, **_keys("old")},
                headers=headers)
    new_endpoint = "https://fcm.googleapis.com/fcm/send/browser-one-rotated"
    rotate = {"old_endpoint": ENDPOINT, "old_auth": _keys("old")["auth"],
              "endpoint": new_endpoint, **_keys("new")}

    # No session: the service worker has none. A guessed secret proves nothing.
    wrong = client.post("/api/v1/push/rotate", json={**rotate, "old_auth": "auth-guessed-xxxx"})
    assert wrong.status_code == 404
    assert _rows() == [(ENDPOINT, "owner@acme.com", _keys("old")["auth"])]

    r = client.post("/api/v1/push/rotate", json=rotate)
    assert r.status_code == 200, r.text
    assert _rows() == [(new_endpoint, "owner@acme.com", _keys("new")["auth"])]

    # Replayed after the page already registered the new one: no duplicate.
    again = client.post("/api/v1/push/rotate", json=rotate)
    assert again.status_code == 404
