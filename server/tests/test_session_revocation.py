"""Signing out ends the session that is signed in.

`/auth/logout` revoked the user's refresh-token family, and the revocation store
was checked when a refresh token was presented — but `current_principal` never
consulted it. So the access token in an attacker's hands stayed valid for its
full fifteen minutes after the victim pressed "sign out of all devices", which is
the exact scenario that button exists for.

`require_role` re-reads the account from the database on every request, so
suspension always worked. Signing out is not a status change, which is why it
fell through the gap.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

PW = "a-long-enough-passphrase"


@pytest.fixture(autouse=True)
def _clean_stores():
    from envelock.security import limits

    limits.reset_all()
    yield
    limits.reset_all()


def _session(client: TestClient, email: str) -> dict:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": "Revoke Co"},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    return client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()


def test_the_access_token_stops_working_the_moment_you_sign_out(
    client: TestClient,
) -> None:
    tokens = _session(client, "signout@revoke.example")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200

    after = client.get("/api/v1/auth/me", headers=headers)
    assert after.status_code == 401, (
        "the access token outlived sign-out — the whole point of the button"
    )
    assert "sign in again" in after.json()["detail"]


def test_the_refresh_token_dies_with_it(client: TestClient) -> None:
    tokens = _session(client, "refresh@revoke.example")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post("/api/v1/auth/logout", headers=headers)

    replayed = client.post(
        "/api/v1/auth/refresh", json={"token": tokens["refresh_token"]}
    )
    assert replayed.status_code == 401


def test_a_revoked_session_reads_as_anonymous_on_public_endpoints(
    client: TestClient,
) -> None:
    """The sandbox returns the internal detection taxonomy to a signed-in caller
    and withholds it from an anonymous one. A revoked session must land on the
    anonymous side, or signing out leaves the caller with the signed-in view."""
    tokens = _session(client, "sandbox@revoke.example")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    body = {
        "raw_message": (
            "From: vendor@partner.example\r\nTo: pay@revoke.example\r\n"
            "Subject: invoice\r\n\r\nPlease pay to a new account.\r\n"
        ),
        "source": "imap_idle",
    }

    signed_in = client.post("/api/v1/analyse", json=body, headers=headers).json()
    client.post("/api/v1/auth/logout", headers=headers)
    revoked = client.post("/api/v1/analyse", json=body, headers=headers).json()

    def services(payload: dict) -> set:
        return {f.get("service") for f in payload.get("findings", [])}

    # Signed in, at least one finding carries its internal service id; revoked,
    # none does.
    assert services(revoked) <= {None}
    if services(signed_in) - {None}:
        assert services(signed_in) != services(revoked)


def test_signing_in_again_works_normally(client: TestClient) -> None:
    """Revocation must be scoped to the tokens that existed, not to the account —
    otherwise "sign out of all devices" locks you out for fourteen days."""
    email = "again@revoke.example"
    tokens = _session(client, email)
    client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )

    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    fresh = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    assert (
        client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {fresh['access_token']}"},
        ).status_code
        == 200
    )


# ── The store itself ─────────────────────────────────────────────────────────
def test_user_revocation_is_a_cutoff_not_a_ban() -> None:
    """The bug in one assertion.

    `revoke_user` recorded "this subject is revoked until now + 14 days" and
    answered yes for ANY token bearing it — including one issued after the
    revocation. Signing out therefore locked the account out of its own refresh
    flow for a fortnight. It went unnoticed because only refresh tokens were
    checked, so the 15-minute access token kept working and the failure surfaced
    later, detached from the sign-out that caused it.
    """
    import time

    from envelock.security.limits import TokenRevocations

    store = TokenRevocations()
    now = time.time()
    store.revoke_user("user-1", until=now + 3600, cutoff=now)

    assert store.is_revoked("old", "user-1", issued_at=now - 60) is True
    assert store.is_revoked("new", "user-1", issued_at=now + 0.001) is False
    # Another user is untouched.
    assert store.is_revoked("other", "user-2", issued_at=now - 60) is False


def test_a_token_with_no_issue_time_fails_closed() -> None:
    """Tokens minted before `iat` existed must be rejected, not trusted — the
    cost is one extra sign-in for sessions open across the deploy."""
    import time

    from envelock.security.limits import TokenRevocations

    store = TokenRevocations()
    now = time.time()
    store.revoke_user("user-1", until=now + 3600, cutoff=now)
    assert store.is_revoked("legacy", "user-1", issued_at=None) is True


def test_a_specific_refresh_token_is_still_revoked_by_jti() -> None:
    """Rotation-on-use is independent of the cutoff and must keep working."""
    import time

    from envelock.security.limits import TokenRevocations

    store = TokenRevocations()
    now = time.time()
    store.revoke_jti("spent", expires_at=now + 3600)
    assert store.is_revoked("spent", "user-1", issued_at=now + 100) is True
    assert store.is_revoked("fresh", "user-1", issued_at=now + 100) is False


def test_the_cutoff_is_forgotten_once_every_older_token_has_expired() -> None:
    import time

    from envelock.security.limits import TokenRevocations

    store = TokenRevocations()
    now = time.time()
    store.revoke_user("user-1", until=now + 10, cutoff=now)
    assert store.is_revoked("t", "user-1", now=now + 5, issued_at=now - 1) is True
    assert store.is_revoked("t", "user-1", now=now + 20, issued_at=now - 1) is False
