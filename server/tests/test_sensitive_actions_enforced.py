"""F3 — SENSITIVE_ACTIONS is a contract the SERVER keeps, not advice to the UI.

The list was advertised by `/auth/sensitive-actions` while nothing enforced it:
a stolen session could disconnect a mailbox (destroying its stored credential)
with no re-auth at all. This asserts the inverse — every action named in
SENSITIVE_ACTIONS maps to an endpoint that refuses a valid session presenting no
re-authentication — and fails if an action is ever added to the list without an
enforcing endpoint (the mapping must cover the set exactly).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from envelock.api.auth import _reset_store
from envelock.auth.security import SENSITIVE_ACTIONS
from envelock.main import app

PW = "a-long-enough-passphrase"
DOMAIN = "sensitive.example"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _owner(client: TestClient) -> dict[str, str]:
    client.post(
        "/api/v1/auth/register",
        json={"email": f"owner@{DOMAIN}", "password": PW, "tenant_name": DOMAIN},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": f"owner@{DOMAIN}", "password": PW}
    ).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    return {"Authorization": f"Bearer {skip['access_token']}"}


def _a_mailbox_id(client: TestClient, h: dict) -> str:
    client.post(
        "/api/v1/tenants/bootstrap", json={"name": DOMAIN, "domain": DOMAIN}, headers=h
    )
    return client.post(
        "/api/v1/mailboxes",
        json={"address": f"ap@{DOMAIN}", "mailbox_class": "monitored", "sources": []},
        headers=h,
    ).json()["id"]


# action name → how to call its endpoint WITH A VALID SESSION BUT NO RE-AUTH.
# Each must be refused (401 when the empty re-auth is checked, or 422 when the
# re-auth field is a required part of the request body). If a new action lands in
# SENSITIVE_ACTIONS with nowhere to enforce it, the equality assertion below
# fails and forces it to be wired here.
_ENFORCE: dict[str, Callable[[TestClient, dict], int]] = {
    "mailbox.disconnect": lambda c, h: c.request(
        "DELETE", f"/api/v1/mailboxes/{_a_mailbox_id(c, h)}", headers=h
    ).status_code,
    "mfa.enroll": lambda c, h: c.post("/api/v1/auth/mfa/enroll", json={}, headers=h).status_code,
    "mfa.disable": lambda c, h: c.post("/api/v1/auth/mfa/disable", json={}, headers=h).status_code,
    "tenant.delete": lambda c, h: c.request(
        "DELETE", "/api/v1/tenant", json={}, headers=h
    ).status_code,
    "export.token_create": lambda c, h: c.post(
        "/api/v1/export/tokens", json={"scopes": ["alerts:read"]}, headers=h
    ).status_code,
}


def test_every_sensitive_action_has_an_enforcing_endpoint() -> None:
    """The mapping must cover the advertised list exactly — no action without a
    place that enforces it, and nothing enforced that is not advertised."""
    assert set(_ENFORCE) == set(SENSITIVE_ACTIONS)


@pytest.mark.parametrize("action", sorted(SENSITIVE_ACTIONS))
def test_a_sensitive_action_refuses_a_session_without_reauth(
    client: TestClient, action: str
) -> None:
    h = _owner(client)
    status = _ENFORCE[action](client, h)
    assert status in (401, 422), f"{action} was not refused without re-auth (got {status})"
