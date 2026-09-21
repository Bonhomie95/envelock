"""Account recovery, end to end.

The flow was broken in a way that looked like it worked: the server always
answered "a reset link has been sent to its email" and — on a deployment whose
SMTP host was unset or `localhost`, which is the default — sent nothing at all,
ever. A locked-out customer had no route back in and no indication why.

These pin the three things that must all hold at once: it never reveals whether
an account exists, it tells the truth about whether email can be delivered, and
an account with an authenticator can always recover without email.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import _totp_at
from envelock.config import get_settings

PW = "a-long-enough-passphrase"
NEW = "an-entirely-different-passphrase"


@pytest.fixture
def relay(monkeypatch):
    """Pretend a working SMTP relay exists, and capture what is sent."""
    from envelock.notify import mail

    sent: list[dict] = []

    async def _send(*, to: str, subject: str, body: str) -> mail.MailResult:
        sent.append({"to": to, "subject": subject, "body": body})
        return mail.MailResult(True, "sent")

    monkeypatch.setattr(mail, "is_configured", lambda: True)
    monkeypatch.setattr(mail, "send_mail", _send)
    return sent


@pytest.fixture
def no_relay(monkeypatch):
    from envelock.notify import mail

    monkeypatch.setattr(mail, "is_configured", lambda: False)


def _next_code(secret: str) -> str:
    """A code from the NEXT time step.

    Enrolment consumes the current step's code, and the replay guard refuses to
    honour an observed code twice — correctly. A test reusing it is testing the
    replay guard, not the reset.
    """
    return _totp_at(secret, int(time.time()) // 30 + 1)


def _register(client: TestClient, email: str, *, mfa: bool) -> str | None:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": "Recovery"},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    if not mfa:
        client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]})
        return None
    setup = client.post(
        "/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}
    ).json()
    client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    )
    return setup["secret"]


# ── The email path ───────────────────────────────────────────────────────────
def test_a_reset_link_is_actually_sent(client: TestClient, relay: list) -> None:
    """The whole bug: this reported success while sending nothing."""
    _register(client, "sendme@recovery.example", mfa=False)
    r = client.post(
        "/api/v1/auth/password/forgot", json={"email": "sendme@recovery.example"}
    )
    assert r.status_code == 200
    assert r.json()["email_delivery"] == "available"
    assert len(relay) == 1, "an email must actually leave the system"
    assert "reset-password?token=" in relay[0]["body"]
    assert relay[0]["to"] == "sendme@recovery.example"


def test_no_email_is_sent_to_an_address_that_is_not_registered(
    client: TestClient, relay: list
) -> None:
    """Otherwise the endpoint is an open relay for anyone's inbox."""
    client.post(
        "/api/v1/auth/password/forgot", json={"email": "stranger@nowhere.example"}
    )
    assert relay == []


def test_the_answer_is_identical_for_a_real_and_an_unknown_address(
    client: TestClient, relay: list
) -> None:
    """Any difference — wording, shape, a token — is an account-enumeration
    oracle, and this endpoint takes an unauthenticated address."""
    _register(client, "known@recovery.example", mfa=False)
    known = client.post(
        "/api/v1/auth/password/forgot", json={"email": "known@recovery.example"}
    ).json()
    unknown = client.post(
        "/api/v1/auth/password/forgot", json={"email": "ghost@recovery.example"}
    ).json()

    strip = lambda d: {k: v for k, v in d.items() if k != "reset_link"}  # noqa: E731
    assert strip(known) == strip(unknown)
    assert "reset_link" not in unknown


def test_an_mfa_account_is_not_distinguishable_from_one_without(
    client: TestClient, relay: list
) -> None:
    """The previous version answered `method: "mfa"` with an inline token for an
    MFA account and `method: "email"` otherwise — a free "does this address exist
    and does it have two-factor?" oracle."""
    _register(client, "withmfa@recovery.example", mfa=True)
    _register(client, "withoutmfa@recovery.example", mfa=False)
    a = client.post(
        "/api/v1/auth/password/forgot", json={"email": "withmfa@recovery.example"}
    ).json()
    b = client.post(
        "/api/v1/auth/password/forgot", json={"email": "withoutmfa@recovery.example"}
    ).json()
    strip = lambda d: {k: v for k, v in d.items() if k != "reset_link"}  # noqa: E731
    assert strip(a) == strip(b)
    assert "reset_token" not in a


def test_a_second_request_inside_the_cooldown_sends_nothing(
    client: TestClient, relay: list
) -> None:
    """The per-caller rate limit is not enough on its own: a distributed request
    set walks straight through it and fills the victim's inbox."""
    _register(client, "cooldown@recovery.example", mfa=False)
    for _ in range(3):
        client.post(
            "/api/v1/auth/password/forgot", json={"email": "cooldown@recovery.example"}
        )
    assert len(relay) == 1


def test_a_reset_link_works_once(client: TestClient, relay: list) -> None:
    _register(client, "once@recovery.example", mfa=False)
    client.post("/api/v1/auth/password/forgot", json={"email": "once@recovery.example"})
    token = relay[0]["body"].split("token=", 1)[1].split()[0]

    assert (
        client.post(
            "/api/v1/auth/password/reset",
            json={"token": token, "new_password": NEW},
        ).status_code
        == 200
    )
    replayed = client.post(
        "/api/v1/auth/password/reset",
        json={"token": token, "new_password": "yet-another-good-passphrase"},
    )
    assert replayed.status_code == 401

    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "once@recovery.example", "password": NEW}
        ).status_code
        == 200
    )


# ── No relay: the deployment must say so, not lie ────────────────────────────
def test_without_a_relay_the_customer_is_told_rather_than_left_waiting(
    client: TestClient, no_relay: None
) -> None:
    """"Check your email" on a deployment that cannot send is the bug the
    customer actually experienced."""
    _register(client, "norelay@recovery.example", mfa=False)
    body = client.post(
        "/api/v1/auth/password/forgot", json={"email": "norelay@recovery.example"}
    ).json()
    assert body["email_delivery"] == "unavailable"
    assert "cannot send email" in body["message"]
    # And it points at the route that still works.
    assert body["code_reset_available"] is True
    assert "authenticator" in body["message"]


def test_the_unavailable_answer_is_the_same_for_an_unknown_address(
    client: TestClient, no_relay: None
) -> None:
    """Reporting delivery is safe precisely because it is a property of the
    deployment, not the account — so it must not vary by account."""
    _register(client, "known2@recovery.example", mfa=False)
    a = client.post(
        "/api/v1/auth/password/forgot", json={"email": "known2@recovery.example"}
    ).json()
    b = client.post(
        "/api/v1/auth/password/forgot", json={"email": "ghost2@recovery.example"}
    ).json()
    assert a == b


# ── The authenticator path — works with no email at all ──────────────────────
def test_an_authenticator_resets_without_any_email(
    client: TestClient, no_relay: None
) -> None:
    secret = _register(client, "code@recovery.example", mfa=True)
    assert secret
    r = client.post(
        "/api/v1/auth/password/reset-with-code",
        json={
            "email": "code@recovery.example",
            "code": _next_code(secret),
            "new_password": NEW,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json()["sessions_revoked"] is True
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "code@recovery.example", "password": NEW}
        ).status_code
        == 200
    )


def test_every_code_reset_failure_looks_the_same(
    client: TestClient, no_relay: None
) -> None:
    """Unknown address, no authenticator on the account, and a wrong code must be
    indistinguishable — otherwise this endpoint enumerates accounts."""
    _register(client, "nomfa@recovery.example", mfa=False)
    secret = _register(client, "hasmfa@recovery.example", mfa=True)

    bodies = []
    for email, code in (
        ("ghost3@recovery.example", "123456"),      # no such account
        ("nomfa@recovery.example", "123456"),       # exists, no authenticator
        ("hasmfa@recovery.example", "000000"),      # exists, wrong code
    ):
        r = client.post(
            "/api/v1/auth/password/reset-with-code",
            json={"email": email, "code": code, "new_password": NEW},
        )
        assert r.status_code == 401
        bodies.append(r.json()["detail"])
    assert len(set(bodies)) == 1, "the refusal must not vary"
    assert secret  # (the MFA account was genuinely enrolled)


def test_a_weak_password_is_rejected_before_the_account_is_looked_up(
    client: TestClient, no_relay: None
) -> None:
    """Otherwise "weak password" versus "no such account" is itself an oracle."""
    r = client.post(
        "/api/v1/auth/password/reset-with-code",
        json={
            "email": "ghost4@recovery.example",
            "code": "123456",
            "new_password": "password1234",
        },
    )
    assert r.status_code == 422


def test_an_observed_code_cannot_be_replayed(client: TestClient, no_relay: None) -> None:
    secret = _register(client, "replay@recovery.example", mfa=True)
    code = _next_code(secret)
    first = client.post(
        "/api/v1/auth/password/reset-with-code",
        json={"email": "replay@recovery.example", "code": code, "new_password": NEW},
    )
    assert first.status_code == 200
    second = client.post(
        "/api/v1/auth/password/reset-with-code",
        json={
            "email": "replay@recovery.example",
            "code": code,
            "new_password": "one-more-good-passphrase",
        },
    )
    assert second.status_code == 401


# ── Rate limiting ────────────────────────────────────────────────────────────
def test_the_password_endpoints_have_their_own_bucket() -> None:
    """They matched no prefix and fell through to the 120-per-minute default,
    which made the reset endpoint an email bomb aimed at any known address."""
    from envelock.security.middleware import _bucket_for

    for path in (
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/password/reset-with-code",
        "/api/v1/auth/password",
    ):
        assert _bucket_for(path) == "auth.password"


def test_a_request_forwarded_by_a_local_proxy_is_identified_by_its_real_client() -> None:
    """The deployment shape is nginx on the same box proxying to 127.0.0.1. If
    the peer address is used, EVERY customer shares one bucket and "10 sign-ins
    per 5 minutes" becomes ten for the whole platform — which presents to the
    customer as sign-in being broken."""
    from starlette.datastructures import Headers

    from envelock.security.middleware import client_identity

    class _Req:
        def __init__(self, peer: str, xff: str | None) -> None:
            self.headers = Headers({"x-forwarded-for": xff} if xff else {})
            self.client = type("C", (), {"host": peer})()

    get_settings.cache_clear()
    # Behind our own proxy: charge the real client.
    assert client_identity(_Req("127.0.0.1", "203.0.113.7, 127.0.0.1")) == "ip:203.0.113.7"
    # Straight off the internet: the header is attacker-controlled, ignore it.
    # (A genuinely routable address — the documentation ranges are marked
    # private by `ipaddress`, and no real client can arrive from one.)
    assert client_identity(_Req("8.8.8.8", "1.2.3.4")) == "ip:8.8.8.8"
    # No header at all: fall back to the peer.
    assert client_identity(_Req("8.8.8.8", None)) == "ip:8.8.8.8"


def test_a_bogus_token_is_rejected(client: TestClient) -> None:
    """Carried over from the previous suite: a made-up token must not open a
    reset, and must not say anything about why."""
    r = client.post(
        "/api/v1/auth/password/reset",
        json={"token": "not-a-real-token", "new_password": "a-fine-long-passphrase-1"},
    )
    assert r.status_code == 401


def test_a_weak_new_password_is_rejected_on_the_link_path(
    client: TestClient, relay: list
) -> None:
    _register(client, "weaklink@recovery.example", mfa=False)
    client.post(
        "/api/v1/auth/password/forgot", json={"email": "weaklink@recovery.example"}
    )
    token = relay[0]["body"].split("token=", 1)[1].split()[0]
    r = client.post(
        "/api/v1/auth/password/reset", json={"token": token, "new_password": "short"}
    )
    assert r.status_code == 422


def test_the_reset_link_is_never_returned_outside_development(
    client: TestClient, relay: list, monkeypatch  # noqa: ANN001
) -> None:
    """The response carries the reset link in development, as a convenience.

    Returning it anywhere else would hand a full account takeover to anyone who
    can name an email address — no inbox access required. The gate is one string
    comparison, so this pins it: `staging` must be as closed as `production`.
    """
    from envelock.config import get_settings

    email = "leakcheck@recovery.example"
    _register(client, email, mfa=False)

    # Production now refuses to boot without row-level security, and refuses to
    # boot without email verification. This test is about the reset link, not
    # either gate (see test_production_boot_gates.py), so take both documented
    # escape hatches rather than provisioning RLS and a relay here — the account
    # registered above is deliberately unverified.
    monkeypatch.setenv("ENVELOCK_ALLOW_RLS_DISABLED", "true")
    monkeypatch.setenv("ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS", "true")

    for env in ("production", "staging"):
        monkeypatch.setenv("ENVELOCK_ENV", env)
        get_settings.cache_clear()
        try:
            resp = client.post(
                "/api/v1/auth/password/forgot", json={"email": email}
            )
            # Assert the status too: a 500 would also lack `reset_link`, and a
            # test that passes because the endpoint broke is worse than none.
            assert resp.status_code == 200, f"env={env}: {resp.text}"
            assert "reset_link" not in resp.json(), f"reset link leaked with env={env}"
        finally:
            get_settings.cache_clear()
