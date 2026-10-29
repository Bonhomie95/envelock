"""Secrets the request path reads back are ciphertext in the database.

Mailbox credentials were always envelope-sealed. Authenticator seeds and SIEM
webhook signing keys were not: a dump or backup of the database was every
account's second factor and every customer's webhook signing key.
"""

from __future__ import annotations

import asyncio

from conftest import platform_sessionmaker as get_sessionmaker
from fastapi.testclient import TestClient
from sqlalchemy import text
from test_api import _auth_header

from envelock.auth.security import hash_password, verify_password
from envelock.security.fields import PREFIX


def _raw(sql: str, **params: object) -> list:
    async def _run() -> list:
        async with get_sessionmaker()() as s:
            result = await s.execute(text(sql), params)
            rows = result.all() if result.returns_rows else []
            await s.commit()
            return rows

    return asyncio.run(_run())


def test_an_authenticator_seed_is_never_stored_in_plain_text(client: TestClient) -> None:
    # Registering, enrolling and signing in with the code exercises the seal on
    # write and the open on every verify.
    _auth_header(client, email="seed@acme.com")
    (stored,) = _raw("SELECT totp_secret FROM users WHERE email = 'seed@acme.com'")[0]
    assert stored.startswith(PREFIX)


def test_a_seed_stored_before_encryption_still_works(client: TestClient) -> None:
    """Rows the migration has not reached yet read as they are."""
    from envelock.auth.security import generate_totp_secret
    from envelock.models import User

    headers = _auth_header(client, email="legacy@acme.com")
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200
    plain = generate_totp_secret()
    _raw("UPDATE users SET totp_secret = :s WHERE email = 'legacy@acme.com'", s=plain)

    async def _read() -> str | None:
        async with get_sessionmaker()() as s:
            from sqlalchemy import select

            query = select(User).where(User.email == "legacy@acme.com")
            return (await s.execute(query)).scalar_one().totp_secret

    assert asyncio.run(_read()) == plain


def test_a_webhook_signing_secret_is_sealed(client: TestClient) -> None:
    headers = _auth_header(client, email="siem@acme.com")
    made = client.post(
        "/api/v1/export/webhooks", json={"url": "https://siem.example.com/hook"}, headers=headers
    )
    assert made.status_code in (200, 201), made.text
    secret = made.json()["secret"]
    (stored,) = _raw("SELECT secret FROM webhook_endpoints")[0]
    assert stored.startswith(PREFIX) and secret not in stored


def test_a_weaker_password_hash_is_upgraded_at_sign_in(client: TestClient, monkeypatch) -> None:  # noqa: ANN001
    import envelock.auth.security as sec

    _auth_header(client, email="oldhash@acme.com")
    pw = "a-long-enough-passphrase"
    # What this account would hold from before the cost factor went up.
    with monkeypatch.context() as m:
        m.setattr(sec, "_SCRYPT_P", 1)
        weak = hash_password(pw)
    _raw("UPDATE users SET password_hash = :h WHERE email = 'oldhash@acme.com'", h=weak)
    assert sec.needs_rehash(weak)

    r = client.post("/api/v1/auth/login", json={"email": "oldhash@acme.com", "password": pw})
    assert r.status_code == 200, r.text
    (stored,) = _raw("SELECT password_hash FROM users WHERE email = 'oldhash@acme.com'")[0]
    assert not sec.needs_rehash(stored)
    assert verify_password(pw, stored)
