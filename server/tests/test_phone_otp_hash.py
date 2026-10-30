"""The stored phone-OTP digest must be keyed, not a bare hash (F5).

A phone one-time code is six digits — a million possibilities — so an unsalted
SHA-256 of it in a database dump IS the live code: anyone who reads the row
inverts it in microseconds. `hash_otp` HMACs under a key derived from
ENVELOCK_SECRET_KEY, so the stored value is useless without the server secret.
"""

from __future__ import annotations

import hashlib


def test_otp_digest_is_not_a_bare_sha256() -> None:
    """The exact regression: the old implementation returned
    `sha256(code)`, which this asserts we no longer do."""
    from envelock.auth.security import hash_otp

    code = "123456"
    assert hash_otp(code) != hashlib.sha256(code.encode()).hexdigest()


def test_otp_digest_is_stable_and_whitespace_trimmed() -> None:
    from envelock.auth.security import hash_otp

    assert hash_otp("654321") == hash_otp("  654321 ")
    assert len(hash_otp("000000")) == 64  # hex SHA-256


def test_otp_digest_depends_on_the_server_secret(monkeypatch) -> None:
    """Change the secret and the digest for the same code changes — proof the
    MAC is keyed by ENVELOCK_SECRET_KEY, not a constant."""
    from envelock.auth import security
    from envelock.config import get_settings

    security._derive_otp_key.cache_clear()
    get_settings.cache_clear()
    monkeypatch.setenv("ENVELOCK_SECRET_KEY", "secret-one-aaaaaaaaaaaaaaaaaaaa")
    first = security.hash_otp("424242")

    security._derive_otp_key.cache_clear()
    get_settings.cache_clear()
    monkeypatch.setenv("ENVELOCK_SECRET_KEY", "secret-two-bbbbbbbbbbbbbbbbbbbb")
    second = security.hash_otp("424242")

    assert first != second
    security._derive_otp_key.cache_clear()
    get_settings.cache_clear()
