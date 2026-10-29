"""Encryption at rest for the few secrets the request path must read back.

Mailbox credentials are envelope-sealed under split custody: the API can seal
them but never open them (`crypto`, `keys`). An authenticator seed and a webhook
signing key cannot work that way — the API verifies the one on every sign-in and
the worker signs with the other — and they used to sit in the database in plain
text, so a stolen dump or backup held every account's second factor.

They are now sealed with AES-256-GCM under a key derived (HKDF-SHA256) from
ENVELOCK_SECRET_KEY, held only by the processes. Rotating that secret makes
these values unreadable, so rotate it only together with a re-seal (open under
the old key, write under the new).
"""

from __future__ import annotations

import base64
import os
from functools import lru_cache

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import String
from sqlalchemy.types import TypeDecorator

PREFIX = "enc1:"


@lru_cache(maxsize=4)
def _derive(secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"envelock/fields/v1"
    ).derive(secret)


def _key() -> bytes:
    from envelock.config import get_settings

    settings = get_settings()
    secret = settings.secret_key.get_secret_value()
    if not secret:
        # Same rule as the processed-mail stamp: only local development may run
        # keyless (production and staging refuse to boot without a secret).
        if settings.env != "development":
            raise RuntimeError("ENVELOCK_SECRET_KEY is required to encrypt secrets at rest")
        secret = "envelock-dev-fields"  # noqa: S105 — development only, refused elsewhere
    return _derive(secret.encode())


def seal_field(value: str) -> str:
    nonce = os.urandom(12)
    blob = nonce + AESGCM(_key()).encrypt(nonce, value.encode(), PREFIX.encode())
    return PREFIX + base64.urlsafe_b64encode(blob).decode()


def open_field(value: str) -> str:
    if not value.startswith(PREFIX):
        return value  # stored before encryption at rest; sealed on its next write
    blob = base64.urlsafe_b64decode(value[len(PREFIX):])
    return AESGCM(_key()).decrypt(blob[:12], blob[12:], PREFIX.encode()).decode()


class EncryptedString(TypeDecorator):
    """A string column stored sealed. Size it for the ciphertext: about
    (plaintext + 28) * 4/3 + 5 characters."""

    impl = String
    cache_ok = True

    def process_bind_param(self, value, dialect):  # noqa: ANN001, ANN201, ARG002
        return None if value is None else seal_field(value)

    def process_result_value(self, value, dialect):  # noqa: ANN001, ANN201, ARG002
        return None if value is None else open_field(value)
