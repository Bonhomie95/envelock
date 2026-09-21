#!/usr/bin/env python3
"""Turn a development `.env` into the two production settings files.

    python3 deploy/make_prod_env.py --source ~/envelock-laptop.env --ip 203.0.113.10 \\
        --owner-password '...' --app-password '...' --backup-password '...'

Writes, next to this repository's `.env`:

* `.env`        — the API. Seals mailbox passwords but cannot open them; runs no
                  mail polling and no scheduler.
* `.env.worker` — the worker. Holds the private key, polls mail, runs the
                  scheduler. The only file the private key ever appears in.

Everything the laptop file already has (SES, Google, Microsoft, Safe Browsing,
IPinfo, OpenAI, VAPID, Stripe…) is carried over untouched. What changes is the
set of values that must differ in production, listed in `PRODUCTION` below, and
those are applied whatever the source file said — a development value leaking
into production is exactly the mistake this exists to prevent.

Standard library only (plus `cryptography`, already a server dependency, when a
key pair has to be generated), so it runs before anything else is set up.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sys
from pathlib import Path

KEY_LINE = re.compile(r"^(?P<key>ENVELOCK_[A-Z0-9_]+)=(?P<value>.*)$")

#: Applied to both files, overriding the source.
PRODUCTION = {
    "ENVELOCK_ENV": "production",
    "ENVELOCK_LOG_JSON": "true",
    "ENVELOCK_TRUST_FORWARDED_FOR": "false",
    "ENVELOCK_FOCUS_CORE": "false",
    "ENVELOCK_RATE_LIMIT_BACKEND": "redis",
    "ENVELOCK_REDIS_DSN": "redis://localhost:6379/0",
    "ENVELOCK_DB_NULLPOOL": "false",
    "ENVELOCK_WEB_BASE_URL": "https://app.envelock.org",
    "ENVELOCK_PUBLIC_BASE_URL": "https://app.envelock.org",
    "ENVELOCK_REDIRECT_BASE_URL": "https://api.envelock.org",
    "ENVELOCK_CORS_ORIGINS": "https://app.envelock.org,https://admin.envelock.org",
    "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "true",
    "ENVELOCK_REQUIRE_DOMAIN_VERIFICATION": "true",
    "ENVELOCK_CHECK_EMAIL_DOMAIN_EXISTS": "true",
    "ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS": "false",
    "ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS": "false",
    "ENVELOCK_IMAP_ALLOW_PLAINTEXT": "false",
    "ENVELOCK_WEBHOOK_ALLOW_PRIVATE_HOSTS": "false",
    "ENVELOCK_RESET_SCHEMA_ON_STARTUP": "false",
    "ENVELOCK_RLS_ENABLED": "true",
    "ENVELOCK_ALLOW_RLS_DISABLED": "false",
    "ENVELOCK_APPLY_RLS": "false",
    "ENVELOCK_DB_APP_ROLE": "envelock_app",
    "ENVELOCK_CREDENTIAL_KEY_PROVIDER": "x25519",
    # A brand-new database holds no credential sealed with the old local key,
    # so there is nothing to migrate and no reason to keep that key anywhere.
    "ENVELOCK_CREDENTIAL_MASTER_KEY": "",
}

#: The API faces the internet: it may seal, never open.
API_ONLY = {
    "ENVELOCK_CREDENTIAL_PRIVATE_KEY": "",
    "ENVELOCK_CREDENTIAL_CAN_DECRYPT": "false",
    "ENVELOCK_SCHEDULER_ENABLED": "false",
    "ENVELOCK_IMAP_POLL_WORKER_ENABLED": "false",
}

#: The worker reads mail, so it alone holds the private key.
WORKER_ONLY = {
    "ENVELOCK_CREDENTIAL_CAN_DECRYPT": "true",
    "ENVELOCK_SCHEDULER_ENABLED": "true",
    "ENVELOCK_IMAP_POLL_WORKER_ENABLED": "true",
    # Sized for a 4-core / 8 GB server: sixteen mailboxes checked at a time,
    # with the pool comfortably above that for the scheduler's own queries.
    # API (10 + 10) plus worker (20 + 10) stays well under Postgres's 100.
    "ENVELOCK_IMAP_POLL_CONCURRENCY": "16",
    "ENVELOCK_DB_POOL_SIZE": "20",
    "ENVELOCK_DB_MAX_OVERFLOW": "10",
}

#: Production refuses to start without these, so say so now rather than at boot.
REQUIRED_FROM_SOURCE = ("ENVELOCK_SMTP_HOST", "ENVELOCK_SMTP_FROM")


def parse(text: str) -> tuple[list[str], dict[str, str]]:
    lines = text.splitlines()
    values: dict[str, str] = {}
    for line in lines:
        m = KEY_LINE.match(line.strip())
        if m:
            values[m["key"]] = m["value"].strip()
    return lines, values


def render(lines: list[str], updates: dict[str, str]) -> str:
    """The source file with `updates` applied in place; new keys appended."""
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        m = KEY_LINE.match(line.strip())
        if m and m["key"] in updates:
            key = m["key"]
            if key in seen:
                continue  # a duplicate key: the last one used to win silently
            seen.add(key)
            out.append(f"{key}={updates[key]}")
        else:
            out.append(line)
    missing = [k for k in updates if k not in seen]
    if missing:
        out.append("")
        out.append("# ─── Added for production by deploy/make_prod_env.py ───")
        out.extend(f"{k}={updates[k]}" for k in missing)
    return "\n".join(out) + "\n"


def _dsn(user: str, password: str, database: str = "envelock") -> str:
    return f"postgresql+asyncpg://{user}:{password}@localhost:5432/{database}"


def _generate_pair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    private = X25519PrivateKey.generate()
    return (
        base64.b64encode(private.public_key().public_bytes_raw()).decode(),
        base64.b64encode(private.private_bytes_raw()).decode(),
    )


def build(
    source_text: str,
    *,
    ip: str,
    owner_password: str,
    app_password: str,
    backup_password: str,
    keep_secret_key: bool = False,
) -> tuple[str, str, list[str]]:
    """Return (api_env, worker_env, notes)."""
    lines, values = parse(source_text)
    notes: list[str] = []

    for key in REQUIRED_FROM_SOURCE:
        if not values.get(key) or values.get(key) == "localhost":
            raise SystemExit(
                f"{key} is empty in the source file. Production will not start without "
                "a real mail relay (every signup needs its verification email). Copy "
                "the SES settings from your laptop's server/.env first."
            )
    for key, value in values.items():
        if value.lstrip().startswith("#"):
            raise SystemExit(
                f"{key} has a comment where its value should be. Put the comment on "
                "its own line above the key."
            )

    public = values.get("ENVELOCK_CREDENTIAL_PUBLIC_KEY", "")
    private = values.get("ENVELOCK_CREDENTIAL_PRIVATE_KEY", "")
    if not (public and private):
        public, private = _generate_pair()
        notes.append(
            "A NEW credential key pair was generated (the source had none). Save the "
            "private key from .env.worker in your password manager NOW — losing it "
            "means every customer must reconnect every mailbox."
        )

    common = dict(PRODUCTION)
    common.update(
        {
            "ENVELOCK_IMAP_EGRESS_IPS": ip,
            "ENVELOCK_POSTGRES_DSN": _dsn("envelock_app", app_password),
            "ENVELOCK_DB_OWNER_DSN": _dsn("envelock", owner_password),
            "ENVELOCK_DB_BACKUP_DSN": _dsn("envelock_backup", backup_password),
            "ENVELOCK_CREDENTIAL_PUBLIC_KEY": public,
        }
    )
    if not keep_secret_key or not values.get("ENVELOCK_SECRET_KEY"):
        # Never reuse the laptop's signing key: anyone who ever saw that file
        # could forge a production session.
        common["ENVELOCK_SECRET_KEY"] = secrets.token_urlsafe(48)
    if not values.get("ENVELOCK_METRICS_TOKEN"):
        common["ENVELOCK_METRICS_TOKEN"] = secrets.token_urlsafe(32)
    if not values.get("ENVELOCK_BACKUP_RETAIN_DAYS"):
        # The dumps share the database's disk. Two weeks of them is most of a
        # small VPS once the database is large; off-server copies keep history.
        common["ENVELOCK_BACKUP_RETAIN_DAYS"] = "5"

    api = render(lines, {**common, **API_ONLY})
    worker = render(lines, {**common, **WORKER_ONLY, "ENVELOCK_CREDENTIAL_PRIVATE_KEY": private})
    return api, worker, notes


def _write_private(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(path, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--source", required=True, help="the .env copied from your laptop")
    parser.add_argument("--ip", required=True, help="this server's public IPv4 address")
    parser.add_argument("--owner-password", required=True)
    parser.add_argument("--app-password", required=True)
    parser.add_argument("--backup-password", required=True)
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parents[1]),
        help="where to write .env and .env.worker (default: the server repo)",
    )
    parser.add_argument(
        "--keep-secret-key",
        action="store_true",
        help="reuse the source's SECRET_KEY (only when re-running on the same server)",
    )
    args = parser.parse_args()

    source = Path(args.source).expanduser().read_text()
    api, worker, notes = build(
        source,
        ip=args.ip,
        owner_password=args.owner_password,
        app_password=args.app_password,
        backup_password=args.backup_password,
        keep_secret_key=args.keep_secret_key,
    )
    out = Path(args.out_dir)
    _write_private(out / ".env", api)
    _write_private(out / ".env.worker", worker)
    print(f"wrote {out / '.env'} (API) and {out / '.env.worker'} (worker), both 0600")
    for note in notes:
        print(f"\n!! {note}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
