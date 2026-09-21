"""Production start-up refuses the configurations that quietly lose data.

Three settings were safe defaults for development and silent catastrophes in
production, and nothing stopped a deploy shipping with them:

* `reset_schema_on_startup` DROPS THE SCHEMA on every boot. It is a one-time
  pre-launch repair tool, and "remember to unset it afterwards" is not a control.
* `rls_enabled=false` means the database-level tenant isolation policies — which
  are written, applied at boot and covered by CI — are not protecting the one
  deployment that holds customer mail.
* an unset ingest allowlist means the forwarding SMTP listener accepts mail from
  anywhere on the internet, so anyone who learns a tenant token can inject
  messages to poison detection or fabricate alerts.
* `require_email_verification=false` lets anyone claim any company's domain by
  registering a fake address on it — the cheapest attack against us there is,
  and one that needs no skill at all.

Each is now a refusal at boot rather than a comment in `.env.example`. Like
`test_key_custody`, these run a real start-up in a clean subprocess from a
directory with no `.env`, because the validator runs inside `Settings()` and the
failure mode being guarded is a deploy that dies (or doesn't) at import time.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

_BOOT = """
import json, os, sys

for key in [k for k in os.environ if k.startswith("ENVELOCK_")]:
    del os.environ[key]
os.environ.update(json.loads(sys.argv[1]))
os.environ.setdefault("ENVELOCK_ENV", "production")
os.environ.setdefault("ENVELOCK_SECRET_KEY", "s" * 64)
os.environ.setdefault("ENVELOCK_CREDENTIAL_MASTER_KEY", "m" * 64)
os.environ.setdefault(
    "ENVELOCK_POSTGRES_DSN", "postgresql+asyncpg://u:p@localhost:5432/db"
)
# A valid email-verification configuration by default, so each test below
# exercises the one gate it is about rather than tripping this one first.
os.environ.setdefault("ENVELOCK_REQUIRE_EMAIL_VERIFICATION", "true")
os.environ.setdefault("ENVELOCK_SMTP_HOST", "smtp.example.com")
try:
    from envelock.config import get_settings

    get_settings()
    print("STARTED")
except Exception as exc:  # noqa: BLE001
    print("REFUSED " + str(exc).replace(chr(10), " "))
"""


def _boot(env: dict[str, str]) -> str:
    src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    with tempfile.TemporaryDirectory() as empty:  # no .env to fall back on
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", _BOOT, json.dumps(env)],
            capture_output=True,
            text=True,
            cwd=empty,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": src},
            timeout=120,
        )
    return (result.stdout or result.stderr).strip()


# ── The data-destruction flag ────────────────────────────────────────────────
def test_production_refuses_the_schema_reset_flag() -> None:
    out = _boot(
        {"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_RESET_SCHEMA_ON_STARTUP": "true"}
    )
    assert out.startswith("REFUSED"), out
    assert "ERASES ALL CUSTOMER DATA" in out


def test_development_still_allows_the_schema_reset_flag() -> None:
    """It is a legitimate repair tool for a drifted throwaway database — the
    refusal must be about production specifically, not about the flag."""
    out = _boot(
        {"ENVELOCK_ENV": "development", "ENVELOCK_RESET_SCHEMA_ON_STARTUP": "true"}
    )
    assert out == "STARTED", out


# ── Tenant isolation ─────────────────────────────────────────────────────────
def test_production_refuses_to_start_without_row_level_security() -> None:
    out = _boot({})
    assert out.startswith("REFUSED"), out
    assert "ENVELOCK_RLS_ENABLED" in out
    # The message has to carry the fix, not just the complaint: whoever reads it
    # is mid-deploy and needs the command, not a documentation hunt.
    assert "provision_rls" in out


def test_production_starts_with_row_level_security_on() -> None:
    assert _boot({"ENVELOCK_RLS_ENABLED": "true"}) == "STARTED"


def test_the_escape_hatch_exists_and_is_explicit() -> None:
    """A deployment that has genuinely accepted the risk can proceed — but only
    by naming it in the environment, where it is visible in review."""
    assert _boot({"ENVELOCK_ALLOW_RLS_DISABLED": "true"}) == "STARTED"


# ── Forwarding ingest ────────────────────────────────────────────────────────
def test_production_refuses_an_open_forwarding_ingest() -> None:
    out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_INGEST_SMTP_IN_APP": "true"})
    assert out.startswith("REFUSED"), out
    assert "ENVELOCK_INGEST_ALLOWED_IPS" in out


def test_a_pinned_forwarding_ingest_starts() -> None:
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_INGEST_SMTP_IN_APP": "true",
            "ENVELOCK_INGEST_ALLOWED_IPS": "203.0.113.0/24",
        }
    )
    assert out == "STARTED", out


def test_the_ingest_gate_only_applies_when_the_listener_runs() -> None:
    """A deployment whose MX points at a dedicated host runs no in-app listener,
    so an empty allowlist is not a hole and must not block the deploy."""
    out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_INGEST_SMTP_IN_APP": "false"})
    assert out == "STARTED", out


# ── Email verification (anti tenant-squatting) ───────────────────────────────
def test_production_refuses_unverified_signups() -> None:
    """Registering `finance@theircompany.com` must not be enough to take
    permanent ownership of that company's workspace."""
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "false",
        }
    )
    assert out.startswith("REFUSED")
    assert "REQUIRE_EMAIL_VERIFICATION" in out


def test_the_unverified_signup_escape_hatch_is_explicit() -> None:
    """A deployment may accept the risk, but it has to say so in the environment
    rather than inherit it from a default."""
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "false",
            "ENVELOCK_ALLOW_UNVERIFIED_SIGNUPS": "true",
        }
    )
    assert out == "STARTED"


def test_production_refuses_verification_without_a_relay() -> None:
    """The worst of both: every signup is sent a link that is never delivered,
    so no new customer can ever sign in and the logs say only 'not_configured'."""
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "true",
            "ENVELOCK_SMTP_HOST": "",
        }
    )
    assert out.startswith("REFUSED")
    assert "relay" in out


def test_localhost_does_not_count_as_a_relay() -> None:
    """It is the .env.example default and almost never a real relay — the same
    rule notify/mail.py applies when it decides whether it can send at all."""
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "true",
            "ENVELOCK_SMTP_HOST": "localhost",
        }
    )
    assert out.startswith("REFUSED")


def test_a_relay_and_verification_together_start() -> None:
    out = _boot(
        {
            "ENVELOCK_RLS_ENABLED": "true",
            "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "true",
            "ENVELOCK_SMTP_HOST": "smtp.example.com",
        }
    )
    assert out == "STARTED"
