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
# Public origins, as deploy/make_prod_env.py writes them.
os.environ.setdefault("ENVELOCK_REDIRECT_BASE_URL", "https://api.example.com")
os.environ.setdefault("ENVELOCK_PUBLIC_BASE_URL", "https://app.example.com")
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


# ── Key strength ─────────────────────────────────────────────────────────────
def test_a_short_secret_key_is_refused_outside_development() -> None:
    """It signs every session and roots the key that seals authenticator seeds
    at rest; a short one can be brute-forced offline."""
    for env in ("staging", "production"):
        out = _boot({"ENVELOCK_ENV": env, "ENVELOCK_RLS_ENABLED": "true",
                     "ENVELOCK_SECRET_KEY": "short-secret"})
        assert out.startswith("REFUSED"), (env, out)
        assert "at least 32 characters" in out
    assert _boot({"ENVELOCK_ENV": "development", "ENVELOCK_SECRET_KEY": "short"}) == "STARTED"


def test_a_webhook_must_use_https_outside_development(monkeypatch) -> None:  # noqa: ANN001
    """An alert payload names the mailbox, the sender and the findings."""
    import pytest

    from envelock.config import get_settings
    from envelock.workers.webhook_delivery import UnsafeUrlError, assert_safe_url

    monkeypatch.setenv("ENVELOCK_ENV", "staging")
    monkeypatch.setenv("ENVELOCK_SECRET_KEY", "s" * 64)
    get_settings.cache_clear()
    with pytest.raises(UnsafeUrlError, match="https"):
        assert_safe_url("http://siem.example.com/hook")


# ── Turnstile: both keys or neither ──────────────────────────────────────────
def test_a_turnstile_site_key_without_its_secret_is_refused() -> None:
    out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_TURNSTILE_SITE_KEY": "0x4AAA"})
    assert out.startswith("REFUSED"), out
    assert "ENVELOCK_TURNSTILE_SECRET_KEY" in out


def test_a_turnstile_secret_without_its_site_key_is_refused() -> None:
    """The secret alone switches enforcement on (`turnstile.verify`), but only the
    site key makes the browser render a challenge — so this pairing refused
    every sign-in and registration, and booted without a word."""
    out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_TURNSTILE_SECRET_KEY": "0x4BBB"})
    assert out.startswith("REFUSED"), out
    assert "every sign-in" in out


def test_turnstile_with_both_keys_or_neither_starts() -> None:
    both = {
        "ENVELOCK_RLS_ENABLED": "true",
        "ENVELOCK_TURNSTILE_SITE_KEY": "0x4AAA",
        "ENVELOCK_TURNSTILE_SECRET_KEY": "0x4BBB",
    }
    assert _boot(both) == "STARTED"
    # Blank lines, as `.env.example` ships them, mean "off" — not "half set".
    neither = {
        "ENVELOCK_RLS_ENABLED": "true",
        "ENVELOCK_TURNSTILE_SITE_KEY": "",
        "ENVELOCK_TURNSTILE_SECRET_KEY": "",
    }
    assert _boot(neither) == "STARTED"


# ── Public origins written into customers' mail and checkout ─────────────────
def test_production_refuses_to_rewrite_links_to_localhost() -> None:
    """Unset, the redirect origin fell back to http://localhost:8010 — and the
    rewritten links are written permanently into customers' mailboxes."""
    for value in ("", "http://localhost:8010", "https://127.0.0.1", "http://10.0.0.4:8010"):
        out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_REDIRECT_BASE_URL": value})
        assert out.startswith("REFUSED"), (value, out)
        assert "ENVELOCK_REDIRECT_BASE_URL" in out


def test_production_refuses_a_local_checkout_return_origin() -> None:
    out = _boot({"ENVELOCK_RLS_ENABLED": "true", "ENVELOCK_PUBLIC_BASE_URL": ""})
    assert out.startswith("REFUSED"), out
    assert "ENVELOCK_PUBLIC_BASE_URL" in out


def test_development_keeps_its_local_redirect_origin() -> None:
    out = _boot({"ENVELOCK_ENV": "development", "ENVELOCK_REDIRECT_BASE_URL": ""})
    assert out == "STARTED", out


# ── Allowed, but loud ────────────────────────────────────────────────────────
def _production_settings(monkeypatch, env: dict[str, str]):  # noqa: ANN001, ANN202
    from envelock.config import Settings

    base = {
        "ENVELOCK_ENV": "production",
        "ENVELOCK_SECRET_KEY": "s" * 64,
        "ENVELOCK_CREDENTIAL_MASTER_KEY": "m" * 64,
        "ENVELOCK_RLS_ENABLED": "true",
        "ENVELOCK_REQUIRE_EMAIL_VERIFICATION": "true",
        "ENVELOCK_SMTP_HOST": "smtp.example.com",
        "ENVELOCK_REDIRECT_BASE_URL": "https://api.example.com",
        "ENVELOCK_PUBLIC_BASE_URL": "https://app.example.com",
    }
    for key, value in {**base, **env}.items():
        monkeypatch.setenv(key, value)
    return Settings(_env_file=None)


def test_stripe_test_keys_boot_in_production_with_a_warning(monkeypatch, caplog) -> None:  # noqa: ANN001
    """Test keys are a legitimate pre-launch state, so not a refusal — but a
    forgotten one lets anyone activate a paid plan with Stripe's public test
    card, so it is logged at every start and listed on the operator console."""
    import logging

    with caplog.at_level(logging.WARNING, logger="envelock.config"):
        settings = _production_settings(monkeypatch, {"ENVELOCK_STRIPE_SECRET_KEY": "sk_test_abc"})
    assert any("TEST mode" in w for w in settings.production_warnings())
    assert "TEST mode" in caplog.text


def test_live_stripe_keys_raise_no_warning(monkeypatch) -> None:  # noqa: ANN001
    settings = _production_settings(monkeypatch, {"ENVELOCK_STRIPE_SECRET_KEY": "sk_live_abc"})
    assert settings.production_warnings() == []


def test_production_warnings_are_production_only(monkeypatch) -> None:  # noqa: ANN001
    settings = _production_settings(
        monkeypatch,
        {"ENVELOCK_ENV": "development", "ENVELOCK_STRIPE_SECRET_KEY": "sk_test_abc"},
    )
    assert settings.production_warnings() == []
