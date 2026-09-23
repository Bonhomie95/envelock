"""`deploy/make_prod_env.py` must produce settings production actually accepts.

A generator whose output the production validator refuses is worse than none:
it fails on the new server at the step after the one that looked finished. So
these load the generated files through the real `Settings` in production mode,
and check the property the split exists for — the API cannot open a stored
mailbox password, the worker can.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _tool():
    path = ROOT / "deploy" / "make_prod_env.py"
    spec = importlib.util.spec_from_file_location("make_prod_env", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _laptop_env() -> str:
    """The committed example, filled in the way the laptop's file is."""
    text = (ROOT / ".env.example").read_text()
    return (
        text.replace(
            "ENVELOCK_SMTP_HOST=\n", "ENVELOCK_SMTP_HOST=email-smtp.us-east-1.amazonaws.com\n"
        )
        .replace("ENVELOCK_SECRET_KEY=\n", "ENVELOCK_SECRET_KEY=the-laptop-secret\n")
        .replace("ENVELOCK_ENV=development", "ENVELOCK_ENV=development")
    )


def _build(**overrides):  # noqa: ANN003, ANN202
    kwargs = {
        "ip": "203.0.113.10",
        "owner_password": "owner-pw",
        "app_password": "app-pw",
        "backup_password": "backup-pw",
    }
    kwargs.update(overrides)
    return _tool().build(_laptop_env(), **kwargs)


def _values(text: str) -> dict[str, str]:
    return _tool().parse(text)[1]


def _settings_from(text: str, tmp_path: Path, monkeypatch):  # noqa: ANN001, ANN202
    """Load a generated file exactly as the service would: as `.env`, production."""
    import os

    from envelock.config import Settings, get_settings

    for key in list(os.environ):
        if key.startswith("ENVELOCK_"):
            monkeypatch.delenv(key, raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(text)
    get_settings.cache_clear()
    return Settings(_env_file=str(env_file))


def test_the_private_key_is_only_in_the_worker_file() -> None:
    api, worker, _ = _build()
    a, w = _values(api), _values(worker)
    assert w["ENVELOCK_CREDENTIAL_PRIVATE_KEY"]
    assert a["ENVELOCK_CREDENTIAL_PRIVATE_KEY"] == ""
    assert w["ENVELOCK_CREDENTIAL_PRIVATE_KEY"] not in api
    assert a["ENVELOCK_CREDENTIAL_PUBLIC_KEY"] == w["ENVELOCK_CREDENTIAL_PUBLIC_KEY"]
    assert a["ENVELOCK_CREDENTIAL_CAN_DECRYPT"] == "false"
    assert w["ENVELOCK_CREDENTIAL_CAN_DECRYPT"] == "true"
    # Only the worker polls mail and runs the scheduler.
    assert a["ENVELOCK_IMAP_POLL_WORKER_ENABLED"] == "false"
    assert w["ENVELOCK_IMAP_POLL_WORKER_ENABLED"] == "true"
    assert a["ENVELOCK_SCHEDULER_ENABLED"] == "false"
    assert w["ENVELOCK_SCHEDULER_ENABLED"] == "true"


def test_development_values_never_reach_production() -> None:
    api, worker, _ = _build()
    for text in (api, worker):
        v = _values(text)
        assert v["ENVELOCK_ENV"] == "production"
        assert v["ENVELOCK_SECRET_KEY"] not in ("", "the-laptop-secret")
        assert v["ENVELOCK_RLS_ENABLED"] == "true"
        assert v["ENVELOCK_POSTGRES_DSN"].startswith("postgresql+asyncpg://envelock_app:app-pw@")
        assert v["ENVELOCK_DB_OWNER_DSN"].startswith("postgresql+asyncpg://envelock:owner-pw@")
        assert v["ENVELOCK_IMAP_EGRESS_IPS"] == "203.0.113.10"
        assert v["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] == "false"
        assert v["ENVELOCK_CREDENTIAL_MASTER_KEY"] == ""
    # Both processes must sign sessions with the same key.
    assert _values(api)["ENVELOCK_SECRET_KEY"] == _values(worker)["ENVELOCK_SECRET_KEY"]


def test_push_and_link_fallback_are_on_from_the_first_boot() -> None:
    """Both are free and need no third-party account, and both are worthless if
    turned on later: a link rewritten without the edge secret can never gain the
    outage fallback."""
    api, worker, _ = _build()
    a, w = _values(api), _values(worker)
    for v in (a, w):
        assert v["ENVELOCK_MS_WEBHOOK_URL"].endswith("/api/v1/webhooks/graph")
        assert len(v["ENVELOCK_LINK_EDGE_SECRET"]) == 64
    # The signature only verifies at the edge if both processes use one secret.
    assert a["ENVELOCK_LINK_EDGE_SECRET"] == w["ENVELOCK_LINK_EDGE_SECRET"]


def test_a_missing_mail_relay_is_refused_up_front() -> None:
    tool = _tool()
    text = _laptop_env().replace(
        "ENVELOCK_SMTP_HOST=email-smtp.us-east-1.amazonaws.com", "ENVELOCK_SMTP_HOST="
    )
    with pytest.raises(SystemExit, match="SMTP_HOST"):
        tool.build(
            text,
            ip="1.2.3.4",
            owner_password="a",  # noqa: S106 — a throwaway test value
            app_password="b",  # noqa: S106
            backup_password="c",  # noqa: S106
        )


def test_both_files_pass_the_production_boot_checks(tmp_path, monkeypatch) -> None:  # noqa: ANN001
    """The real validator, the real key custody: the API is seal-only, the
    worker can decrypt."""
    from envelock.security import keys

    api, worker, _ = _build()

    api_settings = _settings_from(api, tmp_path, monkeypatch)
    assert api_settings.env == "production"
    api_provider = keys.build_provider(api_settings)
    assert not api_provider.can_unwrap

    worker_settings = _settings_from(worker, tmp_path, monkeypatch)
    worker_provider = keys.build_provider(worker_settings)
    assert worker_provider.can_unwrap
