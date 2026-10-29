"""Guards the Alembic migration chain.

Two failures had crept in and stayed invisible because the app builds its schema
at boot via `create_all` (+ the reconciler), not via migrations:
  * the migrations were DEAD — they called `StringList()` / `JsonDict()` as if
    callable, so `alembic upgrade head` crashed on the first migration; and
  * they had drifted far behind the models (no user roles/MFA/recovery, no
    billing/imap/domain-lifecycle columns, missing whole tables).

These tests keep both from recurring: the chain must have a single head, must
apply cleanly end-to-end, and must leave ZERO difference from the models.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import uuid

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_INI = os.path.join(os.path.dirname(_HERE), "alembic.ini")


def _config(url: str | None = None):
    from alembic.config import Config

    cfg = Config(_INI)
    if url:
        cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def test_single_migration_head() -> None:
    """A branched history (two heads) means a merge was missed — upgrades become
    ambiguous. There must be exactly one head."""
    from alembic.script import ScriptDirectory

    heads = ScriptDirectory.from_config(_config()).get_heads()
    assert len(heads) == 1, f"expected a single migration head, got {heads}"


def test_migrations_apply_and_match_models(monkeypatch) -> None:
    """Run the whole chain into a throwaway database and assert it matches the
    models (compare_metadata finds nothing). Skips where the DB role can't create
    databases/roles — where it runs, it is the real drift guard."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from envelock.config import get_settings
    from envelock.db import Base, _normalise_dsn

    base_url = _normalise_dsn(get_settings().postgres_dsn)
    if "@" not in base_url or "/" not in base_url.rsplit("@", 1)[1]:
        pytest.skip("non-standard DSN; migration apply-test skipped")
    prefix, tail = base_url.rsplit("/", 1)  # tail = dbname
    tmp_db = f"envelock_migcheck_{uuid.uuid4().hex[:10]}"
    tmp_url = f"{prefix}/{tmp_db}"
    admin_url = f"{prefix}/postgres"

    async def _run_admin(sql: str) -> None:
        eng = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
        try:
            from sqlalchemy import text

            async with eng.connect() as conn:
                await conn.execute(text(sql))
        finally:
            await eng.dispose()

    try:
        asyncio.run(_run_admin(f'CREATE DATABASE "{tmp_db}"'))
    except Exception as exc:  # noqa: BLE001 — no createdb privilege in this env
        pytest.skip(f"cannot create a scratch database here: {exc}")

    try:
        # env.py reads ENVELOCK_POSTGRES_DSN via get_settings(); point it at the
        # scratch DB (the autouse settings-cache fixture keeps this from leaking).
        monkeypatch.setenv("ENVELOCK_POSTGRES_DSN", tmp_url)
        get_settings.cache_clear()

        from alembic import command

        try:
            command.upgrade(_config(), "head")
        except Exception as exc:  # noqa: BLE001
            if "permission denied to create role" in str(exc).lower():
                pytest.skip("role lacks CREATEROLE for the RLS migration")
            raise

        async def _diff() -> list:
            from alembic.autogenerate import compare_metadata
            from alembic.migration import MigrationContext

            eng = create_async_engine(tmp_url)
            try:
                async with eng.connect() as conn:
                    return await conn.run_sync(
                        lambda sconn: compare_metadata(
                            MigrationContext.configure(sconn), Base.metadata
                        )
                    )
            finally:
                await eng.dispose()

        diffs = asyncio.run(_diff())
        assert diffs == [], f"migrations drifted from the models: {diffs}"
    finally:
        get_settings.cache_clear()
        with contextlib.suppress(Exception):  # best-effort cleanup
            asyncio.run(_run_admin(f'DROP DATABASE IF EXISTS "{tmp_db}" WITH (FORCE)'))


def test_running_migrations_does_not_silence_the_application() -> None:
    """Alembic must not take the app's logging with it.

    `logging.config.fileConfig` defaults to `disable_existing_loggers=True`, so
    loading `alembic.ini` DISABLED every logger that already existed. In this
    suite that muted the application for every test that ran afterwards, which
    surfaced as log assertions passing alone and failing together — an hour to
    diagnose, because a disabled logger raises nothing and drops records before
    any handler can see them.

    It matters beyond tests: anything that runs a migration in-process before
    serving would come up mute, and a service that cannot say what is wrong is
    the failure this codebase spends most of its effort avoiding.
    """
    import logging

    from alembic.config import Config

    probe = logging.getLogger("envelock.billing.price_check")
    assert not probe.disabled

    Config(_INI)  # loads alembic.ini through migrations/env.py's fileConfig

    assert not probe.disabled, (
        "loading the Alembic config disabled an application logger — "
        "migrations/env.py must pass disable_existing_loggers=False"
    )



@contextlib.contextmanager
def _scratch_db(monkeypatch, label: str):  # noqa: ANN001, ANN202
    """A throwaway database for migrating populated data. Yields `sql(*steps)`,
    which runs statements on one connection and returns the last one's rows.
    Row-level security is forced, so it opts into system scope."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    from envelock.config import get_settings
    from envelock.db import _normalise_dsn

    base_url = _normalise_dsn(get_settings().postgres_dsn)
    if "@" not in base_url or "/" not in base_url.rsplit("@", 1)[1]:
        pytest.skip("non-standard DSN; migration apply-test skipped")
    prefix, _ = base_url.rsplit("/", 1)
    tmp_db = f"envelock_{label}_{uuid.uuid4().hex[:10]}"
    tmp_url, admin_url = f"{prefix}/{tmp_db}", f"{prefix}/postgres"

    async def _sql(url: str, *steps: tuple[str, dict]) -> list:
        eng = create_async_engine(url, isolation_level="AUTOCOMMIT")
        try:
            async with eng.connect() as conn:
                if url == tmp_url:
                    await conn.execute(text("SELECT set_config('envelock.system', 'on', false)"))
                result = None
                for sql, params in steps:
                    result = await conn.execute(text(sql), params)
                return result.all() if result is not None and result.returns_rows else []
        finally:
            await eng.dispose()

    try:
        asyncio.run(_sql(admin_url, (f'CREATE DATABASE "{tmp_db}"', {})))
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"cannot create a scratch database here: {exc}")
    try:
        monkeypatch.setenv("ENVELOCK_POSTGRES_DSN", tmp_url)
        get_settings.cache_clear()
        yield lambda *steps: asyncio.run(_sql(tmp_url, *steps))
    finally:
        get_settings.cache_clear()
        with contextlib.suppress(Exception):
            asyncio.run(_sql(admin_url, (f'DROP DATABASE IF EXISTS "{tmp_db}" WITH (FORCE)', {})))


def _upgrade(revision: str) -> None:
    from alembic import command

    try:
        command.upgrade(_config(), revision)
    except Exception as exc:  # noqa: BLE001
        if "permission denied to create role" in str(exc).lower():
            pytest.skip("role lacks CREATEROLE for the RLS migration")
        raise


_INSERT_TENANT = (
    "INSERT INTO tenants (id, name, plan, billing_term, payment_method_ok, is_active,"
    " created_at, updated_at) VALUES (:t, 'Old Co', 'guard', 'monthly', false, true,"
    " now(), now())"
)


def test_the_sealing_migration_encrypts_secrets_already_stored(monkeypatch) -> None:
    """Stored before encryption at rest, authenticator seeds and webhook signing
    keys are plain text. Upgrading must seal every one of them — and leave each
    still readable through the model."""
    from envelock.security.fields import PREFIX, open_field

    with _scratch_db(monkeypatch, "migseal") as sql:
        _upgrade("e0f1a2b3c4d5")
        seed, hook = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "whsec_plain-signing-key"
        tid = str(uuid.uuid4())
        sql(
            (_INSERT_TENANT, {"t": tid}),
            ("INSERT INTO users (id, tenant_id, email, role, is_admin, status,"
             " must_change_password, mfa_enabled, recovery_hashes, known_devices,"
             " phone_verified, totp_secret, created_at, updated_at) VALUES (gen_random_uuid(),"
             " :t, 'old@co.example', 'owner', true, 'active', false, true, '{}', '{}', false,"
             " :seed, now(), now())", {"t": tid, "seed": seed}),
            ("INSERT INTO staff_accounts (id, email, department, granted_permissions,"
             " revoked_permissions, status, must_change_password, mfa_enabled, recovery_hashes,"
             " totp_secret, created_at, updated_at) VALUES (gen_random_uuid(), 'op@envelock.org',"
             " 'support', '{}', '{}', 'active', false, true, '{}', :seed, now(), now())",
             {"seed": seed}),
            ("INSERT INTO webhook_endpoints (id, tenant_id, url, secret, events, active,"
             " created_at, updated_at) VALUES (gen_random_uuid(), :t, 'https://siem.example',"
             " :hook, '{}', true, now(), now())", {"t": tid, "hook": hook}),
        )

        _upgrade("head")

        stored = sql((
            "SELECT totp_secret FROM users UNION ALL SELECT totp_secret FROM staff_accounts"
            " UNION ALL SELECT secret FROM webhook_endpoints", {},
        ))
    values = [v for (v,) in stored]
    assert len(values) == 3 and all(v.startswith(PREFIX) for v in values), values
    assert [open_field(v) for v in values] == [seed, seed, hook]


def test_the_ingest_token_migration_gives_every_tenant_a_secret(monkeypatch) -> None:
    """Existing tenants each get their own secret forwarding token — never the
    DNS token they published — and only those already forwarding mail are
    flagged to update their rule."""
    with _scratch_db(monkeypatch, "migingest") as sql:
        _upgrade("f1a2b3c4d5e6")
        forwarding, other = str(uuid.uuid4()), str(uuid.uuid4())
        for tid, sources in ((forwarding, ["imap_idle", "forward_ingest"]), (other, ["imap_idle"])):
            sql(
                (_INSERT_TENANT, {"t": tid}),
                ("INSERT INTO domains (id, tenant_id, name, registrable_domain,"
                 " verification_token, is_defensive, created_at, updated_at) VALUES"
                 " (gen_random_uuid(), :t, :d, :d, :tok, false, now(), now())",
                 {"t": tid, "d": f"{tid[:8]}.example", "tok": f"dns{tid[:8]}"}),
                ("INSERT INTO mailboxes (id, tenant_id, address, mailbox_class,"
                 " integration_tier, sources, protection_level, inactive_detections,"
                 " is_shared, known_user_count, is_active, created_at, updated_at) VALUES"
                 " (gen_random_uuid(), :t, :a, 'protected', 4, :s,"
                 " 'limited', '{}', false, 1, true, now(), now())",
                 {"t": tid, "a": f"pay@{tid[:8]}.example", "s": sources}),
            )

        _upgrade("head")

        rows = sql((
            "SELECT t.id::text, t.ingest_token, t.forwarding_rule_stale, d.verification_token"
            " FROM tenants t JOIN domains d ON d.tenant_id = t.id", {},
        ))
    tokens = {tid: token for tid, token, _, _ in rows}
    assert len(set(tokens.values())) == 2, rows
    assert all(len(t) == 32 and int(t, 16) >= 0 for t in tokens.values()), rows
    assert all(token != dns for _, token, _, dns in rows), rows
    assert {tid: stale for tid, _, stale, _ in rows} == {forwarding: True, other: False}
