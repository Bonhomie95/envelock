"""Schema changes run as the owner, not the request-path role.

Under RLS the application connects as `envelock_app`, which `provision_rls`
deliberately grants only SELECT/INSERT/UPDATE/DELETE — having no DDL rights is
the entire point of it. But two things also need DDL:

  * `alembic upgrade head`, which `deploy.sh` runs on every deploy;
  * `apply_rls` at boot, which issues ALTER TABLE / CREATE POLICY / GRANT so a
    table added by a later migration is covered.

Both read the same DSN the app serves requests with. So the moment a deployment
was set up *correctly*, every deploy's migration step would fail — and the boot
path would fail into a logged warning, leaving an operator believing tenant
isolation was on when no policy had ever been created.

`ddl_dsn` is the separation. These pin it, because the failure only appears on a
correctly-configured production box and nowhere else.
"""

from __future__ import annotations

import pytest

APP_DSN = "postgresql+asyncpg://envelock_app:restricted@localhost:5432/envelock"
OWNER_DSN = "postgresql+asyncpg://envelock:owner@localhost:5432/envelock"


@pytest.fixture
def settings_with(monkeypatch):  # noqa: ANN001, ANN201
    from envelock.config import get_settings

    def build(**env: str):
        for key, value in env.items():
            monkeypatch.setenv(f"ENVELOCK_{key.upper()}", value)
        get_settings.cache_clear()
        return get_settings()

    yield build
    get_settings.cache_clear()


def test_ddl_falls_back_to_the_app_dsn_when_no_owner_is_set(settings_with) -> None:  # noqa: ANN001
    """Development connects as the owner anyway — one DSN is correct there, and
    requiring a second would be ceremony."""
    s = settings_with(postgres_dsn=APP_DSN)
    assert s.ddl_dsn == APP_DSN


def test_the_owner_dsn_is_used_for_ddl_when_set(settings_with) -> None:  # noqa: ANN001
    s = settings_with(postgres_dsn=APP_DSN, db_owner_dsn=OWNER_DSN)
    assert s.ddl_dsn == OWNER_DSN
    # And the request path is untouched — it must keep the restricted role.
    assert s.postgres_dsn == APP_DSN


def test_alembic_is_configured_from_the_ddl_dsn_not_the_app_dsn() -> None:
    """The regression itself. `migrations/env.py` read `postgres_dsn`, so once the
    app was pointed at the restricted role, `alembic upgrade head` — which
    `deploy.sh` runs before every restart — failed on a permissions error."""
    import pathlib

    env_py = (
        pathlib.Path(__file__).resolve().parents[1] / "migrations" / "env.py"
    ).read_text()
    assert "ddl_dsn" in env_py, "alembic must take the owner DSN"
    assert "get_settings().postgres_dsn" not in env_py, (
        "alembic is back on the request-path DSN — migrations will fail under RLS"
    )


def test_the_app_engine_never_uses_the_owner_dsn(settings_with) -> None:  # noqa: ANN001
    """Owner credentials must not end up in the pool that serves requests —
    that would hand every request DDL rights and make RLS inert."""
    from envelock import db

    s = settings_with(postgres_dsn=APP_DSN, db_owner_dsn=OWNER_DSN)
    assert s.postgres_dsn == APP_DSN
    # The engine builder reads postgres_dsn and nothing else.
    source = (
        __import__("pathlib").Path(db.__file__).read_text()
    )
    builder = source.split("def get_engine()")[1].split("def _install_rls_guc")[0]
    assert "postgres_dsn" in builder
    assert "db_owner_dsn" not in builder, (
        "the request-path engine must never be built from owner credentials"
    )


@pytest.mark.asyncio
async def test_boot_schema_repair_runs_as_the_owner_not_the_app_role(db, monkeypatch) -> None:  # noqa: ANN001
    """The boot-time reconciler, not just `apply_rls`, is DDL.

    It used to run on the request-path engine. Under RLS that role owns nothing,
    so a release that added a column booted, logged one warning per ALTER, and
    then failed every query touching the column. Proven here with a real role
    that has no DDL rights: drop a column as the owner, boot as that role with
    the owner DSN set, and the column must come back.
    """
    import asyncpg
    from conftest import ADMIN_DSN, TEST_DSN
    from sqlalchemy import text

    from envelock import db as db_module
    from envelock.config import get_settings

    role, pw = "envelock_ddl_probe", "ddl-probe-local-only"
    plain = ADMIN_DSN.replace("postgresql+asyncpg://", "postgresql://")
    admin = await asyncpg.connect(plain)
    try:
        await admin.execute(
            f"DO $$ BEGIN CREATE ROLE {role} LOGIN PASSWORD '{pw}'; "
            f"EXCEPTION WHEN duplicate_object THEN "
            f"ALTER ROLE {role} LOGIN PASSWORD '{pw}'; END $$;"
        )
        name = await admin.fetchval("SELECT current_database()")
        await admin.execute(f'GRANT CONNECT ON DATABASE "{name}" TO {role}')
    finally:
        await admin.close()

    await db_module.create_all()
    async with db_module.get_engine().begin() as c:
        await c.execute(text("ALTER TABLE mailboxes DROP COLUMN backfill_state"))

    prefix, _, tail = TEST_DSN.partition("://")
    restricted = f"{prefix}://{role}:{pw}@{tail.partition('@')[2]}"

    async def _rebind(**env: str) -> None:
        for key, value in env.items():
            monkeypatch.setenv(f"ENVELOCK_{key.upper()}", value)
        get_settings.cache_clear()
        await db_module.dispose()

    try:
        await _rebind(postgres_dsn=restricted, db_owner_dsn=TEST_DSN)
        await db_module.create_all()
    finally:
        await _rebind(postgres_dsn=TEST_DSN, db_owner_dsn="")

    async with db_module.get_engine().begin() as c:
        present = (
            await c.execute(
                text(
                    "SELECT 1 FROM information_schema.columns "
                    "WHERE table_name='mailboxes' AND column_name='backfill_state'"
                )
            )
        ).first()
    assert present, "boot DDL ran as the app role, which cannot ALTER — column lost"
