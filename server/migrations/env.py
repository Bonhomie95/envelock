"""Alembic environment. Postgres owns production schema; SQLite bootstraps
itself in dev (see envelock.db.create_all)."""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import async_engine_from_config
from sqlalchemy import pool

from envelock.config import get_settings
from envelock.db import Base, _normalise_dsn
from envelock import models  # noqa: F401  (register metadata)

config = context.config
if config.config_file_name:
    # `disable_existing_loggers=False` matters outside Alembic's own process.
    # The default is True, which DISABLES every logger that already exists — so
    # anything that runs a migration in-process (the test suite does; a boot-time
    # upgrade would too) silences the whole application afterwards. A disabled
    # logger drops records before any handler sees them, so nothing downstream
    # can notice or recover: the app simply stops saying anything, which is the
    # exact failure mode the rest of this codebase works to avoid.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

# `ddl_dsn`, not `postgres_dsn`: under RLS the application connects as a
# restricted role with no DDL rights, so migrations run with the owner's
# credentials (ENVELOCK_DB_OWNER_DSN). Unset, it is the same DSN.
config.set_main_option("sqlalchemy.url", _normalise_dsn(get_settings().ddl_dsn))
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _do_run(connection) -> None:  # noqa: ANN001
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(_do_run)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
