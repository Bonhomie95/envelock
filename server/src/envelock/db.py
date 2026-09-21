"""Database engine, session and base model.

**Postgres only.** The same engine runs in local development, test and
production — moving between them is one thing: the `ENVELOCK_POSTGRES_DSN` URL.
Native Postgres column types (ARRAY, JSONB) are used directly (see `types.py`).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextvars import ContextVar
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import DateTime, MetaData, event, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from envelock.config import get_settings

#: The tenant whose rows the current task may touch. Set by the auth dependency
#: (per request) or explicitly by a worker acting for one tenant. When RLS is
#: enabled, this drives the `envelock.tenant_id` GUC on every connection, so the
#: database backstops isolation even if an application query forgets its filter.
current_tenant_id: ContextVar[str | None] = ContextVar("current_tenant_id", default=None)


def set_current_tenant(tenant_id: UUID | str | None) -> None:
    current_tenant_id.set(str(tenant_id) if tenant_id else None)

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


class UUIDMixin:
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _normalise_dsn(dsn: str) -> str:
    """Accept a plain Postgres URL and route it through the asyncpg driver.

    Only Postgres is supported — a non-Postgres DSN is a configuration error we
    fail on loudly rather than silently degrading to a different database.
    """
    if dsn.startswith("postgresql+asyncpg:"):
        return dsn
    if dsn.startswith("postgresql:"):
        return dsn.replace("postgresql:", "postgresql+asyncpg:", 1)
    raise ValueError(
        "ENVELOCK_POSTGRES_DSN must be a PostgreSQL URL "
        "(postgresql://… or postgresql+asyncpg://…); "
        f"got {dsn.split('://', 1)[0] if '://' in dsn else dsn!r}"
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        dsn = _normalise_dsn(settings.postgres_dsn)
        kwargs: dict = {
            "pool_pre_ping": True,
            "pool_size": settings.db_pool_size,
            "max_overflow": settings.db_max_overflow,
        }
        if settings.db_nullpool:
            from sqlalchemy.pool import NullPool

            # No pooled connection outlives the loop that opened it — required for
            # the test suite, which spins up many short-lived event loops.
            kwargs = {"poolclass": NullPool}
        _engine = create_async_engine(dsn, **kwargs)
        if settings.rls_enabled:
            _install_rls_guc(_engine)
    return _engine


def _install_rls_guc(engine: AsyncEngine) -> None:
    """Set the tenant GUC at the start of every transaction, from the
    `current_tenant_id` contextvar, so Postgres scopes every query to the active
    tenant (PRD §11).

    A request with no tenant in context — anything unauthenticated — sets an
    empty string. The policy turns that into NULL via `NULLIF`, which compares
    false, which matches no rows: fail closed. (The predicate used to cast `''`
    to uuid directly, which *raises* rather than matching nothing; see
    `db_rls._predicate`.)

    The second GUC carries `system_scope`, for the platform-wide work that
    genuinely has to see every tenant — the poll scan, the retention sweep, the
    operator console. It is off unless a `system_scope()` block is active.
    """
    from envelock.db_rls import GUC_SYSTEM, GUC_TENANT, current_system_scope

    # Bound parameters via `text()`, not `exec_driver_sql` with `%s`. The
    # original used the latter, which the asyncpg dialect does not translate —
    # it reaches Postgres as a literal `%` and raises a syntax error on the very
    # first transaction. Nothing caught it because this whole function only runs
    # when RLS is enabled, and RLS had never been enabled.
    #
    # The GUC names are module constants and safe to interpolate; the *values*
    # stay bound, which is the part that matters — the tenant id comes from a
    # token claim and must never be concatenated into SQL.
    _sql = text(
        f"SELECT set_config('{GUC_TENANT}', :tenant, true), "
        f"set_config('{GUC_SYSTEM}', :system, true)"
    )

    @event.listens_for(engine.sync_engine, "begin")
    def _set_tenant(conn) -> None:  # noqa: ANN001
        conn.execute(
            _sql,
            {
                "tenant": current_tenant_id.get() or "",
                "system": "on" if current_system_scope.get() else "",
            },
        )


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with get_sessionmaker()() as session:
        yield session


#: Columns added to existing tables after their first release. `create_all` only
#: creates missing *tables*, never new columns on an existing one, so a table that
#: already exists on a long-running database would silently miss these. Each entry
#: is an idempotent `ADD COLUMN IF NOT EXISTS`, applied on every startup.
_RUNTIME_COLUMNS: tuple[str, ...] = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "status varchar(16) NOT NULL DEFAULT 'active'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "must_change_password boolean NOT NULL DEFAULT false",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_customer_id varchar(64)",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "extra_mailbox_seats integer NOT NULL DEFAULT 0",
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS "
    "imap_security varchar(16) DEFAULT 'ssl'",
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS imap_username varchar(320)",
    # OAuth access-token expiry, tracked in plaintext so the refresh scheduler can
    # find due tokens without decrypting every credential.
    "ALTER TABLE mailbox_credentials ADD COLUMN IF NOT EXISTS "
    "token_expires_at timestamptz",
    # Domain-verification challenge method (txt|cname) alongside the token.
    "ALTER TABLE domains ADD COLUMN IF NOT EXISTS "
    "verification_method varchar(8) NOT NULL DEFAULT 'txt'",
    # ── Auth self-heal ──────────────────────────────────────────────────────
    # A database first built by an older release can be missing columns that
    # register/login/MFA write. Bringing them up to date here means a plain
    # redeploy fixes a drifted schema WITHOUT dropping data (the old, lossy path
    # was ENVELOCK_RESET_SCHEMA_ON_STARTUP). All nullable or defaulted so they
    # apply cleanly to a populated table.
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS plan varchar(32) NOT NULL DEFAULT 'guard'",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "billing_term varchar(16) NOT NULL DEFAULT 'monthly'",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_started_at timestamptz",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS trial_ends_at timestamptz",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS "
    "payment_method_ok boolean NOT NULL DEFAULT false",
    "ALTER TABLE tenants ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id uuid",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS name varchar(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash varchar(255)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS role varchar(16) NOT NULL DEFAULT 'member'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret varchar(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "recovery_hashes varchar[] NOT NULL DEFAULT '{}'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS out_of_band_email varchar(320)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone varchar(32)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
    "phone_verified boolean NOT NULL DEFAULT false",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_otp_hash varchar(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_otp_expires_at timestamptz",
    # ── Widen columns that an older schema sized too small ───────────────────
    # `ADD COLUMN IF NOT EXISTS` cannot fix a column that already exists with the
    # wrong TYPE. An old `users.password_hash varchar(32)` truncates a scrypt hash
    # (~76 chars) and 500s every registration. Widening varchar is a metadata-only,
    # data-safe change in Postgres; setting a column to the size it already has is a
    # harmless no-op. These run after the ADDs above, so the column always exists.
    "ALTER TABLE users ALTER COLUMN password_hash TYPE varchar(255)",
    "ALTER TABLE users ALTER COLUMN email TYPE varchar(320)",
    "ALTER TABLE users ALTER COLUMN name TYPE varchar(255)",
    "ALTER TABLE users ALTER COLUMN role TYPE varchar(16)",
    "ALTER TABLE users ALTER COLUMN status TYPE varchar(16)",
    "ALTER TABLE users ALTER COLUMN totp_secret TYPE varchar(64)",
    "ALTER TABLE users ALTER COLUMN out_of_band_email TYPE varchar(320)",
    "ALTER TABLE users ALTER COLUMN phone TYPE varchar(32)",
    "ALTER TABLE users ALTER COLUMN phone_otp_hash TYPE varchar(64)",
    "ALTER TABLE tenants ALTER COLUMN name TYPE varchar(255)",
    "ALTER TABLE tenants ALTER COLUMN plan TYPE varchar(32)",
    "ALTER TABLE tenants ALTER COLUMN billing_term TYPE varchar(16)",
)


def _reconcile_plan(sync_conn) -> list[str]:  # noqa: ANN001
    """Compare every mapped table to the live database and return the DDL needed to
    bring the database up to the models — WITHOUT dropping anything.

    Two kinds of drift on a long-running database bite `create_all` (which only ever
    creates whole *missing tables*): a column the models added later that the live
    table lacks, and a column the live table sized too small for what the app now
    writes (the real Render failure: `users.password_hash varchar(32)` truncating a
    scrypt hash). This introspects the DB and emits, per table that already exists:

      * `ADD COLUMN` for every model column missing on the live table — always
        NULLABLE (never NOT NULL), so it applies cleanly to a populated table; the
        ORM supplies values on write.
      * `ALTER COLUMN … TYPE varchar(N)` for every text column the DB sized SMALLER
        than the model. Only ever *widens* — never shrinks (which could truncate) —
        and widening a varchar in Postgres is a metadata-only, data-safe change.

    Purely additive and non-destructive: no DROP, no NOT NULL, no narrowing.
    """
    from sqlalchemy import inspect as sa_inspect

    insp = sa_inspect(sync_conn)
    dialect = sync_conn.dialect
    existing_tables = set(insp.get_table_names())
    stmts: list[str] = []

    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # a brand-new table — create_all already built it in full
        db_cols = {c["name"]: c for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in db_cols:
                type_sql = col.type.compile(dialect=dialect)
                stmts.append(
                    f'ALTER TABLE "{table.name}" '
                    f'ADD COLUMN IF NOT EXISTS "{col.name}" {type_sql}'
                )
                continue
            model_len = getattr(col.type, "length", None)
            db_len = getattr(db_cols[col.name]["type"], "length", None)
            if isinstance(model_len, int) and isinstance(db_len, int) and db_len < model_len:
                stmts.append(
                    f'ALTER TABLE "{table.name}" '
                    f'ALTER COLUMN "{col.name}" TYPE varchar({model_len})'
                )
    return stmts


async def create_all() -> None:
    """Create any missing tables, then reconcile the live schema to the models
    (add missing columns, widen under-sized ones). Idempotent, so it is safe to run
    on every startup — this is what makes "just point at a Postgres, even a drifted
    one" work without dropping data. Alembic remains available for managed
    migrations and RLS."""

    import logging

    from envelock import models  # noqa: F401  (register metadata)

    logger = logging.getLogger("envelock.db")
    settings = get_settings()

    # Every statement below is DDL. Under RLS the request-path role deliberately
    # owns nothing and can run none of it, so on the ordinary engine a release
    # that adds a column would boot, log a warning per statement, and then fail
    # every query that touches the column. Use the owner's DSN when one is set:
    # a dedicated engine, disposed at the end, so owner credentials never sit in
    # the request-path pool.
    owner_engine = None
    if settings.db_owner_dsn:
        from sqlalchemy.pool import NullPool

        owner_engine = create_async_engine(
            _normalise_dsn(settings.db_owner_dsn), poolclass=NullPool
        )
    try:
        await _apply_schema(owner_engine or get_engine(), settings, logger)
    finally:
        if owner_engine is not None:
            await owner_engine.dispose()

    if settings.rls_enabled:
        from envelock.db_rls import verify_rls

        async with get_engine().connect() as conn:
            status = await verify_rls(conn, enabled=True)
        if status.effective:
            logger.info("%s", status.summary())
        else:
            # Loud, and specific about which of the three ways it is off. A
            # deployment that believes it has tenant isolation and does not is
            # worse than one that knows it does not.
            logger.error("%s", status.summary())


async def _apply_schema(ddl_engine, settings, logger) -> None:  # noqa: ANN001
    async with ddl_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Generic, whole-schema reconcile: introspect the live DB and fix ANY table that
    # is missing columns or has an under-sized one — not just the hand-listed few.
    # This is what catches drift on tables we didn't anticipate here.
    try:
        async with ddl_engine.connect() as conn:
            plan = await conn.run_sync(_reconcile_plan)
    except Exception as exc:  # noqa: BLE001 — introspection failure must not block boot
        logger.warning("schema reconcile introspection skipped: %s", exc)
        plan = []

    # Specific defaults/types first (some columns want a server DEFAULT the generic
    # ADD can't infer), then the generic reconcile as the catch-all. Each statement
    # runs in its OWN transaction and is tolerant: a single ALTER that can't apply
    # (e.g. a legacy column with unexpected data) is logged and skipped rather than
    # aborting startup and taking the whole service down. The rest still apply.
    applied = 0
    for stmt in (*_RUNTIME_COLUMNS, *plan):
        try:
            async with ddl_engine.begin() as conn:
                await conn.execute(text(stmt))
            if stmt in plan:
                logger.info("schema reconcile: %s", stmt)
                applied += 1
        except Exception as exc:  # noqa: BLE001 — one bad stmt must not block boot
            logger.warning("runtime schema statement skipped: %s — %s", stmt, exc)
    if applied:
        logger.warning("schema reconcile applied %d drift-fix statement(s)", applied)

    # Row-level security, applied from here rather than only from a migration.
    # The schema can be built by create_all as well as by Alembic, so an RLS that
    # only existed in a migration was an RLS that might never reach production —
    # the flag would set the tenant GUC against a database with no policies on
    # it, which costs the same and protects nothing.
    if settings.rls_enabled:
        from envelock.db_rls import apply_rls

        try:
            async with ddl_engine.begin() as conn:
                await apply_rls(conn, app_role=settings.db_app_role)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "RLS could not be applied: %s. If the app connects as the "
                "restricted role, set ENVELOCK_DB_OWNER_DSN to the table "
                "owner's DSN so the policies can be created.",
                exc,
            )


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
