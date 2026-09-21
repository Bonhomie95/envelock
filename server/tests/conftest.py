"""Shared test fixtures."""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

# The suite runs against a dedicated Postgres database (the same engine as
# production — Postgres is the only supported backend). Override the *server*
# with ENVELOCK_TEST_POSTGRES_DSN if your local role or host differ; the
# database name on the end of it is replaced per run, see below.
_BASE_DSN = os.environ.get(
    "ENVELOCK_TEST_POSTGRES_DSN",
    "postgresql+asyncpg://envelock:envelock@localhost:5432/envelock_test",
)


def _per_run_dsn(base: str) -> str:
    """Give this pytest process its own database.

    Every run used to share one fixed `envelock_test`, while both the
    session-scoped schema fixture and the per-test `db` fixture ran
    drop_all/create_all against it. Two consequences, both real:

    * Two runs at once destroyed each other — the second one dropped the first
      one's tables mid-test, producing failures that looked like code defects
      and were not. That makes `pytest -n auto` impossible and breaks the moment
      CI runs two jobs against one database server.
    * A killed run left the database populated, so the *next* run started dirty.

    The name carries the pid and a short random suffix, plus the xdist worker id
    when running distributed, so no two processes can collide.

    The one cost: a run killed with SIGKILL never reaches its teardown and leaves
    its database behind. They are small and harmless, and this clears any strays:

        psql -d postgres -tAc "select datname from pg_database
          where datname like 'envelock_test\\_%'" \\
          | xargs -r -n1 -I{} dropdb --if-exists --force {}

    Run it only when no suite is in flight — it does not distinguish a stray from
    a database a concurrent run is using.
    """
    prefix, _, name = base.rpartition("/")
    name = name.split("?")[0] or "envelock_test"
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    suffix = f"{os.getpid()}_{uuid.uuid4().hex[:8]}{('_' + worker) if worker else ''}"
    # Postgres identifiers cap at 63 bytes.
    return f"{prefix}/{name[:32]}_{suffix}"


#: The database this run owns. Created and dropped by the `_schema` fixture.
TEST_DSN = _per_run_dsn(_BASE_DSN)
os.environ["ENVELOCK_POSTGRES_DSN"] = TEST_DSN

#: Run the entire suite with row-level security enforced. Opt-in because it is a
#: different question from "does the code work" — it asks "does the code work
#: when the database refuses anything the caller did not scope". CI should run
#: both; see .github/workflows/ci.yml.
RLS_MODE = os.environ.get("ENVELOCK_TEST_RLS", "").strip().lower() in {"1", "true", "yes"}

#: In RLS mode the suite runs as a dedicated role that OWNS the run's database.
#: Owning it means DDL still works (`create_all` on boot); being a plain role
#: means `FORCE ROW LEVEL SECURITY` actually binds it. Both halves are required:
#: Postgres ignores every policy for a superuser or a BYPASSRLS role, and the
#: default `POSTGRES_USER` in the official Postgres image — which is what CI
#: uses — *is* a superuser. Running RLS mode as that role would pass every test
#: while enforcing nothing.
RLS_ROLE = "envelock_rls_suite"
RLS_ROLE_PW = "rls-suite-local-only"  # noqa: S105 — a throwaway test database

if RLS_MODE:
    os.environ["ENVELOCK_RLS_ENABLED"] = "true"
    _prefix, _, _tail = TEST_DSN.partition("://")
    _creds, _, _hostpart = _tail.partition("@")
    ADMIN_DSN = TEST_DSN
    TEST_DSN = f"{_prefix}://{RLS_ROLE}:{RLS_ROLE_PW}@{_hostpart}"
    os.environ["ENVELOCK_POSTGRES_DSN"] = TEST_DSN
else:
    ADMIN_DSN = TEST_DSN
os.environ.setdefault("ENVELOCK_SECRET_KEY", "test-secret-key-not-for-production")
# The suite must not depend on a developer's `.env` existing. Several tests build
# Settings with ENVELOCK_ENV=production to exercise the boot validators, and that
# path requires usable credential key custody — which a local `.env` happened to
# supply and CI, correctly, does not. The result was a suite that was green on
# every laptop and red on the first real CI run, for a reason unrelated to any
# change in it.
os.environ.setdefault("ENVELOCK_CREDENTIAL_MASTER_KEY", "0" * 64)
os.environ.setdefault("ENVELOCK_ENV", "development")
# No connection pooling in tests: the suite runs many short event loops and a
# pooled asyncpg connection must never be reused across a different loop.
os.environ["ENVELOCK_DB_NULLPOOL"] = "true"
# Force the in-memory rate limiter / auth stores in tests, overriding any local
# .env=redis. Tests reset the in-process state between cases; a shared Redis would
# leak counters from a dev server (or a prior run) and cause spurious 429s.
os.environ["ENVELOCK_RATE_LIMIT_BACKEND"] = "memory"
# Keep the domain scan hermetic — no live RDAP calls to date lookalike hits.
os.environ.setdefault("ENVELOCK_SCAN_REGISTRATION_DATES", "false")
# The live IMAP poll worker must not run during tests — the suite drives
# sync_mailbox / run_imap_poll_cycle directly with an injected client. A real
# background poller would open sockets and leak tasks across the TestClient
# lifespan.
os.environ["ENVELOCK_IMAP_POLL_WORKER_ENABLED"] = "false"
# Likewise, the periodic scheduler (escalation, retention, watchers, OAuth
# refresh) is driven directly by its own tests, never as a background loop under
# the TestClient — a live CT-log websocket or purge loop would leak tasks.
os.environ["ENVELOCK_SCHEDULER_ENABLED"] = "false"
# L2 email and L3 SMS are unconfigured in the suite so the ladder reports them as
# skipped rather than attempting a real network send against a dev .env's SMTP
# host. Delivery transports have their own focused tests with injected fakes.
os.environ["ENVELOCK_SMTP_HOST"] = ""
os.environ["ENVELOCK_SMS_ENABLED"] = "false"
# Most connect-flow tests predate domain verification and connect mailboxes
# directly; the enforcement has its own focused test that flips this on.
os.environ["ENVELOCK_REQUIRE_DOMAIN_VERIFICATION"] = "false"
# Same shape, and pinned for the same reason the block above exists: nearly every
# test in the suite registers an account and signs straight in, which email
# verification correctly refuses. Turning the flag on in the deployment's own
# `.env` therefore failed 135 tests that have nothing to do with verification —
# the suite has to be hermetic against `.env`, not a reader of it. Assignment,
# not `setdefault`: `test_email_verification.py` turns it on with monkeypatch,
# which still wins.
os.environ["ENVELOCK_REQUIRE_EMAIL_VERIFICATION"] = "false"
# The suite registers made-up domains (acme.com, *.example) that don't resolve;
# the real-domain-existence check has its own focused test that flips this on.
os.environ["ENVELOCK_CHECK_EMAIL_DOMAIN_EXISTS"] = "false"
# Sender-domain reputation does live DNSBL lookups; keep the suite hermetic and
# fast. Its own test drives the checker directly.
os.environ["ENVELOCK_DOMAIN_REPUTATION_ENABLED"] = "false"

# The suite must be hermetic against the developer's own .env: environment
# variables outrank the file in pydantic-settings, so these force every network
# provider OFF regardless of what real keys sit in server/.env. Without this,
# a developer with ENVELOCK_LLM_PROVIDER=openai in .env had the test suite
# making LIVE OpenAI calls on every payment-signal fixture — non-deterministic
# verdicts, real spend, and tier promotions the assertions never asked for.
os.environ["ENVELOCK_LLM_PROVIDER"] = "none"
os.environ["ENVELOCK_IPINFO_TOKEN"] = ""
os.environ["ENVELOCK_SAFEBROWSING_API_KEY"] = ""
os.environ["ENVELOCK_VIRUSTOTAL_API_KEY"] = ""
os.environ["ENVELOCK_SCAN_REGISTRATION_DATES"] = "false"
# OAuth app creds too: tests provision them per-case (configured_ms / configured_
# google fixtures), so a developer's real .env keys must not make an
# "unconfigured provider" case read as configured.
os.environ["ENVELOCK_MS_CLIENT_ID"] = ""
os.environ["ENVELOCK_MS_CLIENT_SECRET"] = ""
os.environ["ENVELOCK_GOOGLE_CLIENT_ID"] = ""
os.environ["ENVELOCK_GOOGLE_CLIENT_SECRET"] = ""
# Payment provider keys too: the billing tests provision Stripe per-case
# (configured_stripe fixture) and assert on the UNCONFIGURED path — a
# developer's real keys in .env otherwise made a test hit the live Stripe API.
for _k in (
    "ENVELOCK_STRIPE_SECRET_KEY",
    "ENVELOCK_STRIPE_WEBHOOK_SECRET",
    "ENVELOCK_STRIPE_PRICE_ESSENTIAL",
    "ENVELOCK_STRIPE_PRICE_COMPLETE",
    "ENVELOCK_ADYEN_API_KEY",
    "ENVELOCK_ADYEN_MERCHANT_ACCOUNT",
    "ENVELOCK_MERCADOPAGO_ACCESS_TOKEN",
    "ENVELOCK_RAZORPAY_KEY_ID",
    "ENVELOCK_RAZORPAY_KEY_SECRET",
    "ENVELOCK_PAYPAL_CLIENT_ID",
    "ENVELOCK_PAYPAL_CLIENT_SECRET",
):
    os.environ[_k] = ""
# Custody must start from the dev baseline (master key only): a developer who
# has generated the x25519 pair in .env would otherwise change which provider
# `auto` selects out from under the custody tests.
os.environ["ENVELOCK_CREDENTIAL_PUBLIC_KEY"] = ""
os.environ["ENVELOCK_CREDENTIAL_PRIVATE_KEY"] = ""
os.environ["ENVELOCK_KMS_KEY_ID"] = ""
os.environ["ENVELOCK_KMS_PROVIDER"] = ""
# Development custody (local master key) is the mode the suite asserts on — a
# developer whose .env selects x25519/KMS would otherwise flip it.
os.environ["ENVELOCK_CREDENTIAL_KEY_PROVIDER"] = "local"
os.environ.setdefault("ENVELOCK_CREDENTIAL_MASTER_KEY", "test-suite-development-master-key")
# The suite exercises the FULL surface (billing, governance, staff, admin), so
# focus mode is off here. Focus-mode routing has its own focused test.
os.environ["ENVELOCK_FOCUS_CORE"] = "false"


async def _admin_execute(statement: str) -> None:
    """Run a CREATE/DROP DATABASE against the `postgres` maintenance database.

    Those statements cannot run inside a transaction, and they cannot run while
    connected to the database they target, so this opens its own short-lived
    asyncpg connection rather than borrowing the app's engine.
    """
    import asyncpg

    prefix, _, _name = ADMIN_DSN.rpartition("/")
    admin_url = f"{prefix}/postgres".replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(admin_url)
    try:
        await conn.execute(statement)
    finally:
        await conn.close()


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    """Own a database for this run: create it, build the schema, drop it after.

    Previously this created the schema inside a *shared* fixed database and
    dropped the tables at the end. Concurrent runs therefore fought over one
    database, and a killed run left it populated for the next one.
    """
    import asyncio
    import contextlib

    _, _, db_name = TEST_DSN.rpartition("/")

    async def _setup() -> None:
        from envelock.db import create_all, dispose

        await _admin_execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')
        if RLS_MODE:
            # A plain role that owns the database: it can run DDL, and FORCE
            # binds it. Created with no attributes, so it is neither superuser
            # nor BYPASSRLS whatever the admin role happens to be.
            await _admin_execute(
                f"DO $$ BEGIN CREATE ROLE {RLS_ROLE} LOGIN PASSWORD "
                f"'{RLS_ROLE_PW}'; EXCEPTION WHEN duplicate_object THEN "
                f"ALTER ROLE {RLS_ROLE} LOGIN PASSWORD '{RLS_ROLE_PW}'; END $$;"
            )
            # Assigning database ownership requires membership in the target
            # role unless we are superuser — which, deliberately, we may not be.
            await _admin_execute(f"GRANT {RLS_ROLE} TO CURRENT_USER")
            await _admin_execute(f'CREATE DATABASE "{db_name}" OWNER {RLS_ROLE}')
        else:
            await _admin_execute(f'CREATE DATABASE "{db_name}"')
        await create_all()

        # ENVELOCK_TEST_RLS=1 runs the WHOLE suite with row-level security
        # actually enforced, rather than only the focused tests in test_rls.py.
        # That is the only way to answer "does the application still work with
        # the database refusing unscoped queries?" — a question no amount of
        # reading can settle, because the failure mode is a query somewhere
        # quietly returning nothing.
        #
        # It works here because the test role owns the tables and is neither a
        # superuser nor BYPASSRLS, so FORCE binds it. On a real deployment the
        # app connects as a separate restricted role; see
        # `python -m envelock.security.provision_rls`.
        if RLS_MODE:
            from envelock.db import get_engine
            from envelock.db_rls import apply_rls, verify_rls

            async with get_engine().begin() as conn:
                await apply_rls(conn, app_role=RLS_ROLE)
            async with get_engine().connect() as conn:
                status = await verify_rls(conn, enabled=True)
            if status.role_bypasses:
                raise RuntimeError(
                    f"ENVELOCK_TEST_RLS=1 but the test role "
                    f"({status.connected_role!r}) bypasses RLS, so the run would "
                    "prove nothing. Use a non-superuser role without BYPASSRLS."
                )
            print(f"\n[conftest] {status.summary()}")
        await dispose()

    asyncio.run(_setup())
    yield

    # The truncation connection is still open on the database we are about to
    # drop. DROP ... WITH (FORCE) would evict it, but closing it cleanly first
    # avoids a spurious "terminating connection" in the log on every run.
    _close_cleanup_connection()

    async def _teardown() -> None:
        from envelock.db import dispose

        await dispose()
        await _admin_execute(f'DROP DATABASE IF EXISTS "{db_name}" WITH (FORCE)')

    with contextlib.suppress(Exception):
        asyncio.run(_teardown())


#: One long-lived connection on its own event loop, used only for the per-test
#: TRUNCATE. Deliberately NOT the app's engine: the suite disposes that engine
#: constantly (NullPool, a new loop per test), so borrowing it would mean
#: building an engine, opening a socket and tearing both down again ~617 times.
#: Measured: doing it that way cost ~190ms per test, +52% on the whole suite.
_cleanup_loop = None
_cleanup_conn = None
_truncate_sql = ""


def _cleanup_connection():
    """The shared truncation connection, opened on first use."""
    global _cleanup_loop, _cleanup_conn, _truncate_sql
    if _cleanup_conn is not None:
        return _cleanup_loop, _cleanup_conn

    import asyncio

    import asyncpg

    from envelock.db import Base

    tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
    _truncate_sql = f"TRUNCATE {tables} RESTART IDENTITY CASCADE" if tables else ""

    _cleanup_loop = asyncio.new_event_loop()
    _cleanup_conn = _cleanup_loop.run_until_complete(
        asyncpg.connect(TEST_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    )
    return _cleanup_loop, _cleanup_conn


def _truncate_all() -> None:
    """Empty every table between tests.

    This is what makes tests independent of each other. The `db` fixture used to
    drop and recreate the whole schema, which only the ~16 tests that requested
    it got — every test built on the `client` fixture inherited whatever the
    previous one had written. That is why `pytest tests/test_mfa_skip.py` passed
    while `pytest tests/test_mfa_skip.py tests/test_oauth.py` failed, and why
    "583 passing" was only true for one particular ordering.

    TRUNCATE rather than DDL: one statement across ~45 mostly-empty tables is far
    cheaper than dropping and recreating them, and CASCADE plus RESTART IDENTITY
    leaves things exactly as a fresh create would.
    """
    loop, conn = _cleanup_connection()
    if not _truncate_sql:
        return
    loop.run_until_complete(conn.execute(_truncate_sql))


def _close_cleanup_connection() -> None:
    global _cleanup_loop, _cleanup_conn
    if _cleanup_conn is None:
        return
    import contextlib

    with contextlib.suppress(Exception):
        _cleanup_loop.run_until_complete(_cleanup_conn.close())
    with contextlib.suppress(Exception):
        _cleanup_loop.close()
    _cleanup_conn = None
    _cleanup_loop = None


@pytest.fixture(autouse=True)
def _clean_database(_schema: None) -> Iterator[None]:
    """Every test starts against empty tables, whichever fixtures it uses."""
    _truncate_all()
    yield


def platform_sessionmaker():  # noqa: ANN201
    """`get_sessionmaker`, for test helpers that act as the platform.

    Import this instead of `envelock.db.get_sessionmaker` in a test that opens a
    session directly — to seed a tenant, flip a user's status, mint a token, read
    a row back. In production that work is done by something with the tenant
    bound (a worker) or by something inherently cross-tenant (a migration, the
    operator console); it is never an anonymous unscoped write, which is exactly
    what RLS refuses.

    Outside RLS mode this is `get_sessionmaker` unchanged, so the ordinary run is
    completely unaffected. The application's own binding is never patched, so
    every API route stays enforced — that is the half these tests are actually
    checking, through `client`.
    """
    from envelock.db import get_sessionmaker

    maker = get_sessionmaker()
    if not RLS_MODE:
        return maker

    def _make(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        return _PlatformSession(maker(*args, **kwargs))

    return _make


class _PlatformSession:
    """An AsyncSession that runs in system scope for its lifetime."""

    def __init__(self, session) -> None:  # noqa: ANN001
        self._session = session
        self._token = None

    async def __aenter__(self):  # noqa: ANN204
        from envelock.db_rls import current_system_scope

        self._token = current_system_scope.set(True)
        return await self._session.__aenter__()

    async def __aexit__(self, *exc) -> object:  # noqa: ANN002
        from envelock.db_rls import current_system_scope

        try:
            return await self._session.__aexit__(*exc)
        finally:
            if self._token is not None:
                current_system_scope.reset(self._token)


@pytest.fixture(autouse=True)
def _test_helpers_act_as_the_platform(monkeypatch) -> Iterator[None]:  # noqa: ANN001
    """Under RLS, a test's own DB helpers run in system scope. The app's do not.

    Around forty test helpers open a session directly to seed a tenant, flip a
    user's status, or read back a row — work that in production is done by the
    platform (a worker with the tenant bound, or a migration), never by an
    anonymous caller. Under RLS those writes are refused by WITH CHECK and those
    reads return nothing, which is correct behaviour and useless as a signal: it
    tells you the harness is unscoped, not that the product is broken.

    The patch is deliberately narrow. It rebinds `get_sessionmaker` **only in
    the test modules that imported it**, leaving `envelock.db.get_sessionmaker`
    untouched — so every session the application itself opens, including the
    `get_session` dependency behind every API route, stays fully enforced. That
    is the half that has to be real, and it is the half these tests exercise
    through `client`.
    """
    if not RLS_MODE:
        yield
        return

    import sys

    from envelock.db import get_sessionmaker as real_maker

    def scoped_maker():  # noqa: ANN202
        maker = real_maker()

        def _make(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            return _PlatformSession(maker(*args, **kwargs))

        return _make

    for name, module in list(sys.modules.items()):
        if not name.startswith("test_") and not name.startswith("tests."):
            continue
        if getattr(module, "get_sessionmaker", None) is not None:
            monkeypatch.setattr(module, "get_sessionmaker", scoped_maker, raising=False)
    yield


@pytest.fixture(autouse=True)
def _isolate_settings_cache() -> Iterator[None]:
    """`get_settings()` is lru_cached and several tests flip env-driven flags
    (e.g. ENVELOCK_REQUIRE_DOMAIN_VERIFICATION). Clearing the cache around every
    test means a Settings object cached while one test had a flag flipped can't
    leak into the next — each test re-reads the conftest env baseline fresh."""
    from envelock.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture(autouse=True)
def _reset_security_state() -> Iterator[None]:
    """Rate limits, lockouts and replay guards are process-global.

    Without this the suite trips its own throttling, and a test that fails
    because of state leaked from an earlier test teaches nothing.
    """
    from envelock.security.limits import reset_all

    reset_all()
    yield
    reset_all()


@pytest_asyncio.fixture
async def db() -> AsyncIterator[None]:
    """Empty tables for this test.

    Kept as a fixture because ~16 tests request it explicitly, but it no longer
    does the work: the autouse `_clean_database` truncates before every test, so
    a fresh state is now the default rather than something a test has to opt
    into. It used to drop and recreate the entire schema here, which was both
    slow and — because only tests that asked for it got any isolation at all —
    the reason the suite was order-dependent.
    """
    from envelock.db import dispose

    yield
    await dispose()


@pytest_asyncio.fixture
async def session(db: None) -> AsyncIterator:
    """A raw session for tests that drive the layers *below* the API.

    Under `ENVELOCK_TEST_RLS` these run in system scope. That is not papering
    over a failure — it mirrors production. A test calling `analyse_event` or
    seeding a `Tenant` directly is standing in for the caller that would bind the
    tenant in production: the IMAP worker does `set_current_tenant(...)` before
    it touches a mailbox's data, and the API binds it from the token. Without
    this the fixture would be asserting that raw un-scoped inserts are refused,
    which `test_rls.py` already proves properly, as the thing it is testing
    rather than as a side effect.

    Tests that exercise the API surface use the `client` fixture instead, and
    those run fully enforced — that is where RLS has to hold.
    """
    import contextlib

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope

    scope = (
        system_scope("test fixture: direct DB access below the API layer")
        if RLS_MODE
        else contextlib.nullcontext()
    )
    with scope:
        async with get_sessionmaker()() as s:
            yield s


@pytest.fixture
def tenant_id() -> UUID:
    """Just an id. Tests that need the row persist it themselves, so creating
    one here would collide on the primary key."""
    return uuid4()


@pytest.fixture
def client() -> Iterator[TestClient]:
    from envelock.api.auth import _reset_store
    from envelock.main import app

    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


@pytest.fixture
def api(client: TestClient) -> TestClient:
    return client
