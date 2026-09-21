"""Row-level security: prove the database refuses, not just that a flag is set.

These tests connect as a *real restricted role* — not the owner, not a superuser
— because that distinction is the whole mechanism. Postgres ignores every policy
for a superuser or a role with BYPASSRLS, FORCE included, so a suite that tested
RLS through the ordinary test connection would pass while proving nothing.

The central test is `test_a_query_with_no_tenant_filter_returns_nothing`: it runs
exactly the mistake RLS exists to catch — `SELECT * FROM alerts` with no
`WHERE tenant_id` — and asserts the database returns the caller's rows only.
"""

from __future__ import annotations

import uuid

import asyncpg
import pytest
from conftest import ADMIN_DSN, RLS_MODE, TEST_DSN

from envelock.db import Base
from envelock.db_rls import (
    EXEMPT,
    GUC_SYSTEM,
    GUC_TENANT,
    SELF_KEYED,
    STAFF_ONLY,
    apply_rls,
    tenant_tables,
    verify_rls,
)

pytestmark = pytest.mark.asyncio

ROLE = "envelock_rls_test"
ROLE_PW = "rls-test-password"

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _plain(dsn: str) -> str:
    return dsn.replace("postgresql+asyncpg://", "postgresql://")


def _as_role(dsn: str) -> str:
    """The same database, connected as the restricted role."""
    prefix, _, tail = _plain(dsn).partition("://")
    _creds, _, hostpart = tail.partition("@")
    return f"{prefix}://{ROLE}:{ROLE_PW}@{hostpart}"


@pytest.fixture
async def rls_db():
    """Apply RLS to this run's database and hand back a restricted connection.

    Torn down afterwards so the rest of the suite (which connects as the owner
    and relies on application-layer scoping) is unaffected.
    """
    from sqlalchemy.ext.asyncio import create_async_engine

    owner = create_async_engine(TEST_DSN, poolclass=None)

    # A restricted role: no superuser, no BYPASSRLS. Without both, the policies
    # below are inert and every assertion here would pass vacuously.
    # ADMIN_DSN, not TEST_DSN: under ENVELOCK_TEST_RLS the suite already runs as
    # a plain role that owns the database and cannot CREATE ROLE.
    admin = await asyncpg.connect(_plain(ADMIN_DSN))
    try:
        # No NOSUPERUSER/NOBYPASSRLS here: they are the defaults for a new role,
        # and *setting* them explicitly requires superuser — which the ordinary
        # test role is not. The properties are asserted below instead of assumed,
        # which is the part that actually matters.
        await admin.execute(
            f"DO $$ BEGIN "
            f"CREATE ROLE {ROLE} LOGIN PASSWORD '{ROLE_PW}'; "
            f"EXCEPTION WHEN duplicate_object THEN "
            f"ALTER ROLE {ROLE} LOGIN PASSWORD '{ROLE_PW}'; END $$;"
        )
        attrs = await admin.fetchrow(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1", ROLE
        )
        assert not attrs["rolsuper"] and not attrs["rolbypassrls"], (
            f"{ROLE} can bypass RLS, so every assertion in this file would pass "
            "without proving anything"
        )
        db = await admin.fetchval("SELECT current_database()")
        await admin.execute(f'GRANT CONNECT ON DATABASE "{db}" TO {ROLE}')
    finally:
        await admin.close()

    async with owner.begin() as conn:
        await apply_rls(conn, app_role=ROLE)

    conn = await asyncpg.connect(_as_role(TEST_DSN))
    try:
        yield conn
    finally:
        await conn.close()
        # Drop the policies again so the remaining tests — which connect as the
        # owner and rely on application-layer scoping — are untouched.
        #
        # Except under ENVELOCK_TEST_RLS, where the whole run is *supposed* to be
        # enforced: tearing down there would quietly switch RLS off partway
        # through and the rest of the suite would pass for the wrong reason.
        if not RLS_MODE:
            async with owner.begin() as conn2:
                from sqlalchemy import text

                for name in tenant_tables(Base.metadata):
                    await conn2.execute(
                        text(f'ALTER TABLE "{name}" DISABLE ROW LEVEL SECURITY')
                    )
                    await conn2.execute(
                        text(f'DROP POLICY IF EXISTS tenant_isolation ON "{name}"')
                    )
        await owner.dispose()


async def _seed(conn: asyncpg.Connection) -> None:
    """Two tenants, each with an alert. Written under system scope."""
    await conn.execute(f"SELECT set_config('{GUC_SYSTEM}', 'on', false)")
    for tid, name in ((TENANT_A, "alpha"), (TENANT_B, "beta")):
        await conn.execute(
            "INSERT INTO tenants (id, name, plan, billing_term, payment_method_ok, "
            "is_active, created_at, updated_at) "
            "VALUES ($1, $2, 'guard', 'monthly', false, true, now(), now())",
            tid,
            name,
        )
        await conn.execute(
            "INSERT INTO alerts (id, tenant_id, tier, title, body, "
            "requires_callback, state, created_at, updated_at) "
            "VALUES ($1, $2, 'critical', $3, 'body', false, 'open', now(), now())",
            uuid.uuid4(),
            tid,
            f"{name} secret",
        )
    await conn.execute(f"SELECT set_config('{GUC_SYSTEM}', '', false)")


# ── The guarantee ────────────────────────────────────────────────────────────
async def test_a_query_with_no_tenant_filter_returns_nothing(rls_db) -> None:
    """The exact mistake RLS exists to catch.

    `SELECT ... FROM alerts` with no `WHERE tenant_id` is one line of ordinary,
    plausible code. Without RLS it returns every customer's alerts. With it, the
    database returns only the bound tenant's — the bug becomes a narrow result
    instead of a cross-customer disclosure.
    """
    await _seed(rls_db)

    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_A))
    rows = await rls_db.fetch("SELECT title FROM alerts")

    titles = {r["title"] for r in rows}
    assert titles == {"alpha secret"}, (
        f"an unfiltered SELECT returned {titles} — the database did not scope it"
    )


async def test_unset_tenant_sees_nothing_rather_than_erroring(rls_db) -> None:
    """Fail closed, and fail *quietly*.

    The original predicate cast the GUC straight to uuid, and `db.py` sets it to
    `''` for an anonymous request. `''::uuid` raises
    `invalid input syntax for type uuid` — so enabling RLS would have turned
    every unauthenticated endpoint (login, register, password reset, the
    landing-page scanner) into a 500, not into a safe empty result. `NULLIF`
    makes it NULL, which compares false, which matches nothing.
    """
    await _seed(rls_db)

    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', '', false)")
    assert await rls_db.fetchval("SELECT count(*) FROM alerts") == 0

    # And with the GUC never set at all.
    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', '', false)")
    assert await rls_db.fetchval("SELECT count(*) FROM alerts") == 0


async def test_cannot_write_into_another_tenant(rls_db) -> None:
    """WITH CHECK: scoping reads is only half of it."""
    await _seed(rls_db)
    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_A))

    with pytest.raises(asyncpg.PostgresError) as exc:
        await rls_db.execute(
            "INSERT INTO alerts (id, tenant_id, tier, title, body, state, "
            "created_at, updated_at) "
            "VALUES ($1, $2, 'low', 'planted', 'x', 'open', now(), now())",
            uuid.uuid4(),
            TENANT_B,
        )
    assert "row-level security" in str(exc.value).lower()


async def test_cannot_update_or_delete_another_tenants_rows(rls_db) -> None:
    await _seed(rls_db)
    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_A))

    # Both statements are deliberately unfiltered — the policy is the filter.
    assert await rls_db.execute("UPDATE alerts SET title = 'tampered'") == "UPDATE 1"
    assert await rls_db.execute("DELETE FROM alerts") == "DELETE 1"

    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_B))
    remaining = await rls_db.fetch("SELECT title FROM alerts")
    assert [r["title"] for r in remaining] == ["beta secret"], (
        "tenant A's unfiltered UPDATE/DELETE reached tenant B's rows"
    )


async def test_the_tenants_table_is_scoped_by_its_own_id(rls_db) -> None:
    """`tenants` has no tenant_id column, so it needs a policy on `id`. The
    original migration granted SELECT on it with no policy at all — every tenant
    could read every customer's name, plan and Stripe id."""
    await _seed(rls_db)
    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_A))
    names = [r["name"] for r in await rls_db.fetch("SELECT name FROM tenants")]
    assert names == ["alpha"]


async def test_system_scope_sees_everything(rls_db) -> None:
    """The escape hatch the workers and the operator console need."""
    await _seed(rls_db)
    await rls_db.execute(f"SELECT set_config('{GUC_SYSTEM}', 'on', false)")
    assert await rls_db.fetchval("SELECT count(*) FROM alerts") == 2


async def test_staff_audit_is_invisible_without_system_scope(rls_db) -> None:
    """Envelock's own operator log is tenant-shaped but must never be readable
    from a customer session, even for their own tenant_id."""
    assert "staff_audit_events" in STAFF_ONLY
    await _seed(rls_db)
    await rls_db.execute(f"SELECT set_config('{GUC_SYSTEM}', 'on', false)")
    await rls_db.execute(
        "INSERT INTO staff_audit_events (id, tenant_id, actor_email, action, "
        "detail, created_at, updated_at) "
        "VALUES ($1, $2, 'ops@envelock.org', 'looked', '{}'::jsonb, now(), now())",
        uuid.uuid4(),
        TENANT_A,
    )
    await rls_db.execute(f"SELECT set_config('{GUC_SYSTEM}', '', false)")
    await rls_db.execute(f"SELECT set_config('{GUC_TENANT}', $1, false)", str(TENANT_A))
    assert await rls_db.fetchval("SELECT count(*) FROM staff_audit_events") == 0


# ── Coverage and reporting ───────────────────────────────────────────────────
async def test_every_tenant_scoped_table_is_covered(rls_db) -> None:
    """Policy coverage is derived from the models, so it cannot drift.

    The hand-written migration listed 17 tables while the models had 25 with a
    `tenant_id` — leaving `link_tokens`, `link_clicks`, `export_tokens`,
    `llm_usage`, `webhook_endpoints`, `webhook_deliveries` and `attested_reads`
    unprotected. Anything genuinely cross-tenant must be named in EXEMPT, as a
    decision rather than an oversight.
    """
    covered = set(tenant_tables(Base.metadata))
    for table in Base.metadata.sorted_tables:
        if table.name in EXEMPT:
            continue
        if "tenant_id" in table.columns or table.name in SELF_KEYED:
            assert table.name in covered, (
                f"{table.name} is tenant-scoped but gets no RLS policy. Either "
                "it is covered, or it belongs in db_rls.EXEMPT with a reason."
            )


async def test_verify_reports_the_truth(rls_db) -> None:
    """`verify_rls` must describe the running database, not the config flag."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(_as_role(TEST_DSN).replace("postgresql://", "postgresql+asyncpg://"))
    try:
        async with engine.connect() as conn:
            status = await verify_rls(conn, enabled=True)
        assert status.connected_role == ROLE
        assert not status.role_bypasses, "the test role can bypass RLS — tests are vacuous"
        assert not status.unprotected, f"unprotected: {status.unprotected}"
        assert status.effective
        assert "enforced" in status.summary()

        # The owner connection *does* bypass, and must be reported as such.
        owner = create_async_engine(TEST_DSN)
        async with owner.connect() as conn:
            await conn.execute(text("SELECT 1"))
            owner_status = await verify_rls(conn, enabled=True)
        await owner.dispose()
        if owner_status.role_bypasses:
            assert not owner_status.effective
            assert "INERT" in owner_status.summary()
    finally:
        await engine.dispose()
