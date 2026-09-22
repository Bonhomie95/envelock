"""Postgres row-level security: apply it, scope it, and prove it is real.

Application code already scopes every query by tenant, carefully. This exists
because "carefully" is not a control. One `select(Alert)` written without a
`WHERE tenant_id` — in a new endpoint, by a new engineer, on a Friday — is one
company reading another's mail, and no amount of review makes that impossible.
RLS makes the database refuse, so the mistake becomes an empty result instead of
a breach.

Three things had to be fixed before it could be turned on at all:

1. **The policy predicate raised on anonymous requests.** It compared
   ``current_setting('envelock.tenant_id', true)::uuid``, and `db.py` sets that
   GUC to `''` when no tenant is bound. `''::uuid` is not "match nothing", it is
   ``ERROR: invalid input syntax for type uuid``. Every unauthenticated
   endpoint — login, register, password reset, the landing-page scanner — would
   have 500'd the moment RLS was enabled. `NULLIF(..., '')` makes the unset case
   NULL, which compares false, which is the fail-closed behaviour the original
   comment claimed.

2. **Coverage had drifted, and would drift again.** The migration hard-coded 17
   tables; the models now have 25 with a `tenant_id`, so eight were unprotected
   — including `link_tokens`, `link_clicks` (rewritten URLs and click IPs) and
   `export_tokens`. Policies are therefore derived from `Base.metadata` here, so
   a new tenant-scoped table is covered the day it is added and
   `verify_rls` fails loudly if one ever is not.

3. **It was only ever applied by a migration nobody runs.** The default deploy
   builds the schema with `create_all` (`db.py`), and `deploy.sh` has no
   migration step, so `ENVELOCK_RLS_ENABLED=true` would have set the GUC on a
   database with no policies on it — all the cost of the flag, none of the
   protection, and nothing saying so. `apply_rls` runs from application startup.

The remaining requirement is one the database enforces and we can only check:
**a superuser, or any role with BYPASSRLS, ignores RLS entirely — even with
FORCE.** If the app connects as one, every policy here is decoration. That is
what `verify_rls` is for, and why it is surfaced rather than assumed.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

logger = logging.getLogger("envelock.rls")

#: Name of the policy this module owns. Dropped and recreated on every apply, so
#: changing the predicate above is a deploy rather than a manual migration.
POLICY = "tenant_isolation"

#: The GUC carrying the tenant for the current transaction.
GUC_TENANT = "envelock.tenant_id"

#: The GUC that opts a transaction out of tenant scoping. See `system_scope`.
GUC_SYSTEM = "envelock.system"

#: Cross-tenant by design — these must NOT get a tenant policy.
EXEMPT: frozenset[str] = frozenset(
    {
        # Permanence IS the anti-abuse mechanism (§12.7) and it holds no personal
        # data: a registrable domain and a timestamp.
        "domain_trial_ledger",
        # The E8 counterparty graph. Cross-tenant is the entire point — one
        # tenant's confirmed fraud protects every other tenant. Keyed by domain,
        # holds no tenant's content.
        "graph_verdicts",
        # Confirmed fraud bank accounts, cross-tenant for the same reason; a
        # keyed hash per account, no customer content.
        "fraud_accounts",
        # Envelock's own operators, not a customer's data.
        "staff_accounts",
        # Verdict cache, keyed by hash; holds no customer data.
        "malicious_domains",
        "attachment_verdicts",
        "alembic_version",
    }
)

#: Tenant-scoped in shape but never readable by a customer. The operator audit
#: log records what Envelock staff did; a tenant seeing it would reveal our
#: internal handling, and it must not be prunable from a tenant session. The
#: policy denies the app role outright; staff tooling reaches it via `system_scope`.
STAFF_ONLY: frozenset[str] = frozenset({"staff_audit_events"})

#: `tenants` has no `tenant_id` — its own primary key is the tenant.
SELF_KEYED: dict[str, str] = {"tenants": "id"}


def _predicate(column: str) -> str:
    """The USING/WITH CHECK expression.

    `NULLIF` is load-bearing: without it an unset-but-present GUC (which is what
    an anonymous request produces) raises rather than matching nothing.
    """
    return (
        f"({column} = NULLIF(current_setting('{GUC_TENANT}', true), '')::uuid"
        f" OR current_setting('{GUC_SYSTEM}', true) = 'on')"
    )


def tenant_tables(metadata) -> list[str]:  # noqa: ANN001
    """Every table RLS should cover, derived from the models rather than listed.

    A hand-maintained list is a list that goes stale, and a stale list here is an
    unprotected table nobody notices.
    """
    names = []
    for table in metadata.sorted_tables:
        if table.name in EXEMPT:
            continue
        if table.name in SELF_KEYED or "tenant_id" in table.columns:
            names.append(table.name)
    return sorted(names)


# ── System scope ─────────────────────────────────────────────────────────────
#: Whether the current task may cross tenant boundaries.
current_system_scope: ContextVar[bool] = ContextVar("envelock_system_scope", default=False)


@contextmanager
def system_scope(reason: str) -> Iterator[None]:
    """Deliberately read or write across tenants, for the duration of the block.

    Some work is genuinely platform-wide and cannot be expressed per tenant: the
    poller choosing which mailboxes are due, the scheduler sweeping expired data,
    the operator console listing customers. Those need to see every tenant's
    rows, and without an escape hatch RLS would simply break them.

    Making it a named context manager rather than an ambient capability is the
    point. Every cross-tenant access is one greppable call with a stated reason,
    it is scoped to a block rather than a process, and `rls_scope_audit()` can
    count them. Compare that to the status quo, where *every* query is
    implicitly cross-tenant and only a `WHERE` clause says otherwise.

    This is not a security boundary against a SQL-injection attacker — anyone who
    can run arbitrary SQL as the app role can set the GUC themselves. It is a
    boundary against the failure that actually happens: a query written without
    a tenant filter.
    """
    token = current_system_scope.set(True)
    logger.debug("system scope entered: %s", reason)
    try:
        yield
    finally:
        current_system_scope.reset(token)


@asynccontextmanager
async def system_scope_on(session, reason: str) -> AsyncIterator[None]:  # noqa: ANN001
    """`system_scope` for a session whose transaction is ALREADY open.

    The GUCs are set by the `begin` event handler, once, when a transaction
    starts. So entering the plain `system_scope` part-way through a request that
    has already touched the database does nothing at all: the transaction was
    begun with `envelock.system` empty, and setting a contextvar afterwards does
    not travel back in time to change it.

    That is a quiet failure — the block runs, reads nothing, and looks like an
    absence of data rather than an absence of scope. It cost a real one: the
    domain-squatting conflict check in `api/tenants.py` silently stopped seeing
    the conflicting row, so the workspace-hijack defence it implements was
    disabled by turning RLS on.

    This sets the GUC on the live transaction and clears it after, so it works
    wherever it is used. Prefer the plain `system_scope` at a router or worker
    boundary, before any query runs; reach for this one when scope has to change
    in the middle of a request.
    """
    token = current_system_scope.set(True)
    logger.debug("system scope (live) entered: %s", reason)
    try:
        await session.execute(text(f"SELECT set_config('{GUC_SYSTEM}', 'on', true)"))
        yield
    finally:
        current_system_scope.reset(token)
        # Transaction-local, so a commit would clear it anyway — but the request
        # may keep using this session, and it must not stay elevated.
        await session.execute(text(f"SELECT set_config('{GUC_SYSTEM}', '', true)"))


# ── Applying ─────────────────────────────────────────────────────────────────
async def apply_rls(conn: AsyncConnection, *, app_role: str) -> list[str]:
    """Enable, force and (re)create the tenant policy on every scoped table.

    Idempotent by construction — the policy is dropped and recreated — so this
    runs on every boot and converges a database provisioned by any path:
    `create_all`, Alembic, or a hand-built one.
    """
    from envelock.db import Base

    applied: list[str] = []

    role_exists = (
        await conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": app_role}
        )
    ).scalar_one_or_none()
    if role_exists is None:
        logger.warning(
            "RLS: role %r does not exist — policies will be applied but no grants "
            "made. Create it with `python -m envelock.security.provision_rls`.",
            app_role,
        )

    live = {
        row[0]
        for row in (
            await conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
            )
        ).all()
    }

    for name in tenant_tables(Base.metadata):
        if name not in live:
            continue
        column = SELF_KEYED.get(name, "tenant_id")
        await conn.execute(text(f'ALTER TABLE "{name}" ENABLE ROW LEVEL SECURITY'))
        # FORCE so the table owner is bound too. Without it, a deployment whose
        # app role happens to own the tables — which is the common case on
        # managed Postgres — gets no protection at all.
        await conn.execute(text(f'ALTER TABLE "{name}" FORCE ROW LEVEL SECURITY'))
        await conn.execute(text(f'DROP POLICY IF EXISTS {POLICY} ON "{name}"'))

        if name in STAFF_ONLY:
            # Readable only under an explicit system scope.
            expr = f"(current_setting('{GUC_SYSTEM}', true) = 'on')"
        else:
            expr = _predicate(column)

        await conn.execute(
            text(
                f"CREATE POLICY {POLICY} ON \"{name}\" "
                f"USING {expr} WITH CHECK {expr}"
            )
        )
        if role_exists is not None:
            await conn.execute(
                text(
                    f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{name}" TO "{app_role}"'
                )
            )
        applied.append(name)

    if role_exists is not None:
        # Exempt tables still need grants, they just carry no tenant policy.
        for name in sorted(EXEMPT - {"alembic_version"}):
            if name in live:
                await conn.execute(
                    text(
                        f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{name}" '
                        f'TO "{app_role}"'
                    )
                )
        await conn.execute(
            text(f'GRANT USAGE ON SCHEMA public TO "{app_role}"')
        )
        await conn.execute(
            text(
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public "
                f'TO "{app_role}"'
            )
        )

    logger.info("RLS applied to %d tables", len(applied))
    return applied


# ── Verifying ────────────────────────────────────────────────────────────────
@dataclass
class RlsStatus:
    """What the *running database* says about tenant isolation."""

    enabled_in_config: bool
    connected_role: str = ""
    role_bypasses: bool = False
    """True if the connected role is a superuser or has BYPASSRLS — in which case
    every policy is inert and isolation rests on application code alone."""

    protected: list[str] = field(default_factory=list)
    unprotected: list[str] = field(default_factory=list)
    """Tenant-scoped tables with no policy: each one is a table where a missing
    `WHERE tenant_id` leaks."""

    error: str = ""

    @property
    def effective(self) -> bool:
        """Whether RLS is actually protecting this deployment right now."""
        return (
            self.enabled_in_config
            and not self.role_bypasses
            and not self.unprotected
            and not self.error
            and bool(self.protected)
        )

    def summary(self) -> str:
        if not self.enabled_in_config:
            return "row-level security is OFF (ENVELOCK_RLS_ENABLED=false)"
        if self.error:
            return f"row-level security could not be verified: {self.error}"
        if self.role_bypasses:
            return (
                f"row-level security is INERT: the app connects as {self.connected_role!r}, "
                "which is a superuser or has BYPASSRLS, so Postgres ignores every "
                "policy. Connect as a restricted role (see provision_rls)."
            )
        if self.unprotected:
            return (
                "row-level security is INCOMPLETE: no policy on "
                f"{', '.join(self.unprotected)}"
            )
        return f"row-level security is enforced on {len(self.protected)} tables"


async def verify_rls(conn: AsyncConnection, *, enabled: bool) -> RlsStatus:
    """Ask the database whether isolation is real, rather than trusting the flag.

    A config flag says what someone intended. This says what Postgres will
    actually do — which is the only version worth reporting to a customer or an
    auditor.
    """
    from envelock.db import Base

    status = RlsStatus(enabled_in_config=enabled)
    try:
        row = (
            await conn.execute(
                text(
                    "SELECT current_user, "
                    "(SELECT rolsuper OR rolbypassrls FROM pg_roles "
                    " WHERE rolname = current_user)"
                )
            )
        ).one()
        status.connected_role = str(row[0])
        status.role_bypasses = bool(row[1])

        have = {
            r[0]
            for r in (
                await conn.execute(
                    text("SELECT tablename FROM pg_policies WHERE policyname = :p"),
                    {"p": POLICY},
                )
            ).all()
        }
        live = {
            r[0]
            for r in (
                await conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname='public'")
                )
            ).all()
        }
        expected = [t for t in tenant_tables(Base.metadata) if t in live]
        status.protected = sorted(t for t in expected if t in have)
        status.unprotected = sorted(t for t in expected if t not in have)
    except Exception as exc:  # noqa: BLE001 — a probe must never take the app down
        status.error = f"{type(exc).__name__}: {exc}"
    return status
