"""Create the restricted role the application connects as under RLS.

    python -m envelock.security.provision_rls --password 's3cret'

Run it as a Postgres superuser (or the database owner) once per database. It is
idempotent, so re-running to rotate the password is fine.

Why a separate role at all: **Postgres ignores every row-level security policy
for a superuser or any role holding BYPASSRLS — FORCE included.** Most
deployments connect as the database owner, which is usually exactly such a role,
so switching on `ENVELOCK_RLS_ENABLED` without also switching roles produces a
system that looks protected, logs nothing unusual, and enforces nothing. This
script creates a role that cannot bypass, and refuses to pretend otherwise.

The owner still owns the tables and runs DDL (`create_all` on boot, Alembic).
Only the request path uses this role.

It also creates a **backup** role, because `FORCE ROW LEVEL SECURITY` applies to
the table owner too, and `pg_dump` sets `row_security = off` — so a policy that
*could* apply makes the dump fail outright rather than silently omit rows. That
refusal is Postgres being careful, and the right answer is a role that genuinely
bypasses RLS and can only read. Without one, enabling RLS silently breaks every
backup, which is the worst possible pairing of two safety features.
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import sys

from envelock.config import get_settings


def _admin_url(dsn: str) -> str:
    return dsn.replace("postgresql+asyncpg://", "postgresql://")


async def provision(
    *, role: str, password: str, dsn: str, backup_password: str
) -> int:
    import asyncpg

    conn = await asyncpg.connect(_admin_url(dsn))
    try:
        me = await conn.fetchrow(
            "SELECT current_user, "
            "(SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su"
        )
        if not me["su"]:
            print(
                f"! connected as {me['current_user']!r}, which is not a superuser.\n"
                "  Creating a role and granting on every table needs superuser or "
                "the database owner. Re-run with those credentials.",
                file=sys.stderr,
            )

        exists = await conn.fetchval(
            "SELECT 1 FROM pg_roles WHERE rolname = $1", role
        )
        if exists:
            # Only the password. Naming NOSUPERUSER / NOBYPASSRLS in an ALTER is
            # itself refused unless you ARE a superuser — even to switch them
            # off — so on a normal deployment (owner with CREATEROLE) every
            # re-run failed, which is the opposite of "safe to re-run". The
            # attributes are checked below instead of re-asserted.
            await conn.execute(f'ALTER ROLE "{role}" LOGIN PASSWORD $${password}$$')
            print(f"· role {role!r} updated")
        else:
            await conn.execute(
                f'CREATE ROLE "{role}" LOGIN PASSWORD $${password}$$ '
                "NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE"
            )
            print(f"· role {role!r} created")

        # A role that pre-existed could carry superuser or BYPASSRLS, which would
        # make every policy inert. Verify rather than assume.
        row = await conn.fetchrow(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = $1", role
        )
        if row["rolsuper"] or row["rolbypassrls"]:
            print(
                f"! {role!r} still has superuser/BYPASSRLS. RLS would be inert. "
                "Fix this before enabling ENVELOCK_RLS_ENABLED.",
                file=sys.stderr,
            )
            return 1

        db = await conn.fetchval("SELECT current_database()")

        # ── The backup role ──────────────────────────────────────────────────
        # BYPASSRLS plus SELECT, and nothing else. It exists so `pg_dump`
        # produces a COMPLETE dump: with FORCE RLS the owner itself is subject
        # to policy, and pg_dump refuses to run rather than emit a partial one.
        #
        # Creating it needs a role that already holds BYPASSRLS (a superuser
        # does), so this is skipped with a clear message when running as the
        # plain owner rather than failing the whole provisioning run.
        backup_role = f"{role.removesuffix('_app')}_backup"
        if me["su"]:
            exists_b = await conn.fetchval(
                "SELECT 1 FROM pg_roles WHERE rolname = $1", backup_role
            )
            verb = "ALTER" if exists_b else "CREATE"
            await conn.execute(
                f'{verb} ROLE "{backup_role}" LOGIN PASSWORD $${backup_password}$$ '
                "NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE"
            )
            await conn.execute(
                f'GRANT CONNECT ON DATABASE "{db}" TO "{backup_role}"'
            )
            await conn.execute(f'GRANT USAGE ON SCHEMA public TO "{backup_role}"')
            await conn.execute(
                f'GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{backup_role}"'
            )
            # Cover tables a later migration adds, so backups do not quietly
            # start missing them.
            owner = await conn.fetchval(
                "SELECT tableowner FROM pg_tables WHERE schemaname='public' LIMIT 1"
            )
            if owner:
                await conn.execute(
                    f'ALTER DEFAULT PRIVILEGES FOR ROLE "{owner}" IN SCHEMA public '
                    f'GRANT SELECT ON TABLES TO "{backup_role}"'
                )
            print(f"· backup role {backup_role!r} {verb.lower()}d (BYPASSRLS, read-only)")
        else:
            print(
                f"! skipped the backup role {backup_role!r} — granting BYPASSRLS\n"
                "  requires a role that already holds it (a superuser does).\n"
                "  Without it `pg_dump` FAILS once RLS is on, because\n"
                "  FORCE RLS applies to the owner too. Create it with:\n"
                f"    sudo -u postgres psql -d {db} -c \"CREATE ROLE {backup_role} "
                f"LOGIN PASSWORD '<pick one>' BYPASSRLS NOSUPERUSER\"\n"
                f"    sudo -u postgres psql -d {db} -c \"GRANT USAGE ON SCHEMA public "
                f"TO {backup_role}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "
                f"{backup_role}\"",
                file=sys.stderr,
            )

        await conn.execute(f'GRANT CONNECT ON DATABASE "{db}" TO "{role}"')
        await conn.execute(f'GRANT USAGE ON SCHEMA public TO "{role}"')
        # Table/sequence grants are (re)applied by `apply_rls` on every boot, so
        # a table added later is covered without re-running this script.
        await conn.execute(
            f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{role}"'
        )
        await conn.execute(
            f'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "{role}"'
        )
        print(f"· granted on database {db!r}")
    finally:
        await conn.close()

    dsn_prefix = dsn.split("://", 1)[0]
    host = dsn.rsplit("@", 1)[-1]
    print()
    backup_role = f"{role.removesuffix('_app')}_backup"
    owner_dsn = dsn.replace("postgresql+asyncpg://", f"{dsn_prefix}://")
    print("Set these on the application deployment, then restart it:")
    print()
    print("  ENVELOCK_RLS_ENABLED=true")
    print(f"  ENVELOCK_DB_APP_ROLE={role}")
    print(f"  ENVELOCK_POSTGRES_DSN={dsn_prefix}://{role}:{password}@{host}")
    print()
    print("  # Schema changes keep the OWNER's credentials — the app role has no")
    print("  # DDL rights, so Alembic and the boot-time RLS setup need this.")
    print(f"  ENVELOCK_DB_OWNER_DSN={owner_dsn}")
    print()
    print("  # Backups need a role that BYPASSES RLS, or pg_dump refuses to run:")
    print("  # FORCE RLS applies to the owner too, and pg_dump will not emit a")
    print("  # partial dump. This role is read-only.")
    print(f"  ENVELOCK_DB_BACKUP_DSN={dsn_prefix}://{backup_role}:{backup_password}@{host}")
    print()
    print(
        "The app logs the verified status at boot and the admin Security page\n"
        "reports it. If either says INERT or INCOMPLETE, isolation is not on."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", default=None, help="role name (default from config)")
    parser.add_argument(
        "--password",
        default=None,
        help="password for the role; generated if omitted",
    )
    parser.add_argument(
        "--backup-password",
        default=None,
        help="password for the read-only backup role; generated if omitted",
    )
    parser.add_argument(
        "--dsn",
        default=None,
        help="admin DSN to connect with (default: ENVELOCK_POSTGRES_DSN)",
    )
    args = parser.parse_args()

    settings = get_settings()
    role = args.role or settings.db_app_role
    password = args.password or secrets.token_urlsafe(24)
    dsn = args.dsn or settings.postgres_dsn
    backup_password = args.backup_password or secrets.token_urlsafe(24)
    return asyncio.run(
        provision(
            role=role,
            password=password,
            dsn=dsn,
            backup_password=backup_password,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
