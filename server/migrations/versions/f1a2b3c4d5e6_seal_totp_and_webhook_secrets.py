"""Seal TOTP seeds and webhook signing secrets at rest

Both sat in plain text, so a database dump or backup held every account's
second factor and every SIEM signing key. The columns become
`security.fields.EncryptedString`; this widens the TOTP columns for the
ciphertext and seals every value already stored.

Revision ID: f1a2b3c4d5e6
Revises: e0f1a2b3c4d5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: str | None = "e0f1a2b3c4d5"
branch_labels = None
depends_on = None

_SEALED = (
    ("users", "totp_secret"),
    ("staff_accounts", "totp_secret"),
    ("webhook_endpoints", "secret"),
)


def _rewrite(transform, *, sealed: bool) -> None:  # noqa: ANN001
    from envelock.db_rls import GUC_SYSTEM
    from envelock.security.fields import PREFIX

    conn = op.get_bind()
    # Row-level security is FORCEd, so even the owner sees no rows unscoped.
    conn.execute(sa.text(f"SELECT set_config('{GUC_SYSTEM}', 'on', true)"))
    match = "LIKE" if sealed else "NOT LIKE"
    for table, column in _SEALED:
        rows = conn.execute(
            sa.text(
                f"SELECT id, {column} FROM {table} "  # noqa: S608 — fixed identifiers
                f"WHERE {column} IS NOT NULL AND {column} {match} :p"
            ),
            {"p": f"{PREFIX}%"},
        ).all()
        for row_id, value in rows:
            conn.execute(
                sa.text(f"UPDATE {table} SET {column} = :v WHERE id = :id"),  # noqa: S608
                {"v": transform(value), "id": row_id},
            )


def upgrade() -> None:
    from envelock.security.fields import seal_field

    for table in ("users", "staff_accounts"):
        op.alter_column(table, "totp_secret", type_=sa.String(128), existing_type=sa.String(64))
    _rewrite(seal_field, sealed=False)


def downgrade() -> None:
    from envelock.security.fields import open_field

    _rewrite(open_field, sealed=True)
    for table in ("users", "staff_accounts"):
        op.alter_column(table, "totp_secret", type_=sa.String(64), existing_type=sa.String(128))
