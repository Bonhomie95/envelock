"""Give each tenant a secret forwarding-ingest token

The forwarding address was `t-<verification_token>@in.envelock.org`, built from
the DNS challenge token every customer publishes at `_envelock.<domain>`, so
anyone could look it up and inject forged mail into that tenant. Each tenant now
gets its own secret token. Addresses built from the DNS token stop working at
once (the owner's call, 2026-10-29), so tenants that already forward mail are
flagged for the dashboard to tell an admin to update the rule.

Revision ID: ca05700c40c5
Revises: f1a2b3c4d5e6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "ca05700c40c5"
down_revision: str | None = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from envelock.db_rls import GUC_SYSTEM

    # A volatile default is evaluated per row, so this one statement mints a
    # distinct token for every existing tenant. It is DDL, which row-level
    # security does not filter.
    op.add_column(
        "tenants",
        sa.Column(
            "ingest_token",
            sa.String(64),
            server_default=sa.text("replace(gen_random_uuid()::text, '-', '')"),
            nullable=False,
        ),
    )
    op.create_index("ix_tenants_ingest_token", "tenants", ["ingest_token"], unique=True)
    op.add_column(
        "tenants",
        sa.Column(
            "forwarding_rule_stale", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    conn = op.get_bind()
    # Row-level security is FORCEd, so even the owner sees no rows unscoped.
    conn.execute(sa.text(f"SELECT set_config('{GUC_SYSTEM}', 'on', true)"))
    conn.execute(
        sa.text(
            "UPDATE tenants SET forwarding_rule_stale = true WHERE id IN"
            " (SELECT tenant_id FROM mailboxes WHERE 'forward_ingest' = ANY(sources))"
        )
    )


def downgrade() -> None:
    op.drop_column("tenants", "forwarding_rule_stale")
    op.drop_index("ix_tenants_ingest_token", table_name="tenants")
    op.drop_column("tenants", "ingest_token")
