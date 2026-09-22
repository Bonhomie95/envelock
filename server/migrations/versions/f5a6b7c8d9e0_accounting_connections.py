"""accounting_connections — Xero / QuickBooks Online links

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "f5a6b7c8d9e0"
down_revision: str | None = "e4f5a6b7c8d9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "accounting_connections",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("provider", sa.String(16), nullable=False),
        sa.Column("external_org_id", sa.String(64), nullable=False),
        sa.Column("org_name", sa.String(255)),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("key_id", sa.String(128), nullable=False),
        sa.Column("token_expires_at", sa.DateTime(timezone=True)),
        sa.Column("connected_by", sa.Uuid()),
        sa.Column("flag_bills", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("sync_requested_at", sa.DateTime(timezone=True)),
        sa.Column("last_sync_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.String(500)),
        sa.Column("last_sync_summary", postgresql.JSONB()),
        sa.Column("supplier_ids", postgresql.JSONB()),
        sa.UniqueConstraint(
            "tenant_id", "provider", name=op.f("uq_accounting_connections_tenant_id")
        ),
    )
    op.create_index(
        "ix_accounting_connections_tenant_id", "accounting_connections", ["tenant_id"]
    )


def downgrade() -> None:
    op.drop_table("accounting_connections")
