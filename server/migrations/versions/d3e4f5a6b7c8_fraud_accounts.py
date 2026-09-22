"""fraud_accounts — cross-tenant confirmed-fraud bank accounts (keyed hashes)

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "d3e4f5a6b7c8"
down_revision: str | None = "c2d3e4f5a6b7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "fraud_accounts",
        sa.Column("account_hash", sa.String(64), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scheme", sa.String(16), nullable=False),
        sa.Column("confirmations", sa.Integer(), nullable=False),
        sa.Column("first_reported", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_reported", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reporter_tenant_ids", postgresql.ARRAY(sa.String()), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("fraud_accounts")
