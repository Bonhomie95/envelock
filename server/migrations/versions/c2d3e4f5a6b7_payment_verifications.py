"""payment_verifications — out-of-band confirmation of a bank-detail change

Revision ID: c2d3e4f5a6b7
Revises: b0c1d2e3f4a5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c2d3e4f5a6b7"
down_revision: str | None = "b0c1d2e3f4a5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "payment_verifications",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("alert_id", sa.Uuid(), sa.ForeignKey("alerts.id"), nullable=False),
        sa.Column("counterparty_domain", sa.String(253)),
        sa.Column("channel", sa.String(8), nullable=False),
        sa.Column("phone", sa.String(32)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("requested_by", sa.Uuid()),
        sa.Column("responded_at", sa.DateTime(timezone=True)),
        sa.Column("recorded_by", sa.Uuid()),
        sa.Column("note", sa.Text()),
        sa.Column("account_masked", sa.String(64)),
    )
    op.create_index("ix_payment_verifications_tenant_id", "payment_verifications", ["tenant_id"])
    op.create_index("ix_payment_verifications_alert_id", "payment_verifications", ["alert_id"])
    op.create_index(
        "ix_payment_verifications_token_hash",
        "payment_verifications",
        ["token_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table("payment_verifications")
