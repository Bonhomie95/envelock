"""AI autoflagging: persist LLM-judge verdicts + AI flag on alerts.

Revision ID: c2d3e4f50816
Revises: b1c2d3e4f5a6
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c2d3e4f50816"
down_revision: str | None = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Server defaults so the ALTER applies cleanly to populated alert tables;
    # the ORM supplies values for new rows (matches the db.py reconciler policy).
    op.add_column(
        "alerts",
        sa.Column("ai_flagged", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("alerts", sa.Column("ai_verdict", sa.String(length=16), nullable=True))

    op.create_table(
        "llm_verdicts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("mailbox_id", sa.Uuid(), nullable=True),
        sa.Column("message_id", sa.Uuid(), nullable=True),
        sa.Column("alert_id", sa.Uuid(), nullable=True),
        sa.Column("verdict", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("escalated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rule_tier", sa.String(length=16), nullable=True),
        sa.Column("final_tier", sa.String(length=16), nullable=True),
        sa.Column("provider", sa.String(length=32), nullable=False, server_default=""),
        sa.Column("model", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_micros", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("human_disposition", sa.String(length=16), nullable=True),
        sa.Column("labeled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"]),
        sa.ForeignKeyConstraint(["alert_id"], ["alerts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_llm_verdicts_tenant_id"), "llm_verdicts", ["tenant_id"], unique=False
    )
    op.create_index(
        op.f("ix_llm_verdicts_mailbox_id"), "llm_verdicts", ["mailbox_id"], unique=False
    )
    op.create_index(
        op.f("ix_llm_verdicts_alert_id"), "llm_verdicts", ["alert_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_llm_verdicts_alert_id"), table_name="llm_verdicts")
    op.drop_index(op.f("ix_llm_verdicts_mailbox_id"), table_name="llm_verdicts")
    op.drop_index(op.f("ix_llm_verdicts_tenant_id"), table_name="llm_verdicts")
    op.drop_table("llm_verdicts")
    op.drop_column("alerts", "ai_verdict")
    op.drop_column("alerts", "ai_flagged")
