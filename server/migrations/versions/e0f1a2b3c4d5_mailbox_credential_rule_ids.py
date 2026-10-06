"""mailbox_credentials.rule_ids — baseline of seen server-side rules (C1/C2)

The mailbox-rule watch stores the ids of rules/filters it has already seen so a
newly-created external-forward or finance-hiding rule alerts once, not on every
poll.

Revision ID: e0f1a2b3c4d5
Revises: d9e0f1a2b3c4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e0f1a2b3c4d5"
down_revision: str | None = "d9e0f1a2b3c4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailbox_credentials",
        sa.Column("rule_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailbox_credentials", "rule_ids")
