"""Message spam filter columns

The spam filter scores every inbound message from outside and moves spam to the
mailbox's Junk folder. A message keeps its score and the reasons (codes, never
its words), when it was moved, and when the customer moved it back to the inbox,
which keeps that sender out of Junk from then on.

Additive and nullable: existing rows were never scored.

Revision ID: 5d3c2b1a0f9e
Revises: 11b17261ed61
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "5d3c2b1a0f9e"
down_revision: str | None = "11b17261ed61"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("spam_score", sa.Float(), nullable=True))
    op.add_column(
        "messages", sa.Column("spam_reasons", postgresql.ARRAY(sa.String()), nullable=True)
    )
    op.add_column("messages", sa.Column("junked_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "messages", sa.Column("spam_rescued_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("messages", "spam_rescued_at")
    op.drop_column("messages", "junked_at")
    op.drop_column("messages", "spam_reasons")
    op.drop_column("messages", "spam_score")
