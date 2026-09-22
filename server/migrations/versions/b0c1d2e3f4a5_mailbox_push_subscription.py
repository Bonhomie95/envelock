"""add mailboxes.push_subscription_id / push_expires_at

Real-time delivery for Gmail/Graph mailboxes: the subscription (or watch) the
worker created, and when it has to be renewed.

Revision ID: b0c1d2e3f4a5
Revises: a9b0c1d2e3f4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "b0c1d2e3f4a5"
down_revision: str | None = "a9b0c1d2e3f4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("mailboxes", sa.Column("push_subscription_id", sa.String(255), nullable=True))
    op.add_column(
        "mailboxes", sa.Column("push_expires_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("mailboxes", "push_expires_at")
    op.drop_column("mailboxes", "push_subscription_id")
