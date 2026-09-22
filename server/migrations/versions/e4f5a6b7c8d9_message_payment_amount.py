"""messages.payment_amount / payment_currency — the sum a payment request asked for

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e4f5a6b7c8d9"
down_revision: str | None = "d3e4f5a6b7c8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("payment_amount", sa.Float(), nullable=True))
    op.add_column("messages", sa.Column("payment_currency", sa.String(8), nullable=True))


def downgrade() -> None:
    op.drop_column("messages", "payment_currency")
    op.drop_column("messages", "payment_amount")
