"""Manual quarantine: persist the provider handle + the human's request.

Revision ID: d3e4f5061927
Revises: c2d3e4f50816
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d3e4f5061927"
down_revision: str | None = "c2d3e4f50816"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("source_ref", sa.String(length=998), nullable=True))
    op.add_column(
        "messages",
        sa.Column("quarantine_requested_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("messages", "quarantine_requested_at")
    op.drop_column("messages", "source_ref")
