"""Email-ownership verification: users.email_verified_at.

Revision ID: e4f506172a38
Revises: d3e4f5061927
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e4f506172a38"
down_revision: str | None = "d3e4f5061927"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("users", "email_verified_at")
