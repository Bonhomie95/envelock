"""E13 metadata-only mode.

Message bodies and attachment bytes are never persisted by any code path, so the
subject line is the one piece of message content that reaches a durable row.
With this flag on it is analysed in memory and then dropped — the alert keeps
its own title, so the customer loses nothing operationally.

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d0e1f2a3b4c5"
down_revision: str | None = "c9d0e1f2a3b4"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "metadata_only", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "metadata_only")
