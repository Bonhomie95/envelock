"""mailboxes.connected_address — the inbox an OAuth token really reads

Delegated OAuth reads /me (whoever consented), which can differ from the label
the customer typed. Storing the resolved address lets the dashboard warn when
"connected" is silently watching the wrong mailbox.

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d9e0f1a2b3c4"
down_revision: str | None = "c8d9e0f1a2b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailboxes",
        sa.Column("connected_address", sa.String(length=320), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailboxes", "connected_address")
