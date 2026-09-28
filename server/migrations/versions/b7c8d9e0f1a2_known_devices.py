"""users.known_devices — so a sign-in from a new device can be reported

Revision ID: b7c8d9e0f1a2
Revises: a6b7c8d9e0f1
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7c8d9e0f1a2"
down_revision: str | None = "a6b7c8d9e0f1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Empty array, not NULL: every existing login starts with no known devices,
    # so each gets ONE "new device" notice on its next sign-in and is quiet
    # after that. Pre-seeding whatever they happen to use next would mean the
    # first genuinely new device went unreported — the wrong way round to be
    # wrong for a security notice.
    op.add_column(
        "users",
        sa.Column(
            "known_devices",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "known_devices")
