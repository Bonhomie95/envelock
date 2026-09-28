"""tenants.trial_reminder_days — which "your trial ends in N days" warning already went

Revision ID: a6b7c8d9e0f1
Revises: f5a6b7c8d9e0
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "a6b7c8d9e0f1"
down_revision: str | None = "f5a6b7c8d9e0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable with no default: NULL means "nothing warned yet for this period",
    # which is the correct state for every existing row — a tenant mid-trial when
    # this ships gets its next due reminder rather than being treated as already
    # warned and silently skipped.
    op.add_column("tenants", sa.Column("trial_reminder_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "trial_reminder_days")
