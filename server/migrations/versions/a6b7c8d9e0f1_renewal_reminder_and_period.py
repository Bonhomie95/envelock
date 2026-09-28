"""tenants: renewal reminder milestone + mirrored Stripe period fields

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
    # which is the right state for every existing row — a tenant mid-trial when
    # this ships gets its next due reminder rather than being treated as already
    # warned and silently skipped.
    op.add_column("tenants", sa.Column("renewal_reminder_days", sa.Integer(), nullable=True))
    # Mirrored from Stripe so the expiry warnings have a date to count down to
    # without calling the API on every scheduler tick.
    op.add_column(
        "tenants",
        sa.Column("subscription_period_end", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "subscription_cancel_at_period_end",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "subscription_cancel_at_period_end")
    op.drop_column("tenants", "subscription_period_end")
    op.drop_column("tenants", "renewal_reminder_days")
