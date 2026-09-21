"""add tenants.stripe_subscription_id

The live Stripe Subscription, so plan changes and extra mailbox seats update it
in place instead of opening a second subscription through Checkout.

Revision ID: a9b0c1d2e3f4
Revises: e8f9a0b1c2d4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "a9b0c1d2e3f4"
down_revision: str | None = "e8f9a0b1c2d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("stripe_subscription_id", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "stripe_subscription_id")
