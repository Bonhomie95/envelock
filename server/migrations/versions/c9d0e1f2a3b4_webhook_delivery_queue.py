"""Outbound SIEM webhook delivery queue.

`webhook_endpoints` existed with no code behind it and `RETRY_SCHEDULE` was a
constant nothing consulted — a customer could be told the SIEM integration
existed and receive nothing. This is the durable queue that makes it real: a row
per delivery, enqueued inside the same transaction that raises the alert, so an
alert cannot exist without its delivery.

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "c9d0e1f2a3b4"
down_revision: str | None = "b8c9d0e1f2a3"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "endpoint_id",
            sa.Uuid(),
            # Removing an endpoint should take its pending deliveries with it —
            # a queue draining to a receiver the customer deleted is noise.
            sa.ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("payload", JSONB(), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error", sa.Text()),
    )
    op.create_index("ix_webhook_deliveries_tenant_id", "webhook_deliveries", ["tenant_id"])
    op.create_index("ix_webhook_deliveries_endpoint_id", "webhook_deliveries", ["endpoint_id"])
    # The drain query is always "pending, due now, oldest first".
    op.create_index(
        "ix_webhook_deliveries_due", "webhook_deliveries", ["status", "next_attempt_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_due", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_endpoint_id", table_name="webhook_deliveries")
    op.drop_index("ix_webhook_deliveries_tenant_id", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
