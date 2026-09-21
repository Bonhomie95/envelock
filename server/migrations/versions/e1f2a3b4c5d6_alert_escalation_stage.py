"""Record how far an alert has escalated, so each stage fires once.

`escalated_at` is a single timestamp overwritten by each step, so the
60-minute "all_admins" rule matched on every subsequent cycle: the escalation
job re-escalated the same alert once a minute, forever, writing an audit entry
and sending an SMS each time. A production tenant would have received an SMS
per minute until they acknowledged — which is how a customer learns to ignore
our notifications entirely.

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "e1f2a3b4c5d6"
down_revision: str | None = "d0e1f2a3b4c5"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("escalated_to", sa.String(length=16)))
    # Backfill: an alert that has already escalated at least once is treated as
    # having reached the first stage. Without this every historical open alert
    # would immediately re-escalate one final time on the next cycle.
    op.execute(
        "UPDATE alerts SET escalated_to = 'it_admin' WHERE escalated_at IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_column("alerts", "escalated_to")
