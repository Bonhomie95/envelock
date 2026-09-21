"""Session geolocation and attested reads — turning on C7, C9, C11, C13, C14.

Five detections were written correctly and could never fire, because the data
they read was never collected:

* `sensor_sessions` had no coordinates, so C7's impossible-travel haversine
  always short-circuited and C14 (counterparty travel) with it.
* There was nowhere to record that the sensor had attested a read, so C11 ("a
  message was read with nobody here") could not distinguish the mailbox owner
  from an intruder.

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "b8c9d0e1f2a3"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Nullable throughout: a deployment with no IP-intelligence provider still
    # records sessions, it just cannot locate them — and the detections stay off
    # rather than firing on a guess.
    op.add_column("sensor_sessions", sa.Column("city", sa.String(length=128)))
    op.add_column("sensor_sessions", sa.Column("latitude", sa.Float()))
    op.add_column("sensor_sessions", sa.Column("longitude", sa.Float()))
    op.add_column(
        "sensor_sessions",
        sa.Column("is_proxy", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "sensor_sessions",
        sa.Column("is_tor", sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        "attested_reads",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column(
            "mailbox_id",
            sa.Uuid(),
            sa.ForeignKey("mailboxes.id"),
            nullable=False,
        ),
        sa.Column("message_ref", sa.String(length=255), nullable=False),
        sa.Column("device_fingerprint", sa.String(length=128)),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_attested_reads_tenant_id", "attested_reads", ["tenant_id"])
    op.create_index("ix_attested_reads_mailbox_id", "attested_reads", ["mailbox_id"])
    op.create_index("ix_attested_reads_read_at", "attested_reads", ["read_at"])
    # The C11 lookup is always (mailbox, message, recently).
    op.create_index(
        "ix_attested_reads_lookup",
        "attested_reads",
        ["mailbox_id", "message_ref", "read_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_attested_reads_lookup", table_name="attested_reads")
    op.drop_index("ix_attested_reads_read_at", table_name="attested_reads")
    op.drop_index("ix_attested_reads_mailbox_id", table_name="attested_reads")
    op.drop_index("ix_attested_reads_tenant_id", table_name="attested_reads")
    op.drop_table("attested_reads")
    for column in ("is_tor", "is_proxy", "longitude", "latitude", "city"):
        op.drop_column("sensor_sessions", column)
