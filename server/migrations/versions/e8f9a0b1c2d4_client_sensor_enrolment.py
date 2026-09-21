"""Client sensor enrolment, silent-access state, and split-custody hand-offs.

Three things, all needed for the sensor to actually detect account takeover:

* `sensor_devices` / `sensor_pairings` — sensors authenticate with their own
  narrowly scoped token, obtained by trading a one-time pairing code, instead of
  holding a person's session on an ordinary laptop.
* `mailboxes.silent_access_armed` and `mailbox_credentials.imap_unseen_uids` —
  C11 compares the inbox's unread set between polls to see what was read. It is
  opt-in per mailbox because only the owner knows whether an unvouched read
  means an intruder or just their phone.
* `mailboxes.sync_requested_at` / `backfill_*` — under split key custody the API
  cannot decrypt a credential, so "Sync now" and "Scan my history" are recorded
  here and carried out by the worker, which can.

Revision ID: e8f9a0b1c2d4
Revises: d7e8f9a0b1c2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "e8f9a0b1c2d4"
down_revision: str | None = "d7e8f9a0b1c2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "sensor_devices",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("mailbox_id", sa.Uuid(), nullable=False),
        sa.Column("prefix", sa.String(length=16), nullable=False),
        sa.Column("hashed", sa.String(length=64), nullable=False),
        sa.Column("client", sa.String(length=32), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("device_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_ip", sa.String(length=45), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["mailbox_id"], ["mailboxes.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sensor_devices_tenant_id", "sensor_devices", ["tenant_id"])
    op.create_index("ix_sensor_devices_user_id", "sensor_devices", ["user_id"])
    op.create_index("ix_sensor_devices_mailbox_id", "sensor_devices", ["mailbox_id"])
    op.create_index("ix_sensor_devices_prefix", "sensor_devices", ["prefix"])

    op.create_table(
        "sensor_pairings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("mailbox_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["mailbox_id"], ["mailboxes.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("code_hash"),
    )
    op.create_index("ix_sensor_pairings_tenant_id", "sensor_pairings", ["tenant_id"])
    op.create_index("ix_sensor_pairings_mailbox_id", "sensor_pairings", ["mailbox_id"])

    # Off for every existing mailbox: arming C11 is the owner's decision, and
    # switching it on silently would page people for every phone read tonight.
    op.add_column(
        "mailboxes",
        sa.Column(
            "silent_access_armed", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column("mailboxes", sa.Column("sync_requested_at", sa.DateTime(timezone=True)))
    op.add_column(
        "mailboxes", sa.Column("backfill_requested_at", sa.DateTime(timezone=True))
    )
    op.add_column("mailboxes", sa.Column("backfill_requested_days", sa.Integer()))
    op.add_column(
        "mailboxes",
        sa.Column("backfill_state", postgresql.JSONB(astext_type=sa.Text())),
    )
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_unseen_uids", postgresql.JSONB(astext_type=sa.Text())),
    )


def downgrade() -> None:
    op.drop_column("mailbox_credentials", "imap_unseen_uids")
    op.drop_column("mailboxes", "backfill_state")
    op.drop_column("mailboxes", "backfill_requested_days")
    op.drop_column("mailboxes", "backfill_requested_at")
    op.drop_column("mailboxes", "sync_requested_at")
    op.drop_column("mailboxes", "silent_access_armed")
    op.drop_index("ix_sensor_pairings_mailbox_id", table_name="sensor_pairings")
    op.drop_index("ix_sensor_pairings_tenant_id", table_name="sensor_pairings")
    op.drop_table("sensor_pairings")
    op.drop_index("ix_sensor_devices_prefix", table_name="sensor_devices")
    op.drop_index("ix_sensor_devices_mailbox_id", table_name="sensor_devices")
    op.drop_index("ix_sensor_devices_user_id", table_name="sensor_devices")
    op.drop_index("ix_sensor_devices_tenant_id", table_name="sensor_devices")
    op.drop_table("sensor_devices")
