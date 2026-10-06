"""mailboxes.signature_fingerprint — C5 outbound-signature baseline

The outbound watch keeps the last-seen sent-mail signature here so it can diff
the bank details in it on the next sync (signature tampering). NULL means "no
baseline yet", which is deliberately never treated as a change.

Revision ID: c8d9e0f1a2b3
Revises: b7c8d9e0f1a2
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "c8d9e0f1a2b3"
down_revision: str | None = "b7c8d9e0f1a2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailboxes",
        sa.Column("signature_fingerprint", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailboxes", "signature_fingerprint")
