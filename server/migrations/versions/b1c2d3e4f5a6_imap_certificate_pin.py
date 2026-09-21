"""add mailbox_credentials.imap_cert_sha256

A server certificate the tenant explicitly approved for one mailbox, so a
mailbox on shared hosting — whose certificate names the hosting provider rather
than the customer's own domain — can connect at all. Without this the only
options were refusing a working mailbox or disabling certificate verification
outright, and the second is unacceptable in a product whose job is to stop
credentials reaching the wrong server.

Nullable, and null is the norm: an absent pin means ordinary strict
verification against the public CA chain.

Revision ID: b1c2d3e4f5a6
Revises: a1b2c3d4e5f7
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "b1c2d3e4f5a6"
down_revision: str | None = "a1b2c3d4e5f7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "mailbox_credentials",
        sa.Column("imap_cert_sha256", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("mailbox_credentials", "imap_cert_sha256")
