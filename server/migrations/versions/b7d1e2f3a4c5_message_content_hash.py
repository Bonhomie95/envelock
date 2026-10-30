"""Message content fingerprint for duplicate detection

The duplicate check keyed on (mailbox_id, rfc_message_id) alone, so a second
message reusing a Message-ID we had already stored was dropped unread — a sender
could mail something benign and then the phish under the same id. A content
fingerprint pairs with the id: a genuine re-delivery (same id, same content) is
still skipped, a reused id carrying different content is analysed.

Nullable and additive: rows stored before this column keep NULL and still count
as duplicates on an id match, exactly as before.

Revision ID: b7d1e2f3a4c5
Revises: ca05700c40c5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "b7d1e2f3a4c5"
down_revision: str | None = "ca05700c40c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("messages", sa.Column("content_hash", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("messages", "content_hash")
