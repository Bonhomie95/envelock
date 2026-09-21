"""One company = one tenant, enforced by the database.

Removes free-mail Domain rows (registration no longer creates them — they can't
be verified and are shared by unrelated tenants), dedupes any corporate domain
claimed twice (keeping the earliest claim), then adds the global unique index
that closes the concurrent-registration race.

Revision ID: f5061728293a
Revises: e4f506172a38
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "f5061728293a"
down_revision: str | None = "e4f506172a38"
branch_labels = None
depends_on = None


def upgrade() -> None:
    from envelock.util.domains import _FREE_MAIL

    conn = op.get_bind()
    conn.execute(
        sa.text("DELETE FROM domains WHERE registrable_domain = ANY(:free)"),
        {"free": sorted(_FREE_MAIL)},
    )
    # Keep the earliest claim of each registrable domain; later duplicates were
    # the race's second tenant and are unreachable through the join logic anyway.
    conn.execute(
        sa.text(
            """
            DELETE FROM domains d USING domains earlier
            WHERE d.registrable_domain = earlier.registrable_domain
              AND d.created_at > earlier.created_at
            """
        )
    )
    op.create_index(
        "uq_domains_registrable", "domains", ["registrable_domain"], unique=True
    )


def downgrade() -> None:
    op.drop_index("uq_domains_registrable", table_name="domains")
