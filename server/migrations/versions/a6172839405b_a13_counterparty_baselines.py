"""A13 baselines: invoice numbers + typical amount on counterparties.

Revision ID: a6172839405b
Revises: f5061728293a
Create Date: 2026-09-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a6172839405b"
down_revision: str | None = "f5061728293a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "counterparties",
        sa.Column(
            "seen_invoice_numbers",
            postgresql.ARRAY(sa.String()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.add_column(
        "counterparties", sa.Column("typical_amount", sa.Float(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("counterparties", "typical_amount")
    op.drop_column("counterparties", "seen_invoice_numbers")
