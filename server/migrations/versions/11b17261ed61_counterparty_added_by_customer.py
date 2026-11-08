"""Counterparty added_by_customer

The Suppliers page listed every sender that had ever emailed, attackers and
newsletters included. It now lists a sender only when it has a payment trail or
the customer named it a supplier — and that second half needs remembering, or a
supplier added by hand drops off the page as soon as it sends a non-payment email.

Additive, false for existing rows: those still qualify through the other signals
(a callback number, an account on file, never having emailed).

Revision ID: 11b17261ed61
Revises: b7d1e2f3a4c5
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "11b17261ed61"
down_revision: str | None = "b7d1e2f3a4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "counterparties",
        sa.Column("added_by_customer", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("counterparties", "added_by_customer")
