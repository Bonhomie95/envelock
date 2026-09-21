"""Record the sum that was about to move, and when the monthly digest last ran.

The product's whole claim is "we stop your money going to the wrong bank
account", and until now nothing in the system recorded how much money that was.
That makes the value of a subscription unarguable at renewal — the customer has
a bill in front of them and we have a count of alerts, which is a cost
conversation rather than a return one. The figure is extracted from the message
at raise time, is null whenever the message named no amount, and carries its
currency so the rollup never adds two of them together.

Revision ID: d7e8f9a0b1c2
Revises: a6172839405b
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "d7e8f9a0b1c2"
down_revision: str | None = "a6172839405b"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Nullable with no backfill and no default, deliberately. Historical alerts
    # genuinely do not have this figure — the message text they were raised from
    # may already be past its 30-day retention — and writing a zero would make
    # "no amount recorded" indistinguishable from "an amount of nothing", which
    # is the one way to turn an honest headline number into a false one.
    op.add_column("alerts", sa.Column("amount_at_risk", sa.Float()))
    op.add_column("alerts", sa.Column("amount_currency", sa.String(length=8)))
    # Null = never sent. The digest job reads this as "due once the tenant is old
    # enough to have a month worth reporting on", so backfilling a timestamp here
    # would silently delay every existing tenant's first digest by a month.
    op.add_column(
        "tenants", sa.Column("last_digest_at", sa.DateTime(timezone=True))
    )


def downgrade() -> None:
    op.drop_column("tenants", "last_digest_at")
    op.drop_column("alerts", "amount_currency")
    op.drop_column("alerts", "amount_at_risk")
