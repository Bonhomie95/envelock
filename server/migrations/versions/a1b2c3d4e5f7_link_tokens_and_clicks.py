"""link safety: click-time link tokens and the click ledger

Feature 1 enforcement. Every URL in a protected message is rewritten to
`{redirect base}/r/{token}`; `link_tokens` maps the token back to the original
URL (with a cached verdict), and `link_clicks` records who fetched it, when,
and whether we allowed, warned, or blocked.

Revision ID: a1b2c3d4e5f7
Revises: e1f2a3b4c5d6
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "a1b2c3d4e5f7"
down_revision: str | None = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "link_tokens",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("mailbox_id", sa.Uuid(), sa.ForeignKey("mailboxes.id")),
        sa.Column("message_id", sa.Uuid(), sa.ForeignKey("messages.id")),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("original_url", sa.Text(), nullable=False),
        sa.Column("last_verdict", sa.String(length=16)),
        sa.Column("last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("click_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_link_tokens_tenant_id", "link_tokens", ["tenant_id"])
    op.create_index("ix_link_tokens_token", "link_tokens", ["token"], unique=True)

    op.create_table(
        "link_clicks",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "link_token_id", sa.Uuid(), sa.ForeignKey("link_tokens.id"), nullable=False
        ),
        sa.Column("tenant_id", sa.Uuid(), sa.ForeignKey("tenants.id"), nullable=False),
        sa.Column("ip", sa.String(length=45)),
        sa.Column("user_agent", sa.String(length=512)),
        sa.Column("action", sa.String(length=16), nullable=False),
    )
    op.create_index("ix_link_clicks_link_token_id", "link_clicks", ["link_token_id"])
    op.create_index("ix_link_clicks_tenant_id", "link_clicks", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_link_clicks_tenant_id", table_name="link_clicks")
    op.drop_index("ix_link_clicks_link_token_id", table_name="link_clicks")
    op.drop_table("link_clicks")
    op.drop_index("ix_link_tokens_token", table_name="link_tokens")
    op.drop_index("ix_link_tokens_tenant_id", table_name="link_tokens")
    op.drop_table("link_tokens")
