"""Link telemetry expires.

`purge_expired` covered message bodies, sensor sessions, audit events, findings
and alerts — and touched neither `LinkToken` nor `LinkClick`. So the redirector
kept, indefinitely:

  * the full ORIGINAL URL of every link in every protected message, which is
    message content that outlived the 30-day body policy by an unbounded margin;
  * the IP address and user agent of everyone who clicked one, which is personal
    data with no class, no cutoff and no answer for a deletion request.

It also undercut metadata-only mode, which regulated buyers ask for by name.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select

from envelock.governance.retention import DataClass, cutoff, purge_expired
from envelock.models import LinkClick, LinkToken, Tenant


async def _tenant(session) -> object:  # noqa: ANN001
    tenant = Tenant(id=uuid4(), name="Retention Co", plan="complete")
    session.add(tenant)
    await session.flush()
    return tenant


def _aged(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


async def test_click_telemetry_is_deleted_after_ninety_days(session) -> None:  # noqa: ANN001
    tenant = await _tenant(session)
    token = LinkToken(
        tenant_id=tenant.id,
        token="t-recent",  # noqa: S106 — a redirector link id, not a secret
        original_url="https://example.com/a",
    )
    session.add(token)
    await session.flush()

    session.add(
        LinkClick(
            link_token_id=token.id,
            tenant_id=tenant.id,
            ip="203.0.113.9",
            user_agent="Mozilla/5.0",
            action="allowed",
            created_at=_aged(120),
        )
    )
    session.add(
        LinkClick(
            link_token_id=token.id,
            tenant_id=tenant.id,
            ip="203.0.113.10",
            action="allowed",
            created_at=_aged(10),
        )
    )
    await session.commit()

    counts = await purge_expired(session)
    assert counts["link_click"] == 1

    remaining = (await session.execute(select(LinkClick))).scalars().all()
    assert [c.ip for c in remaining] == ["203.0.113.10"]


async def test_a_rewritten_url_expires_after_a_year(session) -> None:  # noqa: ANN001
    tenant = await _tenant(session)
    session.add(
        LinkToken(
            tenant_id=tenant.id,
            token="t-old",  # noqa: S106 — a redirector link id, not a secret
            original_url="https://example.com/old",
            created_at=_aged(400),
        )
    )
    session.add(
        LinkToken(
            tenant_id=tenant.id,
            token="t-young",  # noqa: S106 — a redirector link id, not a secret
            original_url="https://example.com/young",
            created_at=_aged(200),
        )
    )
    await session.commit()

    counts = await purge_expired(session)
    assert counts["link_token"] == 1

    left = (await session.execute(select(LinkToken.token))).scalars().all()
    assert left == ["t-young"]


async def test_expiring_a_token_takes_its_clicks_with_it(session) -> None:  # noqa: ANN001
    """Whatever their own age — the foreign key would otherwise block the delete
    and leave orphaned telemetry behind."""
    tenant = await _tenant(session)
    token = LinkToken(
        tenant_id=tenant.id,
        token="t-expiring",  # noqa: S106 — a redirector link id, not a secret
        original_url="https://example.com/x",
        created_at=_aged(400),
    )
    session.add(token)
    await session.flush()
    session.add(
        LinkClick(
            link_token_id=token.id,
            tenant_id=tenant.id,
            ip="203.0.113.5",
            action="warned",
            created_at=_aged(1),  # young enough to survive on its own
        )
    )
    await session.commit()

    await purge_expired(session)

    assert (await session.execute(select(LinkToken))).scalars().all() == []
    assert (await session.execute(select(LinkClick))).scalars().all() == []


def test_a_link_lives_longer_than_the_body_it_came_from() -> None:
    """The trade-off, written down.

    The URL is content, so it cannot be kept forever. But the token is also the
    only thing that makes the rewritten link WORK, and a customer opening a
    year-old invoice must not find a dead link where we rewrote a live one — so
    it outlives the 30-day body window on purpose.
    """
    body = cutoff(DataClass.MESSAGE_BODY)
    token = cutoff(DataClass.LINK_TOKEN)
    click = cutoff(DataClass.LINK_CLICK)
    assert body is not None and token is not None and click is not None
    assert token < body, "links must outlive the body they were rewritten in"
    assert token < click, "the URL outlives the click telemetry about it"


def test_neither_class_survives_metadata_only_mode() -> None:
    """Both hold message content or personal data, so a metadata-only tenant must
    not accumulate either."""
    from envelock.governance.retention import policy_for

    assert policy_for(DataClass.LINK_TOKEN).metadata_only_mode is False
    assert policy_for(DataClass.LINK_CLICK).metadata_only_mode is False
