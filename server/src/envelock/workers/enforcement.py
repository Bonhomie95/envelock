"""What to write back into a delivered message — shared by every connection.

The IMAP worker and the Gmail/Graph worker make the same decision about a
message: which of its links go through the click-time redirector, and whether
it carries a warning banner. Only the mailbox surgery differs, so the decision
lives here once.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import enforce
from envelock.config import get_settings
from envelock.core.enums import AlertTier
from envelock.platform import links as link_safety
from envelock.platform.pipeline import PipelineResult


async def plan_protected_copy(
    session: AsyncSession,
    event,  # noqa: ANN001 — core.events.MailEvent
    pr: PipelineResult,
    *,
    owned: frozenset[str],
    banner_allowed: bool = True,
) -> tuple[dict[str, str], enforce.Banner | None]:
    """(link map, banner). Both empty/None means there is nothing to write."""
    settings = get_settings()

    mapping: dict[str, str] = {}
    if settings.link_rewrite_enabled and event.urls:
        urls = link_safety.rewritable_urls(
            list(event.urls), owned_domains=owned, redirect_base=settings.redirect_base
        )
        mapping = await link_safety.mint_link_tokens(
            session,
            urls,
            tenant_id=event.tenant_id,
            mailbox_id=event.mailbox_id,
            message_id=pr.message_id,
        )

    banner = None
    if (
        banner_allowed
        and settings.banner_enabled
        and pr.alert_id is not None
        and pr.assessment is not None
    ):
        severity = (
            "critical"
            if pr.assessment.tier is AlertTier.CRITICAL
            else "warning"
            if pr.assessment.tier in (AlertTier.HIGH, AlertTier.MEDIUM)
            else "info"
        )
        banner = enforce.Banner(
            severity=severity,
            title=pr.assessment.title,
            lines=tuple(f.summary for f in pr.findings[:3]),
        )
    return mapping, banner


__all__ = ["plan_protected_copy"]
