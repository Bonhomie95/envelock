"""Feature 1 — link safety.

Two halves, both here so delivery-time rewriting and the click-time redirector
share one evaluation path:

* `mint_link_tokens` stores one `LinkToken` row per URL and returns the
  url → token map the enforcement layer substitutes into the message body.
* `evaluate_url` is the live verdict: cross-tenant graph, DNSBL domain lists,
  static heuristics, and Google Safe Browsing (when a key is configured).
  Called at delivery (to decide banners) and again on every click (a page
  weaponised after delivery is the standard evasion).

Every failure mode degrades to a softer verdict rather than raising — a broken
reputation source must never break the customer's links.
"""

from __future__ import annotations

import logging
import secrets
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.detections.cascade import Verdict, get_url_cascade
from envelock.models import LinkToken
from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.links")

#: Link classes that must never be rewritten (plan §7): breaking an unsubscribe
#: or calendar link creates support pain disproportionate to any protection.
_NEVER_REWRITE_MARKERS = ("unsubscribe", "list-manage", "calendar.google.com/calendar", ".ics")


def url_host(url: str) -> str:
    """Hostname of a URL without pulling in a full parser for hostile input."""
    return url.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()


def rewritable_urls(
    urls: list[str], *, owned_domains: frozenset[str], redirect_base: str
) -> list[str]:
    """The subset of a message's URLs that should be rewritten.

    Skips the tenant's own domains, anything already pointing at our redirector,
    and unsubscribe/calendar links.
    """
    out: list[str] = []
    seen: set[str] = set()
    base_host = url_host(redirect_base) if "//" in redirect_base else redirect_base
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        host = url_host(url)
        if not host or host == base_host:
            continue
        if registrable_domain(host) in owned_domains:
            continue
        lowered = url.lower()
        if any(marker in lowered for marker in _NEVER_REWRITE_MARKERS):
            continue
        out.append(url)
    return out


async def mint_link_tokens(
    session: AsyncSession,
    urls: list[str],
    *,
    tenant_id: UUID,
    mailbox_id: UUID | None,
    message_id: UUID | None,
) -> dict[str, str]:
    """Create one token per URL; returns url → token. Flushes, does not commit."""
    mapping: dict[str, str] = {}
    for url in urls:
        token = secrets.token_urlsafe(24)
        session.add(
            LinkToken(
                tenant_id=tenant_id,
                mailbox_id=mailbox_id,
                message_id=message_id,
                token=token,
                original_url=url[:8192],
            )
        )
        mapping[url] = token
    if mapping:
        await session.flush()
    return mapping


async def get_link_token(session: AsyncSession, token: str) -> LinkToken | None:
    return (
        await session.execute(select(LinkToken).where(LinkToken.token == token))
    ).scalar_one_or_none()


async def evaluate_url(url: str) -> tuple[str, list[str]]:
    """Live verdict for one URL: ``("clean"|"unknown"|"suspicious"|"malicious", reasons)``.

    Order is cheap → expensive with short-circuit on a malicious hit:
    1. the cross-tenant counterparty graph (confirmed fraud domains),
    2. DNSBL domain lists (free DNS, when enabled),
    3. static heuristics + Google Safe Browsing via the shared ``UrlCascade``.
    """
    from envelock.config import get_settings

    reg = registrable_domain(url_host(url))
    reasons: list[str] = []

    try:
        from envelock.platform.graph import GRAPH

        if reg and reg in GRAPH.known_bad():
            return "malicious", [f"{reg} is confirmed fraudulent across the network"]
    except Exception:  # noqa: BLE001 — one signal, never the answer
        logger.debug("graph lookup failed for %s", reg, exc_info=True)

    settings = get_settings()
    if reg and settings.domain_reputation_enabled:
        try:
            from envelock.channels.external.reputation import check_sender_domain

            rep = await check_sender_domain(reg)
            if rep.listed:
                sources = ", ".join(rep.sources) or "a public blocklist"
                return "malicious", [f"{reg} is listed on {sources}"]
        except Exception:  # noqa: BLE001
            logger.debug("dnsbl lookup failed for %s", reg, exc_info=True)

    try:
        verdict = await get_url_cascade().check(url)
        reasons.extend(verdict.reasons)
        if verdict.verdict is Verdict.MALICIOUS:
            return "malicious", reasons
        if verdict.verdict is Verdict.SUSPICIOUS:
            return "suspicious", reasons
        if verdict.verdict is Verdict.CLEAN:
            return "clean", reasons
    except Exception:  # noqa: BLE001
        logger.debug("url cascade failed for %s", url, exc_info=True)

    return "unknown", reasons


__all__ = [
    "evaluate_url",
    "get_link_token",
    "mint_link_tokens",
    "rewritable_urls",
    "url_host",
]
