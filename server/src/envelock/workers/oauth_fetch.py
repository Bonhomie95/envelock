"""Live mail pull for Tier-1 (Graph / Gmail) OAuth mailboxes.

This closes the biggest launch gap: after OAuth consent a mailbox was marked
`FULL_API` but nothing ever read it — `gmail_fetch`/`graph_fetch` had no caller.
Here we decrypt the (refreshed) access token, pull recent mail, and run each
message through the same detection pipeline the IMAP worker uses. The pipeline
dedupes by (mailbox_id, rfc_message_id), so a webhook-less poll never
double-alerts.

A Graph subscription / Gmail Pub/Sub webhook (see api/webhooks.py) short-circuits
this for real-time delivery; polling is the always-correct fallback.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import api_enforce, enforce
from envelock.channels.mail.api_fetch import gmail_fetch_raw, graph_fetch_raw
from envelock.channels.mail.forward_runner import _recipients
from envelock.channels.mail.oauth_refresh import current_access_token
from envelock.channels.mail.parser import parse_message_async
from envelock.config import get_settings
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox, Message
from envelock.notify.dispatch import deliver_pending
from envelock.platform.alerts import AuditAction, record_audit
from envelock.platform.pipeline import analyse_event
from envelock.workers.enforcement import plan_protected_copy

logger = logging.getLogger("envelock.oauthfetch")

_OAUTH_SOURCES = {
    SourceMechanism.GRAPH_API.value,
    SourceMechanism.GMAIL_API.value,
}


async def _owned_domains(session: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    rows = (
        await session.execute(
            select(Domain.registrable_domain).where(Domain.tenant_id == tenant_id)
        )
    ).all()
    return frozenset(d for (d,) in rows)


async def _write_back(
    session: AsyncSession,
    *,
    provider: str,
    access_token: str,
    mailbox: Mailbox,
    ref: str,
    raw: bytes,
    event,  # noqa: ANN001 — core.events.MailEvent
    pr,  # noqa: ANN001 — platform.pipeline.PipelineResult
    owned: frozenset[str],
    banner_allowed: bool,
    transport=None,  # noqa: ANN001 — api_enforce.WriteTransport, injected in tests
) -> bool:
    """Replace the message with its protected copy, if this provider's copy
    write-back is switched on and there is anything to write."""
    settings = get_settings()
    enabled = (
        settings.gmail_rewrite_enabled if provider == "google" else settings.graph_rewrite_enabled
    )
    if not enabled:
        return False
    mapping, banner = await plan_protected_copy(
        session, event, pr, owned=owned, banner_allowed=banner_allowed
    )
    if not mapping and banner is None:
        return False
    if provider == "google":
        new_raw = enforce.build_protected_copy(
            raw, link_map=mapping, redirect_base=settings.redirect_base, banner=banner
        )
        return await api_enforce.gmail_replace(
            access_token=access_token, message_id=ref, new_raw=new_raw, transport=transport
        )
    return await api_enforce.graph_replace(
        access_token=access_token,
        message_id=ref,
        link_map=mapping,
        redirect_base=settings.redirect_base,
        banner=banner,
        mailbox_address=mailbox.address,
        transport=transport,
    )


async def _quarantine(
    *, provider: str, access_token: str, mailbox: Mailbox, ref: str, transport=None  # noqa: ANN001
) -> bool:
    if provider == "google":
        return await api_enforce.gmail_quarantine(
            access_token=access_token, message_id=ref, transport=transport
        )
    return await api_enforce.graph_quarantine(
        access_token=access_token,
        message_id=ref,
        mailbox_address=mailbox.address,
        transport=transport,
    )


async def _run_requested_quarantines(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    provider: str,
    access_token: str,
    transport=None,  # noqa: ANN001
) -> int:
    """Human QUARANTINE clicks recorded while no process could act (the API
    seals but cannot decrypt). The provider message id is `Message.source_ref`."""
    pending = (
        (
            await session.execute(
                select(Message).where(
                    Message.mailbox_id == mailbox.id,
                    Message.quarantine_requested_at.is_not(None),
                    Message.quarantined_at.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )
    done = 0
    for pm in pending:
        if not pm.source_ref:
            continue
        if await _quarantine(
            provider=provider, access_token=access_token, mailbox=mailbox,
            ref=pm.source_ref, transport=transport,
        ):
            pm.quarantined_at = datetime.now(UTC)
            pm.quarantine_requested_at = None
            done += 1
            await record_audit(
                session,
                tenant_id=mailbox.tenant_id,
                action=AuditAction.MESSAGE_QUARANTINED,
                target_type="message",
                target_id=pm.id,
                detail={"requested_by_user": True},
            )
    return done


async def sync_oauth_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    transport=None,  # noqa: ANN001 — api_fetch.HttpTransport
    write_transport=None,  # noqa: ANN001 — api_enforce.WriteTransport
) -> dict:
    """Fetch, analyse and enforce recent mail for one OAuth mailbox.

    The same tier policy as the IMAP worker (see `imap_fetch.sync_mailbox`):
    Critical is quarantined; High gets a banner + protected links; Medium/Low and
    clean mail get protected links only. Only a Protected-class mailbox is ever
    written to.
    """
    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)  # scope RLS to this mailbox's tenant
    tok = await current_access_token(session, mailbox.id)
    if tok is None:
        return {"ok": False, "reason": "no usable oauth token", "fetched": 0}
    access_token, provider = tok
    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)
    settings = get_settings()
    protected = mailbox.mailbox_class == MailboxClass.PROTECTED.value
    source = SourceMechanism.GMAIL_API if provider == "google" else SourceMechanism.GRAPH_API

    try:
        if provider == "google":
            fetched = await gmail_fetch_raw(access_token=access_token, transport=transport)
        else:
            fetched = await graph_fetch_raw(
                access_token=access_token,
                mailbox_address=mailbox.address,
                transport=transport,
            )
    except Exception as exc:  # noqa: BLE001 — provider/network errors are non-fatal
        logger.warning("oauth fetch failed for mailbox %s: %s", mailbox.id, exc)
        return {"ok": False, "reason": str(exc), "fetched": 0}

    alerted = quarantined = rewritten = 0
    for item in fetched:
        # Our own protected copy — never re-analyse or re-rewrite it.
        if enforce.is_processed(item.raw):
            continue
        event = await parse_message_async(
            item.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=source,
            owned_domains=owned,
            remediable=protected,
            source_ref=item.ref,
        )
        pr = await analyse_event(
            session,
            event,
            tenant_id=mailbox.tenant_id,
            owned_domains=owned,
            recipients=recipients,
        )
        if pr.duplicate:
            continue
        common: dict[str, Any] = {
            "provider": provider, "access_token": access_token, "mailbox": mailbox,
            "ref": item.ref,
        }
        if pr.alert_id is not None:
            alerted += 1
            tier = pr.assessment.tier if pr.assessment else None
            if protected and tier is AlertTier.CRITICAL and settings.api_quarantine_enabled:
                if await _quarantine(**common, transport=write_transport):
                    quarantined += 1
                    if pr.message_id is not None:
                        stored = await session.get(Message, pr.message_id)
                        if stored is not None:
                            stored.quarantined_at = datetime.now(UTC)
                elif await _write_back(
                    session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
                    banner_allowed=True, transport=write_transport,
                ):
                    rewritten += 1
            elif protected and await _write_back(
                session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
                banner_allowed=tier is AlertTier.HIGH, transport=write_transport,
            ):
                rewritten += 1
            await deliver_pending(session, alert_id=pr.alert_id)
        elif protected and event.urls and await _write_back(
            session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
            banner_allowed=False, transport=write_transport,
        ):
            rewritten += 1

    quarantined += await _run_requested_quarantines(
        session, mailbox, provider=provider, access_token=access_token,
        transport=write_transport,
    )

    mailbox.last_sync_at = datetime.now(UTC)
    mailbox.sync_requested_at = None  # answers any queued push / "Sync now"
    await session.commit()
    return {
        "ok": True,
        "fetched": len(fetched),
        "alerted": alerted,
        "quarantined": quarantined,
        "rewritten": rewritten,
    }


async def _oauth_mailboxes(session: AsyncSession, *, requested_only: bool = False) -> list[UUID]:
    query = select(Mailbox).where(Mailbox.is_active.is_(True))
    if requested_only:
        query = query.where(Mailbox.sync_requested_at.is_not(None))
    rows = (await session.execute(query)).scalars().all()
    candidates = [m for m in rows if any(s in _OAUTH_SOURCES for s in (m.sources or []))]
    # Same poll-side seat-cap enforcement as the IMAP worker: a lapsed unpaid
    # trial (or seats beyond a downgraded plan) must not keep live protection.
    from envelock.workers.imap_fetch import _entitled_only

    return [m.id for m in await _entitled_only(session, candidates)]


async def _sync_ids(ids: list[UUID], *, transport=None, write_transport=None) -> dict:  # noqa: ANN001
    from envelock.db_rls import system_scope

    sessionmaker = get_sessionmaker()
    totals = {"mailboxes": 0, "fetched": 0, "alerted": 0, "quarantined": 0,
              "rewritten": 0, "errors": 0}
    for mailbox_id in ids:
        # `system_scope` is a SYNC context manager. It used to share the
        # `async with` clause with the session, which makes Python demand
        # `__aenter__` on it — so this raised TypeError on the first mailbox of
        # every cycle, and no OAuth (Microsoft 365 / Gmail) mailbox was ever
        # polled. The two have to nest, not share a clause.
        summary: dict | None = None
        with system_scope("oauth poll: load mailbox"):
            async with sessionmaker() as session:
                mailbox = await session.get(Mailbox, mailbox_id)
                if mailbox is None:
                    continue
                try:
                    summary = await sync_oauth_mailbox(
                        session, mailbox, transport=transport,
                        write_transport=write_transport,
                    )
                except Exception:  # noqa: BLE001
                    logger.exception("oauth fetch: error on mailbox %s", mailbox_id)
                    totals["errors"] += 1
                    continue
        totals["mailboxes"] += 1
        if summary is not None and summary.get("ok"):
            for k in ("fetched", "alerted", "quarantined", "rewritten"):
                totals[k] += summary.get(k, 0)
        else:
            totals["errors"] += 1
    return totals


async def fetch_all_oauth_mailboxes(*, transport=None, write_transport=None) -> dict:  # noqa: ANN001
    """Poll every connected Tier-1 mailbox once — the fallback behind push.
    Per-mailbox session + try/except so one failure never aborts the cycle."""
    from envelock.db_rls import system_scope

    # Selecting which mailboxes are due spans tenants; everything after binds
    # the owning tenant per mailbox (see `sync_oauth_mailbox`).
    with system_scope("oauth poll: select connected mailboxes"):
        async with get_sessionmaker()() as session:
            ids = await _oauth_mailboxes(session)
    return await _sync_ids(ids, transport=transport, write_transport=write_transport)


async def drain_requested(*, transport=None, write_transport=None) -> dict:  # noqa: ANN001
    """Sync the mailboxes a push notification, a "Sync now" or a QUARANTINE
    click flagged. The real-time path: runs every few seconds, and is cheap when
    nothing is flagged (one indexed query)."""
    from envelock.db_rls import system_scope

    with system_scope("oauth poll: select requested mailboxes"):
        async with get_sessionmaker()() as session:
            ids = await _oauth_mailboxes(session, requested_only=True)
    if not ids:
        return {"mailboxes": 0}
    return await _sync_ids(ids, transport=transport, write_transport=write_transport)


__all__ = ["drain_requested", "fetch_all_oauth_mailboxes", "sync_oauth_mailbox"]
