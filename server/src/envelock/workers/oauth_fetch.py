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

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import api_enforce, enforce
from envelock.channels.mail.api_fetch import (
    HttpxTransport,
    gmail_fetch_history,
    gmail_fetch_outbound,
    gmail_fetch_raw,
    gmail_message_id,
    gmail_unread_ids,
    gmail_whoami,
    graph_fetch_history,
    graph_fetch_outbound,
    graph_fetch_raw,
    graph_read_states,
    graph_whoami,
)
from envelock.channels.mail.forward_runner import _recipients
from envelock.channels.mail.oauth_refresh import current_access_token
from envelock.channels.mail.parser import parse_message_async
from envelock.config import get_settings
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox, MailboxCredential, Message
from envelock.notify.dispatch import deliver_pending
from envelock.platform.alerts import AuditAction, record_audit
from envelock.platform.pipeline import analyse_event
from envelock.workers.enforcement import plan_protected_copy
from envelock.workers.outbound import process_outbound

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
            raw, link_map=mapping, redirect_base=settings.redirect_base,
            mailbox_id=mailbox.id, banner=banner,
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
        mailbox_id=mailbox.id,
        # Delegated token → /me (see the fetch note); /users/{label} 403s.
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
        # Delegated token → /me (see the fetch note); /users/{label} 403s.
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


async def _watch_reads_graph(
    session: AsyncSession,
    mailbox: Mailbox,
    cred: MailboxCredential,
    *,
    access_token: str,
    owned: frozenset[str],
    transport=None,  # noqa: ANN001 — api_fetch.HttpTransport
) -> dict:
    """Silent-access (C11) for a Graph mailbox: a message read while none of the
    owner's sensor devices were open is "someone else opened your mail".

    The IMAP worker has had this for IMAP mailboxes; a Graph mailbox got the
    sensor's inbound detections but never this poll-time read-watch, so the
    sensor's headline promise was inert on Microsoft 365. Graph exposes isRead,
    so the mechanism is the same: snapshot the unread set, and on the next poll
    anything that left it by being READ (not deleted) is a read to judge.
    """
    from envelock.platform import sensor as sensor_rules

    armed = bool(mailbox.silent_access_armed) and await sensor_rules.has_enrolled_sensor(
        session, mailbox_id=mailbox.id
    )
    if not armed:
        # Drop any stale snapshot so re-arming starts from a fresh baseline
        # rather than reporting every read since it was switched off.
        cred.imap_unseen_uids = None
        return {"observed": 0, "alerted": 0}

    try:
        states = await graph_read_states(access_token=access_token, transport=transport)
    except Exception as exc:  # noqa: BLE001 — a failed look is not evidence of a read
        logger.info("graph read-watch skipped for %s: %s", mailbox.id, exc)
        return {"observed": 0, "alerted": 0}

    previous = set(cred.imap_unseen_uids or [])
    current_unread = [st.ref for st in states if not st.is_read]
    # Read since last poll: was in the unread snapshot, and is present now AND
    # read. A ref that merely vanished (deleted/moved) is NOT a read, so it is
    # deliberately not counted — matching the IMAP watch's intent.
    became_read = [st for st in states if st.is_read and st.ref in previous]

    cred.imap_unseen_uids = current_unread[: sensor_rules.MAX_TRACKED_UNSEEN]

    alerted = 0
    for st in became_read:
        verdict = await sensor_rules.evaluate_read(
            session,
            mailbox=mailbox,
            message_ref=st.message_id or f"graph:{st.ref}",
            owned_domains=owned,
        )
        alerted += int(verdict.alerted)
    return {"observed": len(became_read), "alerted": alerted}


async def _watch_reads_gmail(
    session: AsyncSession,
    mailbox: Mailbox,
    cred: MailboxCredential,
    *,
    access_token: str,
    owned: frozenset[str],
    transport=None,  # noqa: ANN001 — api_fetch.HttpTransport
) -> dict:
    """Silent-access (C11) for a Gmail mailbox. Read state is the UNREAD label,
    so the snapshot is the set of currently-unread ids; anything that left it is
    a read, and we fetch just those few messages' Message-ID for the attestation
    match. A deleted message returns no id and is not counted as a read."""
    from envelock.platform import sensor as sensor_rules

    armed = bool(mailbox.silent_access_armed) and await sensor_rules.has_enrolled_sensor(
        session, mailbox_id=mailbox.id
    )
    if not armed:
        cred.imap_unseen_uids = None
        return {"observed": 0, "alerted": 0}

    try:
        current_unread = await gmail_unread_ids(access_token=access_token, transport=transport)
    except Exception as exc:  # noqa: BLE001 — a failed look is not evidence of a read
        logger.info("gmail read-watch skipped for %s: %s", mailbox.id, exc)
        return {"observed": 0, "alerted": 0}

    previous = set(cred.imap_unseen_uids or [])
    current_set = set(current_unread)
    became_read = [gid for gid in previous if gid not in current_set]

    cred.imap_unseen_uids = current_unread[: sensor_rules.MAX_TRACKED_UNSEEN]

    alerted = observed = 0
    for gid in became_read:
        message_id = await gmail_message_id(
            access_token=access_token, gmail_id=gid, transport=transport
        )
        if message_id is None:
            continue  # gone from the mailbox — a delete is not a read
        observed += 1
        verdict = await sensor_rules.evaluate_read(
            session, mailbox=mailbox, message_ref=message_id, owned_domains=owned,
        )
        alerted += int(verdict.alerted)
    return {"observed": observed, "alerted": alerted}


#: Provider message ids this worker has already run through the pipeline, per
#: mailbox, oldest first. A listing still returns them on every sync; this is
#: what keeps them from being downloaded again. In memory on purpose: after a
#: restart the first sync downloads its listing once — what every sync cost.
_SEEN_REFS: dict[UUID, dict[str, None]] = {}

#: Comfortably more than one inbox listing (50) plus one Sent listing (20).
_SEEN_PER_MAILBOX = 500


def _seen(mailbox_id: UUID) -> dict[str, None]:
    return _SEEN_REFS.setdefault(mailbox_id, {})


def _remember(mailbox_id: UUID, ref: str) -> None:
    seen = _seen(mailbox_id)
    seen.pop(ref, None)
    seen[ref] = None
    while len(seen) > _SEEN_PER_MAILBOX:
        del seen[next(iter(seen))]


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

    Every provider read in one sync shares one HTTP connection unless a
    transport is injected.
    """
    if transport is not None:
        return await _sync_oauth_mailbox(
            session, mailbox, transport=transport, write_transport=write_transport
        )
    import httpx

    async with httpx.AsyncClient(timeout=20) as client:
        return await _sync_oauth_mailbox(
            session, mailbox, transport=HttpxTransport(client),
            write_transport=write_transport,
        )


async def _sync_oauth_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    transport,  # noqa: ANN001 — api_fetch.HttpTransport
    write_transport=None,  # noqa: ANN001 — api_enforce.WriteTransport
) -> dict:
    from envelock.db import set_current_tenant
    from envelock.workers.imap_fetch import clear_sync_request

    set_current_tenant(mailbox.tenant_id)  # scope RLS to this mailbox's tenant
    # The push/"Sync now" flag this sync answers. Read before the fetch, so one
    # set while the sync runs is left standing for the next drain.
    requested = mailbox.sync_requested_at
    tok = await current_access_token(session, mailbox.id)
    if tok is None:
        return {"ok": False, "reason": "no usable oauth token", "fetched": 0}
    access_token, provider = tok

    # Which mailbox does this token ACTUALLY read? Delegated OAuth reads /me — the
    # account that consented — which can differ from the address the customer
    # typed. Learn it so the dashboard can warn instead of showing a confident
    # "connected" over the wrong inbox. Best-effort: never fail a sync over it.
    try:
        whoami = gmail_whoami if provider == "google" else graph_whoami
        real = await whoami(access_token=access_token, transport=transport)
        if real:
            mailbox.connected_address = real
    except Exception as exc:  # noqa: BLE001 — identity probe is non-fatal
        logger.info("whoami skipped for mailbox %s: %s", mailbox.id, exc)

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id, mailbox.address)
    settings = get_settings()
    protected = mailbox.mailbox_class == MailboxClass.PROTECTED.value
    source = SourceMechanism.GMAIL_API if provider == "google" else SourceMechanism.GRAPH_API
    # Ids already analysed are listed but not downloaded again.
    known = _seen(mailbox.id)

    try:
        if provider == "google":
            fetched = await gmail_fetch_raw(
                access_token=access_token, transport=transport, known=known
            )
        else:
            # Delegated OAuth token: read as /me, never /users/{address}. The
            # token IS the signed-in user, and /me resolves to their own mailbox
            # whatever label we stored. Passing the label built
            # /users/admin@cyberlex.store, a name Graph does not know when the
            # account's real UPN is different (e.g. the tenant's .onmicrosoft.com
            # address) — a 403 on every poll, so nothing was ever fetched.
            # /users/{upn} is only for app-permission connections, which this
            # delegated connect is not.
            fetched = await graph_fetch_raw(
                access_token=access_token,
                transport=transport,
                known=known,
            )
    except Exception as exc:  # noqa: BLE001 — provider/network errors are non-fatal
        logger.warning("oauth fetch failed for mailbox %s: %s", mailbox.id, exc)
        return {"ok": False, "reason": str(exc), "fetched": 0}

    alerted = quarantined = rewritten = 0
    for item in fetched:
        outcome = await _handle_inbound(
            session, mailbox, item,
            provider=provider, access_token=access_token, source=source,
            owned=owned, recipients=recipients, protected=protected,
            write_transport=write_transport,
        )
        # Only once it went through: a message that failed is retried.
        _remember(mailbox.id, item.ref)
        alerted += outcome["alerted"]
        quarantined += outcome["quarantined"]
        rewritten += outcome["rewritten"]

    quarantined += await _run_requested_quarantines(
        session, mailbox, provider=provider, access_token=access_token,
        transport=write_transport,
    )

    # Silent-access read-watch — Graph via isRead, Gmail via the UNREAD label.
    reads = {"observed": 0, "alerted": 0}
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    rules = {"rules_new": 0, "rules_alerted": 0}
    if cred is not None:
        watch = _watch_reads_gmail if provider == "google" else _watch_reads_graph
        reads = await watch(
            session, mailbox, cred,
            access_token=access_token, owned=owned, transport=transport,
        )
        # Server-side rule watch (C1 external forward / C2 finance-hiding).
        if settings.rule_scan_enabled:
            from envelock.workers.mailbox_rules import watch_rules

            rules = await watch_rules(
                session, mailbox, cred,
                provider=provider, access_token=access_token,
                owned=owned, recipients=recipients, transport=transport,
            )

    # Outbound (Sent folder): A12 reply-stall data + C5 signature watch. Read-only
    # and best-effort — a provider hiccup on sent mail must never fail the sync.
    outbound = {"outbound_ingested": 0, "signature_alert": False}
    if settings.outbound_scan_enabled:
        try:
            fetch_sent = gmail_fetch_outbound if provider == "google" else graph_fetch_outbound
            sent = await fetch_sent(
                access_token=access_token, transport=transport, known=known
            )
            outbound = await process_outbound(
                session, mailbox, sent, source=source, owned=owned, recipients=recipients,
            )
            for item in sent:
                _remember(mailbox.id, item.ref)
        except Exception as exc:  # noqa: BLE001 — sent-mail scan is non-fatal
            logger.info("oauth outbound scan skipped for %s: %s", mailbox.id, exc)

    mailbox.last_sync_at = datetime.now(UTC)
    # Answers the queued push / "Sync now" it started from — not one that
    # arrived while it ran, which the next drain picks up.
    await clear_sync_request(session, mailbox.id, requested)
    await session.commit()
    return {
        "ok": True,
        "fetched": len(fetched),
        "alerted": alerted,
        "quarantined": quarantined,
        "rewritten": rewritten,
        "silent_access_alerts": reads["alerted"],
        "outbound_ingested": outbound["outbound_ingested"],
        "signature_alert": outbound["signature_alert"],
        "rule_alerts": rules["rules_alerted"],
    }


async def _handle_inbound(
    session: AsyncSession,
    mailbox: Mailbox,
    item,  # noqa: ANN001 — api_fetch.FetchedMessage
    *,
    provider: str,
    access_token: str,
    source: SourceMechanism,
    owned: frozenset[str],
    recipients: list,
    protected: bool,
    write_transport=None,  # noqa: ANN001 — api_enforce.WriteTransport
) -> dict:
    """Analyse one inbound message, notify, then enforce. Returns its counts."""
    counts = {"alerted": 0, "quarantined": 0, "rewritten": 0}
    # Our own protected copy — never re-analyse or re-rewrite it.
    if enforce.is_processed(item.raw, mailbox.id):
        return counts
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
        return counts
    common: dict[str, Any] = {
        "provider": provider, "access_token": access_token, "mailbox": mailbox,
        "ref": item.ref,
    }
    if pr.alert_id is None:
        if protected and event.urls and await _write_back(
            session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
            banner_allowed=False, transport=write_transport,
        ):
            counts["rewritten"] += 1
        return counts

    counts["alerted"] += 1
    # Notify first, enforce after — see `imap_fetch.sync_mailbox`: the push
    # must not wait behind the provider round trips of a move or a rewrite.
    await session.commit()
    await deliver_pending(session, alert_id=pr.alert_id)
    # At once: `deliver_pending` holds the rows it claimed until a commit, and a
    # later rollback would hand them back to the scheduler to send again.
    await session.commit()

    settings = get_settings()
    tier = pr.assessment.tier if pr.assessment else None
    if protected and tier is AlertTier.CRITICAL and settings.api_quarantine_enabled:
        if await _quarantine(**common, transport=write_transport):
            counts["quarantined"] += 1
            if pr.message_id is not None:
                stored = await session.get(Message, pr.message_id)
                if stored is not None:
                    stored.quarantined_at = datetime.now(UTC)
        elif await _write_back(
            session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
            banner_allowed=True, transport=write_transport,
        ):
            counts["rewritten"] += 1
    elif protected and await _write_back(
        session, **common, raw=item.raw, event=event, pr=pr, owned=owned,
        banner_allowed=tier is AlertTier.HIGH, transport=write_transport,
    ):
        counts["rewritten"] += 1
    return counts


async def _oauth_mailboxes(session: AsyncSession, *, requested_only: bool = False) -> list[UUID]:
    # A mailbox waiting on a reconnect cannot be read; trying anyway hit the
    # provider's token endpoint every cycle (every 5 s once a push had flagged
    # it). The 30-minute refresh job still retries it and clears the flag.
    query = select(Mailbox).where(
        Mailbox.is_active.is_(True), Mailbox.needs_reconnect.is_not(True)
    )
    if requested_only:
        query = query.where(Mailbox.sync_requested_at.is_not(None))
    rows = (await session.execute(query)).scalars().all()
    candidates = [m for m in rows if any(s in _OAUTH_SOURCES for s in (m.sources or []))]
    # Same poll-side seat-cap enforcement as the IMAP worker: a lapsed unpaid
    # trial (or seats beyond a downgraded plan) must not keep live protection.
    from envelock.workers.imap_fetch import _entitled_only

    return [m.id for m in await _entitled_only(session, candidates)]


#: One sync at a time per mailbox: the fallback poll and the push drain are
#: separate jobs, and both can pick the same mailbox in the same second — two
#: syncs would each analyse, alert on and rewrite the same new message.
_SYNC_LOCKS: dict[UUID, asyncio.Lock] = {}


async def _sync_one(
    mailbox_id: UUID, *, transport=None, write_transport=None  # noqa: ANN001
) -> dict | None:
    """Load and sync one mailbox in its own session: None when it no longer
    exists, `{"crashed": True}` when it failed. Never raises."""
    from envelock.db_rls import system_scope

    lock = _SYNC_LOCKS.setdefault(mailbox_id, asyncio.Lock())
    # `system_scope` is a SYNC context manager. It used to share the `async
    # with` clause with the session, which makes Python demand `__aenter__` on
    # it — so this raised TypeError on the first mailbox of every cycle, and no
    # OAuth (Microsoft 365 / Gmail) mailbox was ever polled. The two have to
    # nest, not share a clause.
    with system_scope("oauth poll: load mailbox"):
        async with lock:
            try:
                async with get_sessionmaker()() as session:
                    mailbox = await session.get(Mailbox, mailbox_id)
                    if mailbox is None:
                        return None
                    return await sync_oauth_mailbox(
                        session, mailbox, transport=transport,
                        write_transport=write_transport,
                    )
            except Exception:  # noqa: BLE001
                logger.exception("oauth fetch: error on mailbox %s", mailbox_id)
                return {"crashed": True}


async def _sync_ids(
    ids: list[UUID], *, transport=None, write_transport=None,  # noqa: ANN001
    budget: str = "oauth-poll",
) -> dict:
    """Sync these mailboxes side by side, at most `oauth_sync_concurrency` at a
    time per `budget`.

    They used to go one at a time, so a push for one mailbox waited behind every
    other flagged mailbox's sync, and the fallback cycle took the sum of them
    all — minutes, not the "60 s" it is configured as, past a dozen mailboxes.
    The push drain has a budget of its own: sharing the poll's, a push flagged
    mid-cycle queued behind every mailbox the poll had lined up."""
    from envelock.workers.imap_fetch import shared_semaphore

    slots = shared_semaphore(budget, get_settings().oauth_sync_concurrency)

    async def _one(mailbox_id: UUID) -> dict | None:
        async with slots:
            return await _sync_one(
                mailbox_id, transport=transport, write_transport=write_transport
            )

    totals = {"mailboxes": 0, "fetched": 0, "alerted": 0, "quarantined": 0,
              "rewritten": 0, "errors": 0}
    for summary in await asyncio.gather(*(_one(m) for m in ids)):
        if summary is None:
            continue
        if summary.get("crashed"):
            totals["errors"] += 1
            continue
        totals["mailboxes"] += 1
        if summary.get("ok"):
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
    return await _sync_ids(
        ids, transport=transport, write_transport=write_transport, budget="oauth-drain"
    )


__all__ = ["drain_requested", "fetch_all_oauth_mailboxes", "sync_oauth_mailbox"]


async def backfill_oauth_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    days: int,
    limit: int | None = None,
    transport=None,  # noqa: ANN001 — api_fetch.HttpTransport
) -> dict:
    """Onboarding backfill (E11) for a Graph mailbox: pull the last ``days`` of
    history and run each message through the pipeline so A9 stylometry and A12
    baselines are warm on day one. Analysis + learning only — historical mail is
    never quarantined (remediable=False). Mirrors imap_fetch.backfill_mailbox for
    the OAuth path, which previously had no backfill at all: a Microsoft 365
    mailbox onboarded with cold baselines and silently stayed that way."""
    from datetime import timedelta

    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)
    if limit is None:
        limit = get_settings().backfill_max_messages

    tok = await current_access_token(session, mailbox.id)
    if tok is None:
        return {"ok": False, "reason": "no usable oauth token", "analysed": 0}
    access_token, provider = tok

    since = datetime.now(UTC) - timedelta(days=days)
    try:
        if provider == "google":
            fetched = await gmail_fetch_history(
                access_token=access_token,
                after_date=since.strftime("%Y/%m/%d"),
                limit=limit,
                transport=transport,
            )
        else:
            fetched = await graph_fetch_history(
                access_token=access_token,
                since_iso=since.strftime("%Y-%m-%dT%H:%M:%SZ"),
                limit=limit,
                transport=transport,
            )
    except Exception as exc:  # noqa: BLE001 — provider/network errors are non-fatal
        logger.warning("oauth backfill fetch failed for mailbox %s: %s", mailbox.id, exc)
        return {"ok": False, "reason": str(exc), "analysed": 0}

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id, mailbox.address)
    analysed = 0
    for item in fetched:
        if enforce.is_processed(item.raw, mailbox.id):
            continue
        event = await parse_message_async(
            item.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=(
                SourceMechanism.GMAIL_API if provider == "google"
                else SourceMechanism.GRAPH_API
            ),
            owned_domains=owned,
            remediable=False,  # never quarantine historical mail
            source_ref=item.ref,
        )
        pr_hist = await analyse_event(
            session, event, tenant_id=mailbox.tenant_id,
            owned_domains=owned, recipients=recipients,
        )
        # Commit per message — see imap_fetch.backfill_mailbox for why one
        # transaction for the whole scan stalled live mail.
        await session.commit()
        # A backfill can surface a live fraud sitting in recent mail — deliver now.
        if pr_hist.alert_id is not None:
            await deliver_pending(session, alert_id=pr_hist.alert_id)
            await session.commit()
        analysed += 1

    mailbox.backfilled_at = datetime.now(UTC)
    await session.commit()
    return {"ok": True, "analysed": analysed, "days": days}
