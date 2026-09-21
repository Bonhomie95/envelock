"""The live IMAP worker: turn a connected mailbox into actual protection.

This is the piece that was missing. `connect_imap` stores an encrypted password
and marks the mailbox connected; without this worker nothing ever *reads* the
mailbox, so no inbound mail is analysed. Here we:

  1. decrypt the stored credential (only ever in this process),
  2. pull the messages we have not seen (`imap_sync.fetch_new`),
  3. run each through the real detection pipeline (`analyse_event`),
  4. for a Protected mailbox, move a flagged message out of the inbox
     (`imap_sync.quarantine_message`) — the quarantine that is the product,
  5. deliver the queued notifications,
  6. advance the per-mailbox UID cursor so the next poll only sees new mail.

The IMAP client is injectable end to end (`client_factory`) so the whole path is
tested without a live server. Each mailbox is polled in its own DB session and
its own try/except: one unreachable server or one poisoned message never aborts
the rest of the cycle.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import enforce, imap_sync
from envelock.channels.mail.forward_runner import _recipients
from envelock.channels.mail.parser import parse_message_async
from envelock.config import get_settings
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Domain, Mailbox, MailboxCredential, Message
from envelock.notify.dispatch import deliver_pending
from envelock.obs.metrics import observe_poll_cycle, set_worker_up
from envelock.platform import links as link_safety
from envelock.platform.pipeline import PipelineResult, analyse_event
from envelock.security.crypto import CryptoError, SealedSecret, open_secret

logger = logging.getLogger("envelock.imap")

_IMAP_SOURCES = {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}

#: Last poll cycle's outcome, surfaced at GET /status/channels so a stalled or
#: erroring worker is visible in the dashboard rather than only in logs.
_LAST_CYCLE: dict = {
    "ran_at": None,
    "mailboxes": 0,
    "fetched": 0,
    "alerted": 0,
    "quarantined": 0,
    "rewritten": 0,
    "errors": 0,
    #: Seconds the last full poll cycle took. The scale-up signal: when this
    #: approaches imap_poll_worker_seconds the worker can't keep its cadence.
    "duration_seconds": 0.0,
}


def worker_health() -> dict:
    """Health snapshot of the live IMAP worker for the ops status endpoint."""
    return dict(_LAST_CYCLE)


async def _owned_domains(session: AsyncSession, tenant_id: UUID) -> frozenset[str]:
    rows = (
        await session.execute(
            select(Domain.registrable_domain).where(Domain.tenant_id == tenant_id)
        )
    ).all()
    return frozenset(d for (d,) in rows)


def _decrypt_password(cred: MailboxCredential) -> str:
    sealed = SealedSecret(
        ciphertext=cred.ciphertext, wrapped_dek=cred.wrapped_dek, key_id=cred.key_id or ""
    )
    return open_secret(sealed, aad=str(cred.mailbox_id).encode()).decode()


def _imap_secret(cred: MailboxCredential) -> tuple[str | None, str | None]:
    """`(password, access_token)` for this credential.

    A mailbox whose provider has switched password authentication off (Microsoft
    365, and increasingly others) can still be reached over IMAP with SASL
    XOAUTH2 using the OAuth access token we already hold. That is the fallback
    layer: same IMAP code path, different credential.
    """
    if cred.kind == "oauth_token":
        import json

        payload = json.loads(_decrypt_password(cred))
        token = payload.get("access_token")
        return (None, token) if token else (None, None)
    return (_decrypt_password(cred), None)


async def _enforce_copy(
    session: AsyncSession,
    event,  # noqa: ANN001 — core.events.MailEvent
    pr: PipelineResult,
    *,
    raw: bytes,
    uid: int,
    owned: frozenset[str],
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None,
    access_token: str | None,
    client_factory=None,  # noqa: ANN001
    pin_sha256: str | None = None,
    banner_allowed: bool = True,
) -> bool:
    """Write the protected copy back: rewritten links, plus a banner when the
    message was flagged (and the tier warrants one — MEDIUM gets protected
    links without a banner). Returns True only when the swap happened."""
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

    if not mapping and banner is None:
        return False

    new_raw = enforce.build_protected_copy(
        raw, link_map=mapping, redirect_base=settings.redirect_base, banner=banner
    )
    return await asyncio.to_thread(
        imap_sync.replace_message,
        host=host,
        port=port,
        security=security,
        username=username,
        password=password,
        access_token=access_token,
        uid=uid,
        raw=new_raw,
        client_factory=client_factory,
        pin_sha256=pin_sha256,
    )


async def quarantine_persisted_message(
    session: AsyncSession,
    message: Message,
    *,
    client_factory=None,  # noqa: ANN001 — imap_sync.ClientFactory, injected in tests
) -> tuple[bool, str]:
    """Quarantine an already-delivered message by its stored provider handle.

    This is what makes the dashboard's QUARANTINE button real: the pipeline now
    persists `Message.source_ref` (the IMAP UID), so a human decision hours after
    delivery can still name the exact message to move. Returns (ok, reason);
    on success stamps `quarantined_at` (the caller commits and audits).
    """
    mailbox = await session.get(Mailbox, message.mailbox_id)
    if mailbox is None:
        return False, "mailbox no longer exists"
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if cred is None or not cred.imap_host:
        return False, "this mailbox is not IMAP-connected"
    try:
        uid = int(message.source_ref or "")
    except ValueError:
        return False, "no provider handle stored for this message"
    try:
        password, access_token = _imap_secret(cred)
    except CryptoError:
        return False, "the stored credential can no longer be decrypted — reconnect the mailbox"
    if password is None and access_token is None:
        return False, "no usable credential on file — reconnect the mailbox"

    moved = await asyncio.to_thread(
        imap_sync.quarantine_message,
        host=cred.imap_host,
        port=cred.imap_port or 993,
        security=cred.imap_security or "ssl",
        username=(cred.imap_username or mailbox.address).strip(),
        password=password,
        access_token=access_token,
        uid=uid,
        client_factory=client_factory,
        pin_sha256=cred.imap_cert_sha256,
    )
    if not moved:
        return False, "the mail server refused to move the message"
    message.quarantined_at = datetime.now(UTC)
    message.quarantine_requested_at = None
    return True, "quarantined"


async def _run_requested_quarantines(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    client_factory=None,  # noqa: ANN001
) -> int:
    """Execute human-requested quarantines recorded while no process could act
    (the API seals but cannot decrypt under split custody). DB is the queue."""
    from envelock.platform.alerts import AuditAction, record_audit

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
        ok, why = await quarantine_persisted_message(
            session, pm, client_factory=client_factory
        )
        if ok:
            done += 1
            await record_audit(
                session,
                tenant_id=mailbox.tenant_id,
                action=AuditAction.MESSAGE_QUARANTINED,
                target_type="message",
                target_id=pm.id,
                detail={"requested_by_user": True},
            )
        else:
            logger.warning(
                "imap: requested quarantine failed for message %s: %s", pm.id, why
            )
    return done


async def sync_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    client_factory=None,  # noqa: ANN001 — imap_sync.ClientFactory, injected in tests
) -> dict:
    """Poll one mailbox once and analyse every new message. Commits on success."""
    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)  # scope RLS to this mailbox's tenant
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if cred is None or cred.kind not in ("imap_password", "oauth_token") or not cred.imap_host:
        return {"ok": False, "reason": "no imap credential", "fetched": 0}

    try:
        password, access_token = _imap_secret(cred)
        if password is None and access_token is None:
            return {
                "ok": False,
                "reason": "no usable IMAP credential on file — reconnect this mailbox",
                "needs_reconnect": True,
                "fetched": 0,
            }
    except CryptoError:
        logger.warning("imap: could not decrypt credential for mailbox %s", mailbox.id)
        # The credential is dead (master key rotated, or ciphertext tampered). Flag
        # the mailbox so the UI prompts a reconnect instead of showing a healthy
        # "connected" state that silently protects nothing.
        mailbox.needs_reconnect = True
        mailbox.connection_error = (
            "stored password can no longer be decrypted — please reconnect this mailbox"
        )
        await session.commit()
        return {
            "ok": False,
            "reason": "credential could not be decrypted — reconnect required",
            "needs_reconnect": True,
            "fetched": 0,
        }

    host = cred.imap_host
    port = cred.imap_port or 993
    security = cred.imap_security or "ssl"
    username = (cred.imap_username or mailbox.address).strip()
    # The certificate this mailbox's owner approved, if any. Without carrying it
    # here the mailbox would connect once and then fail every poll — looking
    # protected while ingesting nothing, which is the worst of both.
    pin = cred.imap_cert_sha256
    protected = mailbox.mailbox_class == MailboxClass.PROTECTED.value

    result = await asyncio.to_thread(
        imap_sync.fetch_new,
        host=host,
        port=port,
        security=security,
        username=username,
        password=password,
        access_token=access_token,
        since_uid=cred.imap_last_uid,
        uidvalidity=cred.imap_uidvalidity,
        limit=imap_sync.DEFAULT_LIMIT,
        client_factory=client_factory,
        pin_sha256=pin,
    )
    cred.imap_last_polled_at = datetime.now(UTC)

    if not result.ok:
        logger.warning("imap: poll failed for mailbox %s — %s", mailbox.id, result.error)
        mailbox.connection_error = result.error
        if result.auth_failed:
            # The server rejected the password — reconnect needed, not transient.
            mailbox.needs_reconnect = True
            mailbox.connection_error = (
                "the mail server rejected the stored password — please reconnect"
            )
        await session.commit()
        return {
            "ok": False,
            "reason": result.error,
            "needs_reconnect": result.auth_failed,
            "fetched": 0,
        }

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)
    settings = get_settings()

    alerts: list[dict] = []
    quarantined = 0
    rewritten = 0
    for msg in result.messages:
        # A copy we already wrote back (banner/rewritten links). Never re-analyse
        # or re-rewrite our own work — that way lies an APPEND loop.
        if enforce.is_processed(msg.raw):
            continue
        event = await parse_message_async(
            msg.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE if protected else SourceMechanism.IMAP_POLL,
            owned_domains=owned,
            remediable=protected,  # only an IDLE/Protected mailbox can quarantine
            source_ref=str(msg.uid),
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
        if pr.alert_id is not None:
            alerts.append(
                {
                    "uid": msg.uid,
                    "alert_id": str(pr.alert_id),
                    "tier": pr.assessment.tier.value if pr.assessment else None,
                    "title": pr.assessment.title if pr.assessment else None,
                }
            )
            # What we do to the message itself is decided by tier, because the
            # tiers are *defined* by required action (PRD §8):
            #
            #   Critical → money or access at risk now. Auto-quarantine.
            #   High     → probable attack. Flag it in place, do not move it.
            #   Medium   → suspicious, needs a human glance. Leave it alone.
            #   Low      → logged for context only.
            #
            # This used to quarantine on *any* alert, which pulled Medium
            # findings out of the inbox — and Medium's own example in the PRD is
            # "first contact discussing payment", i.e. every new supplier a
            # company ever emails. Quarantining those trains people to distrust
            # the product, and the calibration rule (P5) exists precisely
            # because an alert nobody believes protects nobody.
            tier = pr.assessment.tier if pr.assessment else None
            if protected and tier is AlertTier.CRITICAL:
                moved = await asyncio.to_thread(
                    imap_sync.quarantine_message,
                    host=host,
                    port=port,
                    security=security,
                    username=username,
                    password=password,
                    access_token=access_token,
                    uid=msg.uid,
                    client_factory=client_factory,
                    pin_sha256=pin,
                )
                if moved:
                    quarantined += 1
                    if pr.message_id is not None:
                        stored = await session.get(Message, pr.message_id)
                        if stored is not None:
                            stored.quarantined_at = datetime.now(UTC)
                # Quarantine failed (folder rights, server quirk): fall back to
                # the protected copy so the flagged message never sits in the
                # inbox looking legitimate. Banner and link rewrite are gated
                # INSIDE by their own flags — gating the whole call on
                # banner_enabled used to switch off link rewriting for the most
                # dangerous mail whenever banners alone were disabled.
                elif await _enforce_copy(
                    session, event, pr,
                    raw=msg.raw, uid=msg.uid, owned=owned,
                    host=host, port=port, security=security,
                    username=username, password=password,
                    access_token=access_token, client_factory=client_factory,
                    pin_sha256=pin,
                ):
                    rewritten += 1
            elif protected:
                # HIGH — "flagged in place": banner + rewritten links.
                # MEDIUM/LOW — protected links WITHOUT a banner: the rewrite
                # branch used to be an elif on the no-alert case, so the one
                # message we'd just flagged as suspicious was the only
                # protected mail keeping its raw links — feature 1 switched
                # off exactly where it mattered most.
                if await _enforce_copy(
                    session, event, pr,
                    raw=msg.raw, uid=msg.uid, owned=owned,
                    host=host, port=port, security=security,
                    username=username, password=password,
                    access_token=access_token, client_factory=client_factory,
                    pin_sha256=pin,
                    banner_allowed=tier is AlertTier.HIGH,
                ):
                    rewritten += 1
            # Fire the notifications this alert queued.
            await deliver_pending(session, alert_id=pr.alert_id)
        elif protected and settings.link_rewrite_enabled and event.urls:
            # Feature 1's core: mail that looks clean NOW is exactly the mail
            # whose links get weaponised later, so its links are rewritten to
            # go through the click-time redirector.
            if await _enforce_copy(
                session, event, pr,
                raw=msg.raw, uid=msg.uid, owned=owned,
                host=host, port=port, security=security,
                username=username, password=password,
                access_token=access_token, client_factory=client_factory,
                        pin_sha256=pin,
            ):
                rewritten += 1

    # A human pressed QUARANTINE while no process could act on it — do it now,
    # while we hold a decrypted credential anyway.
    quarantined += await _run_requested_quarantines(
        session, mailbox, client_factory=client_factory
    )

    # C11 — was anything read since the last poll, and was the owner here?
    # After enforcement on purpose: quarantine and rewrite move and re-append
    # messages, and a UID that vanished because *we* moved it must not read as
    # a message someone opened. Only for mailboxes whose owner has armed the
    # detection and that have a sensor to vouch for them — without a sensor
    # every read is unvouched, and without arming a phone read is an "intruder".
    reads = await _watch_reads(
        session, mailbox, cred,
        host=host, port=port, security=security, username=username,
        password=password, access_token=access_token,
        client_factory=client_factory, pin_sha256=pin, owned=owned,
    )

    if result.uidvalidity is not None:
        cred.imap_uidvalidity = result.uidvalidity
    if result.highest_uid is not None:
        cred.imap_last_uid = result.highest_uid
    mailbox.last_sync_at = datetime.now(UTC)
    # This poll answers any "Sync now" the API could not carry out itself.
    mailbox.sync_requested_at = None
    # A successful poll clears any prior connection problem.
    if mailbox.needs_reconnect:
        mailbox.needs_reconnect = False
        mailbox.connection_error = None

    await session.commit()
    return {
        "ok": True,
        "fetched": len(result.messages),
        "alerted": len(alerts),
        "quarantined": quarantined,
        "rewritten": rewritten,
        "alerts": alerts,
        "reads_observed": reads["observed"],
        "silent_access_alerts": reads["alerted"],
    }


async def _watch_reads(
    session: AsyncSession,
    mailbox: Mailbox,
    cred: MailboxCredential,
    *,
    owned: frozenset[str],
    client_factory=None,  # noqa: ANN001
    **conn,  # noqa: ANN003 — host/port/security/username/password/access_token/pin
) -> dict:
    """Run the read-watch for one mailbox and C11 on every read it finds."""
    from envelock.platform import sensor as sensor_rules

    armed = bool(mailbox.silent_access_armed) and await sensor_rules.has_enrolled_sensor(
        session, mailbox_id=mailbox.id
    )
    if not armed:
        # Do not keep a stale snapshot: re-arming later must start from a fresh
        # baseline, not report every read since it was switched off.
        cred.imap_unseen_uids = None
        return {"observed": 0, "alerted": 0}

    pin = conn.pop("pin_sha256", None)
    watch = await asyncio.to_thread(
        imap_sync.watch_reads,
        previous_unseen=cred.imap_unseen_uids,
        previous_uidvalidity=cred.imap_uidvalidity,
        max_tracked=sensor_rules.MAX_TRACKED_UNSEEN,
        client_factory=client_factory,
        pin_sha256=pin,
        **conn,
    )
    if not watch.ok:
        # A failed look is not evidence of anything. Keep the old baseline so the
        # next successful poll still catches what happened in between.
        logger.info("imap: read-watch skipped for %s — %s", mailbox.id, watch.error)
        return {"observed": 0, "alerted": 0}

    cred.imap_unseen_uids = watch.unseen
    alerted = 0
    for read in watch.became_read:
        verdict = await sensor_rules.evaluate_read(
            session,
            mailbox=mailbox,
            message_ref=read.message_id or f"uid:{read.uid}",
            owned_domains=owned,
        )
        alerted += int(verdict.alerted)
    return {"observed": len(watch.became_read), "alerted": alerted}


async def backfill_mailbox(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    days: int,
    limit: int | None = None,
    client_factory=None,  # noqa: ANN001
) -> dict:
    """Onboarding backfill (E11): pull the last ``days`` of history and run each
    message through the pipeline so A9 stylometry and A12 baselines work on day one,
    not day ninety. Analysis + learning only — old mail is never quarantined.

    ``days`` is the look-back window and ``limit`` the message ceiling (defaults to
    ENVELOCK_BACKFILL_MAX_MESSAGES) — a large ``days`` scans effectively all history."""
    from datetime import timedelta

    from envelock.config import get_settings

    if limit is None:
        limit = get_settings().backfill_max_messages

    from envelock.channels.mail.parser import parse_message_async

    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if cred is None or cred.kind not in ("imap_password", "oauth_token") or not cred.imap_host:
        return {"ok": False, "reason": "no imap credential", "analysed": 0}

    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)
    try:
        password, access_token = _imap_secret(cred)
    except CryptoError:
        return {"ok": False, "reason": "credential could not be decrypted", "analysed": 0}

    since_date = (datetime.now(UTC) - timedelta(days=days)).date()
    result = await asyncio.to_thread(
        imap_sync.fetch_since,
        host=cred.imap_host,
        port=cred.imap_port or 993,
        security=cred.imap_security or "ssl",
        username=(cred.imap_username or mailbox.address).strip(),
        password=password,
        access_token=access_token,
        pin_sha256=cred.imap_cert_sha256,
        since_date=since_date,
        limit=limit,
        client_factory=client_factory,
    )
    if not result.ok:
        return {"ok": False, "reason": result.error, "analysed": 0}

    owned = await _owned_domains(session, mailbox.tenant_id)
    recipients = await _recipients(session, mailbox.tenant_id)
    analysed = 0
    for msg in result.messages:
        event = await parse_message_async(
            msg.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_POLL,
            owned_domains=owned,
            remediable=False,  # never quarantine historical mail
            source_ref=str(msg.uid),
        )
        pr_hist = await analyse_event(
            session, event, tenant_id=mailbox.tenant_id,
            owned_domains=owned, recipients=recipients,
        )
        # A backfill can surface a live fraud sitting in last week's mail —
        # deliver its notifications now, not on the next escalation sweep.
        if pr_hist.alert_id is not None:
            await deliver_pending(session, alert_id=pr_hist.alert_id)
        analysed += 1

    mailbox.backfilled_at = datetime.now(UTC)
    await session.commit()
    return {"ok": True, "analysed": analysed, "days": days}


async def _imap_hosts(session: AsyncSession, mailbox_ids: list[UUID]) -> dict[UUID, str]:
    """Each mailbox's IMAP server, lower-cased — the key for the per-server cap."""
    if not mailbox_ids:
        return {}
    rows = await session.execute(
        select(MailboxCredential.mailbox_id, MailboxCredential.imap_host).where(
            MailboxCredential.mailbox_id.in_(mailbox_ids)
        )
    )
    return {mid: (host or "").strip().lower() for mid, host in rows.all()}


async def _imap_mailboxes(session: AsyncSession) -> list[Mailbox]:
    """Every active mailbox that has an IMAP source, a stored credential, AND a
    tenant still entitled to protect it. The entitlement filter is the poll-side
    half of the seat cap: without it a lapsed unpaid trial (or seats beyond a
    downgraded plan) would keep full live protection forever, free."""
    rows = (
        (
            await session.execute(
                select(Mailbox)
                .join(MailboxCredential, MailboxCredential.mailbox_id == Mailbox.id)
                .where(
                    Mailbox.is_active.is_(True),
                    MailboxCredential.kind.in_(("imap_password", "oauth_token")),
                    MailboxCredential.imap_host.is_not(None),
                )
            )
        )
        .scalars()
        .all()
    )
    candidates = [m for m in rows if any(s in _IMAP_SOURCES for s in (m.sources or []))]
    return await _entitled_only(session, candidates)


async def _entitled_only(
    session: AsyncSession, candidates: list[Mailbox]
) -> list[Mailbox]:
    """Keep only mailboxes whose tenant may protect them right now (plan seats)."""
    from collections import defaultdict

    from envelock.billing.entitlement import entitled_mailboxes
    from envelock.models import Tenant

    by_tenant: dict = defaultdict(list)
    for m in candidates:
        by_tenant[m.tenant_id].append(m)

    kept: list[Mailbox] = []
    for tenant_id, group in by_tenant.items():
        tenant = await session.get(Tenant, tenant_id)
        if tenant is None:
            continue
        allowed = entitled_mailboxes(tenant, group)
        skipped = len(group) - len(allowed)
        if skipped:
            logger.info(
                "poll: tenant %s not entitled to %d connected mailbox(es) "
                "(lapsed trial or over plan capacity) — skipping them",
                tenant_id, skipped,
            )
        kept.extend(allowed)
    return kept


#: History scans queued by an API that could not decrypt, running in this
#: (worker) process. Keyed by mailbox so one is never started twice.
_RUNNING_BACKFILLS: dict = {}

#: A scan is minutes of IMAP and analysis. Two at a time keeps the worker
#: responsive for the live polls that actually protect people.
MAX_CONCURRENT_BACKFILLS = 2


async def start_requested_backfills(*, client_factory=None) -> list[asyncio.Task]:  # noqa: ANN001
    """Start any history scans the API queued, and return their tasks.

    Detached rather than awaited: a scan takes minutes, and awaiting it inside
    the poll cycle would stall the live polling of every other mailbox for that
    long. Each request is claimed with a conditional UPDATE, so it runs exactly
    once however many replicas look at it.
    """
    from sqlalchemy import update

    from envelock.db_rls import system_scope

    for done in [k for k, t in _RUNNING_BACKFILLS.items() if t.done()]:
        _RUNNING_BACKFILLS.pop(done, None)
    free = MAX_CONCURRENT_BACKFILLS - len(_RUNNING_BACKFILLS)
    if free <= 0:
        return []

    sessionmaker = get_sessionmaker()
    claimed: list[tuple] = []
    with system_scope("imap backfill: claim queued scans"):
        async with sessionmaker() as session:
            pending = (
                await session.execute(
                    select(Mailbox.id)
                    .where(Mailbox.backfill_requested_at.is_not(None))
                    .order_by(Mailbox.backfill_requested_at)
                    .limit(free)
                )
            ).scalars().all()
            for mailbox_id in pending:
                if mailbox_id in _RUNNING_BACKFILLS:
                    continue
                started = datetime.now(UTC)
                days = (
                    await session.execute(
                        update(Mailbox)
                        .where(
                            Mailbox.id == mailbox_id,
                            Mailbox.backfill_requested_at.is_not(None),
                        )
                        .values(
                            backfill_requested_at=None,
                            backfill_state={
                                "status": "running",
                                "started_at": started.isoformat(),
                            },
                        )
                        .returning(Mailbox.backfill_requested_days)
                    )
                ).scalar_one_or_none()
                if days is not None:
                    claimed.append((mailbox_id, int(days)))
            await session.commit()

    tasks: list[asyncio.Task] = []
    for mailbox_id, days in claimed:
        task = asyncio.create_task(
            _run_queued_backfill(mailbox_id, days, client_factory=client_factory)
        )
        _RUNNING_BACKFILLS[mailbox_id] = task
        tasks.append(task)
    return tasks


async def _run_queued_backfill(mailbox_id, days: int, *, client_factory=None) -> None:  # noqa: ANN001
    """Run one claimed scan and record how it went where the dashboard reads."""
    from envelock.db import set_current_tenant
    from envelock.db_rls import system_scope

    sessionmaker = get_sessionmaker()
    # A task started by the poll loop carries no tenant; see `_poll` in
    # `run_imap_poll_cycle` for why the load needs system scope.
    with system_scope("imap backfill: run a queued scan"):
        async with sessionmaker() as session:
            mailbox = await session.get(Mailbox, mailbox_id)
            if mailbox is None:
                return
            set_current_tenant(mailbox.tenant_id)
            try:
                outcome = await backfill_mailbox(
                    session, mailbox, days=days, client_factory=client_factory
                )
            except Exception as exc:  # noqa: BLE001 — record it; never kill the worker
                logger.exception("imap: queued backfill failed for mailbox %s", mailbox_id)
                outcome = {"ok": False, "reason": f"{type(exc).__name__}: {exc}"[:200]}
                await session.rollback()
                mailbox = await session.get(Mailbox, mailbox_id)
                if mailbox is None:
                    return
            mailbox.backfill_state = {
                "status": "done" if outcome.get("ok") else "failed",
                "days": days,
                "analysed": outcome.get("analysed", 0),
                "reason": None if outcome.get("ok") else outcome.get("reason"),
                "finished_at": datetime.now(UTC).isoformat(),
            }
            await session.commit()


async def run_imap_poll_cycle(*, client_factory=None) -> dict:  # noqa: ANN001
    """Poll every connected IMAP mailbox once. Each mailbox gets its own session
    so a failure is isolated. Returns an aggregate summary for diagnostics."""
    from time import monotonic

    from envelock.db_rls import system_scope

    started = monotonic()
    sessionmaker = get_sessionmaker()
    # Choosing WHICH mailboxes are due is platform-wide; processing each one is
    # not, and `sync_mailbox` binds that mailbox's tenant before it touches any
    # of its data.
    with system_scope("imap poll: select due mailboxes"):
        async with sessionmaker() as session:
            mailboxes = await _imap_mailboxes(session)
            mailbox_ids = [m.id for m in mailboxes]
            hosts = await _imap_hosts(session, mailbox_ids)

    # Mailboxes are polled side by side. One at a time, a cycle took the SUM of
    # every mail server's round trips — about a second each against a real
    # provider — so past a few dozen mailboxes the 60-second cadence silently
    # became minutes, for everyone. Two limits apply at once: an overall one
    # (each poll holds a database connection and a thread while it waits on the
    # network) and one per mail server, because providers cap simultaneous
    # connections per source IP and answer a burst by refusing all of them.
    settings = get_settings()
    overall = asyncio.Semaphore(max(1, settings.imap_poll_concurrency))
    per_host = max(1, settings.imap_max_connections_per_egress_ip)
    host_gates: dict[str, asyncio.Semaphore] = {}

    async def _poll(mailbox_id: UUID) -> dict | None:
        gate = host_gates.setdefault(hosts.get(mailbox_id, ""), asyncio.Semaphore(per_host))
        # Loading the mailbox happens before anything knows its tenant, so under
        # row-level security it must be done in system scope — unscoped, the
        # load returned None and every cycle skipped every mailbox without a
        # word. Same shape as the OAuth poller. (`system_scope` is sync: it
        # nests around the `async with`, it cannot share its clause.)
        with system_scope("imap poll: load mailbox"):
            async with overall, gate, sessionmaker() as session:
                mailbox = await session.get(Mailbox, mailbox_id)
                if mailbox is None:
                    return None
                try:
                    return await sync_mailbox(session, mailbox, client_factory=client_factory)
                except Exception:  # noqa: BLE001 — never let one mailbox kill the cycle
                    logger.exception("imap: unexpected error polling mailbox %s", mailbox_id)
                    return {"crashed": True}

    totals = {
        "mailboxes": 0, "fetched": 0, "alerted": 0,
        "quarantined": 0, "rewritten": 0, "errors": 0,
    }
    for summary in await asyncio.gather(*(_poll(m) for m in mailbox_ids)):
        if summary is None:
            continue
        if summary.get("crashed"):
            totals["errors"] += 1
            continue
        totals["mailboxes"] += 1
        if summary.get("ok"):
            totals["fetched"] += summary.get("fetched", 0)
            totals["alerted"] += summary.get("alerted", 0)
            totals["quarantined"] += summary.get("quarantined", 0)
            totals["rewritten"] += summary.get("rewritten", 0)
        else:
            totals["errors"] += 1
    _LAST_CYCLE.update(
        totals,
        ran_at=datetime.now(UTC).isoformat(),
        duration_seconds=round(monotonic() - started, 2),
    )
    observe_poll_cycle(
        outcome="ok",
        mailboxes=totals["mailboxes"],
        fetched=totals["fetched"],
        errors=totals["errors"],
        quarantined=totals["quarantined"],
        rewritten=totals["rewritten"],
    )
    # History scans the API queued because it could not decrypt. Started, not
    # awaited — see `start_requested_backfills`.
    try:
        started_scans = await start_requested_backfills(client_factory=client_factory)
        totals["backfills_started"] = len(started_scans)
    except Exception:  # noqa: BLE001 — a scan problem must never stop live polling
        logger.exception("imap: could not start queued backfills")
    # A poller that has stopped is indistinguishable from a set of quiet inboxes
    # unless something records that it *ran*. This gauge is what an alert rule
    # watches: `time() - envelock_worker_last_success_timestamp_seconds > 600`.
    set_worker_up("imap_poller", up=True)
    return totals


async def imap_poll_loop(stop: asyncio.Event, *, interval_seconds: int) -> None:
    """Run `run_imap_poll_cycle` forever, `interval_seconds` apart, until stopped.

    Started from the FastAPI lifespan. A poll interval is a correct, reliable v1
    for both Protected and Monitored mailboxes; true IDLE (sub-second latency for
    Protected) is a latency optimisation layered on top later.
    """
    # Every IMAP call runs on a worker thread (imapclient is blocking), and the
    # default pool is min(32, cores + 4) — eight threads on a 4-core box, shared
    # with parsing and link checks. Sized to the poll concurrency so parallel
    # polls actually run in parallel instead of queueing for a thread.
    from concurrent.futures import ThreadPoolExecutor

    workers = max(32, get_settings().imap_poll_concurrency * 2 + 8)
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=workers, thread_name_prefix="envelock-io")
    )
    logger.info("imap poll loop started (interval=%ss)", interval_seconds)
    while not stop.is_set():
        try:
            totals = await run_imap_poll_cycle()
            if totals["mailboxes"]:
                logger.info("imap poll cycle: %s", totals)
        except Exception:  # noqa: BLE001
            logger.exception("imap: poll cycle crashed; continuing")
            observe_poll_cycle(outcome="crashed")
            set_worker_up("imap_poller", up=False)
        # Sleep the interval, but wake immediately if asked to stop.
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
    logger.info("imap poll loop stopped")


__all__ = ["sync_mailbox", "run_imap_poll_cycle", "imap_poll_loop"]
