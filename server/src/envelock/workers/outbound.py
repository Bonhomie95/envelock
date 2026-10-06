"""Outbound (sent-mail) ingestion — the data source A12 and C5 were missing.

Both the OAuth worker (Graph/Gmail) and the IMAP worker fetch the owner's Sent
folder and hand the raw messages here. Two things happen:

* **Storage for A12.** Each sent message is parsed as an OUTBOUND event and run
  through the normal pipeline, which stores it as a `Message`. The reply-stall
  sweep (`workers/stall_sweep`) reads those rows; without them A12 had the
  capability (READ_OUTBOUND) but no data, so it could never fire.
* **C5 signature watch.** The newest sent message's signature block is diffed
  against the per-mailbox baseline. New bank identifiers in it mean someone
  changed where this mailbox's future payments go — emitted as a
  SIGNATURE_CHANGED identity event so C5 judges and alerts like anything else.

Detection stays in the detections; this module only *feeds* them.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import enforce
from envelock.channels.mail.parser import parse_message_async
from envelock.core.enums import MailDirection, SourceMechanism
from envelock.models import Mailbox
from envelock.platform.pipeline import analyse_event
from envelock.util.signature import extract_signature, signature_bank_ids

logger = logging.getLogger("envelock.outbound")


async def process_outbound(
    session: AsyncSession,
    mailbox: Mailbox,
    fetched: list,  # noqa: ANN001 — api_fetch.FetchedMessage (ref, raw), newest first
    *,
    source: SourceMechanism,
    owned: frozenset[str],
    recipients: list | None = None,
) -> dict:
    """Analyse and store sent messages, then run the C5 signature watch.

    ``fetched`` is newest-first (both providers order by sent date desc, and the
    IMAP path reverses to match). Returns a small summary for the worker log.
    """
    ingested = 0
    newest_body: str | None = None
    for item in fetched:
        if enforce.is_processed(item.raw):
            continue
        event = await parse_message_async(
            item.raw,
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            source=source,
            owned_domains=owned,
            remediable=False,  # we never rewrite or quarantine the owner's sent mail
            source_ref=item.ref,
        )
        # Defence in depth: the Sent folder should only hold the owner's own mail,
        # but a mis-filed message must not masquerade as outbound and poison A12.
        if event.direction is not MailDirection.OUTBOUND:
            continue
        if newest_body is None and event.body_text:
            newest_body = event.body_text
        pr = await analyse_event(
            session,
            event,
            tenant_id=mailbox.tenant_id,
            owned_domains=owned,
            recipients=recipients or [],
        )
        if not pr.duplicate:
            ingested += 1

    sig_alert = await watch_signature(
        session, mailbox, newest_body, source=source, owned=owned, recipients=recipients
    )
    return {"outbound_ingested": ingested, "signature_alert": sig_alert}


async def watch_signature(
    session: AsyncSession,
    mailbox: Mailbox,
    newest_body: str | None,
    *,
    source: SourceMechanism,
    owned: frozenset[str],
    recipients: list | None = None,
) -> bool:
    """C5: a changed set of bank identifiers in the sent-mail signature.

    First signature ever seen becomes the baseline silently (no baseline = no
    change). After that, a differing set of bank identifiers raises a
    SIGNATURE_CHANGED event for C5 to judge, and the baseline advances to the new
    signature so the same change is not re-alerted on every subsequent sync.
    """
    sig = extract_signature(newest_body)
    if not sig:
        return False

    baseline = mailbox.signature_fingerprint
    if baseline is None:
        mailbox.signature_fingerprint = sig
        return False

    old_ids = signature_bank_ids(baseline)
    new_ids = signature_bank_ids(sig)
    if old_ids == new_ids:
        # Keep the baseline fresh (wording can drift without the bank line
        # changing) but nothing to judge.
        mailbox.signature_fingerprint = sig
        return False

    # The bank details in the signature changed — let C5 decide the tier.
    mailbox.signature_fingerprint = sig
    alerted = await _emit_signature_changed(
        session, mailbox, before=baseline, after=sig,
        source=source, owned=owned, recipients=recipients,
    )
    logger.info(
        "signature change on mailbox %s: %s -> %s (alerted=%s)",
        mailbox.id, sorted(old_ids), sorted(new_ids), alerted,
    )
    return alerted


async def _emit_signature_changed(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    before: str,
    after: str,
    source: SourceMechanism,
    owned: frozenset[str],
    recipients: list | None,
) -> bool:
    from envelock.core.enums import IdentityEventKind
    from envelock.core.events import DeviceContext, IdentityEvent, NetworkContext

    at = datetime.now(UTC)
    event = IdentityEvent(
        tenant_id=mailbox.tenant_id,
        mailbox_id=mailbox.id,
        occurred_at=at,
        ingested_at=at,
        source=source,
        kind=IdentityEventKind.SIGNATURE_CHANGED,
        before=before[:2000],
        after=after[:2000],
        network=NetworkContext(),
        device=DeviceContext(),
    )
    result = await analyse_event(
        session,
        event,
        tenant_id=mailbox.tenant_id,
        owned_domains=owned,
        recipients=recipients or [],
    )
    if result.alert_id is not None:
        from envelock.notify.dispatch import deliver_pending

        await deliver_pending(session, alert_id=result.alert_id)
        return True
    return False


__all__ = ["process_outbound", "watch_signature"]
