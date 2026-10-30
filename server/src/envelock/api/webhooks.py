"""Tier-1 push receivers (PRD §5, §12.11D — "Protected = real-time").

Microsoft Graph and Gmail can push a notification the instant mail arrives, which
is what makes sub-second quarantine possible instead of waiting for the next poll.
This module is the receiver those providers call:

* **Graph** validates a new subscription by echoing `validationToken`, then POSTs
  a change notification whose `clientState` we signed at subscription time — that
  signature is the authentication, and it names the one mailbox the notification
  is allowed to touch.
* **Gmail** (via Pub/Sub push) POSTs `{message:{data: base64(json)}}` to a URL
  that carries our `?token=`; the token is the authentication and the payload
  names the affected address, which must belong to a mailbox we hold.

Neither endpoint can carry a customer bearer token, so without those two checks
they are unauthenticated cross-tenant triggers: anyone could name a mailbox and
make us sync it, burning the tenant's provider quota and probing which addresses
we hold. The polling fetch job (workers/oauth_fetch) remains the always-correct
fallback, so rejecting a forged or unconfigured push costs latency, never
coverage.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, or_, select

from envelock.auth.deps import SystemScoped
from envelock.db import get_sessionmaker
from envelock.models import Mailbox
from envelock.security.webhook_auth import verify_client_state, verify_push_token

logger = logging.getLogger("envelock.webhooks")

router = APIRouter(
    prefix="/api/v1/webhooks",
    tags=["webhooks"],
    # Provider push notifications arrive unauthenticated and resolve their own
    # tenant from an HMAC-signed clientState / token.
    dependencies=[SystemScoped],
)

#: Graph's validation handshake sends a short opaque token. Cap what we will
#: echo so the endpoint cannot be used as a general-purpose content reflector.
MAX_VALIDATION_TOKEN = 512


async def _fetch_mailbox(
    address: str,
    *,
    tenant_id: UUID | None,
    require_source: str | None = None,
    renew_push: bool = False,
) -> bool:
    """Flag a mailbox for an immediate sync, scoped to the tenant the
    notification was issued for. True when a mailbox matched.

    Flag, don't fetch: this runs in the API, which under split key custody can
    seal but not decrypt the mailbox's access token — fetching here failed on
    every notification in production. The worker drains flagged mailboxes every
    few seconds (`oauth_fetch.drain_requested`). It also answers the provider
    at once: Graph drops notifications to an endpoint slower than ~3 seconds.

    The Gmail push token is one process-wide secret (the URL is registered with
    a single Pub/Sub subscription, so it cannot carry a tenant). To keep that
    single token from being a cross-tenant sync trigger for *any* address we
    hold, the Gmail path also requires the mailbox to actually be configured for
    the named provider source — a forged notification for an IMAP-only mailbox
    matches nothing.

    The flag is stamped afresh on every notification, never only when it is
    empty: a sync clears the stamp it started from, so a notification landing
    while that sync runs must leave a newer one behind — otherwise the message
    it announced waits for the fallback poll.

    `renew_push` (a Graph lifecycle event) also marks the subscription for the
    worker to renew or recreate on its next pass.
    """
    async with get_sessionmaker()() as session:
        query = select(Mailbox).where(Mailbox.is_active.is_(True))
        # Graph subscriptions name the mailbox by id (see push_subscriptions);
        # ones created earlier, and every Gmail notification, by address.
        try:
            query = query.where(Mailbox.id == UUID(address))
        except ValueError:
            wanted = address.strip().lower()
            # Gmail names the account the token reads, which is the mailbox's
            # `connected_address` when that differs from the label it was
            # added under (an alias, a second domain).
            query = query.where(
                or_(
                    Mailbox.address == wanted,
                    func.lower(Mailbox.connected_address) == wanted,
                )
            )
        if tenant_id is not None:
            query = query.where(Mailbox.tenant_id == tenant_id)
        if require_source is not None:
            query = query.where(Mailbox.sources.contains([require_source]))
        mailboxes = (await session.execute(query)).scalars().all()
        if not mailboxes:
            return False
        now = datetime.now(UTC)
        for mailbox in mailboxes:
            mailbox.sync_requested_at = now
            if renew_push:
                mailbox.push_expires_at = None
        await session.commit()
        return True


@router.post("/graph")
@router.get("/graph")
async def graph_notifications(request: Request) -> Response:
    """Microsoft Graph change-notification endpoint."""
    token = request.query_params.get("validationToken")
    if token is not None:
        if len(token) > MAX_VALIDATION_TOKEN:
            return Response(status_code=400)
        return Response(content=token, media_type="text/plain")

    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return Response(status_code=202)

    for note in body.get("value", []) or []:
        verified = verify_client_state(note.get("clientState"))
        if verified is None:
            # Not from a subscription we created — say nothing useful about it.
            logger.warning("graph webhook rejected: clientState did not verify")
            continue
        tenant_id, address = verified
        # Lifecycle events arrive here too (the subscription names this URL for
        # both). `subscriptionRemoved` and `reauthorizationRequired` mean push
        # has stopped or is about to: have the worker renew or recreate it, and
        # sync now for anything already missed. `missed` asks for the sync only.
        lifecycle = note.get("lifecycleEvent")
        if lifecycle:
            logger.info("graph lifecycle event %s for mailbox %s", lifecycle, address)
        try:
            if lifecycle in ("subscriptionRemoved", "reauthorizationRequired"):
                await _fetch_mailbox(address, tenant_id=tenant_id, renew_push=True)
            else:
                await _fetch_mailbox(address, tenant_id=tenant_id)
        except Exception as exc:  # noqa: BLE001 — never fail a provider callback
            logger.warning("graph webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)


@router.post("/gmail")
async def gmail_notifications(request: Request) -> Response:
    """Gmail Pub/Sub push endpoint. The message data base64-encodes
    `{"emailAddress": ..., "historyId": ...}`."""
    if not verify_push_token(request.query_params.get("token")):
        logger.warning("gmail webhook rejected: missing or wrong push token")
        # 202 rather than 401: a Pub/Sub subscription retries on error for days,
        # and we do not want a forged caller to learn whether the token was close.
        return Response(status_code=202)

    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return Response(status_code=202)

    message = body.get("message") or {}
    data_b64 = message.get("data")
    if not data_b64:
        return Response(status_code=202)
    try:
        decoded = json.loads(base64.b64decode(data_b64).decode())
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return Response(status_code=202)

    address = decoded.get("emailAddress")
    if isinstance(address, str) and address:
        from envelock.core.enums import SourceMechanism

        try:
            await _fetch_mailbox(
                address,
                tenant_id=None,
                require_source=SourceMechanism.GMAIL_API.value,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("gmail webhook fetch failed for %s: %s", address, exc)
    return Response(status_code=202)
