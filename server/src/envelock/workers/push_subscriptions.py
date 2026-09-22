"""Keep real-time push alive for Gmail and Microsoft Graph mailboxes.

The receivers (api/webhooks.py) only ever hear about new mail if a subscription
exists, and both providers expire theirs: a Graph mail subscription lasts under
three days, a Gmail watch seven. Nothing used to create either, so every
API-connected mailbox ran on the poll alone. This job creates a subscription
for each connected mailbox and renews it once less than a day is left.

Runs in the worker: creating or renewing needs the mailbox's access token,
which only the process holding the decryption key can open.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail import api_enforce
from envelock.channels.mail.oauth_refresh import current_access_token
from envelock.config import get_settings
from envelock.core.enums import SourceMechanism
from envelock.db import get_sessionmaker
from envelock.models import Mailbox

logger = logging.getLogger("envelock.push")

GRAPH_SUBSCRIPTIONS = "https://graph.microsoft.com/v1.0/subscriptions"
GMAIL_WATCH = "https://gmail.googleapis.com/gmail/v1/users/me/watch"
GMAIL_WATCH_ID = "gmail-watch"
#: Graph's ceiling for mail subscriptions is 4,230 minutes (just under 3 days).
GRAPH_LIFETIME = timedelta(minutes=4200)
RENEW_WHEN_UNDER = timedelta(hours=24)
_OAUTH_SOURCES = {SourceMechanism.GRAPH_API.value, SourceMechanism.GMAIL_API.value}


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.0000000Z")


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


async def _graph(
    mailbox: Mailbox, token: str, t: api_enforce.WriteTransport, now: datetime
) -> None:
    settings = get_settings()
    if not settings.ms_webhook_url:
        return
    h = {"Authorization": f"Bearer {token}"}
    expires = now + GRAPH_LIFETIME
    if mailbox.push_subscription_id:
        try:
            body = await t.request(
                "PATCH",
                f"{GRAPH_SUBSCRIPTIONS}/{quote(mailbox.push_subscription_id, safe='')}",
                headers=h,
                json={"expirationDateTime": _iso(expires)},
            )
            mailbox.push_expires_at = _parse(body.get("expirationDateTime")) or expires
            return
        except Exception as exc:  # noqa: BLE001 — gone or expired: create a fresh one
            logger.info("graph subscription %s not renewable (%s); recreating",
                        mailbox.push_subscription_id, exc)
    from envelock.channels.mail.providers import GraphProvider

    payload: dict[str, Any] = GraphProvider().subscription_body(
        mailbox=mailbox.address, tenant_id=mailbox.tenant_id
    )
    # New mail only: "updated" fired on every read/flag/move, including the
    # moves our own quarantine makes.
    payload["changeType"] = "created"
    payload["expirationDateTime"] = _iso(expires)
    body = await t.request("POST", GRAPH_SUBSCRIPTIONS, headers=h, json=payload)
    mailbox.push_subscription_id = body.get("id")
    mailbox.push_expires_at = _parse(body.get("expirationDateTime")) or expires


async def _gmail(
    mailbox: Mailbox, token: str, t: api_enforce.WriteTransport, now: datetime
) -> None:
    settings = get_settings()
    if not settings.google_pubsub_topic:
        return
    body = await t.request(
        "POST",
        GMAIL_WATCH,
        headers={"Authorization": f"Bearer {token}"},
        json={"topicName": settings.google_pubsub_topic, "labelIds": ["INBOX"],
              "labelFilterBehavior": "include"},
    )
    ms = body.get("expiration")
    mailbox.push_subscription_id = GMAIL_WATCH_ID
    mailbox.push_expires_at = (
        datetime.fromtimestamp(int(ms) / 1000, tz=UTC) if ms else now + timedelta(days=7)
    )


async def ensure_push(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    transport: api_enforce.WriteTransport | None = None,
    now: datetime | None = None,
) -> bool:
    """Create or renew this mailbox's subscription if it is missing or due.
    True when one was created or renewed."""
    now = now or datetime.now(UTC)
    if (
        mailbox.push_subscription_id
        and mailbox.push_expires_at
        and mailbox.push_expires_at - now > RENEW_WHEN_UNDER
    ):
        return False
    from envelock.db import set_current_tenant

    set_current_tenant(mailbox.tenant_id)
    tok = await current_access_token(session, mailbox.id)
    if tok is None:
        return False
    token, provider = tok
    t = transport or api_enforce.HttpxWriteTransport()
    before = mailbox.push_expires_at
    try:
        if provider == "google":
            await _gmail(mailbox, token, t, now)
        else:
            await _graph(mailbox, token, t, now)
    except Exception as exc:  # noqa: BLE001 — polling still covers this mailbox
        logger.warning("push subscription failed for mailbox %s: %s", mailbox.id, exc)
        return False
    await session.commit()
    return mailbox.push_expires_at != before


async def ensure_all(*, transport: api_enforce.WriteTransport | None = None) -> dict:
    """One pass over every connected Gmail/Graph mailbox."""
    from envelock.db_rls import system_scope
    from envelock.workers.imap_fetch import _entitled_only

    sessionmaker = get_sessionmaker()
    with system_scope("push: select oauth mailboxes"):
        async with sessionmaker() as session:
            rows = (
                await session.execute(select(Mailbox).where(Mailbox.is_active.is_(True)))
            ).scalars().all()
            candidates = [m for m in rows if _OAUTH_SOURCES & set(m.sources or [])]
            ids = [m.id for m in await _entitled_only(session, candidates)]
    renewed = 0
    for mailbox_id in ids:
        with system_scope("push: ensure subscription"):
            async with sessionmaker() as session:
                mailbox = await session.get(Mailbox, mailbox_id)
                if mailbox is not None and await ensure_push(
                    session, mailbox, transport=transport
                ):
                    renewed += 1
    return {"mailboxes": len(ids), "renewed": renewed}


__all__ = ["ensure_all", "ensure_push"]
