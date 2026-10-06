"""Live message pull for the OAuth providers (Tier 1: Gmail, Microsoft 365).

The provider adapters normalise a raw RFC822 message into a `MailEvent`
(`GmailProvider.to_event` / `GraphProvider.to_event`); this module is the part
that actually *gets* the bytes from the provider's REST API. Both return raw MIME,
so the same downstream parser handles them.

Network access sits behind an injectable `HttpTransport` (mirroring
`oauth.Transport`) so the fetch + normalisation is unit-tested against a fake and
production uses a real httpx client. Access tokens are passed in by the caller
(decrypted from the stored OAuth credential in the worker process) — this module
never reads or stores them.

Live use needs a real OAuth app registration and a valid access token; the
fetch/normalisation logic here is complete and tested regardless.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import quote
from uuid import UUID

from envelock.channels.mail.parser import parse_message
from envelock.core.enums import SourceMechanism
from envelock.core.events import MailEvent

logger = logging.getLogger("envelock.apifetch")

GMAIL_API = "https://gmail.googleapis.com/gmail/v1"
GRAPH_API = "https://graph.microsoft.com/v1.0"


class HttpTransport(Protocol):
    async def get_json(self, url: str, *, headers: dict) -> dict: ...
    async def get_bytes(self, url: str, *, headers: dict) -> bytes: ...


class HttpxTransport:
    """Default transport — real GETs against the provider API."""

    async def get_json(self, url: str, *, headers: dict) -> dict:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:
        import httpx

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.content


@dataclass(frozen=True, slots=True)
class FetchedMessage:
    """One provider message: its API id (the handle write-back acts on) and the
    raw RFC822 (what the parser and the protected-stamp check read)."""

    ref: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class ReadState:
    """One inbox message's read/unread state, for the silent-access watch.

    `ref` is Graph's message id (the stable snapshot key); `message_id` is the
    RFC 5322 Message-ID the sensor attests against; `is_read` is the current
    read flag."""

    ref: str
    message_id: str | None
    is_read: bool


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def _retry(coro_factory, *, attempts: int = 3, backoff: float = 0.5):  # noqa: ANN001, ANN201
    """Call an async factory with exponential backoff.

    Graph and Gmail throttle aggressively (HTTP 429) and have transient 5xx; a
    single try means a poll cycle drops mail on a blip. Retries any exception,
    backing off `backoff * 2**n`, and re-raises the last error if all attempts
    fail. `backoff=0` disables the delay (tests)."""
    last: Exception | None = None
    for n in range(max(attempts, 1)):
        try:
            return await coro_factory()
        except Exception as exc:  # noqa: BLE001 — provider errors are all retryable here
            last = exc
            if n + 1 < attempts and backoff > 0:
                await asyncio.sleep(backoff * (2**n))
            elif n + 1 < attempts:
                continue
    logger.warning("provider request failed after %d attempts: %s", attempts, last)
    raise last  # type: ignore[misc]


async def gmail_fetch_raw(
    *,
    access_token: str,
    query: str = "in:inbox newer_than:2d",
    limit: int = 50,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Recent INBOX messages as raw RFC822 (`format=raw`). `in:inbox` matters: an
    unfiltered listing also returned sent mail and drafts."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    listing = await _retry(
        lambda: transport.get_json(
            f"{GMAIL_API}/users/me/messages?maxResults={limit}&q={quote(query)}",
            headers=headers,
        ),
        backoff=backoff,
    )
    out: list[FetchedMessage] = []
    for ref in listing.get("messages", []) or []:
        msg_id = ref.get("id")
        if not msg_id:
            continue
        detail = await _retry(
            lambda mid=msg_id: transport.get_json(
                f"{GMAIL_API}/users/me/messages/{mid}?format=raw", headers=headers
            ),
            backoff=backoff,
        )
        raw_b64 = detail.get("raw")
        if raw_b64:
            out.append(
                FetchedMessage(msg_id, base64.urlsafe_b64decode(raw_b64.encode() + b"==="))
            )
    return out


async def gmail_unread_ids(
    *,
    access_token: str,
    limit: int = 500,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[str]:
    """Gmail ids of messages currently UNREAD in the inbox — the silent-access
    snapshot. Read state on Gmail is the UNREAD label, so `is:unread` is the
    whole query; the poller diffs this set between cycles."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    out: list[str] = []
    page = ""
    while len(out) < limit:
        url = (
            f"{GMAIL_API}/users/me/messages?maxResults=500"
            f"&q={quote('in:inbox is:unread')}"
        )
        if page:
            url += f"&pageToken={page}"
        body = await _retry(lambda u=url: transport.get_json(u, headers=headers), backoff=backoff)
        for ref in body.get("messages", []) or []:
            if ref.get("id"):
                out.append(ref["id"])
        page = body.get("nextPageToken") or ""
        if not page:
            break
    return out[:limit]


async def gmail_message_id(
    *,
    access_token: str,
    gmail_id: str,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> str | None:
    """The RFC 5322 Message-ID of one Gmail message, for the C11 attestation
    match. None if the message is gone (a deleted message is not a read) or has
    no such header."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    try:
        detail = await _retry(
            lambda: transport.get_json(
                f"{GMAIL_API}/users/me/messages/{gmail_id}"
                f"?format=metadata&metadataHeaders=Message-ID",
                headers=headers,
            ),
            backoff=backoff,
        )
    except Exception:  # noqa: BLE001 — 404 (deleted) or transient; treat as "no read"
        return None
    for h in (detail.get("payload") or {}).get("headers", []) or []:
        if (h.get("name") or "").lower() == "message-id":
            return h.get("value") or None
    return None


async def gmail_fetch_history(
    *,
    access_token: str,
    after_date: str,
    limit: int,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Inbox messages received on or after ``after_date`` (Gmail YYYY/MM/DD), up
    to ``limit`` — the onboarding backfill over Gmail. Paginates nextPageToken
    and pulls each message's raw MIME (format=raw)."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    q = f"in:inbox after:{after_date}"
    ids: list[str] = []
    page = ""
    while len(ids) < limit:
        url = f"{GMAIL_API}/users/me/messages?maxResults=500&q={quote(q)}"
        if page:
            url += f"&pageToken={page}"
        body = await _retry(lambda u=url: transport.get_json(u, headers=headers), backoff=backoff)
        for ref in body.get("messages", []) or []:
            if ref.get("id"):
                ids.append(ref["id"])
        page = body.get("nextPageToken") or ""
        if not page:
            break
    ids = ids[:limit]

    out: list[FetchedMessage] = []
    for mid in ids:
        detail = await _retry(
            lambda m=mid: transport.get_json(
                f"{GMAIL_API}/users/me/messages/{m}?format=raw", headers=headers
            ),
            backoff=backoff,
        )
        raw_b64 = detail.get("raw")
        if raw_b64:
            out.append(
                FetchedMessage(mid, base64.urlsafe_b64decode(raw_b64.encode() + b"==="))
            )
    return out


async def gmail_whoami(
    *,
    access_token: str,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> str | None:
    """The actual Gmail address this token reads, lower-cased.

    Delegated OAuth reads the signed-in account's own mailbox, so this is the one
    source of truth for *which* mailbox is really connected — not the label the
    customer typed. A mismatch means "connected" is watching the wrong inbox."""
    transport = transport or HttpxTransport()
    body = await _retry(
        lambda: transport.get_json(
            f"{GMAIL_API}/users/me/profile", headers=_bearer(access_token)
        ),
        backoff=backoff,
    )
    addr = body.get("emailAddress")
    return addr.lower() if addr else None


async def graph_whoami(
    *,
    access_token: str,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> str | None:
    """The actual Microsoft 365 address this token reads, lower-cased — `mail` if
    the account has one, else its userPrincipalName. See `gmail_whoami`."""
    transport = transport or HttpxTransport()
    body = await _retry(
        lambda: transport.get_json(
            f"{GRAPH_API}/me?$select=mail,userPrincipalName", headers=_bearer(access_token)
        ),
        backoff=backoff,
    )
    addr = body.get("mail") or body.get("userPrincipalName")
    return addr.lower() if addr else None


async def gmail_fetch_outbound(
    *,
    access_token: str,
    limit: int = 20,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Recent SENT messages as raw RFC822 — the owner's own outbound mail, which
    C5 (signature tampering) and A12 (reply-stall) need and nothing else fetches.
    `in:sent` is the whole query; read-only, never written back to."""
    return await gmail_fetch_raw(
        access_token=access_token, query="in:sent newer_than:2d", limit=limit,
        transport=transport, backoff=backoff,
    )


async def gmail_fetch(
    *,
    access_token: str,
    tenant_id: UUID,
    mailbox_id: UUID,
    owned_domains: frozenset[str],
    query: str = "in:inbox newer_than:2d",
    limit: int = 50,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[MailEvent]:
    """Pull recent inbox messages from Gmail and normalise to MailEvents."""
    fetched = await gmail_fetch_raw(
        access_token=access_token, query=query, limit=limit,
        transport=transport, backoff=backoff,
    )
    return [
        parse_message(
            m.raw,
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            source=SourceMechanism.GMAIL_API,
            owned_domains=owned_domains,
            remediable=True,
            source_ref=m.ref,
        )
        for m in fetched
    ]


async def graph_fetch_raw(
    *,
    access_token: str,
    mailbox_address: str | None = None,
    limit: int = 50,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Recent inbox messages as raw RFC822 via `/$value` — the full MIME, so the
    shared parser gets the same fidelity (URLs, auth results, attachments) as
    IMAP/Gmail, richer than Graph's JSON projection."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    base = f"{GRAPH_API}/users/{mailbox_address}" if mailbox_address else f"{GRAPH_API}/me"
    listing = await _retry(
        lambda: transport.get_json(
            f"{base}/mailFolders/inbox/messages?$top={limit}&$select=id"
            f"&$orderby=receivedDateTime%20desc",
            headers=headers,
        ),
        backoff=backoff,
    )
    out: list[FetchedMessage] = []
    for ref in listing.get("value", []) or []:
        msg_id = ref.get("id")
        if not msg_id:
            continue
        raw = await _retry(
            lambda mid=msg_id: transport.get_bytes(
                f"{base}/messages/{mid}/$value", headers=headers
            ),
            backoff=backoff,
        )
        if raw:
            out.append(FetchedMessage(msg_id, raw))
    return out


async def graph_read_states(
    *,
    access_token: str,
    limit: int = 200,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[ReadState]:
    """Current read/unread state of recent inbox messages, for C11 silent-access.

    One cheap projection call — id, isRead, internetMessageId — on /me (a
    delegated token reads its own mailbox; /users/{label} 403s when the stored
    label is not the account's real UPN). The poller diffs this against the
    previous snapshot to find messages that were read since the last cycle."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    body = await _retry(
        lambda: transport.get_json(
            f"{GRAPH_API}/me/mailFolders/inbox/messages?$top={limit}"
            f"&$select=id,isRead,internetMessageId&$orderby=receivedDateTime%20desc",
            headers=headers,
        ),
        backoff=backoff,
    )
    out: list[ReadState] = []
    for m in body.get("value", []) or []:
        ref = m.get("id")
        if not ref:
            continue
        out.append(
            ReadState(
                ref=ref,
                message_id=(m.get("internetMessageId") or None),
                is_read=bool(m.get("isRead")),
            )
        )
    return out


async def graph_fetch_history(
    *,
    access_token: str,
    since_iso: str,
    limit: int,
    page_size: int = 50,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Inbox messages received on or after ``since_iso``, up to ``limit`` — the
    onboarding backfill (E11) over Graph, so A9/A12 baselines are warm on day one.

    Paginates @odata.nextLink (Graph caps a page), reads /me (delegated token),
    and pulls each message's raw MIME via /$value so the shared parser gets the
    same fidelity as the live fetch."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    from urllib.parse import quote

    url = (
        f"{GRAPH_API}/me/mailFolders/inbox/messages?$top={page_size}&$select=id"
        f"&$orderby=receivedDateTime%20desc"
        f"&$filter=receivedDateTime%20ge%20{quote(since_iso)}"
    )
    ids: list[str] = []
    while url and len(ids) < limit:
        body = await _retry(lambda u=url: transport.get_json(u, headers=headers), backoff=backoff)
        for ref in body.get("value", []) or []:
            if ref.get("id"):
                ids.append(ref["id"])
        url = body.get("@odata.nextLink") or ""
    ids = ids[:limit]

    out: list[FetchedMessage] = []
    for mid in ids:
        raw = await _retry(
            lambda m=mid: transport.get_bytes(
                f"{GRAPH_API}/me/messages/{m}/$value", headers=headers
            ),
            backoff=backoff,
        )
        if raw:
            out.append(FetchedMessage(mid, raw))
    return out


async def graph_fetch_outbound(
    *,
    access_token: str,
    limit: int = 20,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[FetchedMessage]:
    """Recent SENT messages as raw RFC822 via the Sent Items folder on /me — the
    owner's own outbound mail for C5 and A12. Delegated token → /me (a stored
    label that is not the real UPN 403s on /users/{label}); read-only."""
    transport = transport or HttpxTransport()
    headers = _bearer(access_token)
    listing = await _retry(
        lambda: transport.get_json(
            f"{GRAPH_API}/me/mailFolders/sentitems/messages?$top={limit}&$select=id"
            f"&$orderby=sentDateTime%20desc",
            headers=headers,
        ),
        backoff=backoff,
    )
    out: list[FetchedMessage] = []
    for ref in listing.get("value", []) or []:
        msg_id = ref.get("id")
        if not msg_id:
            continue
        raw = await _retry(
            lambda mid=msg_id: transport.get_bytes(
                f"{GRAPH_API}/me/messages/{mid}/$value", headers=headers
            ),
            backoff=backoff,
        )
        if raw:
            out.append(FetchedMessage(msg_id, raw))
    return out


async def graph_fetch(
    *,
    access_token: str,
    tenant_id: UUID,
    mailbox_id: UUID,
    owned_domains: frozenset[str],
    mailbox_address: str | None = None,
    limit: int = 50,
    transport: HttpTransport | None = None,
    backoff: float = 0.5,
) -> list[MailEvent]:
    """Pull recent inbox messages from Microsoft Graph and normalise to MailEvents."""
    fetched = await graph_fetch_raw(
        access_token=access_token, mailbox_address=mailbox_address, limit=limit,
        transport=transport, backoff=backoff,
    )
    return [
        parse_message(
            m.raw,
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            source=SourceMechanism.GRAPH_API,
            owned_domains=owned_domains,
            remediable=True,
            source_ref=m.ref,
        )
        for m in fetched
    ]


__all__ = [
    "FetchedMessage",
    "HttpTransport",
    "HttpxTransport",
    "gmail_fetch",
    "gmail_fetch_history",
    "gmail_fetch_outbound",
    "gmail_message_id",
    "gmail_unread_ids",
    "gmail_fetch_raw",
    "gmail_whoami",
    "graph_fetch",
    "graph_fetch_history",
    "graph_fetch_outbound",
    "graph_fetch_raw",
    "graph_read_states",
    "graph_whoami",
]
