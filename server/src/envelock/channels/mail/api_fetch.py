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
    "gmail_fetch_raw",
    "graph_fetch",
    "graph_fetch_raw",
]
