"""Write-back for mailboxes connected through the Gmail and Microsoft Graph APIs.

The IMAP path (`imap_sync`) moves a message to quarantine and swaps it for a
protected copy (rewritten links, warning banner). Microsoft 365 no longer
accepts password IMAP and Google Workspace admins can turn app passwords off,
so the same two operations have to exist over the providers' own APIs or those
customers get detection with no enforcement.

* **Quarantine** — Gmail: add an "Envelock Quarantine" label and remove INBOX
  (the message leaves the inbox; nothing is deleted). Graph: move the message to
  an "Envelock Quarantine" mail folder.
* **Protected copy** — Gmail: `messages.insert` the rewritten RFC822 with the
  original's labels and thread, then trash the original (`gmail.modify` cannot
  hard-delete, by design). Graph cannot edit a received message's body, so the
  copy is created as a new NON-draft message (MAPI `PR_MESSAGE_FLAGS`) in the
  same folder with the original's headers, delivery time and file attachments,
  then the original is permanently deleted. Anything the copy cannot carry
  faithfully (item attachments, > ~3 MB of attachments) is left untouched
  rather than degraded.

Network access sits behind an injectable transport so all of this is unit-tested
against fakes of the two APIs; access tokens are passed in by the worker.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Protocol
from urllib.parse import quote

from envelock.channels.mail import enforce

logger = logging.getLogger("envelock.api_enforce")

GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
GRAPH_API = "https://graph.microsoft.com/v1.0"
QUARANTINE_NAME = "Envelock Quarantine"
#: Graph's create-message request tops out around 4 MB; base64 inflates by a
#: third, so file attachments above this are not re-attached — and a copy that
#: silently dropped an attachment would be worse than no copy.
GRAPH_MAX_ATTACHMENT_BYTES = 3 * 1024 * 1024


class ApiError(Exception):
    """A provider API call failed (non-2xx or transport error)."""


class WriteTransport(Protocol):
    async def request(
        self, method: str, url: str, *, headers: dict, json: Any = None
    ) -> Any: ...


class HttpxWriteTransport:
    async def request(self, method: str, url: str, *, headers: dict, json: Any = None) -> Any:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.request(method, url, headers=headers, json=json)
        if resp.status_code >= 400:
            raise ApiError(f"{method} {url.split('?')[0]} → {resp.status_code}: {resp.text[:200]}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {}


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _t(transport: WriteTransport | None) -> WriteTransport:
    return transport or HttpxWriteTransport()


# ── Gmail ────────────────────────────────────────────────────────────────────
async def _gmail_label_id(token: str, transport: WriteTransport) -> str:
    listing = await transport.request("GET", f"{GMAIL_API}/labels", headers=_h(token))
    for label in listing.get("labels", []) or []:
        if label.get("name") == QUARANTINE_NAME:
            return label["id"]
    created = await transport.request(
        "POST",
        f"{GMAIL_API}/labels",
        headers=_h(token),
        json={
            "name": QUARANTINE_NAME,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        },
    )
    return created["id"]


async def gmail_quarantine(
    *, access_token: str, message_id: str, transport: WriteTransport | None = None
) -> bool:
    """Take the message out of the inbox under the quarantine label."""
    t = _t(transport)
    try:
        label = await _gmail_label_id(access_token, t)
        await t.request(
            "POST",
            f"{GMAIL_API}/messages/{quote(message_id, safe='')}/modify",
            headers=_h(access_token),
            json={"addLabelIds": [label], "removeLabelIds": ["INBOX"]},
        )
    except Exception as exc:  # noqa: BLE001 — any provider failure means "not moved"
        logger.warning("gmail quarantine failed for %s: %s", message_id, exc)
        return False
    return True


async def gmail_replace(
    *,
    access_token: str,
    message_id: str,
    new_raw: bytes,
    transport: WriteTransport | None = None,
) -> bool:
    """Insert the protected copy where the original was, then trash the original.

    Insert first: if it fails, the original is still there and nothing is lost.
    """
    t = _t(transport)
    mid = quote(message_id, safe="")
    try:
        original = await t.request(
            "GET", f"{GMAIL_API}/messages/{mid}?format=minimal", headers=_h(access_token)
        )
        labels = [lbl for lbl in original.get("labelIds", []) or [] if lbl != "DRAFT"]
        body: dict[str, Any] = {
            "raw": base64.urlsafe_b64encode(new_raw).decode().rstrip("="),
            "labelIds": labels or ["INBOX"],
        }
        if original.get("threadId"):
            body["threadId"] = original["threadId"]
        await t.request(
            "POST",
            f"{GMAIL_API}/messages?internalDateSource=dateHeader",
            headers=_h(access_token),
            json=body,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("gmail protected-copy insert failed for %s: %s", message_id, exc)
        return False
    try:
        await t.request("POST", f"{GMAIL_API}/messages/{mid}/trash", headers=_h(access_token))
    except Exception as exc:  # noqa: BLE001
        # The copy is in; the original stays visible beside it. Say so loudly —
        # the unprotected original is exactly what this was meant to remove.
        logger.error("gmail: copy inserted but original %s not trashed: %s", message_id, exc)
        return False
    return True


# ── Microsoft Graph ──────────────────────────────────────────────────────────
def graph_base(mailbox_address: str | None) -> str:
    return f"{GRAPH_API}/users/{quote(mailbox_address, safe='@')}" if mailbox_address else (
        f"{GRAPH_API}/me"
    )


async def _graph_folder_id(base: str, token: str, transport: WriteTransport) -> str:
    flt = quote(f"displayName eq '{QUARANTINE_NAME}'", safe="")
    listing = await transport.request(
        "GET", f"{base}/mailFolders?$filter={flt}&$select=id", headers=_h(token)
    )
    found = listing.get("value", []) or []
    if found:
        return found[0]["id"]
    created = await transport.request(
        "POST", f"{base}/mailFolders", headers=_h(token), json={"displayName": QUARANTINE_NAME}
    )
    return created["id"]


async def graph_quarantine(
    *,
    access_token: str,
    message_id: str,
    mailbox_address: str | None = None,
    transport: WriteTransport | None = None,
) -> bool:
    """Move the message into the quarantine folder."""
    t = _t(transport)
    base = graph_base(mailbox_address)
    try:
        folder = await _graph_folder_id(base, access_token, t)
        await t.request(
            "POST",
            f"{base}/messages/{quote(message_id, safe='')}/move",
            headers=_h(access_token),
            json={"destinationId": folder},
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("graph quarantine failed for %s: %s", message_id, exc)
        return False
    return True


_GRAPH_SELECT = (
    "subject,body,from,sender,toRecipients,ccRecipients,replyTo,receivedDateTime,"
    "sentDateTime,importance,isRead,internetMessageId,parentFolderId,hasAttachments,"
    "categories"
)


def _protected_body(body: dict, link_map: dict[str, str], redirect_base: str,
                    banner: enforce.Banner | None) -> dict:
    content = body.get("content") or ""
    kind = (body.get("contentType") or "text").lower()
    content = enforce._rewrite(content, link_map, redirect_base)  # noqa: SLF001 — shared rewrite
    if banner is not None:
        if kind == "html":
            injected = enforce.banner_html(banner)
            match = enforce._BODY_TAG.search(content)  # noqa: SLF001
            content = (
                content[: match.end()] + injected + content[match.end():]
                if match
                else injected + content
            )
        else:
            content = enforce.banner_text(banner) + content
    return {"contentType": "html" if kind == "html" else "text", "content": content}


async def graph_replace(
    *,
    access_token: str,
    message_id: str,
    link_map: dict[str, str],
    redirect_base: str,
    banner: enforce.Banner | None,
    mailbox_address: str | None = None,
    transport: WriteTransport | None = None,
) -> bool:
    """Replace a received message with its protected copy. False (and the
    original untouched) whenever the copy could not be made faithfully."""
    t = _t(transport)
    base = graph_base(mailbox_address)
    mid = quote(message_id, safe="")
    h = _h(access_token)
    try:
        msg = await t.request("GET", f"{base}/messages/{mid}?$select={_GRAPH_SELECT}", headers=h)
        attachments: list[dict] = []
        if msg.get("hasAttachments"):
            listing = await t.request("GET", f"{base}/messages/{mid}/attachments", headers=h)
            total = 0
            for att in listing.get("value", []) or []:
                if att.get("@odata.type") != "#microsoft.graph.fileAttachment":
                    return False  # an attached email/cloud link can't be re-created
                total += int(att.get("size") or 0)
                attachments.append(
                    {
                        "@odata.type": "#microsoft.graph.fileAttachment",
                        "name": att.get("name"),
                        "contentType": att.get("contentType"),
                        "contentBytes": att.get("contentBytes"),
                        "isInline": bool(att.get("isInline")),
                        **({"contentId": att["contentId"]} if att.get("contentId") else {}),
                    }
                )
            if total > GRAPH_MAX_ATTACHMENT_BYTES:
                return False
        internet_id = msg.get("internetMessageId")
        props = [
            # PR_MESSAGE_FLAGS = MSGFLAG_READ, and crucially NOT MSGFLAG_UNSENT:
            # without this Graph creates a draft ("[Draft]" in the inbox).
            {"id": "Integer 0x0E07", "value": "1"},
        ]
        if msg.get("receivedDateTime"):
            props.append({"id": "SystemTime 0x0E06", "value": msg["receivedDateTime"]})
        if msg.get("sentDateTime"):
            props.append({"id": "SystemTime 0x0039", "value": msg["sentDateTime"]})
        copy: dict[str, Any] = {
            "subject": msg.get("subject"),
            "body": _protected_body(msg.get("body") or {}, link_map, redirect_base, banner),
            "from": msg.get("from"),
            "sender": msg.get("sender") or msg.get("from"),
            "toRecipients": msg.get("toRecipients") or [],
            "ccRecipients": msg.get("ccRecipients") or [],
            "replyTo": msg.get("replyTo") or [],
            "importance": msg.get("importance") or "normal",
            "categories": msg.get("categories") or [],
            "internetMessageHeaders": [
                {"name": enforce.PROCESSED_HEADER, "value": enforce._stamp_for(internet_id)}  # noqa: SLF001
            ],
            "singleValueExtendedProperties": props,
        }
        if internet_id:
            copy["internetMessageId"] = internet_id
        if attachments:
            copy["attachments"] = attachments
        folder = msg.get("parentFolderId") or "inbox"
        created = await t.request(
            "POST", f"{base}/mailFolders/{quote(folder, safe='')}/messages", headers=h, json=copy
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("graph protected copy failed for %s: %s", message_id, exc)
        return False

    new_id = created.get("id")
    if new_id and msg.get("isRead") is False:
        try:
            await t.request(
                "PATCH", f"{base}/messages/{quote(new_id, safe='')}", headers=h,
                json={"isRead": False},
            )
        except Exception as exc:  # noqa: BLE001 — cosmetic
            logger.info("graph: could not mark copy unread: %s", exc)
    try:
        await t.request("POST", f"{base}/messages/{mid}/permanentDelete", headers=h)
    except Exception:  # noqa: BLE001
        try:
            await t.request("DELETE", f"{base}/messages/{mid}", headers=h)
        except Exception as exc:  # noqa: BLE001
            logger.error("graph: copy created but original %s not removed: %s", message_id, exc)
            return False
    return True


__all__ = [
    "ApiError",
    "HttpxWriteTransport",
    "QUARANTINE_NAME",
    "WriteTransport",
    "gmail_quarantine",
    "gmail_replace",
    "graph_base",
    "graph_quarantine",
    "graph_replace",
]
