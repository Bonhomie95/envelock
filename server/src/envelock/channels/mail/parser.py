"""RFC822 → `MailEvent`.

Used by forwarding ingest (Tier 4) and the IMAP broker (Tier 3). Graph and Gmail
map their own payloads onto the same model — that is the point of the normaliser.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parsedate_to_datetime
from uuid import UUID

from envelock.channels.mail.attachments import extract as extract_attachment
from envelock.core.enums import AuthResult, MailDirection, SourceMechanism
from envelock.core.events import (
    AttachmentRef,
    AuthenticationResults,
    EmailAddress,
    MailEvent,
)
from envelock.util.domains import registrable_domain

_URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_ARCHIVE_EXT = (".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".cab")

_AUTH_MAP = {
    "pass": AuthResult.PASS,
    "fail": AuthResult.FAIL,
    "softfail": AuthResult.SOFTFAIL,
    "neutral": AuthResult.NEUTRAL,
    "none": AuthResult.NONE,
    "temperror": AuthResult.TEMPERROR,
    "permerror": AuthResult.PERMERROR,
}


#: The widest column each header value is stored in (messages, counterparties,
#: sender profiles). Headers are attacker-controlled and unbounded: one value
#: over its column failed the insert, the sync re-fetched that message every
#: cycle, and nothing after it in the mailbox was ever analysed.
_MAX_ADDRESS = 320
_MAX_DISPLAY = 255
_MAX_MESSAGE_ID = 255


def _clip(value: str | None, limit: int = _MAX_MESSAGE_ID) -> str | None:
    return str(value)[:limit] if value else None


def _address(raw: str | None) -> EmailAddress | None:
    if not raw:
        return None
    pairs = getaddresses([raw])
    if not pairs:
        return None
    display, addr = pairs[0]
    if not addr:
        return None
    return EmailAddress(
        address=addr.strip().lower()[:_MAX_ADDRESS],
        display=display.strip()[:_MAX_DISPLAY] or None,
    )


def _addresses(raw: str | None) -> tuple[EmailAddress, ...]:
    if not raw:
        return ()
    out = []
    for display, addr in getaddresses([raw]):
        if addr:
            out.append(
                EmailAddress(
                    address=addr.strip().lower()[:_MAX_ADDRESS],
                    display=display.strip()[:_MAX_DISPLAY] or None,
                )
            )
    return tuple(out)


#: Channels whose mailbox provider stamps its own Authentication-Results on every
#: inbound message, above anything the sender wrote, and the authserv-id it
#: stamps with (Exchange Online writes none). IMAP hosts, forwarding and
#: journaling promise no stamp, and where there is none the sender's header is on top.
_PROVIDER_STAMP: dict[SourceMechanism, str | None] = {
    SourceMechanism.GMAIL_API: "mx.google.com",
    SourceMechanism.GRAPH_API: None,
}


def _provider_dmarc(top: str, *, source: SourceMechanism, sender_domain: str) -> AuthResult:
    """DMARC from the provider's own stamp (the topmost header), or NONE.

    The joined result below takes the first `dmarc=` in ANY header, so a sender
    who writes `Authentication-Results: x; dmarc=pass` is believed wherever the
    host stamps nothing, or stamps no dmarc clause. This reads only the top
    header, only on a channel where the provider always writes it, and only for
    the From domain we parsed.
    """
    if source not in _PROVIDER_STAMP:
        return AuthResult.NONE
    authserv = _PROVIDER_STAMP[source]
    if authserv is not None and top.split(";", 1)[0].strip().lower() != authserv:
        return AuthResult.NONE
    match = re.search(r"\bdmarc=(\w+)[^;]*?\bheader\.from=([\w.-]+)", top, re.IGNORECASE)
    if not match or registrable_domain(match.group(2)) != registrable_domain(sender_domain):
        return AuthResult.NONE
    return _AUTH_MAP.get(match.group(1).lower(), AuthResult.NONE)


def _parse_auth_results(
    msg: EmailMessage, *, source: SourceMechanism, sender_domain: str
) -> AuthenticationResults:
    headers = [str(h) for h in msg.get_all("Authentication-Results", [])]
    header = " ".join(headers)
    if not header:
        return AuthenticationResults()

    def find(mech: str) -> AuthResult:
        match = re.search(rf"\b{mech}=(\w+)", header, re.IGNORECASE)
        return _AUTH_MAP.get(match.group(1).lower(), AuthResult.NONE) if match else AuthResult.NONE

    dkim_domain: str | None = None
    domain_match = re.search(r"header\.d=([A-Za-z0-9.\-]+)", header)
    if domain_match:
        dkim_domain = domain_match.group(1).lower()

    return AuthenticationResults(
        spf=find("spf"),
        dkim=find("dkim"),
        dmarc=find("dmarc"),
        dkim_domain=dkim_domain,
        provider_dmarc=_provider_dmarc(headers[0], source=source, sender_domain=sender_domain),
    )


def _bodies(msg: EmailMessage) -> tuple[str | None, str | None]:
    text = html = None
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_maintype() != "text" or part.get_filename():
                continue
            try:
                content = part.get_content()
            except (LookupError, ValueError):
                continue
            if part.get_content_subtype() == "plain" and text is None:
                text = content
            elif part.get_content_subtype() == "html" and html is None:
                html = content
    else:
        try:
            content = msg.get_content()
        except (LookupError, ValueError):
            content = None
        if msg.get_content_subtype() == "html":
            html = content
        else:
            text = content
    return text, html


def _attachments(msg: EmailMessage) -> tuple[AttachmentRef, ...]:
    from envelock.security.limits import MAX_ATTACHMENTS_SCANNED

    refs: list[AttachmentRef] = []
    if not msg.is_multipart():
        return ()
    for part in msg.walk():
        # The declared bound, finally enforced: a crafted message with thousands
        # of parts otherwise walks every one through pypdf/docx/OCR and pins a
        # worker thread per request — and /analyse is reachable anonymously.
        if len(refs) >= MAX_ATTACHMENTS_SCANNED:
            break
        filename = part.get_filename()
        if not filename:
            continue
        payload = part.get_payload(decode=True) or b""
        name = filename.lower()
        # Pull text (and QR URLs) out of PDF/DOCX/image attachments so A1 sees a
        # changed IBAN inside an attached invoice, and B3 sees a quishing URL. The
        # extracted text is transient — used for this analysis, never persisted.
        content_type = part.get_content_type()
        extracted, qr_urls = extract_attachment(payload, mime=content_type, filename=filename)
        refs.append(
            AttachmentRef(
                filename=filename,
                raw=payload or None,
                # Layer 0 of the cascade is a consequence of the schema: hashing
                # here makes the shared cross-tenant verdict cache automatic.
                sha256=hashlib.sha256(payload).hexdigest(),
                size_bytes=len(payload),
                declared_mime=content_type,
                detected_mime=_sniff(payload),
                is_archive=name.endswith(_ARCHIVE_EXT),
                extracted_text=extracted or None,
                qr_urls=qr_urls,
            )
        )
    return tuple(refs)


def _sniff(payload: bytes) -> str | None:
    """Magic bytes. A mismatch with the declared type is itself a signal (B6)."""
    if payload.startswith(b"%PDF"):
        return "application/pdf"
    if payload.startswith(b"PK\x03\x04"):
        return "application/zip"
    if payload.startswith(b"\xd0\xcf\x11\xe0"):
        return "application/vnd.ms-office"
    if payload.startswith((b"\xff\xd8\xff", b"\x89PNG")):
        return "image"
    if payload.startswith(b"MZ"):
        return "application/x-dosexec"
    if payload[:4] == b"Rar!":
        return "application/x-rar"
    return None


def parse_message(
    raw: bytes,
    *,
    tenant_id: UUID,
    mailbox_id: UUID,
    source: SourceMechanism,
    owned_domains: frozenset[str] = frozenset(),
    remediable: bool = False,
    source_ref: str | None = None,
) -> MailEvent:
    msg: EmailMessage = message_from_bytes(raw, policy=policy.default)  # type: ignore[assignment]

    sender = _address(msg.get("From")) or EmailAddress(address="unknown@invalid")
    text, html = _bodies(msg)

    sent_at: datetime | None = None
    if date_header := msg.get("Date"):
        try:
            sent_at = parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            sent_at = None
        # "-0000" means "zone unknown" and parses naive; compared with the
        # aware timestamps everywhere else, it raised TypeError mid-sync.
        if sent_at is not None and sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=UTC)

    sender_domain = registrable_domain(sender.domain)
    direction = (
        MailDirection.OUTBOUND if sender_domain in owned_domains else MailDirection.INBOUND
    )

    references = tuple(
        r[:_MAX_MESSAGE_ID] for r in (msg.get("References") or "").split()
    )
    attachments = _attachments(msg)
    # URLs from the body AND from attachment text/QR codes: a fake invoice
    # portal link inside an attached PDF is the dominant quishing vector, and
    # collecting from the body alone meant B1/B3 and the click-time redirector
    # never saw it. Bounded by the global URL cap.
    from envelock.security.limits import MAX_URLS_SCANNED

    attachment_text = " ".join(a.extracted_text or "" for a in attachments)
    urls = tuple(
        dict.fromkeys(
            [
                *_URL_RE.findall(f"{text or ''} {html or ''} {attachment_text}"),
                *(u for a in attachments for u in a.qr_urls),
            ]
        )
    )[:MAX_URLS_SCANNED]

    now = datetime.now(UTC)
    return MailEvent(
        tenant_id=tenant_id,
        mailbox_id=mailbox_id,
        occurred_at=sent_at or now,
        ingested_at=now,
        source=source,
        source_ref=source_ref or _clip(msg.get("Message-ID")),
        direction=direction,
        rfc_message_id=_clip(msg.get("Message-ID")),
        in_reply_to=_clip(msg.get("In-Reply-To")),
        references=references,
        sender=sender,
        reply_to=_address(msg.get("Reply-To")),
        return_path=_address(msg.get("Return-Path")),
        recipients_to=_addresses(msg.get("To")),
        recipients_cc=_addresses(msg.get("Cc")),
        subject=msg.get("Subject"),
        sent_at=sent_at,
        body_text=text,
        body_html=html,
        attachments=attachments,
        urls=urls,
        authentication=_parse_auth_results(msg, source=source, sender_domain=sender.domain),
        received_headers=tuple(msg.get_all("Received", [])),
        # Forwarding arrives post-delivery: nothing can be quarantined no matter
        # what we detect (PRD §4 fn.3).
        remediable=remediable
        and source not in (SourceMechanism.FORWARD_INGEST, SourceMechanism.JOURNAL),
    )


async def parse_message_async(raw: bytes, **kwargs) -> MailEvent:  # noqa: ANN003
    """`parse_message` on a worker thread.

    Parsing is not cheap and it is not safe to assume it is bounded: this walks a
    MIME tree from a hostile sender and then hands each attachment to pypdf
    (up to 30 pages), python-docx, Tesseract OCR and a QR decoder. Bodies are
    capped at 25 MB, which is far more work than an event loop should ever do
    inline.

    Called directly from an async handler it blocked the ONE event loop this
    process has — including `/api/v1/analyse`, which takes anonymous callers. A
    handful of crafted messages stalled every customer's dashboard, the IMAP
    poller and the readiness probe at the same time. Every async caller now goes
    through here; the sync function stays for code already running on a thread.
    """
    import asyncio

    return await asyncio.to_thread(lambda: parse_message(raw, **kwargs))
