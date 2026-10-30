"""RFC822 → `MailEvent`.

Used by forwarding ingest (Tier 4) and the IMAP broker (Tier 3). Graph and Gmail
map their own payloads onto the same model — that is the point of the normaliser.
"""

from __future__ import annotations

import contextlib
import hashlib
import html as _html
import re
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.header import decode_header, make_header
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
#: An href attribute, quoted or not. Shared with `enforce`, so every link we
#: collect from an attribute is one the rewriter can find again.
HREF_RE = re.compile(r"""\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`=]+))""", re.IGNORECASE)
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


_ANGLE_ADDR = re.compile(r"<\s*([^<>\s@]+@[^<>\s@]+)\s*>")


def _sender(msg: EmailMessage) -> EmailAddress | None:
    """The From address the receiving side authenticated.

    `From: accounts@vendor.example <x@other.example>` is not valid RFC 5322, and
    Python's parser keeps the bare address in front and drops the bracketed one.
    Mail servers and DMARC go by the bracketed address, and a mail client shows the
    front text as the sender's name. Believing the front text made a stranger's
    authenticated mail read as the vendor's own: no display-name alert, and their
    bank details learned as the vendor's. So when the raw header holds exactly one
    bracketed address, that address is the sender and the rest is the name.
    """
    parsed = _address(msg.get("From"))
    raw = next((str(v) for k, v in msg.raw_items() if k.lower() == "from"), "")
    angles = _ANGLE_ADDR.findall(raw)
    if len(angles) != 1:
        return parsed
    address = angles[0].strip().lower()[:_MAX_ADDRESS]
    if parsed is not None and parsed.address == address:
        return parsed
    shown = raw[: raw.find("<")].strip()
    with contextlib.suppress(LookupError, ValueError, UnicodeError):
        shown = str(make_header(decode_header(shown)))
    display = " ".join(shown.strip().strip('"').split())[:_MAX_DISPLAY] or None
    return EmailAddress(address=address, display=display)


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
#: stamps with (Exchange Online writes none). Only these feed `provider_dmarc`,
#: the one result the platform-notice skip believes.
_PROVIDER_STAMP: dict[SourceMechanism, str | None] = {
    SourceMechanism.GMAIL_API: "mx.google.com",
    SourceMechanism.GRAPH_API: None,
}

#: Longest header value we tokenise. The trusted stamp is a few hundred bytes;
#: anything far longer is not one.
_MAX_AUTHRES = 16_384
_RESULT_TOKEN = re.compile(r"[a-z0-9_-]+")
_DOMAIN_TOKEN = re.compile(r"[a-z0-9.-]+")

#: (method, result, properties) for one resinfo clause.
_ResInfo = tuple[str, str, dict[str, str]]


def _authres(value: str) -> tuple[str, list[_ResInfo]]:
    """One Authentication-Results value as (authserv-id, results), per RFC 8601.

    The old parser ran regexes over the raw text, comments and property values
    included, and the receiving host copies sender-chosen text into both. Gmail
    writes `spf=pass (google.com: domain of <envelope sender> designates ...)
    smtp.mailfrom=<envelope sender>` ahead of its real dmarc clause, so an
    envelope sender like `dmarc=pass.header.from=x.example@y.example` read as a
    DMARC pass for x.example on Google's own stamp. Here comments are dropped,
    quoted strings are kept whole (a quoted local part can hold `;`), clauses
    split only on `;` outside both, and `method=result` is read only as the first
    token of a clause. Everything after it is a property and never a result.
    """
    clauses: list[list[str]] = [[]]
    token: list[str] = []
    depth = 0  # comment nesting
    quoted = escaped = False

    def end_token() -> None:
        if token:
            clauses[-1].append("".join(token))
            token.clear()

    for ch in value[:_MAX_AUTHRES]:
        if escaped:  # a quoted-pair is literal text, never syntax
            if not depth:
                token.append(ch)
            escaped = False
        elif ch == "\\" and (quoted or depth):
            escaped = True
        elif depth:
            depth += {"(": 1, ")": -1}.get(ch, 0)
        elif quoted:
            token.append(ch)
            quoted = ch != '"'
        elif ch == '"':
            quoted = True
            token.append(ch)
        elif ch == "(":
            end_token()
            depth = 1
        elif ch == ";":
            end_token()
            clauses.append([])
        elif ch.isspace():
            end_token()
        else:
            token.append(ch)
    end_token()

    authserv = ""
    results: list[_ResInfo] = []
    for index, raw_tokens in enumerate(clauses):
        # CFWS may sit either side of "=" ("dkim = pass"): rejoin it.
        tokens: list[str] = []
        for tok in raw_tokens:
            if tokens and (tok.startswith("=") or tokens[-1].endswith("=")):
                tokens[-1] += tok
            else:
                tokens.append(tok)
        if not tokens:
            continue
        # Exchange Online writes no authserv-id: its first clause is a result.
        if index == 0 and "=" not in tokens[0]:
            authserv = tokens[0].lower()
            continue
        method, _, result = tokens[0].partition("=")
        method, result = method.split("/", 1)[0].lower(), result.lower()
        if not _RESULT_TOKEN.fullmatch(method) or not _RESULT_TOKEN.fullmatch(result):
            continue
        props: dict[str, str] = {}
        for tok in tokens[1:]:
            key, eq, prop = tok.partition("=")
            if eq and key:
                props.setdefault(key.lower(), prop.strip('"'))
        results.append((method, result, props))
    return authserv, results


def _signing_domain(props: dict[str, str]) -> str | None:
    """The DKIM `d=` of one result. Gmail writes `header.i=@domain` and no
    `header.d=`, so on GMAIL_API this was always empty and A10 had no baseline."""
    value = props.get("header.d") or props.get("header.i", "").rpartition("@")[2]
    value = value.lower().strip(".")
    return value if value and value != "none" and _DOMAIN_TOKEN.fullmatch(value) else None


def _parse_auth_results(
    msg: EmailMessage, *, source: SourceMechanism, sender_domain: str
) -> AuthenticationResults:
    """Results from the receiving host's own stamp: the topmost header, only.

    Every value here used to be the first match in ANY Authentication-Results
    header, so a sender's own `Authentication-Results: x; dkim=pass dmarc=pass`
    was believed wherever the host stamped nothing, or stamped no clause for that
    method. A host prepends its stamp above everything the sender wrote, so the
    top header is the only one read and a missing result never falls through to a
    lower header. Gmail's stamp must also carry Google's authserv-id; POP-fetched
    or appended mail has none on top, and then nothing is trusted.

    Remaining limit: an IMAP host that writes no Authentication-Results at all
    leaves the sender's header on top, and it is read as the stamp. Closing that
    needs the host's authserv-id pinned per mailbox, or DKIM verified here.
    """
    headers = msg.get_all("Authentication-Results", [])
    if not headers:
        return AuthenticationResults()
    authserv, results = _authres(str(headers[0]))
    expected = _PROVIDER_STAMP.get(source)
    if expected is not None and authserv != expected:
        return AuthenticationResults()

    def first(method: str) -> _ResInfo | None:
        return next((r for r in results if r[0] == method), None)

    spf = first("spf")
    dkims = [r for r in results if r[0] == "dkim"]
    passing = [r for r in dkims if r[1] == "pass"]
    # A signature counts only if it verified (a broken one can name any d=), and
    # the one aligned with the From domain wins, so a vendor that also carries
    # its mail provider's signature keeps one stable signing domain.
    aligned = [
        r
        for r in passing
        if registrable_domain(_signing_domain(r[2]) or "") == registrable_domain(sender_domain)
    ]
    candidates = aligned or passing
    signer = candidates[0] if candidates else None
    dmarc = first("dmarc")
    dmarc_result = AuthResult.NONE
    if dmarc is not None:
        # A verdict about some other domain says nothing about this sender.
        claimed = dmarc[2].get("header.from")
        if not claimed or registrable_domain(claimed) == registrable_domain(sender_domain):
            dmarc_result = _AUTH_MAP.get(dmarc[1], AuthResult.NONE)

    return AuthenticationResults(
        spf=_AUTH_MAP.get(spf[1], AuthResult.NONE) if spf else AuthResult.NONE,
        dkim=(
            AuthResult.PASS
            if passing
            else _AUTH_MAP.get(dkims[0][1], AuthResult.NONE) if dkims else AuthResult.NONE
        ),
        dmarc=dmarc_result,
        dkim_domain=_signing_domain(signer[2]) if signer else None,
        provider_dmarc=dmarc_result if source in _PROVIDER_STAMP else AuthResult.NONE,
        stamped=True,
    )


def decode_text(part: EmailMessage) -> str:
    """A text part's content, even when its declared charset is bogus.

    `charset="x-nonexistent"` raised LookupError and the part was dropped: no body,
    no URLs, links left unrewritten — while every mail client still showed the
    ASCII underneath. Undecodable bytes become U+FFFD instead.
    """
    try:
        return part.get_content()
    except (LookupError, ValueError):
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""


def _bodies(msg: EmailMessage) -> tuple[str | None, str | None]:
    """Every inline text/plain part, and every text/html part, each joined.

    Taking only the first of each hid an IBAN placed in a second inline part,
    which clients show one after the other.
    """
    if not msg.is_multipart():
        content = decode_text(msg)
        return (None, content) if msg.get_content_subtype() == "html" else (content, None)
    texts: list[str] = []
    htmls: list[str] = []
    for part in msg.walk():
        if part.get_content_maintype() != "text" or part.get_filename():
            continue
        if part.get_content_subtype() == "plain":
            texts.append(decode_text(part))
        elif part.get_content_subtype() == "html":
            htmls.append(decode_text(part))
    return "\n".join(texts) or None, "\n".join(htmls) or None


#: Leading/trailing characters a browser strips from an href (C0 controls, space).
_URL_EDGE = "".join(chr(i) for i in range(33))


def normalise_href(value: str) -> str | None:
    """The http(s) URL a browser opens for this raw href value, or None.

    The URL pattern only ever saw links spelled literally. A browser decodes
    entities (`&#104;ttps://`), drops tabs and newlines anywhere, reads `\\` as
    `/`, accepts `https:host` without slashes and resolves `//host` to https, so
    each of those spellings reached a working phishing page that B1, the
    reputation feeds and the click-time redirector never saw.
    """
    url = _html.unescape(value).strip(_URL_EDGE)
    url = re.sub(r"[\t\n\r]", "", url)
    if url[:2] in ("//", "\\\\", "/\\", "\\/"):
        url = "https:" + url
    match = re.match(r"(https?):[/\\]*", url, re.IGNORECASE)
    if not match:
        return None
    rest = url[match.end() :]
    # A backslash is a slash in the host and path, not in the query or fragment.
    cut = min((i for i in (rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
    rest = rest[:cut].replace("\\", "/") + rest[cut:]
    if not rest or rest.startswith("/"):
        return None
    return f"{match.group(1).lower()}://{rest}"


def href_urls(html: str | None) -> list[str]:
    """Every http(s) href in `html`, as a browser would resolve it."""
    out: list[str] = []
    for match in HREF_RE.finditer(html or ""):
        url = normalise_href(next(g for g in match.groups() if g is not None))
        if url:
            out.append(url)
    return out


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

    sender = _sender(msg) or EmailAddress(address="unknown@invalid")
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
                # The hrefs as a browser resolves them: an entity-encoded or
                # backslashed href never matches the pattern above.
                *href_urls(html),
                *(u for a in attachments for u in a.qr_urls),
            ]
        )
    )[:MAX_URLS_SCANNED]

    from envelock.channels.mail.enforce import is_processed

    try:
        protected_copy = is_processed(raw, mailbox_id)
    except RuntimeError:  # no stamp key (keyless non-dev): then it is not ours
        protected_copy = False

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
        protected_copy=protected_copy,
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
