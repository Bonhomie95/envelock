"""Write-back enforcement (the one idea the product rests on).

The email body is the only UI that renders on every client — Outlook desktop,
Apple Mail, the Gmail app, webmail, a phone on a plane. None of them render a
browser extension, so enforcement is not "warn the user in our app": it is
mutating the delivered message. This module builds that mutated copy:

* every URL is substituted with a click-time redirector link, and
* a flagged message gets a high-contrast warning banner injected at the top of
  the body (inline styles, table layout, no images — Outlook's renderer is not
  a real browser).

Pure functions over bytes: no I/O, no DB. `imap_sync.replace_message` does the
mailbox surgery; the worker decides when.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from dataclasses import dataclass, field
from email import message_from_bytes, policy
from email.message import EmailMessage

logger = logging.getLogger("envelock.enforce")

#: Stamped on every copy we write back. Its presence tells the poller "this is
#: ours" before any parsing happens — the second guard after rfc_message_id
#: dedupe against analysing (or re-rewriting) our own APPENDed copy.
PROCESSED_HEADER = "X-Envelock-Protected"
_STAMP_VERSION = "v2"


def _stamp_key() -> bytes:
    from envelock.config import get_settings

    settings = get_settings()
    secret = settings.secret_key.get_secret_value()
    if secret:
        return secret.encode()
    # Only local development may run keyless. Anywhere else a fixed fallback key
    # would let an attacker forge the protected stamp and opt a phishing mail out
    # of analysis entirely (production and staging refuse to boot without a
    # secret, so this is a belt-and-braces guard, not a reachable path there).
    if settings.env != "development":
        raise RuntimeError("ENVELOCK_SECRET_KEY is required to stamp protected mail")
    return b"envelock-dev-stamp"


def _stamp_for(message_id: str | None) -> str:
    """HMAC of the Message-ID under the server secret.

    The stamp used to be the bare header name, and `is_processed` looked for that
    string anywhere in the first 16KB. Anyone could add `X-Envelock-Protected: v1`
    to a phishing email, or type the phrase in its body, and the poller would skip
    it: no analysis, no alert, no quarantine. A keyed stamp cannot be forged from
    outside, and it is bound to the Message-ID so one stamp cannot be replayed onto
    another message.
    """
    mac = hmac.new(
        _stamp_key(), f"protected:{(message_id or '').strip()}".encode(), hashlib.sha256
    ).hexdigest()[:40]
    return f"{_STAMP_VERSION}; sig={mac}"

_BODY_TAG = re.compile(r"<body\b[^>]*>", re.IGNORECASE)

_STYLES = {
    "critical": ("#b91c1c", "#fef2f2", "DO NOT ACT ON THIS MESSAGE YET"),
    "warning": ("#b45309", "#fffbeb", "Verify before acting"),
    "info": ("#4b5563", "#f3f4f6", "For your awareness"),
}


@dataclass(frozen=True, slots=True)
class Banner:
    severity: str  # critical | warning | info
    title: str
    lines: tuple[str, ...] = field(default_factory=tuple)


def _esc(text: str) -> str:
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )


def banner_html(banner: Banner) -> str:
    border, bg, tagline = _STYLES.get(banner.severity, _STYLES["info"])
    lines = "".join(
        f'<div style="font-size:13px;color:#1f2937;margin-top:6px;">&#8226; {_esc(line)}</div>'
        for line in banner.lines
    )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="margin:0 0 16px 0;border-collapse:collapse;">'
        f'<tr><td style="border:2px solid {border};background:{bg};'
        'padding:12px 16px;font-family:Arial,Helvetica,sans-serif;">'
        f'<div style="font-size:14px;font-weight:bold;color:{border};">'
        f"&#9888; {_esc(banner.title)} &mdash; {tagline}</div>"
        f"{lines}"
        '<div style="font-size:11px;color:#6b7280;margin-top:8px;">'
        "Protected by Envelock &middot; links in this message are re-checked at the "
        "moment you click them.</div>"
        "</td></tr></table>"
    )


def banner_text(banner: Banner) -> str:
    _, _, tagline = _STYLES.get(banner.severity, _STYLES["info"])
    bar = "=" * 64
    body = "\n".join(f"  * {line}" for line in banner.lines)
    parts = [bar, f"  !! {banner.title.upper()} — {tagline}"]
    if body:
        parts.append(body)
    parts.append("  Protected by Envelock. Links are re-checked when clicked.")
    parts.append(bar)
    return "\n".join(parts) + "\n\n"


def _rewrite(text: str, link_map: dict[str, str], redirect_base: str) -> str:
    # Longest URL first: one URL can be a prefix of another, and replacing the
    # short one first would corrupt the long one.
    for url in sorted(link_map, key=len, reverse=True):
        text = text.replace(url, f"{redirect_base}/r/{link_map[url]}")
    return text


def build_protected_copy(
    raw: bytes,
    *,
    link_map: dict[str, str],
    redirect_base: str,
    banner: Banner | None = None,
) -> bytes:
    """The delivered message, with links rewritten and the banner injected.

    Headers (Message-ID, Date, threading) are preserved so the copy keeps its
    thread position and reply/forward keep quoting correctly.
    """
    msg = message_from_bytes(raw, policy=policy.default)

    banner_done_html = False
    banner_done_text = False
    for part in msg.walk():
        if part.get_content_maintype() != "text":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        subtype = part.get_content_subtype()
        if subtype not in ("plain", "html"):
            continue
        try:
            content = part.get_content()
        except Exception as exc:  # noqa: BLE001 — undecodable part: leave it untouched
            # Logged, not silent: a part we cannot decode is a part whose links
            # go unrewritten, and that is worth being able to find later.
            logger.debug("skipping undecodable part %s: %s", subtype, exc)
            continue
        content = _rewrite(content, link_map, redirect_base)
        if banner is not None and subtype == "html" and not banner_done_html:
            injected = banner_html(banner)
            match = _BODY_TAG.search(content)
            if match:
                pos = match.end()
                content = content[:pos] + injected + content[pos:]
            else:
                content = injected + content
            banner_done_html = True
        elif banner is not None and subtype == "plain" and not banner_done_text:
            content = banner_text(banner) + content
            banner_done_text = True
        part.set_content(content, subtype=subtype, charset="utf-8")
        # set_content on a non-multipart re-adds MIME-Version; harmless on the
        # top level, noise on a sub-part.
        if part is not msg:
            del part["MIME-Version"]

    if isinstance(msg, EmailMessage):
        del msg[PROCESSED_HEADER]
        msg[PROCESSED_HEADER] = _stamp_for(msg.get("Message-ID"))
    return msg.as_bytes(policy=policy.SMTP)


def _header_block(raw: bytes) -> bytes:
    head = raw[:65536]
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = head.find(sep)
        if idx != -1:
            return head[: idx + len(sep)]
    return head


def is_processed(raw: bytes) -> bool:
    """True only when this raw message carries a valid stamp from THIS server.

    Headers only (never the body), and the signature must verify against the
    message's own Message-ID. A forged, copied or unsigned stamp reads as "not
    ours", so the message is analysed like any other.
    """
    from email.parser import BytesHeaderParser

    headers = BytesHeaderParser(policy=policy.compat32).parsebytes(_header_block(raw))
    stamps = headers.get_all(PROCESSED_HEADER) or []
    if not stamps:
        return False
    expected = _stamp_for(headers.get("Message-ID"))
    return any(hmac.compare_digest(str(v).strip(), expected) for v in stamps)


__all__ = [
    "PROCESSED_HEADER",
    "Banner",
    "banner_html",
    "banner_text",
    "build_protected_copy",
    "is_processed",
]
