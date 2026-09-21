"""The click-time redirector (feature 1 — link safety).

Every link in a protected message points here. When the recipient taps it —
from any device, any mail client, anywhere — the original destination is
re-checked *live* and the answer decides what they see:

* clean / unknown → 302 straight through (the product must never be friction),
* suspicious     → interstitial naming the real destination, with a continue,
* malicious      → block page, no bypass.

Unauthenticated by design: the person clicking is reading their mail, not
logged into Envelock. The token is an unguessable 24-byte secret and resolves
to nothing but a redirect, so there is nothing here worth enumerating.

Fail-open is a hard rule: if our own checks throw, the user still reaches the
internet. A link rewriter that breaks all links is worse than no product.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import SystemScoped
from envelock.db import get_session
from envelock.obs.metrics import observe_link_click
from envelock.platform.links import evaluate_url, get_link_token, url_host

logger = logging.getLogger("envelock.redirect")

router = APIRouter(
    tags=["redirect"],
    # /r/{token} is clicked by a recipient with no session; the token itself
    # identifies the tenant.
    dependencies=[SystemScoped],
)
Session = Annotated[AsyncSession, Depends(get_session)]

_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>{title}</title></head>
<body style="margin:0;background:#f6f7f9;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
<div style="max-width:560px;margin:8vh auto;padding:0 16px;">
<div style="background:#fff;border:1px solid #e5e7eb;border-top:6px solid {color};border-radius:8px;padding:28px;">
<div style="font-size:20px;font-weight:700;color:#111827;">{heading}</div>
<div style="font-size:14px;color:#374151;margin-top:12px;line-height:1.6;">{body}</div>
{actions}
<div style="font-size:11px;color:#9ca3af;margin-top:24px;">Envelock checked this link the moment you clicked it.</div>
</div></div></body></html>"""


def _reasons_html(reasons: list[str]) -> str:
    if not reasons:
        return ""
    items = "".join(f"<li>{_esc(r)}</li>" for r in reasons[:5])
    return f'<ul style="margin:8px 0 0 18px;padding:0;">{items}</ul>'


def _esc(text: str) -> str:
    # Quotes too: some of this lands inside HTML attributes.
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


async def _log_click(
    session: AsyncSession, row, request: Request, action: str  # noqa: ANN001
) -> None:
    from datetime import UTC, datetime

    from envelock.models import LinkClick

    # Counted before the write, so a click still registers in the metrics even if
    # the ledger insert fails — the redirect must never depend on either.
    observe_link_click(action)

    try:
        row.click_count = (row.click_count or 0) + 1
        row.last_verdict = action if action in ("blocked", "warned") else row.last_verdict
        row.last_checked_at = datetime.now(UTC)
        session.add(
            LinkClick(
                link_token_id=row.id,
                tenant_id=row.tenant_id,
                ip=(request.client.host if request.client else None),
                user_agent=(request.headers.get("user-agent") or "")[:512] or None,
                action=action,
            )
        )
        await session.commit()
    except Exception:  # noqa: BLE001 — the ledger must never block the redirect
        logger.debug("click log failed", exc_info=True)


@router.get("/r/{token}", response_model=None)
async def click(token: str, request: Request, session: Session, go: int = 0) -> Response:
    row = await get_link_token(session, token)
    if row is None:
        return HTMLResponse(
            _PAGE.format(
                title="Link not recognised",
                color="#6b7280",
                heading="This link is not recognised",
                body=(
                    "Protected links expire a year after the message was "
                    "delivered, and this one is either older than that or was "
                    "not issued by this service. The original message in your "
                    "mailbox is unchanged — ask the sender to resend it if you "
                    "still need the destination."
                ),
                actions="",
            ),
            status_code=404,
        )

    url = row.original_url
    # Belt-and-braces at the moment of the 302: only http(s) ever reaches the
    # Location header. The mail parser already only extracts http(s) URLs, but a
    # redirector must not depend on what its writer happened to store — a future
    # mint path handing us javascript:/data: must fail here, not in the browser.
    from urllib.parse import urlparse

    if urlparse(url).scheme not in ("http", "https"):
        await _log_click(session, row, request, "blocked")
        return HTMLResponse(
            _PAGE.format(
                title="Link blocked",
                color="#b91c1c",
                heading="⚠ Link blocked",
                body="This link does not go to a normal web address, so Envelock will not open it.",
                actions="",
            ),
            status_code=403,
        )
    try:
        verdict, reasons = await evaluate_url(url)
    except Exception:  # noqa: BLE001 — fail open, always
        logger.exception("live check failed for token %s", token)
        verdict, reasons = "unknown", []

    if verdict == "malicious":
        await _log_click(session, row, request, "blocked")
        return HTMLResponse(
            _PAGE.format(
                title="Dangerous link blocked",
                color="#b91c1c",
                heading="⚠ Dangerous link blocked",
                body=(
                    f"The destination <b>{_esc(url_host(url))}</b> is flagged as "
                    "malicious, so Envelock has stopped this visit."
                    + _reasons_html(reasons)
                    + "<div style='margin-top:12px;'>If you believe this is wrong, "
                    "report it to your administrator.</div>"
                ),
                actions="",
            ),
            status_code=403,
        )

    if verdict == "suspicious" and not go:
        await _log_click(session, row, request, "warned")
        continue_url = f"{request.url.path}?go=1"
        return HTMLResponse(
            _PAGE.format(
                title="Check before you continue",
                color="#b45309",
                heading="⚠ Check before you continue",
                body=(
                    "This link has warning signs:"
                    + _reasons_html(reasons)
                    + "<div style='margin-top:12px;'>It goes to "
                    f"<b>{_esc(url_host(url))}</b>. Only continue if you were "
                    "expecting this exact link.</div>"
                ),
                actions=(
                    f'<div style="margin-top:20px;"><a href="{continue_url}" '
                    'style="display:inline-block;background:#b45309;color:#fff;'
                    'text-decoration:none;padding:10px 18px;border-radius:6px;'
                    'font-size:14px;">I understand the risk — continue</a></div>'
                ),
            ),
            status_code=200,
        )

    await _log_click(session, row, request, "allowed")
    return RedirectResponse(url, status_code=302)
