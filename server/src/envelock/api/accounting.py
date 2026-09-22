"""Connecting Xero / QuickBooks Online (integrations/accounting.py).

The API does the part that needs no stored secret — building the consent URL,
exchanging the code, sealing the tokens — and hands the reading to the worker by
flagging the connection for a sync.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import AdminUser, CurrentUser, SystemScoped
from envelock.channels.mail import oauth
from envelock.config import get_settings
from envelock.db import get_session
from envelock.integrations import accounting as acct
from envelock.models import AccountingConnection
from envelock.platform.alerts import record_audit

logger = logging.getLogger("envelock.api.accounting")
router = APIRouter(prefix="/api/v1/accounting", tags=["accounting"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _payload(c: AccountingConnection) -> dict:
    return {
        "provider": c.provider,
        "label": acct.PROVIDERS[c.provider].label if c.provider in acct.PROVIDERS else c.provider,
        "org_name": c.org_name,
        "flag_bills": c.flag_bills,
        "connected_at": c.created_at.isoformat(),
        "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
        "syncing": c.sync_requested_at is not None,
        "last_error": c.last_error,
        "summary": c.last_sync_summary or None,
    }


async def _connection(session: AsyncSession, tenant_id, provider: str):  # noqa: ANN001, ANN202
    return (
        await session.execute(
            select(AccountingConnection).where(
                AccountingConnection.tenant_id == tenant_id,
                AccountingConnection.provider == provider,
            )
        )
    ).scalars().first()


@router.get("")
async def status(principal: CurrentUser, session: Session) -> dict:
    rows = (
        await session.execute(
            select(AccountingConnection).where(
                AccountingConnection.tenant_id == principal.tenant_id
            )
        )
    ).scalars().all()
    return {
        "available": [
            {"provider": p.name, "label": p.label} for p in acct.PROVIDERS.values()
            if p.configured()
        ],
        "connections": [_payload(c) for c in rows],
    }


@router.post("/{provider}/connect")
async def connect(provider: str, principal: AdminUser) -> dict:
    prov = acct.provider(provider)
    if prov is None:
        raise HTTPException(404, "unknown accounting system")
    if not prov.configured():
        raise HTTPException(503, f"{prov.label} isn't set up on this deployment yet.")
    state = oauth.issue_state(
        tenant_id=str(principal.tenant_id), mailbox=str(principal.user_id),
        provider=provider, mode="accounting",
    )
    return {"url": prov.authorize_url(state)}


def _back(result: str) -> RedirectResponse:
    base = get_settings().web_base_url.rstrip("/")
    return RedirectResponse(f"{base}/suppliers?accounting={result}", status_code=302)


@router.get("/{provider}/callback", dependencies=[SystemScoped])
async def callback(
    provider: str,
    session: Session,
    code: str | None = None,
    state: str | None = None,
    realmId: str | None = None,  # noqa: N803 — QuickBooks' own parameter name
    error: str | None = None,
) -> RedirectResponse:
    """The provider's browser redirect. The signed `state` is the authorisation
    (there is no session on this request)."""
    from uuid import UUID

    prov = acct.provider(provider)
    if prov is None:
        raise HTTPException(404, "unknown accounting system")
    if error or not code or not state:
        return _back("declined")
    try:
        claims = oauth.verify_state(state, provider=provider)
        if claims.get("k") != "accounting":
            raise oauth.OAuthError("not an accounting state")
        tenant_id, user_id = UUID(claims["t"]), UUID(claims["m"])
        tokens, org_id, org_name = await prov.exchange(code, realmId)
    except (oauth.OAuthError, acct.AccountingError, ValueError, KeyError) as exc:
        logger.warning("accounting connect failed for %s: %s", provider, exc)
        return _back("failed")

    from envelock.workers.accounting_sync import seal_tokens

    conn = await _connection(session, tenant_id, provider)
    if conn is None:
        conn = AccountingConnection(
            tenant_id=tenant_id, provider=provider, external_org_id=org_id,
            ciphertext=b"", wrapped_dek=b"", key_id="",
        )
        session.add(conn)
    conn.external_org_id = org_id
    conn.org_name = org_name
    conn.connected_by = user_id
    conn.last_error = None
    conn.sync_requested_at = datetime.now(UTC)  # the worker reads it within seconds
    seal_tokens(conn, tokens)
    await record_audit(
        session, tenant_id=tenant_id, actor_id=user_id, action="accounting.connected",
        target_type="tenant", detail={"provider": provider, "org": org_name},
    )
    await session.commit()
    return _back("connected")


@router.post("/{provider}/sync")
async def sync_now(provider: str, principal: AdminUser, session: Session) -> dict:
    conn = await _connection(session, principal.tenant_id, provider)
    if conn is None:
        raise HTTPException(404, "not connected")
    conn.sync_requested_at = datetime.now(UTC)
    await session.commit()
    return _payload(conn)


class Settings(BaseModel):
    flag_bills: bool


@router.patch("/{provider}")
async def update(provider: str, body: Settings, principal: AdminUser, session: Session) -> dict:
    conn = await _connection(session, principal.tenant_id, provider)
    if conn is None:
        raise HTTPException(404, "not connected")
    conn.flag_bills = body.flag_bills
    await session.commit()
    return _payload(conn)


@router.delete("/{provider}")
async def disconnect(provider: str, principal: AdminUser, session: Session) -> dict:
    """Forget the connection and its tokens. Suppliers already imported stay —
    they're the customer's ledger now, not the integration's."""
    conn = await _connection(session, principal.tenant_id, provider)
    if conn is None:
        raise HTTPException(404, "not connected")
    await session.delete(conn)
    await record_audit(
        session, tenant_id=principal.tenant_id, actor_id=principal.user_id,
        action="accounting.disconnected", target_type="tenant", detail={"provider": provider},
    )
    await session.commit()
    return {"disconnected": True}
