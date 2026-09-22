"""Keep connected accounting systems in step, and flag bills on bank-change alerts.

Runs in the worker: both jobs need the connection's access token, which only
the process holding the decryption key can open (the API seals it at connect).
"""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.config import get_settings
from envelock.db import get_sessionmaker
from envelock.integrations import accounting as acct
from envelock.models import AccountingConnection, Alert, AuditEvent, Finding
from envelock.platform.alerts import record_audit
from envelock.security.crypto import SealedSecret, open_secret, seal

logger = logging.getLogger("envelock.accounting")

#: A bank-change alert older than this is history, not something to act on.
FLAG_WINDOW = timedelta(days=14)
BILLS_FLAGGED = "accounting.bills_flagged"


def _aad(conn: AccountingConnection) -> bytes:
    return f"accounting|{conn.tenant_id}|{conn.provider}".encode()


def seal_tokens(conn: AccountingConnection, tokens: acct.Tokens) -> None:
    """Store tokens on the connection (envelope-encrypted, bound to it)."""
    sealed = seal(
        json.dumps({"access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token}).encode(),
        aad=_aad(conn),
    )
    conn.ciphertext = sealed.ciphertext
    conn.wrapped_dek = sealed.wrapped_dek
    conn.key_id = sealed.key_id
    conn.token_expires_at = datetime.fromtimestamp(tokens.expires_at, tz=UTC)


async def _access_token(session: AsyncSession, conn: AccountingConnection) -> str:
    stored = json.loads(open_secret(
        SealedSecret(conn.ciphertext, conn.wrapped_dek, conn.key_id), aad=_aad(conn)
    ))
    expires = conn.token_expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    if expires is None or expires - datetime.now(UTC) < timedelta(minutes=5):
        prov = acct.provider(conn.provider)
        if prov is None:
            raise acct.AccountingError(f"unknown provider {conn.provider}")
        fresh = await prov.refresh(stored["refresh_token"])
        # Both providers rotate the refresh token; keep the new one or the
        # connection dies at the next refresh.
        if not fresh.refresh_token:
            fresh = acct.Tokens(fresh.access_token, stored["refresh_token"], fresh.expires_at)
        seal_tokens(conn, fresh)
        await session.commit()
        return fresh.access_token
    return stored["access_token"]


async def sync_connection(session: AsyncSession, conn: AccountingConnection) -> dict:
    """Read the supplier list and write it into the ledger."""
    from envelock.db import set_current_tenant
    from envelock.services.suppliers import apply_supplier_rows

    set_current_tenant(conn.tenant_id)
    prov = acct.provider(conn.provider)
    try:
        if prov is None:
            raise acct.AccountingError(f"unknown provider {conn.provider}")
        token = await _access_token(session, conn)
        suppliers = await prov.suppliers(token, conn.external_org_id)
    except Exception as exc:  # noqa: BLE001 — recorded on the connection, shown in the UI
        logger.warning("accounting sync failed for %s/%s: %s", conn.tenant_id, conn.provider, exc)
        conn.last_error = str(exc)[:500]
        conn.sync_requested_at = None
        await session.commit()
        return {"ok": False, "error": conn.last_error}

    rows, ids, skipped = [], dict(conn.supplier_ids or {}), 0
    for s in suppliers:
        row = acct.supplier_row(s)
        if row is None:
            skipped += 1
            continue
        rows.append(row)
        ids[row["domain"]] = s.external_id
    counts = await apply_supplier_rows(
        session, tenant_id=conn.tenant_id, rows=rows, actor_id=conn.connected_by
    )
    summary = {
        "suppliers_seen": len(suppliers),
        "suppliers_imported": len(rows),
        "skipped_no_domain": skipped,
        **counts,
    }
    conn.supplier_ids = ids
    conn.last_sync_summary = summary
    conn.last_sync_at = datetime.now(UTC)
    conn.last_error = None
    conn.sync_requested_at = None
    await session.commit()
    return {"ok": True, **summary}


def _note(alert: Alert) -> str:
    ref = "ENV-" + alert.id.hex[:6].upper()
    return (
        f"ENVELOCK WARNING ({ref}): an email asked to change this supplier's bank "
        "details. Do not pay this bill to any new account until the change has been "
        "verified by phone on the number on file — not one from the email. "
        "Details: Envelock dashboard."
    )


async def flag_bills_for_new_alerts(*, now: datetime | None = None) -> dict:
    """Note the unpaid bills of every supplier named by a recent bank-change
    alert, once per alert (the audit event is the marker)."""
    from envelock.db_rls import system_scope

    now = now or datetime.now(UTC)
    sessionmaker = get_sessionmaker()
    with system_scope("accounting: select bank-change alerts"):
        async with sessionmaker() as session:
            rows = (
                await session.execute(
                    select(Alert, AccountingConnection)
                    .join(Finding, Finding.alert_id == Alert.id)
                    .join(AccountingConnection, AccountingConnection.tenant_id == Alert.tenant_id)
                    .where(
                        Finding.service.in_(("A1", "A15")),
                        Alert.tier == "critical",
                        Alert.state != "dismissed",
                        Alert.created_at >= now - FLAG_WINDOW,
                        Alert.counterparty_domain.is_not(None),
                        AccountingConnection.flag_bills.is_(True),
                    )
                )
            ).all()
            done = set((
                await session.execute(
                    select(AuditEvent.target_id).where(AuditEvent.action == BILLS_FLAGGED)
                )
            ).scalars().all())
    todo = {(a.id, c.id) for a, c in rows if a.id not in done}
    flagged = 0
    for alert_id, conn_id in todo:
        with system_scope("accounting: flag bills"):
            async with sessionmaker() as session:
                alert = await session.get(Alert, alert_id)
                conn = await session.get(AccountingConnection, conn_id)
                if alert is None or conn is None:
                    continue
                supplier_id = (conn.supplier_ids or {}).get(alert.counterparty_domain or "")
                count, error = 0, None
                if supplier_id:
                    prov = acct.provider(conn.provider)
                    try:
                        token = await _access_token(session, conn)
                        count = await prov.flag_bills(  # type: ignore[union-attr]
                            token, conn.external_org_id, supplier_id, _note(alert)
                        )
                    except Exception as exc:  # noqa: BLE001
                        error = str(exc)[:300]
                        logger.warning("bill flagging failed for alert %s: %s", alert.id, exc)
                if error is not None:
                    continue  # retried next cycle; not marked done
                await record_audit(
                    session, tenant_id=alert.tenant_id, action=BILLS_FLAGGED,
                    target_type="alert", target_id=alert.id,
                    detail={"provider": conn.provider, "bills": count,
                            "matched_supplier": bool(supplier_id)},
                )
                await session.commit()
                flagged += count
    return {"alerts": len(todo), "bills_flagged": flagged}


async def sync_due(*, requested_only: bool = False) -> dict:
    from envelock.db_rls import system_scope

    cutoff = datetime.now(UTC) - timedelta(seconds=get_settings().accounting_sync_seconds)
    sessionmaker = get_sessionmaker()
    with system_scope("accounting: select due connections"):
        async with sessionmaker() as session:
            query = select(AccountingConnection.id)
            if requested_only:
                query = query.where(AccountingConnection.sync_requested_at.is_not(None))
            else:
                query = query.where(
                    (AccountingConnection.last_sync_at.is_(None))
                    | (AccountingConnection.last_sync_at < cutoff)
                    | (AccountingConnection.sync_requested_at.is_not(None))
                )
            ids = (await session.execute(query)).scalars().all()
    synced = 0
    started = time.monotonic()
    for conn_id in ids:
        with system_scope("accounting: sync"):
            async with sessionmaker() as session:
                conn = await session.get(AccountingConnection, conn_id)
                if conn is not None and (await sync_connection(session, conn)).get("ok"):
                    synced += 1
    if ids:
        logger.info("accounting sync: %d/%d in %.1fs", synced, len(ids),
                    time.monotonic() - started)
    return {"connections": len(ids), "synced": synced}


__all__ = [
    "flag_bills_for_new_alerts",
    "seal_tokens",
    "sync_connection",
    "sync_due",
]
