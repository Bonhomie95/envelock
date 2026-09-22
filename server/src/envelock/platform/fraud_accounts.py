"""Shared intelligence on fraud bank accounts (see models.FraudAccount).

Written when a customer confirms a bank-change fraud; read by the pipeline for
every inbound payment email, so an account used against one customer is flagged
for all of them the next time it appears.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import FraudAccount


def _key() -> bytes:
    from envelock.config import get_settings

    secret = get_settings().secret_key.get_secret_value()
    return (secret or "envelock-dev-fraud-accounts").encode()


def account_hash(scheme: str, identifier: str) -> str:
    """HMAC, not a bare hash: account numbers are short enough to brute-force
    from a plain SHA-256, so a leaked table would leak the accounts."""
    norm = "".join(identifier.split()).upper()
    return hmac.new(_key(), f"fraud-account|{scheme.lower()}|{norm}".encode(),
                    hashlib.sha256).hexdigest()


async def report(
    session: AsyncSession, *, tenant_id: UUID, identifiers: list[dict]
) -> int:
    """Record `[{scheme, identifier}]` as confirmed fraud. Idempotent per
    tenant; returns how many accounts were new or newly corroborated."""
    now = datetime.now(UTC)
    changed = 0
    for item in identifiers:
        scheme, ident = item.get("scheme"), item.get("identifier")
        if not scheme or not ident:
            continue
        h = account_hash(scheme, ident)
        row = await session.get(FraudAccount, h)
        if row is None:
            session.add(FraudAccount(
                account_hash=h, scheme=scheme, confirmations=1, first_reported=now,
                last_reported=now, reporter_tenant_ids=[str(tenant_id)],
            ))
            changed += 1
        elif str(tenant_id) not in (row.reporter_tenant_ids or []):
            row.reporter_tenant_ids = [*(row.reporter_tenant_ids or []), str(tenant_id)]
            row.confirmations = len(row.reporter_tenant_ids)
            row.last_reported = now
            changed += 1
    if changed:
        await session.flush()
    return changed


async def lookup(
    session: AsyncSession, *, tenant_id: UUID, identifiers: list[tuple[str, str]]
) -> dict[str, dict]:
    """identifier -> {"scheme", "other_tenants", "own"} for every known one."""
    if not identifiers:
        return {}
    by_hash = {account_hash(s, i): (s, i) for s, i in identifiers}
    rows = (
        await session.execute(
            select(FraudAccount).where(FraudAccount.account_hash.in_(list(by_hash)))
        )
    ).scalars().all()
    out: dict[str, dict] = {}
    for row in rows:
        scheme, ident = by_hash[row.account_hash]
        reporters = set(row.reporter_tenant_ids or [])
        out[ident] = {
            "scheme": scheme,
            "other_tenants": len(reporters - {str(tenant_id)}),
            "own": str(tenant_id) in reporters,
        }
    return out


__all__ = ["account_hash", "lookup", "report"]
