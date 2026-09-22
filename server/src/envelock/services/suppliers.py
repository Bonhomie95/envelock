"""Writing suppliers into the ledger the payment detections check against.

Two ways in, one set of rules: the CSV export a finance team pastes, and the
live sync from their accounting system (integrations/accounting.py). Both say
the same thing — "this is who we pay, this is where, this is their number" —
out of band from any email, which is why their bank records are stored as
verified and a phone number fills an empty callback slot but never overwrites
one a person typed in.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import BankRecord, Counterparty
from envelock.util.payments import normalise_identifier

SCHEMES = ("iban", "account", "swift", "sortcode", "ach", "crypto")


async def apply_supplier_rows(
    session: AsyncSession, *, tenant_id: UUID, rows: list[dict], actor_id: UUID | None
) -> dict:
    """Upsert `rows` ({domain, name?, phone?, <scheme>?, bank_name?}). Idempotent
    by (supplier, scheme, identifier). Flushes; the caller commits."""
    created_suppliers = matched = created_records = skipped_records = 0
    seen: dict[str, Counterparty] = {}
    for row in rows:
        reg = row["domain"]
        counterparty = seen.get(reg)
        if counterparty is None:
            counterparty = (
                await session.execute(
                    select(Counterparty).where(
                        Counterparty.tenant_id == tenant_id,
                        Counterparty.registrable_domain == reg,
                    )
                )
            ).scalar_one_or_none()
            if counterparty is None:
                now = datetime.now(UTC)
                counterparty = Counterparty(
                    tenant_id=tenant_id,
                    registrable_domain=reg,
                    first_seen_at=now,
                    last_seen_at=now,
                    message_count=0,
                )
                session.add(counterparty)
                await session.flush()
                created_suppliers += 1
            else:
                matched += 1
            seen[reg] = counterparty

        if name := row.get("name"):
            counterparty.display_name = counterparty.display_name or name
        if phone := row.get("phone"):
            counterparty.verified_phone = counterparty.verified_phone or phone

        for scheme in SCHEMES:
            value = normalise_identifier(scheme, row.get(scheme) or "")
            if not value:
                continue
            existing = (
                await session.execute(
                    select(BankRecord.id).where(
                        BankRecord.counterparty_id == counterparty.id,
                        BankRecord.scheme == scheme,
                        BankRecord.identifier == value,
                    )
                )
            ).scalar_one_or_none()
            if existing is not None:
                skipped_records += 1
                continue
            now = datetime.now(UTC)
            session.add(
                BankRecord(
                    tenant_id=tenant_id,
                    counterparty_id=counterparty.id,
                    scheme=scheme,
                    identifier=value,
                    bank_name=row.get("bank_name") or None,
                    first_seen_at=now,
                    # From the customer's own accounting system, out of band from
                    # any email — stronger provenance than anything inferred
                    # from a message.
                    verified_at=now,
                    verified_by=actor_id,
                )
            )
            created_records += 1
    await session.flush()
    return {
        "suppliers_created": created_suppliers,
        "suppliers_matched": matched,
        "bank_records_created": created_records,
        "bank_records_already_present": skipped_records,
    }


__all__ = ["SCHEMES", "apply_supplier_rows"]
