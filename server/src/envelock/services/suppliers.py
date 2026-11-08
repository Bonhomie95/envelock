"""Writing suppliers into the ledger the payment detections check against.

Two ways in, one set of rules: the CSV export a finance team pastes, and the
live sync from their accounting system (integrations/accounting.py). Both say
the same thing — "this is who we pay, this is where, this is their number" —
out of band from any email, which is why their bank records are stored as
verified and a phone number fills an empty callback slot but never overwrites
one a person typed in.

Also what tells a supplier apart from everyone else who emails (`impostors`,
`payment_senders`), for the Suppliers page.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import MailDirection
from envelock.models import Alert, BankRecord, Counterparty, Finding, Message
from envelock.util.domains import counterparty_key
from envelock.util.payments import normalise_identifier

SCHEMES = ("iban", "account", "swift", "sortcode", "ach", "crypto")

#: Findings that say the SENDER is not who it claims to be: a near-copy of a
#: domain you know (A3), a character-swap copy (A4), someone else's name on the
#: From line (A5). Every other finding is about one message (a changed account, a
#: hijacked thread, a bad link, even a listed domain) and can land on a real
#: supplier, so it must not take the supplier off the page; confirming such an
#: alert as fraud would otherwise bury the supplier for good.
IMPOSTOR_SERVICES = ("A3", "A4", "A5")


def _impostor_reason(service: str, evidence: dict) -> str:
    if service in ("A3", "A4"):
        return f"Look-alike of {evidence.get('resembles') or 'a domain you know'}"
    if claims := evidence.get("claims"):
        return f"Uses the name of {claims}"
    return "Uses the name of someone at your company"


async def impostors(session: AsyncSession, *, tenant_id: UUID) -> dict[str, str]:
    """Counterparty key → why an alert said this sender is an impostor.

    Keyed by `counterparty_key` of the sender's address, not the alert's
    `counterparty_domain`, so an impostor on free mail (keyed by address) is
    caught too. An alert dismissed as a false alarm no longer counts: dismissing
    it is how a real supplier wrongly flagged gets back on the list."""
    rows = (
        await session.execute(
            select(Message.sender_address, Finding.service, Finding.evidence)
            .join(Finding, Finding.message_id == Message.id)
            .join(Alert, Alert.id == Finding.alert_id)
            .where(
                Finding.tenant_id == tenant_id,
                Finding.service.in_(IMPOSTOR_SERVICES),
                Alert.state != "dismissed",
            )
            .order_by(Finding.service)  # A3/A4 name the real domain: say that first
        )
    ).all()
    out: dict[str, str] = {}
    for address, service, evidence in rows:
        out.setdefault(counterparty_key(address), _impostor_reason(service, evidence or {}))
    return out


async def payment_senders(session: AsyncSession, *, tenant_id: UUID) -> set[str]:
    """Counterparty keys that have sent a payment request with an amount, whether
    or not it alerted: a real supplier's first invoice usually does (first
    contact), and that is exactly when finance should record its details."""
    # ponytail: reads the tenant's inbound messages per call; add a partial index
    # on (tenant_id) WHERE payment_amount IS NOT NULL if the Suppliers page slows.
    addresses = (
        await session.execute(
            select(Message.sender_address)
            .where(
                Message.tenant_id == tenant_id,
                Message.direction == MailDirection.INBOUND.value,
                Message.payment_amount.is_not(None),
            )
            .distinct()
        )
    ).scalars()
    return {counterparty_key(a) for a in addresses}


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
        counterparty.added_by_customer = True

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


__all__ = ["IMPOSTOR_SERVICES", "SCHEMES", "apply_supplier_rows", "impostors", "payment_senders"]
