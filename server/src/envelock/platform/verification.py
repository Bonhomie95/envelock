"""Out-of-band confirmation of a payment-detail change (see models.PaymentVerification).

The rule the whole feature rests on: confirm through the phone number already
on file for the supplier, never a number or address from the email. The email
is the thing under suspicion — and in the common version of this fraud the
supplier's own mailbox is compromised, so an emailed "please confirm" would be
answered by the attacker.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import Alert, Counterparty, PaymentVerification, Tenant
from envelock.platform import alerts as alert_svc

SMS_LINK_TTL = timedelta(hours=72)
SMS_PER_ALERT_PER_DAY = 3
OUTCOMES = ("confirmed", "denied", "no_answer")


class VerificationError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def mask_account(scheme: str | None, identifier: str | None) -> str | None:
    if not identifier:
        return None
    tail = "".join(identifier.split())[-4:]
    label = {"iban": "IBAN", "ach": "Account", "account": "Account", "sortcode": "Account",
             "swift": "SWIFT", "crypto": "Wallet"}.get((scheme or "").lower(), "Account")
    return f"{label} ••••{tail}"


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def context(session: AsyncSession, alert: Alert) -> dict:
    """Everything the verify panel shows: who, the number on file, what changed."""
    cp = None
    if alert.counterparty_domain:
        cp = (
            await session.execute(
                select(Counterparty).where(
                    Counterparty.tenant_id == alert.tenant_id,
                    Counterparty.registrable_domain == alert.counterparty_domain,
                )
            )
        ).scalars().first()
    accounts = await alert_svc.alert_bank_identifiers(session, alert)
    account = mask_account(accounts[0]["scheme"], accounts[0]["identifier"]) if accounts else None
    return {
        "supplier": alert.counterparty_domain,
        "supplier_name": (cp.display_name if cp else None) or alert.counterparty_domain,
        # The number on the SUPPLIER record now, not a copy taken at alert time:
        # adding it on the Suppliers page after the alert must make it usable.
        "phone_on_file": (cp.verified_phone if cp else None) or alert.callback_phone,
        "account": account,
        "amount": alert.amount_at_risk,
        "currency": alert.amount_currency,
    }


def _sms_sender():  # noqa: ANN202 — notify.senders.SmsSender
    from envelock.notify.senders import SmsSender

    return SmsSender()


def sms_available() -> bool:
    return _sms_sender().configured


async def attempts(session: AsyncSession, alert: Alert) -> list[PaymentVerification]:
    return list(
        (
            await session.execute(
                select(PaymentVerification)
                .where(PaymentVerification.alert_id == alert.id)
                .order_by(PaymentVerification.created_at.desc())
            )
        ).scalars().all()
    )


def payload(v: PaymentVerification) -> dict:
    return {
        "id": str(v.id),
        "channel": v.channel,
        "status": v.status,
        "phone": v.phone,
        "account": v.account_masked,
        "note": v.note,
        "created_at": v.created_at.isoformat(),
        "responded_at": v.responded_at.isoformat() if v.responded_at else None,
        "expires_at": v.expires_at.isoformat() if v.expires_at else None,
    }


async def _apply(
    session: AsyncSession, alert: Alert, outcome: str, *, actor_id: UUID | None
) -> None:
    """What an answer means for the alert. A supplier saying "not us" is
    confirmed fraud, full stop: resolve it (which feeds the shared graph and the
    fraud-account list). "Yes, that's us" is left for a person to close — the
    panel offers it — because paying is a decision, not a side effect."""
    if outcome != "denied" or alert.state in ("resolved", "dismissed"):
        return
    await alert_svc.resolve(
        session,
        alert_id=alert.id,
        tenant_id=alert.tenant_id,
        actor_id=actor_id,
        dismissed=False,
    )


async def record_call(
    session: AsyncSession, alert: Alert, *, actor_id: UUID, outcome: str, note: str | None
) -> PaymentVerification:
    if outcome not in OUTCOMES:
        raise VerificationError(422, "outcome must be confirmed, denied or no_answer")
    ctx = await context(session, alert)
    now = datetime.now(UTC)
    v = PaymentVerification(
        tenant_id=alert.tenant_id,
        alert_id=alert.id,
        counterparty_domain=alert.counterparty_domain,
        channel="call",
        phone=ctx["phone_on_file"],
        status=outcome,
        requested_by=actor_id,
        recorded_by=actor_id,
        responded_at=now,
        note=(note or "").strip()[:2000] or None,
        account_masked=ctx["account"],
    )
    session.add(v)
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=alert.tenant_id,
        actor_id=actor_id,
        action="payment.verified_by_call",
        target_type="alert",
        target_id=alert.id,
        detail={"outcome": outcome},
    )
    await _apply(session, alert, outcome, actor_id=actor_id)
    return v


async def send_sms(
    session: AsyncSession, alert: Alert, *, actor_id: UUID, link_base: str
) -> PaymentVerification:
    sender = _sms_sender()
    if not sender.configured:
        raise VerificationError(
            503, "Text messages aren't set up on this deployment — call instead."
        )
    ctx = await context(session, alert)
    phone = ctx["phone_on_file"]
    if not phone:
        raise VerificationError(
            409, "There's no phone number on file for this supplier. Add it on the Suppliers page."
        )
    since = datetime.now(UTC) - timedelta(days=1)
    sent_today = (
        await session.execute(
            select(func.count()).select_from(PaymentVerification).where(
                PaymentVerification.alert_id == alert.id,
                PaymentVerification.channel == "sms",
                PaymentVerification.created_at >= since,
            )
        )
    ).scalar_one()
    if sent_today >= SMS_PER_ALERT_PER_DAY:
        raise VerificationError(429, "Three texts have gone out for this today — call instead.")

    tenant = await session.get(Tenant, alert.tenant_id)
    company = (tenant.name if tenant else None) or "Your customer"
    token = secrets.token_urlsafe(24)
    now = datetime.now(UTC)
    v = PaymentVerification(
        tenant_id=alert.tenant_id,
        alert_id=alert.id,
        counterparty_domain=alert.counterparty_domain,
        channel="sms",
        phone=phone,
        status="pending",
        token_hash=_hash(token),
        expires_at=now + SMS_LINK_TTL,
        requested_by=actor_id,
        account_masked=ctx["account"],
    )
    session.add(v)
    await session.flush()
    # No amounts, no account numbers: a text can be read over a shoulder or on
    # a lock screen. The page behind the link shows the masked account.
    text = (
        f"{company} is confirming a change to your payment details. "
        f"Please answer here: {link_base.rstrip('/')}/v/{token}"
    )
    try:
        await sender._deliver_sms(phone, text)  # noqa: SLF001 — raw text, not an alert
    except Exception as exc:  # noqa: BLE001
        raise VerificationError(502, f"The text couldn't be sent ({exc}). Call instead.") from exc
    await alert_svc.record_audit(
        session,
        tenant_id=alert.tenant_id,
        actor_id=actor_id,
        action="payment.verification_sms_sent",
        target_type="alert",
        target_id=alert.id,
        detail={"phone_tail": phone[-4:]},
    )
    return v


async def by_token(session: AsyncSession, token: str) -> PaymentVerification | None:
    return (
        await session.execute(
            select(PaymentVerification).where(PaymentVerification.token_hash == _hash(token))
        )
    ).scalars().first()


async def public_view(session: AsyncSession, token: str) -> dict:
    v = await by_token(session, token)
    if v is None:
        raise VerificationError(404, "This link isn't valid.")
    tenant = await session.get(Tenant, v.tenant_id)
    expired = v.expires_at is not None and v.expires_at < datetime.now(UTC)
    return {
        "company": (tenant.name if tenant else None) or "Your customer",
        "account": v.account_masked,
        "status": "expired" if (expired and v.status == "pending") else v.status,
    }


async def answer(session: AsyncSession, token: str, *, yes: bool) -> dict:
    v = await by_token(session, token)
    if v is None:
        raise VerificationError(404, "This link isn't valid.")
    if v.status != "pending":
        raise VerificationError(409, "This has already been answered — thank you.")
    if v.expires_at is not None and v.expires_at < datetime.now(UTC):
        v.status = "expired"
        await session.commit()
        raise VerificationError(410, "This link has expired. They'll call you instead.")
    v.status = "confirmed" if yes else "denied"
    v.responded_at = datetime.now(UTC)
    alert = await session.get(Alert, v.alert_id)
    await alert_svc.record_audit(
        session,
        tenant_id=v.tenant_id,
        action="payment.verified_by_sms",
        target_type="alert",
        target_id=v.alert_id,
        detail={"outcome": v.status},
    )
    if alert is not None:
        await _apply(session, alert, v.status, actor_id=None)
    await session.commit()
    return {"status": v.status}


__all__ = [
    "OUTCOMES",
    "VerificationError",
    "answer",
    "attempts",
    "context",
    "mask_account",
    "payload",
    "public_view",
    "record_call",
    "send_sms",
    "sms_available",
]
