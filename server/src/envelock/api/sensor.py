"""Enrolling, listing and removing sensors.

The flow a person actually follows:

1. In the dashboard, they choose "Add a device" on a mailbox and get a code like
   `K7QM-4XRT`.
2. They install the Envelock extension (browser), add-on (Thunderbird) or
   add-in (Outlook), and type the code into it.
3. The client trades the code — once — for its own token, and starts reporting.

Nothing about this hands the client the person's session. See
`models.SensorDevice` for what a sensor token can and cannot do, and
`models.SensorPairing` for why the code is short-lived and single-use.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import ActiveUser, SystemScoped
from envelock.db import get_session
from envelock.models import Mailbox, SensorDevice, SensorPairing, SensorSession
from envelock.platform import alerts as alert_svc
from envelock.platform import sensor as rules

router = APIRouter(prefix="/api/v1", tags=["sensor"])
Session = Annotated[AsyncSession, Depends(get_session)]


def _device_payload(d: SensorDevice, mailbox_address: str | None, now: datetime) -> dict:
    return {
        "id": str(d.id),
        "mailbox_id": str(d.mailbox_id),
        "mailbox": mailbox_address,
        "client": d.client,
        "label": d.label,
        "enrolled_at": d.created_at.isoformat() if d.created_at else None,
        "last_seen_at": d.last_seen_at.isoformat() if d.last_seen_at else None,
        "live": rules.is_live(d.last_seen_at, now=now) and d.revoked_at is None,
        "revoked": d.revoked_at is not None,
    }


# ── 1. Pairing code (signed-in person) ───────────────────────────────────────
class PairingRequest(BaseModel):
    mailbox_id: UUID


@router.post("/sensor/pairings", status_code=201)
async def create_pairing(req: PairingRequest, actor: ActiveUser, session: Session) -> dict:
    """Mint a one-time code that a sensor can trade for its own token.

    A member may pair only their own mailbox. An admin may pair any mailbox in
    the workspace — IT installing the extension on a colleague's machine is the
    normal way this gets rolled out.
    """
    mailbox = await session.get(Mailbox, req.mailbox_id)
    if mailbox is None or mailbox.tenant_id != actor.tenant_id:
        raise HTTPException(404, "mailbox not found")
    if actor.is_member and mailbox.address != actor.email:
        raise HTTPException(404, "mailbox not found")

    display, hashed = rules.mint_pairing_code()
    expires_at = datetime.now(UTC) + rules.PAIRING_TTL
    session.add(
        SensorPairing(
            tenant_id=actor.tenant_id,
            user_id=actor.user_id,
            mailbox_id=mailbox.id,
            code_hash=hashed,
            expires_at=expires_at,
        )
    )
    await alert_svc.record_audit(
        session,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        action=alert_svc.AuditAction.SENSOR_PAIRING_CREATED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address},
    )
    await session.commit()
    return {
        "code": display,
        "expires_at": expires_at.isoformat(),
        "mailbox": mailbox.address,
        "ttl_seconds": int(rules.PAIRING_TTL.total_seconds()),
    }


# ── 2. Redeem (the sensor, unauthenticated) ──────────────────────────────────
class EnrollRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)
    client: str = Field(min_length=3, max_length=32)
    #: The random device id the client generated for itself before enrolling.
    #: The token is pinned to it.
    device_fingerprint: str = Field(min_length=8, max_length=128)
    label: str | None = Field(default=None, max_length=128)


# SystemScoped: the caller has no session, and the tenant is not known until the
# code has been matched — which is the whole point of the code. The handler
# binds nothing broader than the one pairing it finds.
@router.post("/sensor/enroll", dependencies=[SystemScoped])
async def enroll(req: EnrollRequest, request: Request, session: Session) -> dict:
    """Trade a pairing code for a sensor token. Single use.

    Every failure answers the same way, so this cannot be used to learn whether
    a code exists, has expired or was already used. The endpoint is rate-limited
    per address (`sensor.enroll`), which is what makes an 8-character code safe.
    """
    client = req.client.strip().lower()
    if client not in rules.CLIENTS:
        raise HTTPException(422, f"unknown client — expected one of {sorted(rules.CLIENTS)}")

    invalid = HTTPException(400, "that code is not valid — create a new one in the dashboard")
    hashed = rules.pairing_code_hash(req.code)
    if hashed is None:
        raise invalid

    now = datetime.now(UTC)
    # Claim the code atomically: exactly one redemption can flip `used_at` from
    # null, however many clients race with the same code.
    claimed = (
        await session.execute(
            update(SensorPairing)
            .where(
                SensorPairing.code_hash == hashed,
                SensorPairing.used_at.is_(None),
                SensorPairing.expires_at > now,
            )
            .values(used_at=now)
            .returning(SensorPairing.id)
        )
    ).scalar_one_or_none()
    if claimed is None:
        await session.rollback()
        raise invalid

    pairing = await session.get(SensorPairing, claimed)
    mailbox = await session.get(Mailbox, pairing.mailbox_id) if pairing else None
    if pairing is None or mailbox is None:
        await session.rollback()
        raise invalid

    plaintext, prefix, token_hash = rules.mint_token()
    device = SensorDevice(
        tenant_id=pairing.tenant_id,
        user_id=pairing.user_id,
        mailbox_id=mailbox.id,
        prefix=prefix,
        hashed=token_hash,
        client=client,
        label=(req.label or "").strip() or None,
        device_fingerprint=req.device_fingerprint,
        last_ip=request.client.host if request.client else None,
    )
    session.add(device)
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=pairing.tenant_id,
        actor_id=pairing.user_id,
        action=alert_svc.AuditAction.SENSOR_ENROLLED,
        target_type="sensor_device",
        target_id=device.id,
        detail={"address": mailbox.address, "client": client, "label": device.label},
    )
    await session.commit()
    return {
        "token": plaintext,
        "device_id": str(device.id),
        "mailbox": mailbox.address,
        "heartbeat_seconds": rules.HEARTBEAT_SECONDS,
    }


# ── 3. See and remove (signed-in person) ─────────────────────────────────────
@router.get("/sensor/devices")
async def list_devices(actor: ActiveUser, session: Session) -> dict:
    """Every device reporting for this workspace — or, for a member, for their
    own mailbox only."""
    query = (
        select(SensorDevice, Mailbox.address)
        .join(Mailbox, Mailbox.id == SensorDevice.mailbox_id)
        .where(SensorDevice.tenant_id == actor.tenant_id)
        .order_by(SensorDevice.created_at.desc())
    )
    if actor.is_member:
        query = query.where(Mailbox.address == actor.email)
    rows = (await session.execute(query)).all()
    now = datetime.now(UTC)
    return {
        "devices": [_device_payload(d, address, now) for d, address in rows],
        "heartbeat_seconds": rules.HEARTBEAT_SECONDS,
    }


@router.delete("/sensor/devices/{device_id}", status_code=204)
async def revoke_device(device_id: UUID, actor: ActiveUser, session: Session) -> None:
    """Stop trusting a device. Its token dies immediately.

    Its open sessions are closed too. Left open, a revoked device's last
    heartbeats would keep the mailbox looking attended for a few more minutes —
    exactly the window in which C11 should be most alert, if the device was
    revoked because it was stolen.
    """
    device = await session.get(SensorDevice, device_id)
    if device is None or device.tenant_id != actor.tenant_id:
        raise HTTPException(404, "device not found")
    mailbox = await session.get(Mailbox, device.mailbox_id)
    if actor.is_member and (mailbox is None or mailbox.address != actor.email):
        raise HTTPException(404, "device not found")
    if device.revoked_at is not None:
        return

    now = datetime.now(UTC)
    device.revoked_at = now
    await session.execute(
        update(SensorSession)
        .where(
            SensorSession.mailbox_id == device.mailbox_id,
            SensorSession.device_fingerprint == device.device_fingerprint,
            SensorSession.ended_at.is_(None),
        )
        .values(ended_at=now)
    )
    await alert_svc.record_audit(
        session,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        action=alert_svc.AuditAction.SENSOR_REVOKED,
        target_type="sensor_device",
        target_id=device.id,
        detail={"address": mailbox.address if mailbox else None, "client": device.client},
    )
    await session.commit()
