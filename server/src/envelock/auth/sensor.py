"""Who is talking to a sensor endpoint.

Two kinds of caller reach `/sensor/heartbeat` and `/sensor/message-opened`:

* **An enrolled sensor**, presenting `Authorization: Sensor envs_…`. This is the
  normal case — the browser extension, Thunderbird add-on or Outlook add-in. Its
  token names exactly one mailbox and one device, and cannot do anything else.
* **A signed-in person**, presenting their ordinary bearer session. Kept so the
  dashboard and the test suite can drive the endpoints directly.

Either way the caller must belong to an active account, re-read on every
request: suspending a person, or revoking a device, silences their sensors
immediately rather than when some token happens to expire.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status

from envelock.auth.deps import _bind_tenant, active_actor, current_principal


@dataclass(frozen=True, slots=True)
class SensorCaller:
    tenant_id: UUID
    user_id: UUID
    email: str
    is_member: bool
    #: Set only for a sensor-token caller: the device, the one mailbox it may
    #: speak for, and the device id the token is pinned to.
    device_id: UUID | None = None
    mailbox_id: UUID | None = None
    device_fingerprint: str | None = None

    @property
    def is_device(self) -> bool:
        return self.device_id is not None


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Sensor"}
    )


async def _from_sensor_token(plaintext: str) -> SensorCaller:
    from sqlalchemy import select

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import SensorDevice, User
    from envelock.platform.sensor import token_matches, token_prefix

    prefix = token_prefix(plaintext)
    if prefix is None:
        raise _unauthorized("not a sensor token")

    # The tenant is not known until the token has been resolved — that is what
    # resolving it is for — so this one lookup has to be allowed to see every
    # tenant's devices. Everything after it runs bound to the device's tenant.
    with system_scope("sensor token resolution"):
        async with get_sessionmaker()() as session:
            rows = (
                await session.execute(
                    select(SensorDevice).where(
                        SensorDevice.prefix == prefix, SensorDevice.revoked_at.is_(None)
                    )
                )
            ).scalars().all()
            device = next((d for d in rows if token_matches(plaintext, d.hashed)), None)
            if device is None:
                raise _unauthorized("this sensor has been removed — pair it again")
            user = await session.get(User, device.user_id)

    if user is None or user.tenant_id != device.tenant_id:
        raise _unauthorized("this sensor has been removed — pair it again")
    if user.status != "active":
        # A suspended person's devices stop being evidence of anything.
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "the account this sensor belongs to is not active"
        )

    _bind_tenant(device.tenant_id)
    return SensorCaller(
        tenant_id=device.tenant_id,
        user_id=user.id,
        email=user.email,
        is_member=user.role == "member",
        device_id=device.id,
        mailbox_id=device.mailbox_id,
        device_fingerprint=device.device_fingerprint,
    )


async def sensor_caller(
    authorization: Annotated[str | None, Header()] = None,
) -> SensorCaller:
    if authorization and authorization.lower().startswith("sensor "):
        return await _from_sensor_token(authorization.split(" ", 1)[1].strip())

    principal = await current_principal(authorization)
    actor = await active_actor(principal)
    return SensorCaller(
        tenant_id=actor.tenant_id,
        user_id=actor.user_id,
        email=actor.email,
        is_member=actor.is_member,
    )


SensorPrincipal = Annotated[SensorCaller, Depends(sensor_caller)]

__all__ = ["SensorCaller", "SensorPrincipal", "sensor_caller"]
