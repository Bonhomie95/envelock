"""Plan gates at the trust boundary, shared by every router that needs one.

`billing/entitlement` and `billing/features` answer *what* a tenant is entitled
to. This turns those answers into the HTTP refusal, in one place, because the
routers that have to ask are spread across three modules and the failure mode of
forgetting is silent: the customer connects a mailbox, is told it worked, and
nothing is ever read from it. A gate that lets the setup succeed is worse than no
gate — it manufactures a customer who believes they are protected.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import Tenant


async def require_mailbox_entitlement(session: AsyncSession, tenant_id: UUID) -> Tenant:
    """The tenant may have live mail read on its behalf (paid plan or live trial).

    Guard is Channel-3 only and free: it watches domains, never mailboxes. So a
    Guard or lapsed-trial tenant is refused anything that would start, resume or
    feed live mail protection.
    """
    from envelock.billing.entitlement import mailbox_entitled

    tenant = await session.get(Tenant, tenant_id)
    if tenant is None or not mailbox_entitled(tenant):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "add a payment method or upgrade to Essential or Complete to protect "
            "mailboxes — domain and brand monitoring stay free on Guard",
        )
    return tenant


async def require_identity_detections(session: AsyncSession, tenant_id: UUID) -> Tenant:
    """The tenant bought Channel 2 — the sign-in/takeover suite (Complete).

    The sensor exists only to feed those detections, so pairing a device without
    them installs software on someone's laptop that will never raise anything.
    """
    from envelock.billing.features import is_complete, upgrade_note

    tenant = await session.get(Tenant, tenant_id)
    if tenant is None or not is_complete(tenant):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            upgrade_note("Sign-in and account-takeover protection"),
        )
    return tenant


__all__ = ["require_identity_detections", "require_mailbox_entitlement"]
