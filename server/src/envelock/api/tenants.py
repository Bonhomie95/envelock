"""Tenant, mailbox, alert and counterparty endpoints — the dashboard's data.

Everything here is persisted, tenant-scoped, and checked against the caller's
tenant on every access. Tenant isolation is verified, never assumed.
"""

from __future__ import annotations

import asyncio
import secrets
from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import ActiveUser, AdminUser, OwnerUser
from envelock.auth.email_policy import is_disposable_email
from envelock.auth.security import (
    Role,
    dummy_hash,
    hash_password,
    verify_password,
    verify_totp,
)
from envelock.billing.pricing import included_mailbox_seats
from envelock.channels.mail.ingest import ingest_address, new_ingest_token, onboarding_instructions
from envelock.core.capabilities import (
    capabilities_for,
    protection_advice,
    protection_level,
)
from envelock.core.enums import IntegrationTier, MailboxClass, SourceMechanism
from envelock.db import get_session
from envelock.db_rls import system_scope_on
from envelock.detections.base import inactive_for
from envelock.models import (
    Alert,
    AuditEvent,
    BankRecord,
    Counterparty,
    Domain,
    Finding,
    Invoice,
    LookalikeDomain,
    Mailbox,
    MailboxCredential,
    Message,
    NotificationDelivery,
    PushSubscription,
    SenderProfile,
    SensorSession,
    Tenant,
    UsageMeter,
    User,
)
from envelock.platform import alerts as alert_svc
from envelock.platform import graph_store
from envelock.platform.graph import GRAPH, RiskProfile, Verdict
from envelock.platform.remediation import (
    RemediationAction,
    plan_remediation,
)
from envelock.security.crypto import seal
from envelock.security.limits import valid_domain
from envelock.services.domains import (
    mail_domain_allowed as _mail_domain_allowed,
)
from envelock.services.domains import (
    require_verified_domain as _require_verified_domain,
)
from envelock.services.domains import (
    revalidate_verified_domains,  # noqa: F401 — re-export (tests, scheduler compat)
    set_domain_verifier,  # noqa: F401 — re-export (test seam lives in services)
)
from envelock.services.domains import (
    verified_registrable_domains as _verified_registrable_domains,
)
from envelock.services.domains import (
    verify_domain_control as _verify_domain_control,
)
from envelock.util.domains import is_free_mail, registrable_domain
from envelock.util.payments import normalise_identifier

router = APIRouter(prefix="/api/v1", tags=["tenant"])

Session = Annotated[AsyncSession, Depends(get_session)]

#: Sources that mean a mailbox's MAIL is actually being ingested (vs identity-only
#: signals). Used to tell "connected" from "unconnected".
_MAIL_SOURCES = frozenset(
    {"graph_api", "gmail_api", "admin_api", "imap_idle", "imap_poll", "forward_ingest", "journal"}
)


async def _tenant_or_404(session: AsyncSession, tenant_id: UUID) -> Tenant:
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "tenant not found")
    return tenant


def _mailbox_entitled(tenant: Tenant) -> bool:
    """Content mailboxes (Channel 1/2) need a paid plan or an active trial. Guard
    is Channel-3-only and free — it protects domains, not mailboxes (PRD §12.3),
    so a lapsed-trial tenant on Guard cannot keep adding protected seats.

    Shared with the pollers (billing/entitlement), which enforce the same answer
    on mailboxes that are ALREADY connected."""
    from envelock.billing.entitlement import mailbox_entitled

    return mailbox_entitled(tenant)


def _require_mailbox_entitlement(tenant: Tenant) -> None:
    if not _mailbox_entitled(tenant):
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "add a payment method or upgrade to Essential or Complete to protect "
            "mailboxes — domain and brand monitoring stay free on Guard",
        )


def _effective_plan(tenant: Tenant) -> str:
    """Guard once the trial has lapsed unpaid, else the subscribed plan (matches
    what `current_tenant` reports to the dashboard)."""
    from envelock.billing.entitlement import effective_plan

    return effective_plan(tenant)


def _mailbox_capacity(tenant: Tenant) -> int:
    """How many mailboxes this tenant may protect right now: the plan's included
    seats plus any purchased, or 0 on Guard (no mailboxes without a paid plan/trial).

    During the trial the tenant sits on the top plan, so the allowance is COMPLETE's
    (7). A paid Essential tenant gets 5. Extra purchased seats add on top."""
    from envelock.billing.entitlement import mailbox_capacity

    return mailbox_capacity(tenant)


async def _mailbox_count(session: AsyncSession, tenant_id: UUID) -> int:
    return int(
        (
            await session.execute(
                select(func.count()).select_from(Mailbox).where(Mailbox.tenant_id == tenant_id)
            )
        ).scalar_one()
    )


async def _require_mailbox_capacity(
    session: AsyncSession, tenant: Tenant, *, adding: int = 1
) -> None:
    """Enforce the plan's mailbox seat cap so a trial or paid tenant can't protect
    more mailboxes than they're entitled to. Over the cap → 402, and the client
    routes the admin to upgrade or buy more seats before anything connects."""
    _require_mailbox_entitlement(tenant)  # Guard / lapsed-unpaid can't add at all.
    # Serialise capacity checks per tenant: N concurrent adds each read
    # `used = cap-1` and all commit — a classic check-then-act walk past the
    # cap. A row lock on the tenant makes the second request wait and see the
    # first one's mailbox.
    await session.execute(
        select(Tenant.id).where(Tenant.id == tenant.id).with_for_update()
    )
    cap = _mailbox_capacity(tenant)
    used = await _mailbox_count(session, tenant.id)
    if used + adding > cap:
        plan = _effective_plan(tenant)
        need = used + adding - cap
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"your {plan.capitalize()} plan covers {cap} mailbox"
            f"{'' if cap == 1 else 'es'} and {used} are in use. "
            f"Buy {need} more seat{'' if need == 1 else 's'} (or upgrade) before "
            "adding another mailbox.",
        )


# ── Bootstrap ────────────────────────────────────────────────────────────────
class BootstrapRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    domain: str


async def _assert_may_claim_domain(session, principal, reg: str) -> None:
    """Refuse to let a tenant claim a registrable domain it has no relationship to.

    This endpoint used to take any well-formed domain from the request body and
    check for duplicates only *within the caller's own tenant*, which made
    workspace hijack a two-request attack:

      1. Register as attacker@evil.example (any account will do).
      2. POST /tenants/bootstrap {"domain": "acme.com"}.

    That wrote a `Domain` row for acme.com under the attacker's tenant. From then
    on `_existing_tenant_for_domain` (api/auth.py:283) — which matches any Domain
    row for the address's registrable domain — routed *every future acme.com
    signup* into the attacker's workspace as a pending member, where the attacker
    is the owner. The real company's staff would be joining the attacker's tenant.

    Two rules close it, and neither blocks a legitimate multi-domain company:

    * **Nobody else already holds it.** First claim wins, and claiming needs an
      account. A domain another tenant has *verified* is refused outright.
    * **You must have a relationship to it**: it matches your own email's
      registrable domain, or your tenant has already DNS-verified some other
      domain (so you have proven you are a real company). The added domain still
      has to pass its own TXT proof before it gates anything.
    """
    # This one query is deliberately cross-tenant, and it has to be: it asks
    # "does ANOTHER tenant already hold this domain?", which is a question about
    # rows the caller must never read.
    #
    # Under RLS without this scope the query is filtered to the caller's own
    # tenant, the conflicting row becomes invisible, no 409 is raised — and the
    # workspace-hijack this function exists to prevent comes straight back. A
    # security control that needs cross-tenant visibility is exactly the kind
    # that RLS silently disables rather than breaks loudly, which is why the
    # regression test for the hijack is also run under enforcement.
    #
    # Nothing about the other tenant escapes: the result is used only as a
    # boolean, and the message below is identical whoever holds the domain.
    async with system_scope_on(
        session, "bootstrap: is this domain claimed by another tenant?"
    ):
        conflict = (
            await session.execute(
                select(Domain).where(
                    Domain.registrable_domain == reg,
                    Domain.tenant_id != principal.tenant_id,
                ).limit(1)
            )
        ).scalar_one_or_none()
    if conflict is not None:
        # Deliberately the same message whether or not the other side verified:
        # "acme.com is verified elsewhere" is a small reconnaissance signal, and
        # the caller's remedy is identical either way.
        raise HTTPException(
            409,
            f"{reg} is already registered to another Envelock workspace. If that "
            "is your company, ask your administrator to invite you, or contact "
            "support to transfer the domain.",
        )

    actor = await session.get(User, principal.user_id)
    own = registrable_domain((actor.email if actor else "").rsplit("@", 1)[-1])
    if own and own == reg:
        return

    already_verified = (
        await session.execute(
            select(Domain.id).where(
                Domain.tenant_id == principal.tenant_id,
                Domain.verified_at.is_not(None),
            ).limit(1)
        )
    ).scalar_one_or_none()
    if already_verified is not None:
        return

    raise HTTPException(
        403,
        f"you can't add {reg} — it doesn't match your own email domain. Verify "
        "your company's first domain, then you can add others from Settings.",
    )


@router.post("/tenants/bootstrap", status_code=201)
async def bootstrap(req: BootstrapRequest, principal: AdminUser, session: Session) -> dict:
    """Create the tenant record and its first domain for the signed-in user."""
    existing = await session.get(Tenant, principal.tenant_id)
    if existing is None:
        existing = Tenant(id=principal.tenant_id, name=req.name)
        session.add(existing)
        await session.flush()

    # Validate the shape *before* deriving the registrable domain: a company
    # name like "Acme Corp" reduces to "acme corp", which is truthy but not a
    # domain. Storing it would silently break every domain-based lookup (MX,
    # DMARC, Certificate Transparency, lookalikes) and the ingest token for the
    # whole tenant, with no error anywhere.
    if not valid_domain(req.domain):
        raise HTTPException(422, "enter a valid domain, e.g. yourcompany.com")
    reg = registrable_domain(req.domain)
    if not reg:
        raise HTTPException(422, "invalid domain")

    await _assert_may_claim_domain(session, principal, reg)

    domain = (
        await session.execute(
            select(Domain).where(
                Domain.tenant_id == principal.tenant_id, Domain.registrable_domain == reg
            )
        )
    ).scalar_one_or_none()
    if domain is None:
        domain = Domain(
            tenant_id=principal.tenant_id,
            name=reg,
            registrable_domain=reg,
            verification_token=new_ingest_token(),
        )
        session.add(domain)

    await session.commit()
    return {
        "tenant_id": str(existing.id),
        "name": existing.name,
        "domain": reg,
        "verification": {
            "record": f"envelock-verify={domain.verification_token}",
            "host": f"_envelock.{reg}",
            "type": "TXT",
        },
        "ingest_address": ingest_address(domain.verification_token or ""),
    }


# ── Domain-control verification (PRD signup funnel) ──────────────────────────
# Lives in services/domains.py — shared by this router, the channels router and
# the background scheduler. Imported (and re-exported) at the top of this file.


async def _load_domain(session: AsyncSession, tenant_id: UUID, domain: str) -> Domain | None:
    reg = registrable_domain(domain)
    return (
        await session.execute(
            select(Domain).where(Domain.tenant_id == tenant_id, Domain.registrable_domain == reg)
        )
    ).scalar_one_or_none()


@router.get("/domains/{domain}/verification")
async def domain_verification_challenge(
    domain: str, principal: AdminUser, session: Session
) -> dict:
    """The DNS record to add to prove control of the domain. Idempotent — safe to
    poll while the customer configures DNS."""
    from envelock.util.dns_verify import challenge_host, cname_target, txt_record_value

    row = await _load_domain(session, principal.tenant_id, domain)
    if row is None:
        raise HTTPException(404, "domain not found on this account")
    if not row.verification_token:
        row.verification_token = new_ingest_token()
        await session.commit()
    reg = row.registrable_domain
    token = row.verification_token
    return {
        "domain": reg,
        "verified": row.verified_at is not None,
        "txt": {"host": challenge_host(reg), "type": "TXT", "value": txt_record_value(token)},
        "cname": {"host": challenge_host(reg), "type": "CNAME", "value": cname_target(token)},
    }


@router.post("/domains/{domain}/verify")
async def verify_domain(domain: str, principal: AdminUser, session: Session) -> dict:
    """Check the DNS challenge and mark the domain verified. Until a domain is
    verified, no mailbox on it can be connected for live mail (see mailbox
    connect)."""
    row = await _load_domain(session, principal.tenant_id, domain)
    if row is None:
        raise HTTPException(404, "domain not found on this account")
    if row.verified_at is not None:
        return {"domain": row.registrable_domain, "verified": True, "already": True}
    if not row.verification_token:
        raise HTTPException(409, "no verification challenge issued — request one first")

    ok = _verify_domain_control(
        row.registrable_domain, row.verification_token, method=row.verification_method or "txt"
    )
    if not ok:
        raise HTTPException(
            422,
            "We can't see the DNS record yet. Double-check it matches the one shown "
        )
    row.verified_at = datetime.now(UTC)
    session.add(
        AuditEvent(
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action="domain.verified",
            target_type="domain",
            target_id=row.id,
            detail={"domain": row.registrable_domain},
        )
    )
    await session.commit()
    return {"domain": row.registrable_domain, "verified": True}


@router.get("/tenant")
async def current_tenant(principal: ActiveUser, session: Session) -> dict:
    """The signed-in user's tenant — its name, plan and registered domains.

    The dashboard shows this instead of guessing the domain from a mailbox, so a
    tenant with no mailbox connected yet still displays who they are."""
    tenant = await session.get(Tenant, principal.tenant_id)
    domains = (
        (
            await session.execute(
                select(Domain)
                .where(Domain.tenant_id == principal.tenant_id)
                .order_by(Domain.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    ends = tenant.trial_ends_at if tenant else None
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_days_left = (
        max(0, (ends - now).days + (1 if (ends - now).seconds else 0)) if ends else None
    )
    trial_active = bool(ends and ends > now)
    paid = tenant.payment_method_ok if tenant else False
    subscribed_plan = tenant.plan if tenant else "guard"
    # Entitlement is the trial plan while the trial runs (or once a card is on
    # file); when the trial lapses unpaid, the tenant is relegated to Guard (free)
    # rather than losing access entirely (PRD §12.3 — Guard is free forever).
    effective_plan = subscribed_plan if (trial_active or paid) else "guard"
    mailbox_used = await _mailbox_count(session, principal.tenant_id) if tenant else 0
    mailbox_capacity = _mailbox_capacity(tenant) if tenant else 0
    # Colleagues who self-registered and are awaiting an admin's approval. Surfaced
    # so the dashboard can alert an admin that someone is waiting (the admin isn't
    # otherwise told). 0 for members (they can't approve anyway).
    pending_members = (
        int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(User)
                    .where(
                        User.tenant_id == principal.tenant_id,
                        User.status == "pending",
                    )
                )
            ).scalar_one()
        )
        if tenant
        else 0
    )
    return {
        "tenant_id": str(principal.tenant_id),
        "name": tenant.name if tenant else None,
        "plan": effective_plan,
        "subscribed_plan": subscribed_plan,
        "pending_members": pending_members,
        "trial_ended": bool(ends and not trial_active and not paid),
        "mailboxes": {
            "used": mailbox_used,
            "capacity": mailbox_capacity,
            "included": included_mailbox_seats(effective_plan),
            "extra_seats": tenant.extra_mailbox_seats if tenant else 0,
            "can_add": mailbox_used < mailbox_capacity,
        },
        "trial": {
            "started_at": tenant.trial_started_at.isoformat()
            if tenant and tenant.trial_started_at
            else None,
            "ends_at": ends.isoformat() if ends else None,
            "days_left": trial_days_left,
            "active": bool(ends and ends > now),
            "payment_method_ok": tenant.payment_method_ok if tenant else False,
        },
        "domains": [
            {
                "name": d.name,
                "registrable_domain": d.registrable_domain,
                "verified": d.verified_at is not None,
                "is_defensive": d.is_defensive,
            }
            for d in domains
        ],
        "primary_domain": domains[0].registrable_domain if domains else None,
    }


_SELECTABLE_PLANS = {"guard", "essential", "complete", "solo"}


class ChangePlanRequest(BaseModel):
    plan: str = Field(description="Target subscribed plan")


@router.post("/tenant/plan")
async def change_plan(req: ChangePlanRequest, principal: OwnerUser, session: Session) -> dict:
    """Change the tenant's subscribed plan (upgrade/downgrade).

    Only the owner can change what the company pays for. Moving to any paid tier
    requires either an active trial or a payment method on file — otherwise we'd
    be handing out paid protection for free. Downgrading to Guard (free) is always
    allowed. Real card capture happens in the billing/confirm flow; this records
    the *chosen* plan, which `current_tenant` then resolves into the effective
    entitlement (Guard once a trial lapses unpaid).
    """
    target = req.plan.strip().lower()
    if target not in _SELECTABLE_PLANS:
        raise HTTPException(422, f"unknown plan: {req.plan}")

    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None:
        raise HTTPException(404, "tenant not found")

    now = datetime.now(UTC)
    ends = tenant.trial_ends_at
    if ends is not None and ends.tzinfo is None:
        ends = ends.replace(tzinfo=UTC)
    trial_active = bool(ends and ends > now)

    is_paid_target = target not in ("guard",)
    if is_paid_target and not (trial_active or tenant.payment_method_ok):
        raise HTTPException(
            402,
            "add a payment method to move to a paid plan — your trial has ended",
        )

    tenant.plan = target
    await session.commit()

    subscribed_plan = tenant.plan
    effective_plan = subscribed_plan if (trial_active or tenant.payment_method_ok) else "guard"
    return {
        "subscribed_plan": subscribed_plan,
        "plan": effective_plan,
        "payment_method_ok": tenant.payment_method_ok,
        "trial_active": trial_active,
    }


class DeleteTenantRequest(BaseModel):
    password: str = Field(max_length=256)
    mfa_code: str | None = Field(default=None, pattern=r"^\d{6}$")


@router.delete("/tenant")
async def delete_tenant(req: DeleteTenantRequest, principal: OwnerUser, session: Session) -> dict:
    """Full account deletion (PRD §15.2). Confirmed with the current password (and
    a TOTP code when MFA is on), then removes the tenant and every row scoped to
    it — mailboxes, credentials, messages, alerts, the audit trail, users.

    The **domain trial ledger is deliberately kept** (PRD §12.7): its permanence is
    the anti-abuse mechanism. So an owner who deletes their account after using the
    trial and later returns gets no fresh trial — they subscribe from the start.
    """
    user = await session.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")
    if not verify_password(req.password, user.password_hash or dummy_hash()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "password is incorrect")
    if user.mfa_enabled and (
        not req.mfa_code or not verify_totp(user.totp_secret or "", req.mfa_code)
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authenticator code is incorrect")

    tid = principal.tenant_id
    # Capture the account ids first — their sessions are revoked after the rows go.
    user_ids = [
        u for (u,) in (await session.execute(select(User.id).where(User.tenant_id == tid))).all()
    ]

    # Children before parents. DomainTrialLedger is intentionally NOT in this list.
    for stmt in (
        delete(Finding).where(Finding.tenant_id == tid),
        delete(NotificationDelivery).where(NotificationDelivery.tenant_id == tid),
        delete(BankRecord).where(BankRecord.tenant_id == tid),
        delete(SenderProfile).where(SenderProfile.tenant_id == tid),
        delete(Message).where(Message.tenant_id == tid),
        delete(SensorSession).where(SensorSession.tenant_id == tid),
        delete(MailboxCredential).where(MailboxCredential.tenant_id == tid),
        delete(Alert).where(Alert.tenant_id == tid),
        delete(Counterparty).where(Counterparty.tenant_id == tid),
        delete(Mailbox).where(Mailbox.tenant_id == tid),
        delete(LookalikeDomain).where(LookalikeDomain.tenant_id == tid),
        delete(PushSubscription).where(PushSubscription.tenant_id == tid),
        delete(UsageMeter).where(UsageMeter.tenant_id == tid),
        delete(Invoice).where(Invoice.tenant_id == tid),
        delete(Domain).where(Domain.tenant_id == tid),
        delete(AuditEvent).where(AuditEvent.tenant_id == tid),
        delete(User).where(User.tenant_id == tid),
        delete(Tenant).where(Tenant.id == tid),
    ):
        await session.execute(stmt)
    # Deleting the rows doesn't kill the sessions: outstanding tokens stay
    # signature-valid for their TTL. Revoke every deleted user's family so a
    # token from the deleted account is dead now, not in fifteen minutes.
    import time as _time

    from envelock.auth.security import REFRESH_TTL as _REFRESH_TTL
    from envelock.security.limits import active_revocations as _revocations

    for uid in user_ids:
        await _revocations().arevoke_user(
            str(uid), until=_time.time() + _REFRESH_TTL.total_seconds()
        )
    await session.commit()
    return {"deleted": True, "domain_ledger_retained": True}


# ── Mailboxes ────────────────────────────────────────────────────────────────
class MailboxRequest(BaseModel):
    address: str
    #: The person's real name. Feeds the exec-impersonation detection (A5b):
    #: "an email using the name of someone at your company, sent from an outside
    #: address" can only fire on names we know — and this was only settable via
    #: a later PATCH nobody called, so the detection was starved by default.
    display_name: str | None = Field(default=None, max_length=255)
    mailbox_class: MailboxClass = MailboxClass.MONITORED
    is_shared: bool = False
    known_user_count: int = 1

    # NOTE: `sources` is deliberately NOT accepted here. Coverage is *derived*
    # from what is actually connected (PRD P4), and letting the caller declare
    # its own sources let a mailbox be created reading "Full protection, zero
    # inactive detections" while nothing was ingesting a single message — the
    # one thing this product must never show. Sources are written only by the
    # connect endpoints, after a real credential has proven itself.


def _mailbox_payload(m: Mailbox) -> dict:
    sources = frozenset(SourceMechanism(s) for s in (m.sources or []) if s)
    caps = capabilities_for(sources)
    return {
        "id": str(m.id),
        "address": m.address,
        "mailbox_class": m.mailbox_class,
        "sources": m.sources or [],
        "protection_level": protection_level(caps).value,
        # The explainer: why this level, and exactly what raises it. Keeps
        # "Standard" from reading as broken when it is the honest ceiling of the
        # connected sources (P4/E7). Distinct from the billing plan/trial, which
        # is tenant-level (see GET /tenant).
        "protection": protection_advice(sources),
        "inactive_detections": inactive_for(caps),
        "is_shared": m.is_shared,
        "last_sync_at": m.last_sync_at.isoformat() if m.last_sync_at else None,
        "needs_reconnect": m.needs_reconnect,
        "connection_error": m.connection_error,
        "silent_access_armed": bool(m.silent_access_armed),
        # Split custody: work the API handed to the worker and is waiting on.
        "sync_pending": m.sync_requested_at is not None,
        "backfill_pending": m.backfill_requested_at is not None,
        "backfill_state": m.backfill_state,
    }


@router.post("/mailboxes", status_code=201)
async def add_mailbox(req: MailboxRequest, principal: AdminUser, session: Session) -> dict:
    tenant = await _tenant_or_404(session, principal.tenant_id)
    # Trust boundary: only mailboxes on a domain the tenant has DNS-verified can be
    # added, so no one can point Envelock at an address they don't own. Same rule
    # the connect step enforces — applied here so a bogus record can't even be made.
    await _require_verified_domain(session, principal.tenant_id, req.address)
    # Don't charge a seat for a mailbox we already have (idempotent re-add).
    existing = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                func.lower(Mailbox.address) == req.address.lower(),
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return _mailbox_payload(existing)  # idempotent — no new seat charged
    await _require_mailbox_capacity(session, tenant, adding=1)
    caps = capabilities_for(frozenset())  # no source yet — added, then connected
    mailbox = Mailbox(
        tenant_id=principal.tenant_id,
        address=req.address.lower(),
        display_name=(req.display_name or "").strip() or None,
        mailbox_class=req.mailbox_class.value,
        sources=[],  # earned by connecting, never declared (see MailboxRequest)
        protection_level=protection_level(caps).value,
        inactive_detections=inactive_for(caps),
        is_shared=req.is_shared,
        known_user_count=req.known_user_count,
    )
    session.add(mailbox)
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address, "event": "added"},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


class BulkMailboxRequest(BaseModel):
    #: Paste a whole team at once — one call instead of adding 50 people by hand.
    addresses: list[str] = Field(min_length=1, max_length=1000)
    mailbox_class: MailboxClass = MailboxClass.MONITORED


@router.post("/mailboxes/bulk", status_code=201)
async def add_mailboxes_bulk(
    req: BulkMailboxRequest, principal: AdminUser, session: Session
) -> dict:
    """Add many mailboxes in one request — the path for a whole finance team or a
    50-seat domain, instead of adding each address by hand. Idempotent: addresses
    that already exist (or repeat within the paste) are skipped, not duplicated."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    _require_mailbox_entitlement(tenant)

    # Trust boundary (see _verified_registrable_domains): every pasted address must
    # sit on a domain the tenant has verified. Foreign-domain addresses are skipped
    # with a reason, never added — one paste can't smuggle in someone else's mail.
    verified = await _verified_registrable_domains(session, principal.tenant_id)

    existing = {
        addr.lower()
        for (addr,) in (
            await session.execute(
                select(Mailbox.address).where(Mailbox.tenant_id == principal.tenant_id)
            )
        ).all()
    }
    caps = capabilities_for(frozenset())  # no source yet — added, then connected
    level = protection_level(caps).value
    inactive = inactive_for(caps)

    # Only add up to the plan's remaining seats; the rest are reported so the admin
    # can buy more seats rather than silently getting free protection.
    remaining = max(0, _mailbox_capacity(tenant) - len(existing))

    created: list[Mailbox] = []
    skipped: list[dict] = []
    over_limit = 0
    seen: set[str] = set()
    for raw in req.addresses:
        addr = raw.strip().lower()
        if not addr:
            continue
        if "@" not in addr or "." not in addr.split("@")[-1]:
            skipped.append({"address": raw.strip(), "reason": "not a valid email address"})
            continue
        if not _mail_domain_allowed(addr, verified):
            skipped.append(
                {
                    "address": addr,
                    "reason": "domain not verified — you can only add mailboxes "
                    "on a domain you control",
                }
            )
            continue
        if addr in existing or addr in seen:
            skipped.append({"address": addr, "reason": "already added"})
            continue
        if remaining <= 0:
            over_limit += 1
            skipped.append({"address": addr, "reason": "no seat available — buy more seats"})
            continue
        remaining -= 1
        seen.add(addr)
        mailbox = Mailbox(
            tenant_id=principal.tenant_id,
            address=addr,
            mailbox_class=req.mailbox_class.value,
            sources=[],
            protection_level=level,
            inactive_detections=inactive,
        )
        session.add(mailbox)
        created.append(mailbox)

    if created:
        await alert_svc.record_audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=alert_svc.AuditAction.MAILBOX_CONNECTED,
            target_type="mailbox",
            detail={"bulk_added": len(created), "class": req.mailbox_class.value},
        )
    await session.commit()
    return {
        "created": [_mailbox_payload(m) for m in created],
        "skipped": skipped,
        "created_count": len(created),
        "skipped_count": len(skipped),
        # >0 means the paste exceeded the plan's seats — the client prompts to buy.
        "over_limit_count": over_limit,
        "capacity": _mailbox_capacity(tenant),
    }


async def _member_mailbox_ids(session: AsyncSession, actor) -> list[UUID]:  # noqa: ANN001
    """The mailbox ids a member may see — the ones addressed to them. Empty if
    they own none. Admins/owners are never restricted (caller checks is_member)."""
    rows = await session.execute(
        select(Mailbox.id).where(
            Mailbox.tenant_id == actor.tenant_id, Mailbox.address == actor.email
        )
    )
    return [mid for (mid,) in rows.all()]


@router.get("/mailboxes")
async def list_mailboxes(actor: ActiveUser, session: Session) -> dict:
    query = select(Mailbox).where(Mailbox.tenant_id == actor.tenant_id)
    # A member sees only their own mailbox (PRD §15.1); admins see the domain.
    if actor.is_member:
        query = query.where(Mailbox.address == actor.email)
    rows = (await session.execute(query)).scalars().all()
    return {"mailboxes": [_mailbox_payload(m) for m in rows]}


async def _mailbox_or_404(session: AsyncSession, mailbox_id: UUID, tenant_id: UUID) -> Mailbox:
    mailbox = await session.get(Mailbox, mailbox_id)
    if mailbox is None or mailbox.tenant_id != tenant_id:
        raise HTTPException(404, "mailbox not found")
    return mailbox


class ImapConnectRequest(BaseModel):
    #: Optional. Left blank, we discover the server from the address (SRV records,
    #: the provider's autoconfig, MX, then conventional names) and fall back
    #: through the candidates until one signs in — the single biggest cause of a
    #: failed IMAP connection is a hostname or TLS mode typed slightly wrong.
    imap_host: str | None = Field(default=None, max_length=253)
    imap_port: int | None = Field(default=None, ge=1, le=65535)
    #: Transport security — we don't assume 993/implicit-TLS, since many ISP servers
    #: use STARTTLS on 143. "ssl" | "starttls" | "none".
    security: Literal["ssl", "starttls", "none"] | None = None
    #: Login username, when it isn't the mailbox address (some providers).
    username: str | None = Field(default=None, max_length=320)
    #: The mailbox password, or (preferred) an app-specific password. Sealed with
    #: envelope encryption and never returned or logged (PRD §5.2).
    password: str = Field(min_length=1, max_length=1024)
    #: Set false to use ONLY the settings given above, with no fallback. Default
    #: true: an explicit host is tried first, then the discovered alternatives.
    autodiscover: bool = True
    #: SHA-256 of a server certificate the customer has looked at and approved,
    #: lowercase hex. Sent only after a `certificate_error` response showed them
    #: what the server presented — its names, issuer and expiry — so this is an
    #: informed decision about one specific certificate, not a blanket "trust
    #: anything" switch. With it set we verify the certificate is byte-for-byte
    #: the approved one instead of checking the public CA chain, which is
    #: narrower than normal verification, not looser: a machine-in-the-middle
    #: holding a certificate a CA *would* vouch for is still refused.
    accept_certificate_sha256: str | None = Field(
        default=None, min_length=64, max_length=64, pattern=r"^[0-9a-fA-F]{64}$"
    )


def _preferred_candidate(req: ImapConnectRequest):  # noqa: ANN202 — Candidate | None
    """The settings the customer typed, if they typed any."""
    from envelock.channels.mail.imap_discovery import Candidate

    host = (req.imap_host or "").strip().lower().rstrip(".")
    if not host:
        return None
    security = req.security or ("starttls" if req.imap_port in (143, 1143) else "ssl")
    port = req.imap_port or (993 if security == "ssl" else 143)
    return Candidate(host=host, port=port, security=security, source="entered", confidence=1000)


async def _probe_imap(mailbox: Mailbox, req: ImapConnectRequest):  # noqa: ANN202 — ProbeResult
    """Run the connect ladder for this mailbox's address."""
    from envelock.channels.mail import imap_probe
    from envelock.config import get_settings

    settings = get_settings()
    preferred = _preferred_candidate(req)
    pin = (req.accept_certificate_sha256 or "").lower() or None
    # A pinned or explicitly-pinned-settings attempt dials exactly one server, so
    # it can afford to wait as long as a desktop client would. The short default
    # exists only to keep a whole ladder inside one request.
    timeout = (
        settings.imap_probe_timeout_seconds * 2
        if (pin or not req.autodiscover)
        else settings.imap_probe_timeout_seconds
    )
    if not req.autodiscover:
        if preferred is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "enter an IMAP server, or leave it blank to detect it automatically",
            )
        return await asyncio.to_thread(
            imap_probe.probe_sync,
            [preferred],
            email=mailbox.address,
            username=req.username,
            password=req.password,
            timeout=timeout,
            max_candidates=1,
            pin_sha256=pin,
        )
    return await imap_probe.probe(
        email=mailbox.address,
        password=req.password,
        username=req.username,
        preferred=preferred,
        timeout=timeout,
        max_candidates=settings.imap_probe_max_candidates,
        pin_sha256=pin,
    )


async def _certificate_for(result, req: ImapConnectRequest) -> dict | None:  # noqa: ANN001
    """What the server presented, when the reason we failed was its certificate.

    A bare "we could not verify the certificate" leaves the customer with
    nothing to act on. Showing the names it covers, who issued it and when it
    expires is what turns an impasse into a decision they can actually make —
    and it is the same information a desktop mail client puts in its exception
    dialog. Returned only for a certificate failure, and it involves no
    credential: we open a second connection purely to look.
    """
    from envelock.channels.mail.imap_errors import ImapErrorCode
    from envelock.channels.mail.imap_tls import inspect_certificate

    failure = result.failure
    if failure is None or failure.code is not ImapErrorCode.CERTIFICATE_ERROR:
        return None
    attempted = result.attempts[-1].candidate if result.attempts else _preferred_candidate(req)
    if attempted is None:
        return None

    info = await asyncio.to_thread(
        inspect_certificate,
        attempted.host,
        attempted.port,
        timeout=8.0,
        starttls=attempted.security == "starttls",
    )
    return info.as_dict() if info else None


@router.get("/mailboxes/{mailbox_id}/connect/imap/settings")
async def discover_imap_settings(
    mailbox_id: UUID, principal: AdminUser, session: Session
) -> dict:
    """What IMAP settings this mailbox most likely needs — no password involved.

    Powers the connect form's "Find my settings" button, so the customer sees the
    right server prefilled instead of guessing and then failing to connect. The
    full ladder is returned (not only the winner) because a support conversation
    goes much faster when both sides can see what was tried.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    from envelock.channels.mail.imap_discovery import discover_safely

    candidates = await discover_safely(mailbox.address)
    best = candidates[0] if candidates else None
    return {
        "address": mailbox.address,
        "detected": bool(candidates) and best is not None and best.source != "convention",
        "settings": best.as_dict() if best else None,
        "candidates": [c.as_dict() for c in candidates[:8]],
        "note": (
            "Detected from your domain's mail records."
            if best is not None and best.source in ("dns-srv", "autoconfig", "autodiscover")
            else "Best guess from your mail provider — we will try the alternatives "
            "automatically if it doesn't work."
        ),
    }


@router.post("/mailboxes/{mailbox_id}/connect/imap/test")
async def test_imap(
    mailbox_id: UUID, req: ImapConnectRequest, principal: AdminUser, session: Session
) -> dict:
    """Verify the IMAP server/port/security/username/password without storing
    anything — the connect form's "Test connection" button. Same tenant scoping
    as the real connect, so it can't probe another tenant's mailbox."""
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    result = await _probe_imap(mailbox, req)
    payload = result.as_dict()
    # `reason` stays for older clients; `error` carries the code + fix.
    payload["reason"] = (
        "Signed in successfully."
        if result.ok
        else (result.failure.reason if result.failure else "")
    )
    payload["certificate"] = await _certificate_for(result, req)
    return payload


@router.post("/mailboxes/{mailbox_id}/connect/imap")
async def connect_imap(
    mailbox_id: UUID, req: ImapConnectRequest, principal: AdminUser, session: Session
) -> dict:
    """Connect a mailbox over IMAP by storing its credentials, envelope-encrypted.

    This is the path for any provider without OAuth — most ISP and custom-domain
    mail. Protected mailboxes hold an IDLE connection (quarantine latency is the
    product); Monitored mailboxes poll (PRD §12.11D)."""
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    await _require_verified_domain(session, principal.tenant_id, mailbox.address)

    # Prove the credentials work before storing them. Reporting "connected" on a
    # wrong password (then silently ingesting nothing) is worse than an error.
    # We store whatever settings actually SIGNED IN, which may not be the ones
    # that were typed — that is the point of the fallback ladder.
    result = await _probe_imap(mailbox, req)
    if not result.ok or result.candidate is None:
        failure = result.failure
        certificate = await _certificate_for(result, req)
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            # A dict detail, not a string, when there is a certificate to show:
            # the customer cannot decide whether to trust a certificate they
            # have not been shown, and this is the only place they can see it.
            {
                "message": failure.reason if failure else "could not connect to the mail server",
                "code": failure.code.value if failure else "unknown",
                "certificate": certificate,
            }
            if certificate
            else (failure.reason if failure else "could not connect to the mail server"),
            headers={"X-Envelock-Imap-Error": failure.code.value if failure else "unknown"},
        )

    host = result.candidate.host
    port = result.candidate.port
    security = result.candidate.security
    # The username that worked — the local part, when the full address did not.
    login_user = result.username or (req.username or mailbox.address).strip()
    stored_username = None if login_user == mailbox.address else login_user

    # Only remember a pin that was actually needed. Storing one from a
    # connection that verified normally would silently downgrade that mailbox to
    # pinned verification, and it would then break at the server's next routine
    # certificate renewal for no reason.
    pin = (req.accept_certificate_sha256 or "").lower() or None

    sealed = seal(req.password.encode(), aad=str(mailbox.id).encode())
    existing = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    if existing is None:
        session.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=principal.tenant_id,
                kind="imap_password",
                imap_host=host,
                imap_port=port,
                imap_security=security,
                imap_username=stored_username,
                imap_cert_sha256=pin,
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
    else:
        # A reconnect re-runs discovery and may land on a different server; a UID
        # cursor is only meaningful for the server that issued it, so drop it
        # when the host changes.
        if existing.imap_host != host:
            existing.imap_last_uid = None
            existing.imap_uidvalidity = None
        existing.kind = "imap_password"
        existing.imap_host = host
        existing.imap_port = port
        existing.imap_security = security
        existing.imap_username = stored_username
        # A reconnect that did not need a pin clears the old one, so a mailbox
        # never keeps pinned verification after its certificate is fixed.
        existing.imap_cert_sha256 = pin
        existing.ciphertext = sealed.ciphertext
        existing.wrapped_dek = sealed.wrapped_dek
        existing.key_id = sealed.key_id

    # Protected → IDLE (real-time, can quarantine); Monitored → poll.
    source = (
        SourceMechanism.IMAP_IDLE
        if mailbox.mailbox_class == MailboxClass.PROTECTED.value
        else SourceMechanism.IMAP_POLL
    )
    mailbox.sources = sorted(set(mailbox.sources or []) | {source.value})
    mailbox.integration_tier = int(IntegrationTier.IMAP)
    caps = capabilities_for(frozenset(SourceMechanism(s) for s in mailbox.sources))
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)
    # Credentials were just re-verified and re-sealed under the current key, so
    # any prior "needs reconnect" state is resolved.
    mailbox.needs_reconnect = False
    mailbox.connection_error = None

    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={
            "address": mailbox.address,
            "method": "imap",
            "host": host,
            "port": port,
            "security": security,
            "discovered_via": result.candidate.source,
        },
    )
    await session.commit()
    payload = _mailbox_payload(mailbox)
    payload["imap"] = {
        "host": host,
        "port": port,
        "security": security,
        "username": login_user,
        "discovered_via": result.candidate.source,
    }
    return payload


@router.post("/mailboxes/{mailbox_id}/sync")
async def sync_mailbox_now(mailbox_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Poll a connected IMAP mailbox immediately instead of waiting for the next
    background cycle. This is the "Sync now" button — connect a mailbox, send a
    test message, click this, and any new mail is fetched and run through the full
    detection pipeline right now. Returns what was fetched, flagged and quarantined."""
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    if not any(
        s in {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}
        for s in (mailbox.sources or [])
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "this mailbox is not connected over IMAP — connect it first",
        )
    from envelock.security.keys import custody_summary

    if not custody_summary().get("can_decrypt"):
        # Split custody: this process holds only the sealing key and cannot open
        # the credential. Calling `sync_mailbox` here used to hit that as an
        # ordinary decryption failure — the same error a dead credential raises
        # — so it marked a perfectly healthy mailbox "reconnect required" and
        # told the customer their stored password was broken. Hand the request
        # to the worker, which can open it, and say so.
        mailbox.sync_requested_at = datetime.now(UTC)
        await session.commit()
        return {
            "ok": True,
            "queued": True,
            "fetched": 0,
            "message": "Sync queued — new mail will be checked within a minute.",
        }

    from envelock.workers.imap_fetch import sync_mailbox

    summary = await sync_mailbox(session, mailbox)
    if not summary.get("ok"):
        # Not a server error — a reachable-but-failing poll (bad creds, unreachable
        # host). Surface the reason so the user can fix the connection.
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"could not sync mailbox — {summary.get('reason', 'unknown error')}",
        )
    return summary


@router.post("/mailboxes/{mailbox_id}/connect/forward")
async def connect_forward(mailbox_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Mark a mailbox as connected by mail forwarding.

    The customer has set a forwarding rule to their ingest address; this records
    it so the mailbox reads as covered. Forwarding arrives *post-delivery*, so it
    is alert-only — it can never quarantine (PRD §4 fn.3) — which is why the
    protection level lands at Limited. That is the honest ceiling of this path,
    not a bug.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    await _require_verified_domain(session, principal.tenant_id, mailbox.address)
    mailbox.sources = sorted(set(mailbox.sources or []) | {SourceMechanism.FORWARD_INGEST.value})
    mailbox.integration_tier = int(IntegrationTier.FORWARDING)
    mailbox.last_sync_at = datetime.now(UTC)
    caps = capabilities_for(frozenset(SourceMechanism(s) for s in mailbox.sources))
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)

    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action=alert_svc.AuditAction.MAILBOX_CONNECTED,
        target_type="mailbox",
        target_id=mailbox.id,
        detail={"address": mailbox.address, "method": "forwarding"},
    )
    await session.commit()
    return _mailbox_payload(mailbox)


class MailboxPatchRequest(BaseModel):
    """What a customer may change about an existing mailbox."""

    mailbox_class: MailboxClass | None = None
    display_name: str | None = Field(default=None, max_length=255)
    is_shared: bool | None = None
    known_user_count: int | None = Field(default=None, ge=1, le=500)
    #: C11 silent-access detection. See `Mailbox.silent_access_armed` for why it
    #: is opt-in: only the person who knows where this mailbox is read can say
    #: whether an unvouched read means an intruder or just a phone.
    silent_access_armed: bool | None = None


@router.patch("/mailboxes/{mailbox_id}")
async def update_mailbox(
    mailbox_id: UUID, req: MailboxPatchRequest, principal: AdminUser, session: Session
) -> dict:
    """Change a mailbox in place — most importantly its class.

    Moving Monitored → Protected previously meant deleting the mailbox and adding
    it again, which threw away its stored credential, its sync cursor and its
    alert history, and forced the customer to re-enter a password to buy an
    upgrade. The class also drives the IMAP strategy (Protected holds IDLE and
    can quarantine; Monitored polls), so the source is re-derived here rather
    than left pointing at the old one.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    before = mailbox.mailbox_class

    if req.display_name is not None:
        mailbox.display_name = req.display_name.strip() or None
    if req.is_shared is not None:
        mailbox.is_shared = req.is_shared
    if req.known_user_count is not None:
        mailbox.known_user_count = req.known_user_count

    if (
        req.silent_access_armed is not None
        and req.silent_access_armed != bool(mailbox.silent_access_armed)
    ):
        mailbox.silent_access_armed = req.silent_access_armed
        # Forget any remembered unread set. It was taken while the detection was
        # off, and comparing against it would report every read since then as
        # happening now — a burst of false alarms the moment it is switched on.
        credential = (
            await session.execute(
                select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
            )
        ).scalar_one_or_none()
        if credential is not None:
            credential.imap_unseen_uids = None
        await alert_svc.record_audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=(
                alert_svc.AuditAction.SILENT_ACCESS_ARMED
                if req.silent_access_armed
                else alert_svc.AuditAction.SILENT_ACCESS_DISARMED
            ),
            target_type="mailbox",
            target_id=mailbox.id,
            detail={"address": mailbox.address},
        )

    if req.mailbox_class is not None and req.mailbox_class.value != before:
        # No capacity check: a seat is consumed per MAILBOX, not per class
        # (_mailbox_capacity / _mailbox_count), so this mailbox already holds
        # one and promoting it takes nothing further. The entitlement check
        # still applies — a lapsed tenant should not be able to promote.
        tenant = await _tenant_or_404(session, principal.tenant_id)
        _require_mailbox_entitlement(tenant)
        mailbox.mailbox_class = req.mailbox_class.value

        # Re-derive the connection source: the class IS the IMAP strategy.
        sources = set(mailbox.sources or [])
        if sources & {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}:
            sources -= {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}
            sources.add(
                SourceMechanism.IMAP_IDLE.value
                if req.mailbox_class is MailboxClass.PROTECTED
                else SourceMechanism.IMAP_POLL.value
            )
            mailbox.sources = sorted(sources)

    caps = capabilities_for(
        frozenset(SourceMechanism(x) for x in (mailbox.sources or []))
    )
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)

    if req.mailbox_class is not None and req.mailbox_class.value != before:
        await alert_svc.record_audit(
            session,
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=alert_svc.AuditAction.SETTINGS_CHANGED,
            target_type="mailbox",
            target_id=mailbox.id,
            detail={
                "address": mailbox.address,
                "mailbox_class": {"from": before, "to": mailbox.mailbox_class},
            },
        )
    await session.commit()
    return _mailbox_payload(mailbox)


@router.get("/mailboxes/{mailbox_id}/activity")
async def mailbox_activity(mailbox_id: UUID, actor: ActiveUser, session: Session) -> dict:
    """What has actually happened on this mailbox — so IT can see it is protected,
    not just wait for an alert. Connection events, coverage, and running counts of
    messages scanned and alerts raised."""
    mailbox = await _mailbox_or_404(session, mailbox_id, actor.tenant_id)
    if actor.is_member and mailbox.address != actor.email:
        raise HTTPException(404, "mailbox not found")

    events = (
        (
            await session.execute(
                select(AuditEvent)
                .where(
                    AuditEvent.tenant_id == actor.tenant_id,
                    AuditEvent.target_id == mailbox.id,
                )
                .order_by(AuditEvent.created_at.desc())
                .limit(50)
            )
        )
        .scalars()
        .all()
    )
    messages_scanned = (
        await session.execute(
            select(func.count()).select_from(Message).where(Message.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    alerts_raised = (
        await session.execute(
            select(func.count()).select_from(Alert).where(Alert.mailbox_id == mailbox.id)
        )
    ).scalar_one()

    caps = capabilities_for(frozenset(SourceMechanism(s) for s in (mailbox.sources or []) if s))
    connected = any(s in _MAIL_SOURCES for s in (mailbox.sources or []))
    return {
        "address": mailbox.address,
        "connected": connected,
        "protection_level": protection_level(caps).value,
        "sources": mailbox.sources or [],
        "inactive_detections": inactive_for(caps),
        "last_sync_at": mailbox.last_sync_at.isoformat() if mailbox.last_sync_at else None,
        "messages_scanned": messages_scanned,
        "alerts_raised": alerts_raised,
        "events": [
            {"action": e.action, "at": e.created_at.isoformat(), "detail": e.detail} for e in events
        ],
    }


@router.delete("/mailboxes/{mailbox_id}")
async def remove_mailbox(mailbox_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Disconnect and remove a mailbox and everything that hangs off it.

    A mailbox is the parent of messages, findings, sensor sessions and its stored
    credential; deleting it while those rows exist violates their foreign keys and
    500s (the reported bug). We remove them in FK-safe order — children first —
    and deliberately *keep* alerts as the customer's incident record, detaching
    them from the mailbox rather than deleting the history.
    """
    mailbox = await _mailbox_or_404(session, mailbox_id, principal.tenant_id)
    address = mailbox.address
    mid = mailbox.id

    # Findings reference messages and alerts, so they go first. Catch both the
    # ones tagged with this mailbox and any tied to its messages.
    msg_ids = select(Message.id).where(Message.mailbox_id == mid)
    await session.execute(
        delete(Finding).where(or_(Finding.mailbox_id == mid, Finding.message_id.in_(msg_ids)))
    )
    await session.execute(delete(Message).where(Message.mailbox_id == mid))
    await session.execute(delete(SensorSession).where(SensorSession.mailbox_id == mid))
    await session.execute(delete(MailboxCredential).where(MailboxCredential.mailbox_id == mid))
    # Preserve the incident record — detach alerts instead of deleting them.
    await session.execute(update(Alert).where(Alert.mailbox_id == mid).values(mailbox_id=None))
    await session.delete(mailbox)
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="mailbox.removed",
        target_type="mailbox",
        detail={"address": address},
    )
    await session.commit()
    return {"removed": True, "address": address}


# ── Team / membership (PRD §15.1) ────────────────────────────────────────────
async def _seat_usage(session: AsyncSession, tenant: Tenant) -> dict:
    """Guard (free) is owner-only. On a trial or paid plan, team logins (everyone
    except the owner) are capped at the number of protected mailboxes — one login
    per protected seat."""
    protected = (
        await session.execute(
            select(func.count())
            .select_from(Mailbox)
            .where(
                Mailbox.tenant_id == tenant.id,
                Mailbox.mailbox_class == MailboxClass.PROTECTED.value,
            )
        )
    ).scalar_one()
    # A seat is consumed by an ACTIVE login. Pending join-requests don't burn a
    # paid seat — the seat is spent only when an admin actually grants access.
    team_used = (
        await session.execute(
            select(func.count())
            .select_from(User)
            .where(
                User.tenant_id == tenant.id,
                User.role != Role.OWNER.value,
                User.status == "active",
            )
        )
    ).scalar_one()
    entitled = _mailbox_entitled(tenant)
    cap = protected if entitled else 0
    return {"used": team_used, "cap": cap, "entitled": entitled, "protected_mailboxes": protected}


async def _is_protected_mailbox(session: AsyncSession, tenant_id: UUID, email: str) -> bool:
    """Is this address one of the tenant's protected mailboxes — i.e. someone they
    are actually paying to protect?"""
    return bool(
        (
            await session.execute(
                select(func.count())
                .select_from(Mailbox)
                .where(
                    Mailbox.tenant_id == tenant_id,
                    func.lower(Mailbox.address) == email.lower(),
                    Mailbox.mailbox_class == MailboxClass.PROTECTED.value,
                )
            )
        ).scalar_one()
    )


async def _assert_can_grant_login(
    session: AsyncSession, tenant: Tenant, *, email: str, role: str
) -> None:
    """Gate for granting a team login — used on both create and approve.

    Three independent limits, so an admin can only give access to their own
    company's people, and only those the company is paying for:
      0. **Company domain** — the email must be on one of the tenant's registered
         domains. An admin can never create a login for an outside address.
      1. **Seats** — active logins can't exceed the number of protected mailboxes.
      2. **Protection pool** — a *member* login must be one of those protected
         mailboxes. (Admins are the company's own overseers and only the owner can
         mint them, so they're exempt from the pool check but still cost a seat.)
    """
    # 0. Must be on one of the company's own domains.
    reg = registrable_domain(email.rsplit("@", 1)[-1] if "@" in email else "")
    domains = {
        d
        for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(Domain.tenant_id == tenant.id)
            )
        ).all()
    }
    # Fail CLOSED for a corporate address: an empty domain set must not mean
    # "anything goes" — it means the tenant has no claim yet, so an external
    # non-free-mail address may not be granted. Free-mail has no domain to check.
    if reg and not is_free_mail(reg) and reg not in domains:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{email} isn't on your company's domain "
            f"({', '.join(sorted(domains))}). Team logins must use a company address.",
        )

    seats = await _seat_usage(session, tenant)
    if not seats["entitled"]:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            "team logins need an active trial or paid plan — Guard is owner-only",
        )
    if seats["used"] >= seats["cap"]:
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            f"all {seats['cap']} paid seat{'' if seats['cap'] == 1 else 's'} are in "
            "use — add a protected mailbox to open another login",
        )
    if role == Role.MEMBER.value and not await _is_protected_mailbox(session, tenant.id, email):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{email} isn't a protected mailbox in your account. Add it as a "
            "protected mailbox first — team logins are only for people you are "
            "paying to protect.",
        )


async def _ensure_login_mailbox(
    session: AsyncSession, tenant: Tenant, *, email: str, role: str
) -> None:
    """Every approved teammate is one of the mailboxes the company is paying for:
    granting access ADDS them as a protected mailbox (counted against the plan's
    seats) if they aren't one already. So "has access" always equals "a counted
    mailbox", and the seat cap is simply the plan's mailbox allowance.

    The owner is the account holder and is exempt. The email must be on the
    company's own (verified) domain — a login is never for an outside address.
    """
    if role == Role.OWNER.value:
        return
    # Must be a company address on a domain the tenant controls.
    reg = registrable_domain(email.rsplit("@", 1)[-1] if "@" in email else "")
    domains = {
        d
        for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(Domain.tenant_id == tenant.id)
            )
        ).all()
    }
    # Fail CLOSED for a corporate address: an empty domain set must not mean
    # "anything goes" — it means the tenant has no claim yet, so an external
    # non-free-mail address may not be granted. Free-mail has no domain to check.
    if reg and not is_free_mail(reg) and reg not in domains:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{email} isn't on your company's domain "
            f"({', '.join(sorted(domains))}). Team logins must use a company address.",
        )
    if await _is_protected_mailbox(session, tenant.id, email):
        return  # already a counted mailbox — nothing to add
    # Adding a mailbox is what counts them; gated by the plan's mailbox seats.
    await _require_mailbox_capacity(session, tenant, adding=1)
    caps = capabilities_for(frozenset())
    session.add(
        Mailbox(
            tenant_id=tenant.id,
            address=email.lower(),
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[],
            protection_level=protection_level(caps).value,
            inactive_detections=inactive_for(caps),
        )
    )


class CreateMemberRequest(BaseModel):
    email: EmailStr
    role: Literal["member", "admin"] = "member"


@router.post("/members", status_code=201)
async def create_member(req: CreateMemberRequest, principal: AdminUser, session: Session) -> dict:
    """Owner-provisioned access (PRD §15.1). The owner (or an admin) creates a
    teammate and hands them a one-time temporary password; they must set their own
    on first sign-in. Seat-limited by plan — see `_seat_usage`."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    if req.role == "admin" and principal.role is not Role.OWNER:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the owner can create admins")

    email = req.email.lower().strip()
    if is_disposable_email(email):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "disposable email addresses are not allowed",
        )
    if (await session.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "a user with this email already exists")

    await _assert_can_grant_login(session, tenant, email=email, role=req.role)

    temp_password = secrets.token_urlsafe(12)
    user = User(
        id=uuid4(),
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password(temp_password),
        role=req.role,
        is_admin=req.role == "admin",
        status="active",
        must_change_password=True,
        # Verified on creation, and this is not a shortcut.
        #
        # Only `/auth/register` ever sends a verification link, so with
        # ENVELOCK_REQUIRE_EMAIL_VERIFICATION on, a colleague provisioned here
        # would be handed a temporary password and then refused at sign-in
        # forever, with no way to ask for a link they were never sent. That is
        # the whole team-provisioning flow dead on the day the flag is turned on.
        #
        # Marking them verified is correct rather than merely convenient: email
        # verification exists to stop a stranger CLAIMING a company's domain, and
        # `_assert_can_grant_login` above has already established that this
        # address is on a domain this tenant has proven by DNS, granted by an
        # admin who is themselves verified. There is no claim left to squat.
        email_verified_at=datetime.now(UTC),
    )
    session.add(user)
    await session.flush()
    await alert_svc.record_audit(
        session,
        tenant_id=tenant.id,
        actor_id=principal.user_id,
        action="member.created",
        target_type="user",
        target_id=user.id,
        detail={"email": email, "role": req.role},
    )
    await session.commit()
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "temporary_password": temp_password,
        "note": "Share this once, in person or over a trusted channel. They must "
        "change it at first sign-in.",
    }


@router.get("/members")
async def list_members(principal: AdminUser, session: Session) -> dict:
    """Admins see everyone in the tenant, including colleagues awaiting approval,
    plus how many team seats the plan allows."""
    tenant = await _tenant_or_404(session, principal.tenant_id)
    rows = (
        (
            await session.execute(
                select(User)
                .where(User.tenant_id == principal.tenant_id)
                .order_by(User.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "members": [
            {
                "id": str(u.id),
                "email": u.email,
                "role": u.role,
                "status": u.status,
                "pending_password": u.must_change_password,
                "is_self": u.id == principal.user_id,
            }
            for u in rows
        ],
        "seats": await _seat_usage(session, tenant),
    }


async def _member_or_404(session: AsyncSession, user_id: UUID, tenant_id: UUID) -> User:
    user = await session.get(User, user_id)
    if user is None or user.tenant_id != tenant_id:
        raise HTTPException(404, "member not found")
    return user


@router.post("/members/{user_id}/approve")
async def approve_member(user_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Grant a pending colleague access to the workspace.

    Approval is the moment a seat is actually spent, so the same limits as
    creating a login apply here — otherwise self-registration would be a way
    around the seat cap and the protection pool."""
    user = await _member_or_404(session, user_id, principal.tenant_id)
    tenant = await _tenant_or_404(session, principal.tenant_id)
    if user.status == "active":
        return {"id": str(user.id), "email": user.email, "status": "active"}
    # Approval both grants access AND counts them: they become a protected mailbox
    # (added here if not already one), so an approved teammate always occupies one
    # of the plan's mailbox seats. Over the cap → 402 (buy more seats / upgrade).
    await _ensure_login_mailbox(session, tenant, email=user.email, role=user.role)
    user.status = "active"
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="member.approved",
        target_type="user",
        target_id=user.id,
        detail={"email": user.email},
    )
    await session.commit()
    return {"id": str(user.id), "email": user.email, "status": user.status}


@router.post("/members/{user_id}/reject")
async def reject_member(user_id: UUID, principal: AdminUser, session: Session) -> dict:
    """Remove a member (or decline a pending request). The owner cannot be removed
    and an admin cannot remove themselves."""
    user = await _member_or_404(session, user_id, principal.tenant_id)
    if user.id == principal.user_id:
        raise HTTPException(400, "you cannot remove yourself")
    if user.role == "owner":
        raise HTTPException(400, "the owner cannot be removed")
    email = user.email
    await session.delete(user)
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="member.removed",
        target_type="user",
        detail={"email": email},
    )
    await session.commit()
    return {"removed": True, "email": email}


# ── Alerts ───────────────────────────────────────────────────────────────────
def _alert_payload(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "tier": a.tier,
        "title": a.title,
        "body": a.body,
        "state": a.state,
        "mailbox_id": str(a.mailbox_id) if a.mailbox_id else None,
        "counterparty_domain": a.counterparty_domain,
        "requires_callback": a.requires_callback,
        "callback_phone": a.callback_phone,
        # AI autoflag: the judge independently confirmed this alert. Verdict word
        # only — confidence/model stay internal (PRD §16).
        "ai_flagged": bool(a.ai_flagged),
        "ai_verdict": a.ai_verdict,
        #: The sum that was about to move, on payment-fraud alerts only. Null is
        #: "no figure in the message", never zero.
        "amount_at_risk": a.amount_at_risk,
        "amount_currency": a.amount_currency,
        "created_at": a.created_at.isoformat(),
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "escalated_at": a.escalated_at.isoformat() if a.escalated_at else None,
    }


async def _assert_alert_access(session: AsyncSession, actor, alert: Alert) -> None:
    """A member may only touch alerts on their own mailbox (PRD §15.1). Return a
    404 (not 403) for out-of-scope alerts so membership isn't an oracle."""
    if not actor.is_member:
        return
    own = await _member_mailbox_ids(session, actor)
    if alert.mailbox_id not in own:
        raise HTTPException(404, "alert not found")


@router.get("/alerts")
async def list_alerts(
    actor: ActiveUser,
    session: Session,
    state: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> dict:
    query = select(Alert).where(Alert.tenant_id == actor.tenant_id)
    if actor.is_member:
        own = await _member_mailbox_ids(session, actor)
        if not own:
            return {"alerts": [], "count": 0}
        query = query.where(Alert.mailbox_id.in_(own))
    if state:
        query = query.where(Alert.state == state)
    rows = (
        (await session.execute(query.order_by(Alert.created_at.desc()).limit(limit)))
        .scalars()
        .all()
    )
    return {"alerts": [_alert_payload(a) for a in rows], "count": len(rows)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    existing = await session.get(Alert, alert_id)
    if existing is None or existing.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, existing)
    alert = await alert_svc.acknowledge(
        session, alert_id=alert_id, tenant_id=actor.tenant_id, actor_id=actor.user_id
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: UUID, actor: ActiveUser, session: Session, dismiss: bool = False
) -> dict:
    existing = await session.get(Alert, alert_id)
    if existing is None or existing.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, existing)
    alert = await alert_svc.resolve(
        session,
        alert_id=alert_id,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        dismissed=dismiss,
    )
    if alert is None:
        raise HTTPException(404, "alert not found")
    await session.commit()
    return _alert_payload(alert)


@router.post("/alerts/{alert_id}/quarantine")
async def quarantine(alert_id: UUID, actor: ActiveUser, session: Session) -> dict:
    """E2. Refuses honestly on forwarding-connected mailboxes."""
    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != actor.tenant_id:
        raise HTTPException(404, "alert not found")
    await _assert_alert_access(session, actor, alert)

    source = SourceMechanism.FORWARD_INGEST
    caps = frozenset()
    if alert.mailbox_id:
        mailbox = await session.get(Mailbox, alert.mailbox_id)
        if mailbox and mailbox.sources:
            sources = frozenset(SourceMechanism(s) for s in mailbox.sources if s)
            caps = capabilities_for(sources)
            source = next(iter(sources))

    result = plan_remediation(action=RemediationAction.QUARANTINE, capabilities=caps, source=source)
    if not result.succeeded:
        # An honest refusal — forwarding-connected, or no write access. Unchanged.
        return {
            "succeeded": False,
            "reason": result.reason,
            "alert_only": result.alert_only,
        }

    # Resolve the alert to its stored message. `Finding` rows carry both ids,
    # and the pipeline persists `Message.source_ref` (the IMAP UID) — the two
    # pieces whose absence used to make this endpoint a placeholder that always
    # answered "not available yet".
    message_id = (
        await session.execute(
            select(Finding.message_id).where(
                Finding.alert_id == alert.id, Finding.message_id.is_not(None)
            )
        )
    ).scalars().first()
    message = await session.get(Message, message_id) if message_id else None
    if message is None or not message.source_ref:
        return {
            "succeeded": False,
            "reason": (
                "This alert predates on-demand quarantine (no stored message "
                "handle). Newly analysed mail can be quarantined from here; for "
                "this one, remove the message from the mailbox directly and "
                "acknowledge the alert."
            ),
            "alert_only": False,
        }
    if message.quarantined_at is not None:
        return {"succeeded": True, "already_quarantined": True, "reason": "already quarantined"}

    from envelock.security.keys import custody_summary

    if custody_summary().get("can_decrypt"):
        # This process holds the decrypting half — act now, on the request path.
        from envelock.workers.imap_fetch import quarantine_persisted_message

        ok, why = await quarantine_persisted_message(session, message)
        if ok:
            await alert_svc.record_audit(
                session,
                tenant_id=actor.tenant_id,
                actor_id=actor.user_id,
                action=alert_svc.AuditAction.MESSAGE_QUARANTINED,
                target_type="message",
                target_id=message.id,
                detail={"alert_id": str(alert.id), "requested_by_user": True},
            )
            await session.commit()
            return {"succeeded": True, "reason": "quarantined"}
        # Fall through to queueing: a transient IMAP failure should not lose the
        # human's decision — the worker retries it on the next cycle.
        message.quarantine_requested_at = datetime.now(UTC)
        await session.commit()
        return {
            "succeeded": False,
            "queued": True,
            "reason": f"{why} — the request is queued and will be retried within a minute",
            "alert_only": False,
        }

    # Split custody: the API seals but cannot decrypt (by design — a compromised
    # web process must not be able to read the credential store). Record the
    # decision; the IMAP worker executes it on its next cycle (≤ the poll
    # interval, 60s by default).
    message.quarantine_requested_at = datetime.now(UTC)
    await alert_svc.record_audit(
        session,
        tenant_id=actor.tenant_id,
        actor_id=actor.user_id,
        action="message.quarantine_requested",
        target_type="message",
        target_id=message.id,
        detail={"alert_id": str(alert.id)},
    )
    await session.commit()
    return {
        "succeeded": False,
        "queued": True,
        "reason": "quarantine requested — the mail worker will move it within a minute",
        "alert_only": False,
    }


@router.get("/alerts/{alert_id}/ai")
async def alert_ai_verdict(alert_id: UUID, principal: AdminUser, session: Session) -> dict:
    """The AI judge's full working for one alert — admin oversight only.

    The dashboard chip and the alert body carry the plain-language line; the
    numbers (confidence, model, tokens, cost) were recorded on every call and
    readable by NOTHING, so "why did the AI (not) act?" was unanswerable. The
    detail stays off member views per the taxonomy rule (PRD §16).
    """
    from envelock.models import LlmVerdictRecord

    alert = await session.get(Alert, alert_id)
    if alert is None or alert.tenant_id != principal.tenant_id:
        raise HTTPException(404, "alert not found")
    rows = (
        (
            await session.execute(
                select(LlmVerdictRecord)
                .where(LlmVerdictRecord.alert_id == alert.id)
                .order_by(LlmVerdictRecord.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "alert_id": str(alert.id),
        "ai_flagged": bool(alert.ai_flagged),
        "verdicts": [
            {
                "verdict": r.verdict,
                "confidence": r.confidence,
                "rationale": r.rationale,
                "escalated": r.escalated,
                "rule_tier": r.rule_tier,
                "final_tier": r.final_tier,
                "provider": r.provider,
                "model": r.model,
                "input_tokens": r.input_tokens,
                "output_tokens": r.output_tokens,
                "cost_micros": r.cost_micros,
                "human_disposition": r.human_disposition,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }


# ── Oversight (E4/E5/E6) ─────────────────────────────────────────────────────
@router.get("/oversight")
async def oversight(principal: AdminUser, session: Session) -> dict:
    summary = await alert_svc.oversight_summary(session, tenant_id=principal.tenant_id)
    mailboxes = (
        (await session.execute(select(Mailbox).where(Mailbox.tenant_id == principal.tenant_id)))
        .scalars()
        .all()
    )
    domains = (
        await session.execute(
            select(func.count()).select_from(Domain).where(Domain.tenant_id == principal.tenant_id)
        )
    ).scalar_one()
    return {
        **summary,
        "mailboxes": len(mailboxes),
        "domains": domains,
        "coverage": {
            level: sum(1 for m in mailboxes if m.protection_level == level)
            for level in ("full", "standard", "limited")
        },
    }


@router.get("/audit")
async def audit_trail(
    principal: AdminUser, session: Session, limit: int = Query(default=100, ge=1, le=500)
) -> dict:
    """E5 — who read it, who acted, who ignored it."""
    rows = (
        (
            await session.execute(
                select(AuditEvent)
                .where(AuditEvent.tenant_id == principal.tenant_id)
                .order_by(AuditEvent.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return {
        "events": [
            {
                "id": str(e.id),
                "action": e.action,
                "actor_id": str(e.actor_id) if e.actor_id else None,
                "target_type": e.target_type,
                "target_id": str(e.target_id) if e.target_id else None,
                "detail": e.detail,
                "at": e.created_at.isoformat(),
            }
            for e in rows
        ]
    }


@router.get("/escalations")
async def escalations(principal: AdminUser, session: Session) -> dict:
    steps = await alert_svc.due_escalations(session, tenant_id=principal.tenant_id)
    return {
        "due": [
            {
                "alert_id": str(step.alert_id),
                "to": step.to,
                "minutes_open": step.minutes_open,
                "tier": step.tier.value,
            }
            for step in steps
        ],
        "count": len(steps),
    }


@router.post("/escalations/run")
async def run_escalations(principal: AdminUser, session: Session) -> dict:
    """Run the E6 escalation cycle for this tenant now: mark unacknowledged
    Criticals escalated to IT, and fire the paid SMS rung only where the ladder
    allows. An ops scheduler calls the same code path tenant-wide."""
    from envelock.notify.dispatch import run_escalation_cycle

    done = await run_escalation_cycle(session, tenant_id=principal.tenant_id)
    await session.commit()
    return {"escalated": done, "count": len(done)}


# ── Counterparties (E10) ─────────────────────────────────────────────────────
#: The payment schemes a customer can record. Closed set: an arbitrary string
#: here would let two spellings of the same scheme sit side by side and each
#: match nothing at detection time.
BankScheme = Literal["iban", "swift", "ach", "sortcode", "account", "crypto"]


class BankRecordRequest(BaseModel):
    scheme: BankScheme
    identifier: str = Field(min_length=4, max_length=128)
    bank_name: str | None = Field(default=None, max_length=255)
    country: str | None = Field(default=None, min_length=2, max_length=2)


class CounterpartyPhoneRequest(BaseModel):
    """A2 — the number we tell people to call.

    This is the whole point of the registry: when a supplier's bank details
    change, the alert must offer a number the ATTACKER did not supply. It was
    previously a bare query parameter with no validation, which meant it could
    be set to anything, including an empty string.
    """

    phone: str = Field(min_length=7, max_length=32, pattern=r"^\+?[0-9 ()\-]{7,31}$")


class CounterpartyRequest(BaseModel):
    """Create or update a supplier by hand, before any mail has arrived.

    Onboarding is exactly when finance knows this — they are looking at the AP
    vendor master — and it is the one moment the product can learn a supplier's
    good details from a source the attacker cannot influence.
    """

    domain: str = Field(min_length=3, max_length=253)
    display_name: str | None = Field(default=None, max_length=255)
    verified_phone: str | None = Field(
        default=None, max_length=32, pattern=r"^\+?[0-9 ()\-]{7,31}$"
    )


@router.get("/counterparties")
async def list_counterparties(principal: ActiveUser, session: Session) -> dict:
    rows = (
        (
            await session.execute(
                select(Counterparty).where(Counterparty.tenant_id == principal.tenant_id)
            )
        )
        .scalars()
        .all()
    )
    # How many verified bank records each supplier has. This was hardcoded to 0,
    # which is not a cosmetic bug: `bank_records` feeds the risk score, so a
    # supplier whose details finance had confirmed scored identically to a
    # stranger, and the registry could not affect the number it exists to move.
    count_rows = (
        await session.execute(
            select(BankRecord.counterparty_id, func.count(BankRecord.id))
            .where(
                BankRecord.tenant_id == principal.tenant_id,
                BankRecord.is_active.is_(True),
            )
            .group_by(BankRecord.counterparty_id)
        )
    ).all()
    counts: dict[UUID, int] = {row[0]: int(row[1]) for row in count_rows}

    out = []
    for c in rows:
        entry = GRAPH.lookup(c.registrable_domain)
        record_count = int(counts.get(c.id, 0))
        profile = RiskProfile(
            domain=c.registrable_domain,
            first_seen=c.first_seen_at,
            message_count=c.message_count,
            bank_records=record_count,
            verified_phone=c.verified_phone,
            auth_pass_rate=1.0,
            incidents=0,
            graph_verdict=entry.verdict if entry else None,
            domain_age_days=None,
        )
        out.append(
            {
                "domain": c.registrable_domain,
                "display_name": c.display_name,
                "message_count": c.message_count,
                "verified_phone": c.verified_phone,
                "bank_records": record_count,
                "risk_score": profile.score,
                "tier": profile.tier.value,
                "advice": profile.advice,
                # What finance has to do next, in the order that closes the gap.
                # A supplier with details on file but no callback number is the
                # common half-finished state, and it is the one that fails at the
                # moment it matters.
                "needs": [
                    *([] if record_count else ["bank_details"]),
                    *([] if c.verified_phone else ["callback_number"]),
                ],
            }
        )
    return {"counterparties": sorted(out, key=lambda c: -c["risk_score"])}


@router.post("/counterparties", status_code=201)
async def upsert_counterparty(
    req: CounterpartyRequest, principal: AdminUser, session: Session
) -> dict:
    """Add a supplier before any mail from them has arrived.

    Every other path into this table is passive — we learn a counterparty when
    they email you. That is too late for the case the product is built around: a
    supplier's first message to a new customer can already be the fraudulent one.
    """
    reg = registrable_domain(req.domain)
    if not valid_domain(reg):
        raise HTTPException(422, f"{req.domain} is not a valid domain")

    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    created = row is None
    if row is None:
        now = datetime.now(UTC)
        row = Counterparty(
            tenant_id=principal.tenant_id,
            registrable_domain=reg,
            first_seen_at=now,
            last_seen_at=now,
            message_count=0,
        )
        session.add(row)
    if req.display_name is not None:
        row.display_name = req.display_name
    if req.verified_phone is not None:
        row.verified_phone = req.verified_phone
    await session.commit()
    return {"domain": reg, "created": created, "display_name": row.display_name}


@router.get("/counterparties/{domain}/bank-records")
async def list_bank_records(
    domain: str, principal: ActiveUser, session: Session
) -> dict:
    """What we hold for this supplier.

    Read by any signed-in member, not just an admin: the person about to pay an
    invoice is usually not the person who can edit the registry, and "what does
    Envelock think this supplier's account is?" is the question that stops the
    payment.
    """
    reg = registrable_domain(domain)
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "counterparty not found")

    records = (
        (
            await session.execute(
                select(BankRecord)
                .where(BankRecord.counterparty_id == row.id)
                .order_by(BankRecord.is_active.desc(), BankRecord.first_seen_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "domain": reg,
        "display_name": row.display_name,
        "verified_phone": row.verified_phone,
        "records": [
            {
                "id": str(r.id),
                "scheme": r.scheme,
                # Shown in full deliberately. This is the number a person compares
                # against an invoice by eye, and a masked one cannot be compared.
                # It is the customer's own supplier data, visible only inside
                # their tenant.
                "identifier": r.identifier,
                "bank_name": r.bank_name,
                "country": r.country,
                "active": r.is_active,
                "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                "verified_at": r.verified_at.isoformat() if r.verified_at else None,
            }
            for r in records
        ],
    }


@router.delete("/counterparties/{domain}/bank-records/{record_id}")
async def retire_bank_record(
    domain: str, record_id: UUID, principal: AdminUser, session: Session
) -> dict:
    """Retire a record — deactivate, never delete.

    A supplier genuinely does change bank once every few years, and the old
    account must stop being "known good". But the history is the evidence: when a
    dispute asks "what did we have on file in March", a deleted row cannot
    answer, and an attacker who gained admin access could otherwise erase the
    detection's entire basis and leave nothing behind.
    """
    reg = registrable_domain(domain)
    record = await session.get(BankRecord, record_id)
    if record is None or record.tenant_id != principal.tenant_id:
        raise HTTPException(404, "bank record not found")

    counterparty = await session.get(Counterparty, record.counterparty_id)
    if counterparty is None or counterparty.registrable_domain != reg:
        raise HTTPException(404, "bank record not found")

    record.is_active = False
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="counterparty.bank_record_retired",
        target_type="bank_record",
        target_id=record.id,
        detail={"domain": reg, "scheme": record.scheme},
    )
    await session.commit()
    return {"domain": reg, "id": str(record_id), "active": False}


@router.post("/counterparties/{domain}/phone")
async def set_phone(
    domain: str,
    req: CounterpartyPhoneRequest,
    principal: AdminUser,
    session: Session,
) -> dict:
    """A2 — the number we prompt users to call. Never the one in the email.

    Takes a validated body rather than the bare query parameter it used to: this
    value is shown to someone about to stop a payment, so an empty or malformed
    number is worse than none at all — it looks like a verified callback and is
    not one.

    Creates the supplier if we have not seen them yet. Refusing with "not seen
    yet" was backwards: recording a callback number BEFORE the first email is
    precisely the safe order to do it in.
    """
    reg = registrable_domain(domain)
    if not valid_domain(reg):
        raise HTTPException(422, f"{domain} is not a valid domain")
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        now = datetime.now(UTC)
        row = Counterparty(
            tenant_id=principal.tenant_id,
            registrable_domain=reg,
            first_seen_at=now,
            last_seen_at=now,
            message_count=0,
        )
        session.add(row)
    row.verified_phone = req.phone
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="counterparty.callback_number_set",
        target_type="counterparty",
        detail={"domain": reg},
    )
    await session.commit()
    return {"domain": reg, "verified_phone": req.phone}


@router.post("/counterparties/{domain}/bank-records", status_code=201)
async def add_bank_record(
    domain: str, req: BankRecordRequest, principal: AdminUser, session: Session
) -> dict:
    reg = registrable_domain(domain)
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == principal.tenant_id,
                Counterparty.registrable_domain == reg,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        row = Counterparty(
            tenant_id=principal.tenant_id,
            registrable_domain=reg,
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
        )
        session.add(row)
        await session.flush()

    record = BankRecord(
        tenant_id=principal.tenant_id,
        counterparty_id=row.id,
        scheme=req.scheme,
        identifier=normalise_identifier(req.scheme, req.identifier),
        bank_name=req.bank_name,
        first_seen_at=datetime.now(UTC),
        verified_at=datetime.now(UTC),
        verified_by=principal.user_id,
    )
    session.add(record)
    await session.commit()
    return {"domain": reg, "identifier": record.identifier, "verified": True}


class VendorImportRequest(BaseModel):
    """A pasted or uploaded slice of the AP vendor master.

    Deliberately a CSV string rather than a file upload: finance exports this
    from their accounting system and pastes it, and a text body keeps the whole
    path — client, API, tests — free of multipart handling for what is a few
    kilobytes of text.
    """

    csv: str = Field(min_length=1, max_length=2_000_000)
    #: Preview without writing. The import screen calls this first so the person
    #: sees exactly what will be created before anything is.
    dry_run: bool = False


#: Accepted header spellings → our field. Finance exports come out of Sage, Xero,
#: NetSuite and QuickBooks with different names for the same column, and telling
#: a customer to rename headers before importing is how an import feature goes
#: unused.
_VENDOR_COLUMNS: dict[str, str] = {
    "domain": "domain", "website": "domain", "supplier domain": "domain",
    "vendor domain": "domain", "email domain": "domain", "email": "domain",
    "name": "name", "supplier": "name", "vendor": "name", "vendor name": "name",
    "supplier name": "name", "company": "name",
    "iban": "iban",
    "account": "account", "account number": "account", "bank account": "account",
    "acct": "account",
    "swift": "swift", "bic": "swift", "swift/bic": "swift",
    "sort code": "sortcode", "sortcode": "sortcode", "routing": "ach",
    "routing number": "ach", "aba": "ach", "ach": "ach", "crypto": "crypto",
    "wallet": "crypto",
    "bank": "bank_name", "bank name": "bank_name",
    "phone": "phone", "telephone": "phone", "contact phone": "phone",
    "verified phone": "phone", "callback": "phone", "callback number": "phone",
}

#: Import ceiling per request. A vendor master is hundreds of rows, not millions,
#: and an unbounded loop here would be a request that never returns.
_MAX_VENDOR_ROWS = 5_000


def _vendor_rows(raw: str) -> tuple[list[dict], list[str]]:
    """Parse the CSV into normalised rows, plus human-readable problems.

    Never raises on bad input: a finance export always has some malformed rows,
    and rejecting the whole file for one of them means the customer gives up.
    Bad rows are reported by line number and skipped.
    """
    import csv as _csv
    import io

    problems: list[str] = []
    try:
        # Sniff the delimiter — European exports are frequently semicolon-separated
        # and would otherwise parse as one giant column.
        sample = raw[:4096]
        try:
            dialect = _csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except _csv.Error:
            dialect = _csv.excel
        reader = _csv.DictReader(io.StringIO(raw), dialect=dialect)
        fieldnames = reader.fieldnames or []
    except Exception as exc:  # noqa: BLE001
        return [], [f"could not read the file: {exc}"]

    mapping = {
        original: _VENDOR_COLUMNS[(original or "").strip().lower()]
        for original in fieldnames
        if (original or "").strip().lower() in _VENDOR_COLUMNS
    }
    if "domain" not in mapping.values():
        return [], [
            "no supplier domain column found. Include a column named one of: "
            + ", ".join(k for k, v in _VENDOR_COLUMNS.items() if v == "domain")
        ]

    rows: list[dict] = []
    for line_no, raw_row in enumerate(reader, start=2):  # line 1 is the header
        if len(rows) >= _MAX_VENDOR_ROWS:
            problems.append(
                f"stopped at {_MAX_VENDOR_ROWS} rows — split the file and import again"
            )
            break
        row = {
            field: (raw_row.get(original) or "").strip()
            for original, field in mapping.items()
        }
        domain_value = row.get("domain", "")
        # An email address in the domain column is the single most common export
        # shape, so take the domain from it rather than rejecting the row.
        if "@" in domain_value:
            domain_value = domain_value.rsplit("@", 1)[-1]
        reg = registrable_domain(domain_value.strip().lower().rstrip("."))
        if not reg or not valid_domain(reg):
            if any(row.values()):
                problems.append(f"line {line_no}: '{domain_value}' is not a usable domain")
            continue
        row["domain"] = reg
        row["line"] = line_no
        rows.append(row)
    return rows, problems


@router.post("/counterparties/import")
async def import_vendor_master(
    req: VendorImportRequest, principal: AdminUser, session: Session
) -> dict:
    """Import the AP vendor master — the highest-value five minutes of onboarding.

    Everything else in the product learns a supplier's "normal" by watching mail
    go by, which takes weeks and is only as trustworthy as the mail it watched.
    Finance already holds the answer in their accounting system: who the
    suppliers are, what account each is paid into, and what number to ring. This
    is the one import that turns A1 from "learn the pattern and hope" into "check
    against what the customer told us", from day one.

    Idempotent by (counterparty, scheme, identifier), so re-importing an updated
    export adds what is new and leaves the rest alone.
    """
    rows, problems = _vendor_rows(req.csv)

    created_suppliers = 0
    updated_suppliers = 0
    created_records = 0
    skipped_records = 0
    seen: dict[str, Counterparty] = {}

    for row in rows:
        reg = row["domain"]
        counterparty = seen.get(reg)
        if counterparty is None:
            counterparty = (
                await session.execute(
                    select(Counterparty).where(
                        Counterparty.tenant_id == principal.tenant_id,
                        Counterparty.registrable_domain == reg,
                    )
                )
            ).scalar_one_or_none()
            if counterparty is None:
                now = datetime.now(UTC)
                counterparty = Counterparty(
                    tenant_id=principal.tenant_id,
                    registrable_domain=reg,
                    first_seen_at=now,
                    last_seen_at=now,
                    message_count=0,
                )
                session.add(counterparty)
                await session.flush()
                created_suppliers += 1
            else:
                updated_suppliers += 1
            seen[reg] = counterparty

        if name := row.get("name"):
            counterparty.display_name = counterparty.display_name or name
        if phone := row.get("phone"):
            counterparty.verified_phone = counterparty.verified_phone or phone

        for scheme in ("iban", "account", "swift", "sortcode", "ach", "crypto"):
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
                    tenant_id=principal.tenant_id,
                    counterparty_id=counterparty.id,
                    scheme=scheme,
                    identifier=value,
                    bank_name=row.get("bank_name") or None,
                    first_seen_at=now,
                    # Imported from the customer's own accounting system, by an
                    # admin, out of band from any email — which is a stronger
                    # provenance than anything we could infer from a message.
                    verified_at=now,
                    verified_by=principal.user_id,
                )
            )
            created_records += 1

    summary = {
        "dry_run": req.dry_run,
        "rows_parsed": len(rows),
        "suppliers_created": created_suppliers,
        "suppliers_matched": updated_suppliers,
        "bank_records_created": created_records,
        "bank_records_already_present": skipped_records,
        "problems": problems[:50],
        "suppliers": [
            {"domain": r["domain"], "name": r.get("name") or None} for r in rows[:25]
        ],
    }

    if req.dry_run:
        # Nothing is written. Rolling back explicitly rather than relying on the
        # session being discarded, because a preview that silently half-committed
        # would be the worst possible behaviour for this particular screen.
        await session.rollback()
        return summary

    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="counterparty.vendor_master_imported",
        target_type="tenant",
        detail={
            "suppliers_created": created_suppliers,
            "bank_records_created": created_records,
        },
    )
    await session.commit()
    return summary


# ── Lookalikes (D1–D4, D7) ───────────────────────────────────────────────────
@router.get("/lookalikes")
async def list_lookalikes(principal: ActiveUser, session: Session) -> dict:
    rows = (
        (
            await session.execute(
                select(LookalikeDomain)
                .where(LookalikeDomain.tenant_id == principal.tenant_id)
                .order_by(LookalikeDomain.has_mx.desc(), LookalikeDomain.similarity.desc())
            )
        )
        .scalars()
        .all()
    )
    return {
        "lookalikes": [
            {
                "candidate": row.candidate_domain,
                "protected": row.protected_domain,
                "technique": row.technique,
                "similarity": float(row.similarity),
                "armed": row.has_mx,
                "status": row.status,
                "first_seen_source": row.first_seen_source,
            }
            for row in rows
        ],
        "armed_count": sum(1 for row in rows if row.has_mx),
    }


@router.post("/lookalikes/{candidate}/report")
async def report_lookalike(
    candidate: str, principal: AdminUser, session: Session, fraudulent: bool = True
) -> dict:
    """E8 — one tenant's confirmation protects every other tenant.

    Guarded like `/takedown`: the report must be about a lookalike WE surfaced to
    this tenant, not an arbitrary path string. Without that, two throwaway
    tenants could vote any domain on the internet into the cross-tenant
    blocklist — every customer's mail to it flagged, every click to it hard-403d
    at the redirector. A censorship primitive, not a moat.
    """
    if not valid_domain(candidate):
        raise HTTPException(422, "invalid domain")
    known = (
        await session.execute(
            select(LookalikeDomain).where(
                LookalikeDomain.tenant_id == principal.tenant_id,
                LookalikeDomain.candidate_domain == registrable_domain(candidate),
            )
        )
    ).scalar_one_or_none()
    if known is None:
        raise HTTPException(
            404,
            "that domain isn't on your lookalike watch list — reports feed the "
            "shared graph, so they must come from a lookalike we detected for you",
        )
    entry = GRAPH.report(
        domain=candidate,
        verdict=Verdict.FRAUDULENT if fraudulent else Verdict.LEGITIMATE,
        tenant_id=principal.tenant_id,
    )
    # Write through so the moat survives a restart and is shared across instances.
    await graph_store.persist_report(session, entry, GRAPH.reporters_of(candidate))
    await alert_svc.record_audit(
        session,
        tenant_id=principal.tenant_id,
        actor_id=principal.user_id,
        action="lookalike.reported",
        detail={"domain": candidate, "fraudulent": fraudulent},
    )
    await session.commit()
    return {
        "domain": entry.registrable_domain,
        "verdict": entry.verdict.value,
        "confirmations": entry.confirmations,
        "confidence": round(entry.confidence, 3),
        "shared_with_all_tenants": entry.actionable,
    }


@router.get("/ingest-address")
async def get_ingest_address(principal: AdminUser, session: Session) -> dict:
    domain = (
        await session.execute(
            select(Domain).where(Domain.tenant_id == principal.tenant_id).limit(1)
        )
    ).scalar_one_or_none()
    token = (domain.verification_token if domain else None) or new_ingest_token()
    return onboarding_instructions(token)
