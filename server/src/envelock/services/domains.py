"""Domain-control verification — the trust boundary for protecting a mailbox.

Owned by the service layer (not a router) because three different consumers
need it: the tenants API (add/verify/connect), the channels API (OAuth
connect), and the background scheduler (periodic re-verification). See the
package docstring for the layering rule.

`require_verified_domain` raises FastAPI's `HTTPException` so both routers keep
their exact error contract; worker callers never invoke it.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import AuditEvent, Domain
from envelock.util.domains import registrable_domain

_DOMAIN_VERIFIER = None


def set_domain_verifier(fn) -> None:  # noqa: ANN001
    """Override the DNS verifier (tests). `fn(domain, token, method=...) -> bool`."""
    global _DOMAIN_VERIFIER
    _DOMAIN_VERIFIER = fn


def verify_domain_control(domain: str, token: str, *, method: str) -> bool:
    if _DOMAIN_VERIFIER is not None:
        return _DOMAIN_VERIFIER(domain, token, method=method)
    from envelock.util.dns_verify import verify

    return verify(domain, token, method=method)


def domain_control_status(domain: str, token: str, *, method: str) -> str:
    """Tri-state control check for re-verification: 'present' | 'absent' | 'unknown'.

    Honors the same test seam as verify_domain_control: an injected verifier
    returning True/False maps to present/absent so tests can simulate a deleted
    record without live DNS."""
    if _DOMAIN_VERIFIER is not None:
        return "present" if _DOMAIN_VERIFIER(domain, token, method=method) else "absent"
    from envelock.util.dns_verify import verification_status

    return verification_status(domain, token, method=method)


async def revalidate_verified_domains(session: AsyncSession) -> dict:
    """Re-check every DNS-verified domain and REVOKE (verified_at → None) any whose
    proof-of-control record has definitively disappeared.

    Ownership is not a one-time gate: if the DNS record we verified is later deleted
    — the domain lapsed, was transferred, or the record was pulled — we must stop
    trusting that control and make the tenant prove it again. Once revoked, the
    dashboard's verify-gate blocks the tenant until they re-verify. Only a
    conclusive 'absent' revokes; a transient/unknown DNS result is left alone so a
    network blip can never lock a paying customer out. Runs on the scheduler."""
    rows = (
        (await session.execute(select(Domain).where(Domain.verified_at.is_not(None))))
        .scalars()
        .all()
    )
    revoked: list[str] = []
    for row in rows:
        if not row.verification_token:
            continue  # nothing to check against — leave it verified
        status = domain_control_status(
            row.registrable_domain,
            row.verification_token,
            method=row.verification_method or "txt",
        )
        if status != "absent":
            continue  # 'present' or 'unknown' → never revoke
        row.verified_at = None
        revoked.append(row.registrable_domain)
        session.add(
            AuditEvent(
                tenant_id=row.tenant_id,
                actor_id=None,
                action="domain.verification_revoked",
                target_type="domain",
                target_id=row.id,
                detail={"domain": row.registrable_domain, "reason": "dns_record_missing"},
            )
        )
    if revoked:
        await session.commit()
    return {"revoked": revoked}


async def verified_registrable_domains(session: AsyncSession, tenant_id: UUID) -> set[str]:
    """The registrable domains this tenant has PROVEN it controls (DNS-verified).

    This is the trust boundary for protecting a mailbox. Without it, anyone could
    verify a $1 throwaway domain they own and then point Envelock at a victim's
    address on a domain they DON'T own — silently monitoring someone else's mail.
    Fetched once so the bulk path can check a whole paste in memory."""
    rows = (
        await session.execute(
            select(Domain.registrable_domain).where(
                Domain.tenant_id == tenant_id,
                Domain.verified_at.is_not(None),
            )
        )
    ).all()
    return {r[0] for r in rows if r[0]}


def mail_domain_allowed(address: str, verified: set[str]) -> bool:
    """Whether a mailbox on `address` may be protected — the single source of truth
    for the domain-ownership boundary, shared by add, bulk-add and connect.

    Honors the require_domain_verification setting (off → allow, for dev/tests) and
    exempts free-mail addresses (gmail.com, qq.com…), which have no domain to verify
    and are the no-domain segment (PRD §12.6). Everything else must sit on a domain
    the tenant has verified."""
    from envelock.config import get_settings
    from envelock.util.domains import is_free_mail

    if not get_settings().require_domain_verification:
        return True
    reg = registrable_domain(address.rsplit("@", 1)[-1] if "@" in address else "")
    if not reg or is_free_mail(reg):
        return True
    return reg in verified


async def require_verified_domain(session: AsyncSession, tenant_id: UUID, address: str) -> None:
    """Block connecting a mailbox for live mail until its domain is DNS-verified.

    Free-mail addresses (gmail.com, qq.com…) have no domain to verify and are the
    no-domain segment (PRD §12.6), so they are exempt. Everything else must prove
    control first. Shares its rule with add/bulk-add via mail_domain_allowed."""
    verified = await verified_registrable_domains(session, tenant_id)
    if mail_domain_allowed(address, verified):
        return
    reg = registrable_domain(address.rsplit("@", 1)[-1] if "@" in address else "")
    raise HTTPException(
        403,
        f"Verify {reg} before connecting a mailbox on it. Add the DNS record shown "
        "under Domains on your dashboard, then press Verify — it usually takes a "
        "few minutes to propagate.",
    )


__all__ = [
    "domain_control_status",
    "mail_domain_allowed",
    "require_verified_domain",
    "revalidate_verified_domains",
    "set_domain_verifier",
    "verified_registrable_domains",
    "verify_domain_control",
]
