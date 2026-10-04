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


#: On-access re-checks share a short TTL cache so the dashboard polling `/tenant`
#: cannot turn into a DNS lookup on every request. DNS has no push — nothing
#: tells us a TXT record was deleted — so the authoritative check is a lookup;
#: the cache just bounds how often an *active* tenant triggers one. A revocation
#: is therefore felt the moment the user next loads the dashboard with a stale
#: cache entry, not on a fixed background tick. 'unknown' (transient) is never
#: cached, so a blip is retried immediately rather than held for the TTL.
_STATUS_TTL_SECONDS = 120.0
_status_cache: dict[tuple[str, str, str], tuple[str, float]] = {}


def _cached_control_status(domain: str, token: str, method: str, *, now: float) -> str:
    key = (domain, token, method)
    hit = _status_cache.get(key)
    if hit is not None and now - hit[1] < _STATUS_TTL_SECONDS:
        return hit[0]
    status = domain_control_status(domain, token, method=method)
    if status != "unknown":
        _status_cache[key] = (status, now)
    return status


async def revalidate_tenant_domains(session: AsyncSession, tenant_id: UUID) -> dict:
    """Incident-driven re-check of ONE tenant's verified domains, called on
    dashboard access rather than on a timer.

    The whole point of the TTL cache and the tenant filter is that this is cheap
    enough to run on every `/tenant` load: the moment a tenant who deleted their
    DNS proof reloads the dashboard (cache stale), the domain is revoked and the
    client's verify-gate blocks them — no waiting for the hourly backstop. DNS is
    resolved off the event loop. Only a conclusive 'absent' revokes."""
    import asyncio
    import time

    rows = (
        (
            await session.execute(
                select(Domain).where(
                    Domain.tenant_id == tenant_id, Domain.verified_at.is_not(None)
                )
            )
        )
        .scalars()
        .all()
    )
    checkable = [r for r in rows if r.verification_token]
    if not checkable:
        return {"revoked": []}
    now = time.monotonic()

    def _statuses() -> dict:
        return {
            r.id: _cached_control_status(
                r.registrable_domain, r.verification_token or "",
                r.verification_method or "txt", now=now,
            )
            for r in checkable
        }

    statuses = await asyncio.to_thread(_statuses)
    return await _revoke_absent(session, rows, statuses)


async def _revoke_absent(session: AsyncSession, rows, statuses: dict) -> dict:  # noqa: ANN001
    """Revoke every row whose pre-computed status is 'absent', then audit and
    notify. Shared by the scheduled sweep and the on-access path."""
    revoked: list[str] = []
    for row in rows:
        if statuses.get(row.id) != "absent":
            continue
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
        # Tell them. A revoked domain silently blocks connecting any mailbox on
        # it, and the cause — a DNS record that was deleted, very often by an
        # unrelated change at the registrar — is invisible from inside the app.
        # Without this the customer's next experience of us is a feature that
        # stopped working for no stated reason.
        from envelock.notify.account import app_url, notify_admins

        for row in rows:
            if row.registrable_domain not in revoked:
                continue
            await notify_admins(
                session,
                row.tenant_id,
                subject=f"Action needed: {row.registrable_domain} is no longer verified",
                heading="Your domain is no longer verified",
                preheader=(
                    f"The DNS record proving you control {row.registrable_domain} "
                    "has gone."
                ),
                paragraphs=[
                    f"The DNS record proving you control {row.registrable_domain} "
                    "is no longer there, so we have stopped treating the domain as "
                    "verified.",
                    "Existing protection continues. You cannot connect any NEW "
                    "mailbox on this domain until it is verified again.",
                ],
                text=(
                    f"The DNS record proving you control {row.registrable_domain} "
                    "is no longer there, so we have stopped treating the domain as "
                    "verified.\n\n"
                    "Existing protection continues. You cannot connect any new "
                    "mailbox on this domain until it is verified again.\n\n"
                    f"Put the record back:\n{app_url('/dashboard')}"
                ),
                cta_label="Verify my domain again",
                cta_url=app_url("/dashboard"),
                footnote=(
                    "If you did not remove it, check whether anything else changed "
                    "at your DNS provider recently — this is usually an unrelated "
                    "edit that took the record with it."
                ),
            )
    return {"revoked": revoked}


async def revalidate_verified_domains(session: AsyncSession) -> dict:
    """The scheduled backstop: re-check EVERY verified domain and revoke any whose
    proof-of-control record has definitively disappeared.

    Ownership is not a one-time gate — if the DNS record is later deleted (the
    domain lapsed, was transferred, or the record was pulled) we stop trusting it
    and make the tenant prove it again. This sweep catches domains of tenants who
    are not actively using the dashboard; active ones are revoked sooner by
    `revalidate_tenant_domains` on access. Fresh lookups, no cache, so the
    backstop is authoritative. Only a conclusive 'absent' revokes; a
    transient/unknown result is left alone so a blip can never lock anyone out."""
    rows = (
        (await session.execute(select(Domain).where(Domain.verified_at.is_not(None))))
        .scalars()
        .all()
    )
    statuses = {
        row.id: domain_control_status(
            row.registrable_domain,
            row.verification_token,
            method=row.verification_method or "txt",
        )
        for row in rows
        if row.verification_token
    }
    return await _revoke_absent(session, rows, statuses)


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
    "revalidate_tenant_domains",
    "revalidate_verified_domains",
    "set_domain_verifier",
    "verified_registrable_domains",
    "verify_domain_control",
]
