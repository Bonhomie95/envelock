"""Channel endpoints: brand posture, client sensor, simulation, worker status."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.auth.deps import ActiveUser, AdminUser, CurrentUser, SystemScoped
from envelock.auth.sensor import SensorCaller, SensorPrincipal
from envelock.billing import entitlement
from envelock.channels.external.brand import (
    build_takedown,
    check_posture,
    probe_domain,
)
from envelock.channels.mail import oauth
from envelock.channels.mail.providers import provider_status
from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import (
    IdentityEventKind,
    IntegrationTier,
    MailboxClass,
    SourceMechanism,
)
from envelock.core.events import DeviceContext, IdentityEvent, NetworkContext
from envelock.db import get_session
from envelock.detections.base import CounterpartyState, DetectionContext, inactive_for, run_all
from envelock.detections.cascade import get_attachment_cascade, get_url_cascade
from envelock.models import (
    Domain,
    LookalikeDomain,
    Mailbox,
    MailboxCredential,
    PushSubscription,
    SensorSession,
    Tenant,
    User,
)
from envelock.notify.dispatch import deliver_pending
from envelock.notify.ladder import Recipient
from envelock.notify.senders import Dispatcher
from envelock.platform.graph import GRAPH, SimulationRun, plan_backfill, simulations
from envelock.platform.pipeline import analyse_event
from envelock.security.crypto import seal
from envelock.security.limits import valid_domain
from envelock.util.domains import registrable_domain
from envelock.workers.watchers import RdapClient

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1", tags=["channels"])
Session = Annotated[AsyncSession, Depends(get_session)]

_RDAP = RdapClient()


# ── D5 / D6 — brand posture ──────────────────────────────────────────────────
@router.get("/brand/{domain}/posture")
async def brand_posture(domain: str) -> dict:
    """Public: needs no mailbox access, so it works before signup."""
    # Structural validation before this reaches a resolver: an IP literal, a
    # single-label internal name, or a URL must never hit DNS from user input.
    if not valid_domain(domain):
        raise HTTPException(422, "invalid domain")
    reg = registrable_domain(domain)
    if not reg:
        raise HTTPException(422, "invalid domain")
    posture = await check_posture(reg)
    return {
        "domain": posture.domain,
        "spf_present": posture.spf_present,
        "dkim_selectors": list(posture.dkim_selectors_found),
        "dmarc_present": posture.dmarc_present,
        "dmarc_policy": posture.dmarc_policy,
        "dmarc_pct": posture.dmarc_pct,
        "protected": posture.protected,
        "tier": posture.tier.value,
        "summary": posture.summary,
        "recommendations": posture.recommendations,
    }


@router.get("/brand/{domain}/probe")
async def brand_probe(domain: str) -> dict:
    """D4 — a lookalike with MX configured is armed."""
    if not valid_domain(domain):
        raise HTTPException(422, "invalid domain")
    probe = await probe_domain(domain)
    return {
        "domain": probe.domain,
        "has_mx": probe.has_mx,
        "has_a": probe.has_a,
        "mx_hosts": list(probe.mx_hosts),
        "armed": probe.armed,
    }


@router.get("/brand/{domain}/registration")
async def brand_registration(domain: str) -> dict:
    """RDAP. Registrant identity is usually redacted post-GDPR; creation date is
    the field we actually need."""
    # Validate before an unauthenticated caller can drive an outbound HTTP lookup.
    if not valid_domain(domain):
        raise HTTPException(422, "invalid domain")
    data = await _RDAP.lookup(domain)
    if data is None:
        return {"domain": registrable_domain(domain), "available": False}
    return {**data, "age_days": _RDAP.age_days(data.get("registered_at")), "available": True}


@router.post("/lookalikes/{candidate}/takedown")
async def takedown(candidate: str, principal: AdminUser, session: Session) -> dict:
    """D7 — turns an alert into a resolution."""
    row = (
        await session.execute(
            select(LookalikeDomain).where(
                LookalikeDomain.tenant_id == principal.tenant_id,
                LookalikeDomain.candidate_domain == registrable_domain(candidate),
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "lookalike not found")

    registration = await _RDAP.lookup(row.candidate_domain)
    packet = build_takedown(
        candidate=row.candidate_domain,
        protected=row.protected_domain,
        technique=row.technique,
        registrar=(registration or {}).get("registrar"),
        registered_at=row.registered_at,
        has_mx=row.has_mx,
    )
    row.status = "takedown_requested"
    await session.commit()
    return {
        "candidate": packet.candidate,
        "subject": packet.subject,
        "body": packet.body,
        "registrar": (registration or {}).get("registrar"),
        "evidence": packet.evidence,
    }


# ── Tier 1 — OAuth connection (PRD §17.1) ────────────────────────────────────
#: Which normalised sources a completed OAuth grant unlocks for the mailbox.
_OAUTH_SOURCES: dict[str, list[SourceMechanism]] = {
    # Microsoft grants only Graph mail read now — the AuditLog scope (which would
    # unlock ENTRA_LOGS / sign-in-log detections) needs org admin consent, so it
    # was dropped to keep the connect free of an admin wall. Without the scope we
    # cannot read sign-in logs, so the mailbox must NOT claim ENTRA_LOGS: its
    # protection level reflects what we can actually deliver.
    "microsoft": [SourceMechanism.GRAPH_API],
    "google": [SourceMechanism.GMAIL_API, SourceMechanism.GOOGLE_REPORTS],
}


class OAuthAuthorizeRequest(BaseModel):
    mailbox_address: str
    #: "api" asks for Graph/Gmail ingest consent. "imap" asks for the mailbox
    #: IMAP scope instead — the way in for a provider that has switched password
    #: authentication off, so IMAP still works without a password.
    mode: Literal["api", "imap"] = "api"


#: Where each provider's IMAP endpoint lives, for the XOAUTH2 fallback.
_IMAP_ENDPOINTS: dict[str, tuple[str, int]] = {
    "microsoft": ("outlook.office365.com", 993),
    "google": ("imap.gmail.com", 993),
}


@router.get("/connect/oauth/providers")
async def oauth_providers(principal: CurrentUser) -> dict:
    """Which Tier-1 providers are wired and ready for a consent click."""
    return {
        "configured": oauth.configured_providers(),
        "supported": sorted(_OAUTH_SOURCES),
    }


@router.post("/connect/oauth/{provider}/authorize")
async def oauth_authorize(
    provider: str,
    req: OAuthAuthorizeRequest,
    principal: AdminUser,
    session: Session,
) -> dict:
    """Return the tenant-consent URL for the admin's browser (PRD S1/S2).

    The mailbox must already exist and belong to the caller's tenant; the signed
    `state` binds this grant to that tenant, mailbox and provider so the callback
    cannot be forged or replayed.
    """
    prov = oauth.provider_for(provider)
    if prov is None or provider not in _OAUTH_SOURCES:
        raise HTTPException(404, "unknown provider")
    if not oauth.is_configured(prov):
        raise HTTPException(
            503,
            f"Connecting with {provider} isn't available right now. "
            "Use IMAP or forwarding instead, or contact support.",
        )

    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    from envelock.services.domains import require_verified_domain

    await require_verified_domain(session, principal.tenant_id, mailbox.address)

    for_imap = req.mode == "imap"
    state = oauth.issue_state(
        tenant_id=str(principal.tenant_id),
        mailbox=mailbox.address,
        provider=provider,
        mode=req.mode,
    )
    return {
        "provider": provider,
        "mode": req.mode,
        "authorize_url": oauth.authorization_url(prov, state=state, for_imap=for_imap),
        "state": state,
        "expires_in": 600,
    }


# SystemScoped: the provider redirects the browser here with no session, and
# the tenant comes from the signed `state` parameter. Under RLS with no
# tenant bound the mailbox lookup matches nothing, so consent would appear
# to succeed while the mailbox silently never flipped to connected.
@router.get("/connect/oauth/{provider}/callback", dependencies=[SystemScoped])
async def oauth_callback(
    provider: str,
    session: Session,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> dict:
    """Consent redirect target. Exchanges the code and seals the tokens.

    No bearer token here — this is a browser redirect from the provider, so the
    HMAC-signed `state` is the authorisation. Tokens are envelope-encrypted
    (PRD §5.2) and never returned to the caller.
    """
    if error:
        raise HTTPException(400, f"consent was not granted: {error}")
    if not code or not state:
        raise HTTPException(400, "missing code or state")

    prov = oauth.provider_for(provider)
    if prov is None or provider not in _OAUTH_SOURCES:
        raise HTTPException(404, "unknown provider")

    try:
        claims = oauth.verify_state(state, provider=provider)
    except oauth.OAuthError as exc:
        logger.warning("oauth state verification failed for %s: %s", provider, exc)
        raise HTTPException(
            400,
            "This connection link is invalid or has expired. Please start again.",
        ) from exc

    # Single-use: a signed state was replayable for its whole 600s window, so a
    # leaked redirect URL (browser history, proxy logs) could re-run the token
    # exchange. Same store that makes TOTP codes one-shot.
    from envelock.security.limits import active_replay

    if not await active_replay().acheck_and_record(f"oauthstate:{state[-48:]}", ttl=600):
        raise HTTPException(
            400, "This connection link was already used. Please start again."
        )

    tenant_id = UUID(claims["t"])
    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == tenant_id,
                Mailbox.address == claims["m"],
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    mode = claims.get("k", "api")

    try:
        tokens = await oauth.exchange_code(prov, code=code)
    except oauth.OAuthError as exc:
        logger.warning("oauth token exchange failed for %s: %s", provider, exc)
        raise HTTPException(
            502,
            "We couldn't finish connecting to your email provider. Please try again.",
        ) from exc

    # Seal the refresh token (the durable secret) bound to this mailbox.
    import json as _json

    payload = _json.dumps(
        {
            "access_token": tokens.access_token,
            "refresh_token": tokens.refresh_token,
            "scope": tokens.scope,
        }
    ).encode()
    sealed = seal(payload, aad=str(mailbox.id).encode())

    existing = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one_or_none()
    from datetime import UTC, datetime

    token_expires_at = datetime.now(UTC) + timedelta(seconds=tokens.expires_in)

    # An "imap" grant is the fallback path for a provider that has switched
    # password authentication off: same IMAP worker, SASL XOAUTH2 instead of a
    # password. Recording the IMAP endpoint on the credential is what tells the
    # worker to use it.
    imap_endpoint = _IMAP_ENDPOINTS.get(provider) if mode == "imap" else None

    if existing is None:
        session.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=tenant_id,
                kind="oauth_token",
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
                token_expires_at=token_expires_at,
                imap_host=imap_endpoint[0] if imap_endpoint else None,
                imap_port=imap_endpoint[1] if imap_endpoint else None,
                imap_security="ssl" if imap_endpoint else None,
            )
        )
    else:
        existing.kind = "oauth_token"
        existing.ciphertext = sealed.ciphertext
        existing.wrapped_dek = sealed.wrapped_dek
        existing.key_id = sealed.key_id
        existing.token_expires_at = token_expires_at
        if imap_endpoint:
            existing.imap_host, existing.imap_port = imap_endpoint
            existing.imap_security = "ssl"
            existing.imap_last_uid = None
            existing.imap_uidvalidity = None

    if mode == "imap":
        # IMAP over OAuth reads and can quarantine, but gives no provider audit
        # log, so it is a Tier-3 source — the capability model then derives an
        # honest protection level rather than claiming Tier-1 coverage.
        source = (
            SourceMechanism.IMAP_IDLE
            if mailbox.mailbox_class == MailboxClass.PROTECTED.value
            else SourceMechanism.IMAP_POLL
        )
        mailbox.sources = sorted(set(mailbox.sources or []) | {source.value})
        mailbox.integration_tier = int(IntegrationTier.IMAP)
    else:
        # The mailbox is now Tier-1: record the sources so coverage is derived,
        # not declared (PRD P4). Preserve any existing sensor source.
        unlocked = {s.value for s in _OAUTH_SOURCES[provider]}
        mailbox.sources = sorted(set(mailbox.sources or []) | unlocked)
        mailbox.integration_tier = int(IntegrationTier.FULL_API)

    caps = capabilities_for(frozenset(SourceMechanism(s) for s in mailbox.sources))
    mailbox.protection_level = protection_level(caps).value
    mailbox.inactive_detections = inactive_for(caps)
    mailbox.needs_reconnect = False
    mailbox.connection_error = None
    await session.commit()

    return {
        "connected": True,
        "provider": provider,
        "mode": mode,
        "mailbox": mailbox.address,
        "integration_tier": mailbox.integration_tier,
        "sources": mailbox.sources,
        "has_refresh_token": tokens.refresh_token is not None,
    }


# ── Channel 2 — client sensor ────────────────────────────────────────────────
class SensorHeartbeat(BaseModel):
    #: Optional for an enrolled sensor, whose token already names its mailbox.
    mailbox_address: str | None = None
    device_fingerprint: str = Field(min_length=8, max_length=128)
    browser: str | None = Field(default=None, max_length=64)
    os: str | None = Field(default=None, max_length=64)
    mail_client: str | None = Field(default=None, max_length=64)
    #: Accepted and ignored — see the heartbeat. Kept so older clients validate.
    ip: str | None = None
    country: str | None = Field(default=None, max_length=2)


class SensorMessageOpened(BaseModel):
    mailbox_address: str | None = None
    device_fingerprint: str = Field(min_length=8, max_length=128)
    #: The RFC 5322 Message-ID of the opened message, or "*" when the client can
    #: tell the owner is reading but cannot name which message.
    message_ref: str = Field(min_length=1, max_length=998)


async def _sensor_mailbox(
    session: AsyncSession, caller: SensorCaller, mailbox_address: str | None
) -> Mailbox:
    """The one mailbox this caller may report for.

    An enrolled sensor's token names its mailbox, and a body naming a different
    one is refused rather than quietly redirected: a sensor reporting for the
    wrong mailbox is either misconfigured or being misused, and either way its
    reports must not land somewhere they were not meant for.
    """
    if caller.is_device:
        mailbox = await session.get(Mailbox, caller.mailbox_id)
        if mailbox is None or mailbox.tenant_id != caller.tenant_id:
            raise HTTPException(404, "mailbox not found")
        if mailbox_address and mailbox_address.strip().lower() != mailbox.address:
            raise HTTPException(
                403, f"this sensor is paired with {mailbox.address}, not {mailbox_address}"
            )
        return mailbox

    if not mailbox_address:
        raise HTTPException(422, "mailbox_address is required")
    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == caller.tenant_id,
                Mailbox.address == mailbox_address.strip().lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")
    _assert_sensor_mailbox_access(caller, mailbox)
    return mailbox


def _assert_sensor_mailbox_access(principal, mailbox) -> None:  # noqa: ANN001
    """A member's sensor may only speak for the member's OWN mailbox.

    These endpoints WRITE detection state — sessions, attested reads, identity
    events. Scoped only by tenant, any member (or one phished member account)
    could blind C11 on the CEO's mailbox with fake attested-reads, or poison its
    identity baseline with their own device/geo. Mirrors the member rule on
    mailbox routes (api/tenants). 404, not 403 — membership isn't an oracle.
    """
    if principal.is_member and mailbox.address != principal.email:
        raise HTTPException(404, "mailbox not found")


def _assert_pinned_device(caller: SensorCaller, device_fingerprint: str) -> None:
    """A sensor token speaks for the one device it enrolled as.

    Without this, one token could report as any number of "devices", which is a
    way to manufacture the concurrency C6 reads, or to keep a mailbox looking
    permanently attended so C11 never fires.
    """
    if caller.is_device and device_fingerprint != caller.device_fingerprint:
        raise HTTPException(403, "this sensor is enrolled as a different device")


@router.post("/sensor/heartbeat")
async def sensor_heartbeat(
    req: SensorHeartbeat, caller: SensorPrincipal, session: Session, request: Request
) -> dict:
    """"This device is here." The sensor is what gives ISP mailboxes Group C at
    all (PRD §7.7).

    A heartbeat either continues a live session or starts a new one, and a new
    one is a sign-in — run through C7/C8/C9/C10 before it is recorded, so the
    session it is compared against is the previous one. Three things start a
    new session, and the last two were missing, which is why this was a sensor
    that could not see a sign-in:

    * a device we have not seen on this mailbox;
    * a known device coming back after going quiet (`SESSION_STALE_SECONDS`) —
      a laptop reopened the next morning in another country is exactly the
      question C7 exists to ask;
    * a known device whose network changed mid-session — the copied browser
      profile, replayed from somewhere else with the same device id and token.
    """
    from envelock.channels.identity import geo
    from envelock.platform import sensor as sensor_rules

    mailbox = await _sensor_mailbox(session, caller, req.mailbox_address)
    _assert_pinned_device(caller, req.device_fingerprint)

    now = datetime.now(UTC)
    # The peer we actually observed — never the caller-supplied `req.ip`, which
    # made every geo/ASN/VPN fact behind C7/C9/C14 forgeable by whoever holds a
    # sensor. The sensor runs on the person's own device, so the peer IS the
    # address that matters.
    observed_ip = request.client.host if request.client else None

    existing = (
        await session.execute(
            select(SensorSession)
            .where(
                SensorSession.mailbox_id == mailbox.id,
                SensorSession.device_fingerprint == req.device_fingerprint,
                SensorSession.ended_at.is_(None),
            )
            .order_by(SensorSession.last_seen_at.desc())
        )
    ).scalars().first()

    facts = None
    reason = None
    if existing is not None and not sensor_rules.is_live(existing.last_seen_at, now=now):
        # Gone quiet long enough to have ended. Close it where it actually
        # stopped, not now, so the session history is true.
        existing.ended_at = existing.last_seen_at
        existing = None
        reason = "returned"
    elif existing is not None and existing.ip != observed_ip:
        facts = await geo.lookup(observed_ip)
        if sensor_rules.network_changed(
            previous_ip=existing.ip,
            previous_country=existing.country,
            previous_asn=existing.asn,
            ip=observed_ip,
            country=facts.country,
            asn=facts.asn,
        ):
            existing.ended_at = now
            existing = None
            reason = "network_changed"

    alerted = False
    findings: list[dict] = []
    if existing is None:
        reason = reason or "new_device"
        owned = {
            d
            for (d,) in (
                await session.execute(
                    select(Domain.registrable_domain).where(
                        Domain.tenant_id == caller.tenant_id
                    )
                )
            ).all()
        }
        # Resolve where this sign-in came from. C7 (impossible travel), C9 (VPN
        # classification) and C14 all read these fields; without the lookup they
        # are None and those three detections silently never fire. A failed or
        # unconfigured lookup returns empty facts and simply leaves them off.
        if facts is None:
            facts = await geo.lookup(observed_ip)

        event = IdentityEvent(
            tenant_id=caller.tenant_id,
            mailbox_id=mailbox.id,
            occurred_at=now,
            ingested_at=now,
            source=SourceMechanism.CLIENT_SENSOR,
            kind=IdentityEventKind.SIGN_IN,
            network=NetworkContext(
                ip=observed_ip,
                # The sensor's self-reported country is a hint; a resolved one is
                # evidence, so the resolved value wins when we have it.
                country=facts.country or req.country,
                city=facts.city,
                asn=facts.asn,
                asn_name=facts.asn_name,
                latitude=facts.latitude,
                longitude=facts.longitude,
                is_vpn=facts.is_vpn,
                is_proxy=facts.is_proxy,
                is_hosting=facts.is_hosting,
                is_tor=facts.is_tor,
            ),
            device=DeviceContext(
                fingerprint=req.device_fingerprint,
                browser=req.browser,
                os=req.os,
                mail_client=req.mail_client,
            ),
        )
        from envelock.channels.mail.forward_runner import _recipients

        recipients = await _recipients(session, caller.tenant_id)
        result = await analyse_event(
            session,
            event,
            tenant_id=caller.tenant_id,
            owned_domains=frozenset(owned),
            recipients=recipients,
        )
        if result.alert_id is not None:
            await deliver_pending(session, alert_id=result.alert_id)
            alerted = True
        findings = [
            {"service": f.service, "tier": f.tier.value, "summary": f.summary}
            for f in result.findings
        ]

        session.add(
            SensorSession(
                tenant_id=caller.tenant_id,
                mailbox_id=mailbox.id,
                user_id=caller.user_id,
                device_fingerprint=req.device_fingerprint,
                ip=observed_ip,
                asn=facts.asn,
                country=facts.country or req.country,
                city=facts.city,
                latitude=facts.latitude,
                longitude=facts.longitude,
                is_vpn=facts.is_vpn,
                is_proxy=facts.is_proxy,
                is_tor=facts.is_tor,
                browser=req.browser,
                os=req.os,
                mail_client=req.mail_client,
                started_at=now,
                last_seen_at=now,
            )
        )
    else:
        existing.last_seen_at = now
        existing.ip = observed_ip or existing.ip

    if caller.is_device:
        from envelock.models import SensorDevice

        device = await session.get(SensorDevice, caller.device_id)
        if device is not None:
            device.last_seen_at = now
            device.last_ip = observed_ip

    # A live sensor is a real source of Channel-2 telemetry, so record it on the
    # mailbox: coverage is derived from sources (PRD P4), and without this the
    # Group-C detections the sensor actually enables kept reading as inactive.
    if SourceMechanism.CLIENT_SENSOR.value not in (mailbox.sources or []):
        mailbox.sources = sorted(
            set(mailbox.sources or []) | {SourceMechanism.CLIENT_SENSOR.value}
        )
        caps = capabilities_for(frozenset(SourceMechanism(x) for x in mailbox.sources))
        mailbox.protection_level = protection_level(caps).value
        mailbox.inactive_detections = inactive_for(caps)

    await session.commit()
    return {
        "acknowledged": True,
        "at": now.isoformat(),
        "new_session": reason is not None,
        "reason": reason,
        "alerted": alerted,
        "findings": findings,
        "protection_level": mailbox.protection_level,
        "heartbeat_seconds": sensor_rules.HEARTBEAT_SECONDS,
    }


@router.post("/sensor/message-opened")
async def sensor_message_opened(
    req: SensorMessageOpened, caller: SensorPrincipal, session: Session
) -> dict:
    """Attested reads. C11 fires when a message becomes read with *no*
    attestation and no covered device present — cleaner than any audit log, and
    it needs no enterprise licence."""
    from envelock.models import AttestedRead
    from envelock.platform.sensor import normalize_message_ref

    mailbox = await _sensor_mailbox(session, caller, req.mailbox_address)
    _assert_pinned_device(caller, req.device_fingerprint)

    ref = normalize_message_ref(req.message_ref)
    if not ref:
        raise HTTPException(422, "message_ref is empty")
    # Actually record it. This endpoint used to validate the mailbox and throw
    # the attestation away, which meant C11 ("a message was read with nobody
    # here") had no way to tell a legitimate read from an intruder's — every
    # read looked like an intrusion, so the detection could only ever have been
    # a false-positive generator.
    session.add(
        AttestedRead(
            tenant_id=caller.tenant_id,
            mailbox_id=mailbox.id,
            message_ref=ref,
            device_fingerprint=req.device_fingerprint,
            read_at=datetime.now(UTC),
        )
    )
    await session.commit()
    return {"recorded": True, "message_ref": ref}


class FlagChanged(BaseModel):
    mailbox_address: str
    message_ref: str
    flag: str = "seen"


@router.post("/sensor/flag-changed")
async def flag_changed(req: FlagChanged, principal: ActiveUser, session: Session) -> dict:
    """Report that a message became read, and run C11 on it.

    The IMAP poller notices reads itself now (workers/imap_fetch.py) and calls
    the same `platform.sensor.evaluate_read`; this endpoint remains for a
    signed-in operator or a test to drive the detection directly.
    """
    from envelock.platform.sensor import evaluate_read

    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")
    _assert_sensor_mailbox_access(principal, mailbox)
    if req.flag != "seen":
        return {"findings": [], "alerted": False}

    domains = {
        d for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(
                    Domain.tenant_id == principal.tenant_id
                )
            )
        ).all()
    }
    verdict = await evaluate_read(
        session,
        mailbox=mailbox,
        message_ref=req.message_ref,
        owned_domains=frozenset(domains),
    )
    await session.commit()
    return {
        "findings": verdict.findings,
        "alerted": verdict.alerted,
        "attested": verdict.attested,
    }


# ── L1 Web Push subscription (PRD §8.1) ──────────────────────────────────────
class PushSubscribeRequest(BaseModel):
    endpoint: str = Field(min_length=8, max_length=2000)
    p256dh: str = Field(min_length=8, max_length=255)
    auth: str = Field(min_length=8, max_length=255)


@router.post("/push/subscribe")
async def push_subscribe(
    req: PushSubscribeRequest, principal: ActiveUser, session: Session
) -> dict:
    """Register this browser for L1 Web Push. Without this write path the free push
    rung can never fire — the sender has no one to send to (PRD §8.1)."""
    existing = (
        await session.execute(
            select(PushSubscription).where(PushSubscription.endpoint == req.endpoint)
        )
    ).scalar_one_or_none()
    if existing is not None:
        # Reassigning a row that belongs to someone else on endpoint match alone
        # was a takeover: submit a victim's endpoint URL and their push alerts go
        # dark while your keys are installed. The endpoint URL can leak (logs,
        # provider dashboards); the p256dh/auth keys are generated inside the
        # subscriber's browser and cannot. So a different user may claim the row
        # only by proving they hold the same browser subscription — same keys.
        same_user = existing.user_id == principal.user_id
        same_browser = existing.p256dh == req.p256dh and existing.auth == req.auth
        if not (same_user or same_browser):
            raise HTTPException(
                409, "this push endpoint is already registered to another account"
            )
        existing.user_id = principal.user_id
        existing.tenant_id = principal.tenant_id
        existing.p256dh = req.p256dh
        existing.auth = req.auth
    else:
        session.add(
            PushSubscription(
                tenant_id=principal.tenant_id,
                user_id=principal.user_id,
                endpoint=req.endpoint,
                p256dh=req.p256dh,
                auth=req.auth,
            )
        )
    await session.commit()
    return {"subscribed": True}


@router.post("/push/unsubscribe")
async def push_unsubscribe(
    req: PushSubscribeRequest, principal: CurrentUser, session: Session
) -> dict:
    from sqlalchemy import delete as sql_delete

    await session.execute(
        sql_delete(PushSubscription).where(
            PushSubscription.endpoint == req.endpoint,
            PushSubscription.user_id == principal.user_id,
        )
    )
    await session.commit()
    return {"subscribed": False}


@router.get("/sensor/config")
async def sensor_config(principal: CurrentUser) -> dict:
    from envelock.config import get_settings

    settings = get_settings()
    return {
        "heartbeat_seconds": 60,
        "vapid_public_key": settings.vapid_public_key,
        "push_available": bool(settings.vapid_public_key),
        "endpoints": {
            "heartbeat": "/api/v1/sensor/heartbeat",
            "message_opened": "/api/v1/sensor/message-opened",
        },
    }


# ── E12 — attack simulation ──────────────────────────────────────────────────
class SimulationRequest(BaseModel):
    protected_domain: str
    vendor_domain: str = "supplier-example.com"


@router.post("/simulate")
async def simulate(req: SimulationRequest, principal: AdminUser, session: Session) -> dict:
    """Benign look-alike attacks that prove the product works. Every message
    carries an X-Envelock-Simulation header so it can never be mistaken for a
    real incident."""
    from envelock.channels.mail.parser import parse_message_async

    owned = frozenset({registrable_domain(req.protected_domain)})
    mailbox = (
        await session.execute(
            select(Mailbox).where(Mailbox.tenant_id == principal.tenant_id).limit(1)
        )
    ).scalar_one_or_none()

    # A simulation is only meaningful against a *known* vendor: A1 needs a
    # bank record to diff against and A3 needs the real domain to compare with.
    # Without that seed the run would report "not detected" for detections that
    # are working correctly — worse than not running it.
    vendor = registrable_domain(req.vendor_domain)
    seeded = CounterpartyState(
        registrable_domain=vendor,
        message_count=40,
        known_bank_ids=frozenset({"GB94BARC10201530093459"}),
        verified_phone="+00 000 000 0000",
        last_seen_at=datetime.now(UTC),
    )

    runs: list[SimulationRun] = []
    for sim in simulations(
        protected_domain=req.protected_domain, vendor_domain=req.vendor_domain
    ):
        event = await parse_message_async(
            sim.raw_message.encode(),
            tenant_id=principal.tenant_id,
            mailbox_id=mailbox.id if mailbox else uuid4(),
            source=SourceMechanism.IMAP_IDLE,
            owned_domains=owned,
            remediable=True,
        )
        ctx = DetectionContext(
            event=event,
            tenant_id=str(principal.tenant_id),
            capabilities=capabilities_for(
                frozenset({SourceMechanism.IMAP_IDLE, SourceMechanism.CLIENT_SENSOR})
            ),
            owned_domains=owned,
            known_counterparties=frozenset({vendor}),
            counterparty=seeded,
            now=datetime.now(UTC),
        )
        findings = run_all(ctx)
        result = type("R", (), {"findings": findings})()
        runs.append(
            SimulationRun(
                simulation_id=sim.id,
                expected=sim.expects,
                detected=[f.service for f in result.findings],
            )
        )

    return {
        "runs": [
            {
                "id": r.simulation_id,
                "expected": r.expected,
                "detected": r.detected,
                "passed": r.passed,
            }
            for r in runs
        ],
        "passed": sum(1 for r in runs if r.passed),
        "total": len(runs),
        "note": "Simulations are analysed but never stored as alerts.",
    }


async def _tenant_recipients(session: Session, tenant_id: UUID) -> list[Recipient]:
    """Everyone who should hear about an alert on this tenant. The IT admins
    always receive it (E4/E6); that independent channel is the safety net that
    makes delaying the paid rung defensible (PRD §8.2)."""
    users = (
        await session.execute(select(User).where(User.tenant_id == tenant_id))
    ).scalars().all()
    push_user_ids = {
        uid
        for (uid,) in (
            await session.execute(
                select(PushSubscription.user_id).where(
                    PushSubscription.tenant_id == tenant_id
                )
            )
        ).all()
    }
    return [
        Recipient(
            user_id=str(u.id),
            is_admin=u.is_admin,
            has_push_subscription=u.id in push_user_ids,
            # Login email as fallback — the delivery layer refuses to send
            # into the alert's own mailbox (see dispatch._destination).
            out_of_band_email=u.out_of_band_email or u.email,
            # Only a verified phone is an SMS destination — never send a Critical
            # fraud alert to an unproven number an attacker could have set.
            phone=u.phone if u.phone_verified else None,
            has_sensor=u.id in push_user_ids,
        )
        for u in users
    ]


# ── Tier 4 ingest over HTTP ──────────────────────────────────────────────────
class IngestRequest(BaseModel):
    raw_message: str
    mailbox_address: str


@router.post("/ingest", status_code=202)
async def ingest_message(
    req: IngestRequest, principal: AdminUser, session: Session
) -> dict:
    """Push a message through the real pipeline: detections run, counterparties
    are learned, and any alert is persisted.

    The SMTP listener uses the same path — this is its HTTP equivalent, which
    also makes the system demonstrable without configuring mail flow.
    """
    from envelock.channels.mail.parser import parse_message_async

    mailbox = (
        await session.execute(
            select(Mailbox).where(
                Mailbox.tenant_id == principal.tenant_id,
                Mailbox.address == req.mailbox_address.lower(),
            )
        )
    ).scalar_one_or_none()
    if mailbox is None:
        raise HTTPException(404, "mailbox not found")

    domains = {
        d
        for (d,) in (
            await session.execute(
                select(Domain.registrable_domain).where(
                    Domain.tenant_id == principal.tenant_id
                )
            )
        ).all()
    }
    sources = frozenset(SourceMechanism(s) for s in (mailbox.sources or []) if s)
    source = next(iter(sources), SourceMechanism.FORWARD_INGEST)

    event = await parse_message_async(
        req.raw_message.encode(),
        tenant_id=principal.tenant_id,
        mailbox_id=mailbox.id,
        source=source,
        owned_domains=frozenset(domains),
        remediable=True,
    )
    recipients = await _tenant_recipients(session, principal.tenant_id)
    result = await analyse_event(
        session,
        event,
        tenant_id=principal.tenant_id,
        owned_domains=frozenset(domains),
        recipients=recipients,
    )
    # Actually deliver the free ladder rungs the alert just queued (PRD §8.1).
    delivered = 0
    if result.alert_id is not None:
        touched = await deliver_pending(session, alert_id=result.alert_id)
        delivered = sum(1 for d in touched if d.status == "sent")
    await session.commit()

    return {
        "alerted": result.alerted,
        "alert_id": str(result.alert_id) if result.alert_id else None,
        "tier": result.assessment.tier.value if result.assessment else None,
        "notifications_sent": delivered,
        "findings": [
            {"service": f.service, "tier": f.tier.value, "summary": f.summary}
            for f in result.findings
        ],
        "latency_seconds": result.latency_seconds,
    }


# ── E11 — backfill ───────────────────────────────────────────────────────────
@router.post("/mailboxes/{mailbox_id}/backfill")
async def backfill(
    mailbox_id: UUID,
    principal: AdminUser,
    session: Session,
    full: bool = False,
    days: int | None = None,
) -> dict:
    """Onboarding backfill (E11). Pulls previous mail and runs it through the
    pipeline so A9 stylometry and A12 baselines work on day one. For an IMAP
    mailbox this actually executes; other tiers return the plan (their history
    arrives via the provider's own backfill or forwarding).

    `full=true` scans essentially all available history (10 years back, up to the
    per-mailbox message ceiling); `days=N` sets a specific look-back window."""
    mailbox = await session.get(Mailbox, mailbox_id)
    if mailbox is None or mailbox.tenant_id != principal.tenant_id:
        raise HTTPException(404, "mailbox not found")

    tenant = await session.get(Tenant, principal.tenant_id)
    if tenant is None or not entitlement.mailbox_entitled(tenant):
        # A lapsed-trial Guard tenant doesn't get to run the expensive part of a
        # trial (full-history analysis: LLM calls, reputation lookups) for free.
        raise HTTPException(
            402, "backfill needs an active trial or plan — add billing to continue"
        )
    now = datetime.now(UTC)
    in_trial = bool(
        tenant.trial_ends_at
        and tenant.trial_ends_at > now
        and not tenant.payment_method_ok
    )
    plan = plan_backfill(mailbox_id=mailbox_id, in_trial=in_trial)
    # The plan window is the COGS boundary for anyone who hasn't paid: `full`
    # and `days` used to be caller-supplied overrides straight past it, letting
    # a trial (or lapsed) tenant bill us ten years of analysis. A tenant with a
    # real payment method keeps the full-history sweep — that cost is backed.
    requested = 3650 if full else (days if days and days > 0 else plan.days)
    cap = 3650 if tenant.payment_method_ok else plan.days
    window = min(requested, cap)

    is_imap = any(
        s in {SourceMechanism.IMAP_IDLE.value, SourceMechanism.IMAP_POLL.value}
        for s in (mailbox.sources or [])
    )

    response = {
        "mailbox": mailbox.address,
        "days": window,
        "since": plan.since.isoformat(),
        "estimated_batches": plan.estimated_batches,
        "reason": plan.reason,
        "job": None,
    }
    if not (is_imap and not mailbox.needs_reconnect):
        return response

    # Backfill used to be awaited right here. It fetches up to
    # `backfill_max_messages` (5,000) messages over IMAP and parses, extracts and
    # analyses each one — minutes of work inside a request the proxy gives up on
    # in thirty seconds. The customer saw a timeout, the work carried on
    # invisibly, and this is the FIRST thing every new customer does. Now it runs
    # in the background and the response hands back a job to poll.
    from envelock.security.keys import custody_summary

    if not custody_summary().get("can_decrypt"):
        # Split custody: this process cannot open the credential, so the scan
        # cannot run here — it used to try, fail to decrypt, and report the
        # first thing every new customer does as a failure. The worker claims
        # the request on its next cycle and records progress on the mailbox,
        # which the dashboard reads.
        now_q = datetime.now(UTC)
        mailbox.backfill_requested_at = now_q
        mailbox.backfill_requested_days = window
        mailbox.backfill_state = {
            "status": "queued",
            "days": window,
            "queued_at": now_q.isoformat(),
        }
        await session.commit()
        response["queued"] = True
        return response

    from envelock.workers import jobs
    from envelock.workers.imap_fetch import backfill_mailbox

    key = str(mailbox_id)
    if existing := jobs.running_for(
        tenant_id=principal.tenant_id, kind="backfill", key=key
    ):
        # Double-clicking "scan my history" joins the run in progress rather than
        # starting a second one competing for the same IMAP connection.
        response["job"] = existing.payload()
        return response

    async def _run(job) -> dict:  # noqa: ANN001
        # Its own session: the request's is closed as soon as we return.
        from envelock.db import get_sessionmaker

        async with get_sessionmaker()() as bg_session:
            live = await bg_session.get(Mailbox, mailbox_id)
            if live is None:
                return {"skipped": "mailbox removed"}
            job.progress["mailbox"] = live.address
            return await backfill_mailbox(bg_session, live, days=window)

    job = jobs.submit(
        kind="backfill", tenant_id=principal.tenant_id, body=_run, key=key
    )
    response["job"] = job.payload()
    return response


@router.get("/jobs/{job_id}")
async def job_status(job_id: UUID, principal: ActiveUser) -> dict:
    """Progress of a background job started by this tenant.

    Jobs are held in the API process, so a restart loses the *status* of a run in
    flight. It does not lose the work: the pipeline commits as it goes and a
    backfill is idempotent by `rfc_message_id`, so re-running one is safe. Saying
    "unknown" is the honest answer to a job we no longer have a record of.
    """
    from envelock.workers import jobs

    job = jobs.get(job_id, tenant_id=principal.tenant_id)
    if job is None:
        return {
            "id": str(job_id),
            "status": "unknown",
            "detail": (
                "No record of this job. It either finished some time ago or the "
                "service restarted while it was running — re-running a backfill "
                "is safe."
            ),
        }
    return job.payload()


# ── Operational status ───────────────────────────────────────────────────────
@router.get("/status/channels")
async def channel_status(principal: ActiveUser) -> dict:
    # Honest sources only. This endpoint used to render three permanently-zero
    # stat blocks from singletons nothing ever drove (a per-request cascade, a
    # never-started broker, a second CT watcher that wasn't the one running) —
    # live-looking numbers that could never move.
    from envelock.detections.cascade import get_attachment_cascade
    from envelock.workers import scheduler as sched
    from envelock.workers.imap_fetch import worker_health

    ct = sched.LIVE_CT_WATCHER
    return {
        "mail_providers": provider_status(),
        "imap_worker": worker_health(),
        "notification_rungs": Dispatcher().status(),
        "attachments": get_attachment_cascade().metrics.payload(),
        "cert_transparency": (
            ct.stats.payload() if ct is not None else {"running": False}
        ),
        "counterparty_graph": {"domains": len(GRAPH), "actionable": len(GRAPH.known_bad())},
    }


@router.get("/status/cost")
async def cost_status(principal: AdminUser, session: Session) -> dict:
    """Fall-through is the number that predicts COGS (PRD §12.12D)."""
    from datetime import UTC, datetime

    from sqlalchemy import func

    from envelock.config import get_settings
    from envelock.llm.providers import get_provider
    from envelock.models import LlmUsage

    settings = get_settings()
    period = datetime.now(UTC).strftime("%Y-%m")
    calls, cost = (
        await session.execute(
            select(
                func.coalesce(func.sum(LlmUsage.calls), 0),
                func.coalesce(func.sum(LlmUsage.cost_micros), 0),
            ).where(LlmUsage.tenant_id == principal.tenant_id, LlmUsage.period == period)
        )
    ).one()
    prov = get_provider()
    return {
        "attachments": get_attachment_cascade().metrics.payload(),
        "urls": get_url_cascade().metrics.payload(),
        "detonation_enabled": get_attachment_cascade().detonation_enabled,
        "ai_cascade": {
            "provider": settings.llm_provider,
            "configured": bool(prov and prov.configured),
            "model": getattr(prov, "model", None),
            "cap_per_mailbox_month": settings.llm_max_calls_per_mailbox_month,
            "calls_this_month": int(calls),
            "cost_micros_this_month": int(cost),
        },
    }
