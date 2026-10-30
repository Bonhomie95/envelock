"""Channel endpoints: brand posture, client sensor, simulation, worker status."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
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
from envelock.platform.graph import SimulationRun, plan_backfill, simulations
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
    # GOOGLE_REPORTS (sign-in logs / MFA state) was claimed here but nothing reads
    # Google's Reports API, so a Gmail mailbox advertised sign-in and MFA coverage
    # it never delivered. Dropped — like Microsoft's ENTRA_LOGS above — so the
    # protection level stays honest. Those login detections come from the sensor.
    "google": [SourceMechanism.GMAIL_API],
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
    from envelock.services.plan_gate import require_mailbox_entitlement

    await require_verified_domain(session, principal.tenant_id, mailbox.address)
    # Before the consent URL, not after the grant: sending a Guard tenant round
    # Microsoft's consent screen and then refusing them is the worst order.
    await require_mailbox_entitlement(session, principal.tenant_id)

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
_START_AGAIN = "This connection link is invalid or has expired. Please start again."


def _connect_result(**params: str) -> RedirectResponse:
    from urllib.parse import urlencode

    from envelock.config import get_settings

    base = get_settings().web_base_url.rstrip("/")
    query = urlencode({"tab": "mailboxes", **params})
    return RedirectResponse(f"{base}/dashboard?{query}", status_code=302)


@router.get("/connect/oauth/{provider}/callback", dependencies=[SystemScoped])
async def oauth_callback(
    provider: str,
    session: Session,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
) -> RedirectResponse:
    """Consent redirect target. Exchanges the code and seals the tokens.

    No bearer token here — this is a browser redirect from the provider, so the
    HMAC-signed `state` is the authorisation. Tokens are envelope-encrypted
    (PRD §5.2) and never returned to the caller.

    Every outcome redirects back to the dashboard: it is the customer's own
    browser that lands here, and a JSON body left them on a raw API page with
    no way back. Failure text is fixed, never echoed from the query string.
    """
    if error:
        return _connect_result(
            connect_error="Permission wasn't granted, so the mailbox was not connected."
        )
    if not code or not state:
        return _connect_result(connect_error=_START_AGAIN)

    prov = oauth.provider_for(provider)
    if prov is None or provider not in _OAUTH_SOURCES:
        return _connect_result(connect_error=_START_AGAIN)

    try:
        claims = oauth.verify_state(state, provider=provider)
    except oauth.OAuthError as exc:
        logger.warning("oauth state verification failed for %s: %s", provider, exc)
        return _connect_result(connect_error=_START_AGAIN)

    # Single-use: a signed state was replayable for its whole 600s window, so a
    # leaked redirect URL (browser history, proxy logs) could re-run the token
    # exchange. Same store that makes TOTP codes one-shot.
    from envelock.security.limits import active_replay

    if not await active_replay().acheck_and_record(f"oauthstate:{state[-48:]}", ttl=600):
        return _connect_result(
            connect_error="This connection link was already used. Please start again."
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
        return _connect_result(connect_error="That mailbox no longer exists. Add it again first.")

    mode = claims.get("k", "api")

    try:
        tokens = await oauth.exchange_code(prov, code=code)
    except oauth.OAuthError as exc:
        logger.warning("oauth token exchange failed for %s: %s", provider, exc)
        return _connect_result(
            connect_error="We couldn't finish connecting to your email provider. Please try again."
        )

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

    # Which inbox does this token actually read? Delegated OAuth reads /me — the
    # account that just consented — which can differ from the address the customer
    # typed. Resolve it NOW so a wrong-account connect is visible on the spot, not
    # only after the first poll. Best-effort with no backoff: a slow or failed
    # probe must never hang or fail the connect redirect; the poller re-checks.
    try:
        from envelock.channels.mail.api_fetch import gmail_whoami, graph_whoami

        whoami = gmail_whoami if provider == "google" else graph_whoami
        real = await whoami(access_token=tokens.access_token, backoff=0.0)
        if real:
            mailbox.connected_address = real
    except Exception as exc:  # noqa: BLE001 — identity probe must not block connect
        logger.info("connect whoami skipped for mailbox %s: %s", mailbox.id, exc)

    await session.commit()

    mismatch = bool(
        mailbox.connected_address
        and mailbox.connected_address.lower() != mailbox.address.lower()
    )
    # The real inbox the token reads differing from the label is said at once,
    # not left behind a clean success.
    #
    # F7: we warn, we do not block. Delegated OAuth's /me returns the CONSENTING
    # user's primary address, which legitimately differs from the label in the
    # normal Tier-1 setups — an alias mailbox, an M365 shared mailbox a person
    # monitors with their own account, or a .onmicrosoft.com UPN behind a vanity
    # domain. Refusing the connect on a mismatch would break all three; surfacing
    # it (the dashboard shows "watching <other inbox>") lets the customer catch a
    # genuinely wrong-account connect without penalising the common ones.
    return _connect_result(
        connected=mailbox.address, **({"mismatch": "1"} if mismatch else {})
    )


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

        recipients = await _recipients(session, caller.tenant_id, mailbox.address)
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
    return {
        "recorded": True,
        "message_ref": ref,
        "warning": await _reading_pane_warning(session, mailbox, ref),
    }


async def _reading_pane_warning(session: AsyncSession, mailbox: Mailbox, ref: str) -> dict | None:
    """What the person just opened, if Envelock flagged it — so the add-on can
    say so where they are reading (Outlook's info bar, Thunderbird's toolbar,
    a banner in webmail) rather than in a dashboard they don't have open.

    The one thing a sensor token can read, and deliberately narrow: only its own
    mailbox, only a message whose Message-ID it just reported opening, only an
    alert still in force (a dismissal means "not fraud"), and only the headline
    — never findings' evidence, amounts or the alert list."""
    from sqlalchemy import func

    from envelock.models import Alert, Finding, Message
    from envelock.platform import verification

    if not ref or ref == "*":
        return None
    message = (
        await session.execute(
            select(Message)
            .where(
                Message.mailbox_id == mailbox.id,
                func.lower(func.btrim(Message.rfc_message_id, "<> ")) == ref,
            )
            .order_by(Message.created_at.desc())
            .limit(1)
        )
    ).scalars().first()
    if message is None:
        return None
    alert_id = (
        await session.execute(
            select(Finding.alert_id).where(
                Finding.message_id == message.id, Finding.alert_id.is_not(None)
            )
        )
    ).scalars().first()
    alert = await session.get(Alert, alert_id) if alert_id else None
    if alert is None or alert.state == "dismissed" or alert.tier not in ("critical", "high"):
        return None
    phone = None
    if alert.requires_callback:
        phone = (await verification.context(session, alert))["phone_on_file"]
    if alert.state == "resolved":
        action = "Confirmed fraud. Do not pay, reply or open anything in this email."
    elif alert.requires_callback:
        action = (
            f"Don't pay until you've called {phone} (the number on file) to verify."
            if phone
            else "Don't pay until you've verified by phone — not a number from this email."
        )
    else:
        action = "Don't click links, open attachments or reply until you've checked."
    return {
        "tier": alert.tier,
        "title": alert.title,
        "action": action,
        "verify_phone": phone,
        "confirmed_fraud": alert.state == "resolved",
    }


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
    rung can never fire — the sender has no one to send to (PRD §8.1).

    The endpoint is looked up across tenants. It is unique platform-wide, so a
    browser last registered by someone in another workspace (a consultant, a
    second workspace, a shared machine) was invisible under the caller's tenant
    scope: the insert hit the unique index, the browser read "off", and pressing
    Enable then unsubscribed it — silently ending the other person's alerts too.
    """
    from envelock.db_rls import system_scope_on

    async with system_scope_on(session, "push: which account holds this browser"):
        existing = (
            await session.execute(
                select(PushSubscription).where(PushSubscription.endpoint == req.endpoint)
            )
        ).scalar_one_or_none()
        if existing is not None:
            # Reassigning a row that belongs to someone else on endpoint match
            # alone was a takeover: submit a victim's endpoint URL and their push
            # alerts go dark while your keys are installed. The endpoint URL can
            # leak (logs, provider dashboards); the p256dh/auth keys are
            # generated inside the subscriber's browser and cannot. So a
            # different user may claim the row only by proving they hold the same
            # browser subscription — same keys.
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
        # Inside the scope: moving a row out of another tenant is an UPDATE the
        # caller's own scope may not make.
        await session.flush()
    await session.commit()
    return {"subscribed": True}


class PushRotateRequest(BaseModel):
    old_endpoint: str = Field(min_length=8, max_length=2000)
    old_auth: str = Field(min_length=8, max_length=255)
    endpoint: str = Field(min_length=8, max_length=2000)
    p256dh: str = Field(min_length=8, max_length=255)
    auth: str = Field(min_length=8, max_length=255)


@router.post("/push/rotate")
async def push_rotate(req: PushRotateRequest, session: Session) -> dict:
    """The browser replaced its push subscription; move the row to the new one.

    Called by the service worker on `pushsubscriptionchange`, which holds no
    session — the bearer token lives in the page's storage. Until this existed
    the new subscription reached us only when someone next opened the app, and
    meanwhile the old endpoint answered 410 and was deleted: no browser alerts
    at all in between.

    Possession of the old subscription's `auth` secret is the proof. It is
    generated inside that browser and known only to it and to us; the endpoint
    URL alone can leak and proves nothing.
    """
    import hmac

    from envelock.db_rls import system_scope_on

    async with system_scope_on(session, "push: rotate a browser subscription"):
        row = (
            await session.execute(
                select(PushSubscription).where(PushSubscription.endpoint == req.old_endpoint)
            )
        ).scalar_one_or_none()
        if row is None or not hmac.compare_digest(row.auth.encode(), req.old_auth.encode()):
            raise HTTPException(404, "no such push subscription")
        taken = (
            await session.execute(
                select(PushSubscription).where(PushSubscription.endpoint == req.endpoint)
            )
        ).scalar_one_or_none()
        if taken is not None and taken.id != row.id:
            # The page registered the new subscription first; the old row only
            # points at a dead endpoint now.
            await session.delete(row)
        else:
            row.endpoint = req.endpoint
            row.p256dh = req.p256dh
            row.auth = req.auth
        await session.flush()
    await session.commit()
    return {"rotated": True}


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


@router.post("/push/test")
async def push_test(principal: ActiveUser, session: Session) -> dict:
    """Push a test notification to every browser this user enabled, now, and
    say what the push service answered — so "nothing arrived" can be told apart
    from "it was delivered and the device kept it quiet"."""
    from envelock.core.enums import AlertTier
    from envelock.notify.dispatch import _push_to_all
    from envelock.notify.senders import Notification

    dispatcher = Dispatcher()
    if not dispatcher.push.configured:
        raise HTTPException(503, "browser alerts are not configured on this deployment")
    note = Notification(
        alert_id=uuid4(),
        tenant_id=principal.tenant_id,
        tier=AlertTier.LOW,
        title="Test notification: browser alerts are working.",
        body="",
    )
    result = await _push_to_all(session, dispatcher, note, principal.user_id)
    await session.commit()  # keep any dead subscription it pruned
    return {"delivered": result.delivered, "detail": result.reason}


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

    # Run the simulation on the plan they actually have. Without this a Guard or
    # Essential tenant watched Complete-only detections pass and concluded their
    # mail was covered by them — a demo that lies in our favour is worse than no
    # demo. `plan_locked` then names what a bigger plan would have caught.
    tenant_row = await session.get(Tenant, principal.tenant_id)
    plan = entitlement.effective_plan(tenant_row) if tenant_row is not None else None

    runs: list[SimulationRun] = []
    names: dict[str, str] = {}
    for sim in simulations(
        protected_domain=req.protected_domain, vendor_domain=req.vendor_domain
    ):
        names[sim.id] = sim.name
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
            plan=plan,
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

    from envelock.billing.features import detection_included

    def locked(expected: str) -> bool:
        """Missed because the plan excludes it, not because detection failed.

        Reported per run so a Guard or Essential tenant reads "your plan does not
        include this" rather than a bare failure, which would look like a broken
        product and is the opposite of the truth.
        """
        return plan is not None and not detection_included(expected, plan)

    return {
        "plan": plan,
        "runs": [
            {
                "id": r.simulation_id,
                "name": names.get(r.simulation_id, "Simulated attack"),
                "expected": r.expected,
                "detected": r.detected,
                "passed": r.passed,
                "plan_locked": locked(r.expected),
            }
            for r in runs
        ],
        "passed": sum(1 for r in runs if r.passed),
        "plan_locked": sum(1 for r in runs if locked(r.expected)),
        "total": len(runs),
        "note": "Simulations are analysed but never stored as alerts.",
    }


async def _tenant_recipients(
    session: Session, tenant_id: UUID, mailbox_address: str | None = None
) -> list[Recipient]:
    """Everyone who should hear about an alert on this tenant. The IT admins
    always receive it (E4/E6); that independent channel is the safety net that
    makes delaying the paid rung defensible (PRD §8.2)."""
    from envelock.channels.mail.forward_runner import _may_hear_about

    users = [
        u
        for u in (
            await session.execute(select(User).where(User.tenant_id == tenant_id))
        ).scalars().all()
        if _may_hear_about(u, mailbox_address)
    ]
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
    from envelock.services.plan_gate import require_mailbox_entitlement

    # Same gate as `backfill` below. Without it a lapsed tenant keeps feeding
    # mail through the full pipeline — reputation lookups, parsing, storage —
    # and the only reason nothing leaks is that the plan filter empties the
    # detection set downstream. Refuse at the door instead of paying for it.
    await require_mailbox_entitlement(session, principal.tenant_id)

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
    recipients = await _tenant_recipients(session, principal.tenant_id, mailbox.address)
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
    # OAuth mailboxes (Microsoft 365 / Gmail) backfill too now — previously only
    # IMAP ran, so an API-connected mailbox onboarded with cold A9/A12 baselines.
    is_oauth = any(
        s in {SourceMechanism.GRAPH_API.value, SourceMechanism.GMAIL_API.value}
        for s in (mailbox.sources or [])
    )
    runnable = is_imap or is_oauth

    response = {
        "mailbox": mailbox.address,
        "days": window,
        "since": plan.since.isoformat(),
        "estimated_batches": plan.estimated_batches,
        "reason": plan.reason,
        "job": None,
    }
    if not (runnable and not mailbox.needs_reconnect):
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
            if any(
                src in {SourceMechanism.GRAPH_API.value, SourceMechanism.GMAIL_API.value}
                for src in (live.sources or [])
            ):
                from envelock.workers.oauth_fetch import backfill_oauth_mailbox

                return await backfill_oauth_mailbox(bg_session, live, days=window)
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
    # Customer-facing availability only; platform internals belong in staff tools.
    return {
        "mail_providers": provider_status(),
        "notification_rungs": Dispatcher().status(),
    }


@router.get("/status/cost")
async def cost_status(principal: AdminUser, session: Session) -> dict:
    """Customer AI availability and usage; no internal costs or pipeline metrics."""
    from datetime import UTC, datetime

    from sqlalchemy import func

    from envelock.config import get_settings
    from envelock.llm.providers import get_provider
    from envelock.models import LlmUsage

    settings = get_settings()
    period = datetime.now(UTC).strftime("%Y-%m")
    calls = (
        await session.execute(
            select(
                func.coalesce(func.sum(LlmUsage.calls), 0),
            ).where(LlmUsage.tenant_id == principal.tenant_id, LlmUsage.period == period)
        )
    ).scalar_one()
    prov = get_provider()
    return {
        "ai_cascade": {
            "configured": bool(prov and prov.configured),
            "cap_per_mailbox_month": settings.llm_max_calls_per_mailbox_month,
            "calls_this_month": int(calls),
        },
    }
