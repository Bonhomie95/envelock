"""The client sensor — Channel 2 — on the server side.

The sensor is the small piece of Envelock that runs on a person's own device:
the browser extension on their webmail, the Thunderbird add-on, the Outlook
add-in. It is how Envelock learns things no mail protocol will tell it — which
devices are signed in to a mailbox, from where, and which messages the owner
actually opened. Group C's account-takeover detections (C6–C11) are built on it.

This module is the one place that knows the sensor's rules, so the HTTP
endpoints, the IMAP poller and the tests cannot drift apart on them:

* **Liveness.** A sensor session is live while it keeps heartbeating. The
  session table used to have an `ended_at` column that nothing ever set, so a
  device that heartbeated once stayed "signed in" forever — which permanently
  suppressed C11 (it only fires when nobody is signed in) and meant a device
  returning from another country never counted as a new sign-in.
* **Identity.** Sensors hold their own narrowly scoped token, never a user
  session. See `models.SensorDevice`.
* **Message identity.** The sensor and the poller must name a message the same
  way, and the only name both can see is the RFC 5322 `Message-ID` header.
* **Silent access (C11).** "A message was marked read while none of your
  devices were here" — evaluated identically whether the poller noticed the
  read or a test posted it.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("envelock.sensor")

# ── Timing ───────────────────────────────────────────────────────────────────
#: How often a sensor reports that its device is present.
HEARTBEAT_SECONDS = 60

#: A session with no heartbeat for this long has ended. Three missed beats, so a
#: laptop that briefly loses Wi-Fi is not treated as having signed out and back
#: in, while a device that has actually gone away stops counting within minutes.
SESSION_STALE_SECONDS = 180

#: How far either side of a read we accept a sensor's attestation as covering
#: it. The sensor reports the read the moment it happens; the poller notices the
#: flag on its next cycle, up to a minute later. Wide enough for that skew,
#: narrow enough that an intruder reading minutes later is not laundered by the
#: owner's earlier legitimate read.
ATTESTATION_WINDOW_SECONDS = 180

#: A pairing code is typed by a person from one screen into another. Ten minutes
#: is ample for that and short enough that one glimpsed over a shoulder expires.
PAIRING_TTL = timedelta(minutes=10)

#: Upper bound on the unread UIDs remembered per mailbox between polls. A mailbox
#: with tens of thousands of unread newsletters must not turn one poll into a
#: megabyte column write; reads of very old unread mail are simply not tracked.
MAX_TRACKED_UNSEEN = 5000

#: A sensor that can tell the owner is actively reading, but cannot name the
#: message (most webmail does not expose the Message-ID header), attests with
#: this instead. It covers any read in its window on that mailbox.
ACTIVITY_REF = "*"

CLIENTS = frozenset({"browser", "thunderbird", "outlook"})


def now_utc() -> datetime:
    return datetime.now(UTC)


def aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ── Message identity ─────────────────────────────────────────────────────────
def normalize_message_ref(value: str | None) -> str:
    """The one spelling of a message's identity that both sides agree on.

    Clients hand over the `Message-ID` header in whatever form their API gives
    it: Thunderbird without angle brackets, Outlook with them, a raw header with
    stray whitespace. Mail systems treat these case-insensitively in practice, so
    the canonical form is trimmed, unbracketed and lower-cased. The activity
    marker passes through unchanged.
    """
    ref = (value or "").strip()
    if ref == ACTIVITY_REF:
        return ref
    if ref.startswith("<") and ref.endswith(">"):
        ref = ref[1:-1].strip()
    return ref.lower()[:255]


# ── Tokens ───────────────────────────────────────────────────────────────────
TOKEN_PREFIX = "envs_"  # noqa: S105 — a public prefix, not a secret


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def mint_token() -> tuple[str, str, str]:
    """`(plaintext, prefix, hashed)`. The plaintext is shown to the client once."""
    secret = secrets.token_urlsafe(32)
    plaintext = f"{TOKEN_PREFIX}{secret}"
    return plaintext, secret[:8], _hash(plaintext)


def token_prefix(plaintext: str) -> str | None:
    if not plaintext.startswith(TOKEN_PREFIX):
        return None
    body = plaintext[len(TOKEN_PREFIX):]
    return body[:8] if len(body) >= 16 else None


def token_matches(plaintext: str, hashed: str) -> bool:
    return hmac.compare_digest(_hash(plaintext), hashed)


# ── Pairing codes ────────────────────────────────────────────────────────────
#: No 0/O, 1/I/L or U: a code is read off one screen and typed into another, and
#: every ambiguous glyph removed is a support ticket that never happens.
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"
_CODE_LENGTH = 8


def mint_pairing_code() -> tuple[str, str]:
    """`(display, hashed)`. Displayed as `ABCD-EFGH`; ~39 bits, single use, ten
    minutes, and the redemption endpoint is rate-limited per address."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
    return f"{raw[:4]}-{raw[4:]}", _hash(raw)


def pairing_code_hash(entered: str) -> str | None:
    """Hash of what a person typed, forgiving dashes, spaces and case."""
    raw = "".join(ch for ch in (entered or "").upper() if ch.isalnum())
    if len(raw) != _CODE_LENGTH or any(ch not in _CODE_ALPHABET for ch in raw):
        return None
    return _hash(raw)


# ── Liveness ─────────────────────────────────────────────────────────────────
def is_live(last_seen_at: datetime | None, *, now: datetime | None = None) -> bool:
    seen = aware(last_seen_at)
    if seen is None:
        return False
    return (now or now_utc()) - seen <= timedelta(seconds=SESSION_STALE_SECONDS)


def network_changed(
    *,
    previous_ip: str | None,
    previous_country: str | None,
    previous_asn: int | None,
    ip: str | None,
    country: str | None,
    asn: int | None,
) -> bool:
    """Has the same device turned up somewhere meaningfully different?

    This is the stolen-profile case: an infostealer copies a browser profile —
    extension storage, sensor token and all — and replays it elsewhere. The
    device id is identical, so the only thing that differs is the network.

    A changed IP alone is not enough when we can resolve location: phones and
    home connections change address constantly, and alerting on DHCP churn is
    how a security product gets muted. So when the resolved country or network
    operator is known, it has to differ. When nothing resolves (no geo provider
    configured), the address is all there is.
    """
    if not ip or not previous_ip or ip == previous_ip:
        return False
    if country and previous_country and country != previous_country:
        return True
    if asn and previous_asn and asn != previous_asn:
        return True
    geo_known = bool(country or previous_country or asn or previous_asn)
    return not geo_known


async def live_session_count(
    session: AsyncSession, *, mailbox_id: UUID, now: datetime | None = None
) -> int:
    from envelock.models import SensorSession

    cutoff = (now or now_utc()) - timedelta(seconds=SESSION_STALE_SECONDS)
    rows = (
        await session.execute(
            select(SensorSession.id).where(
                SensorSession.mailbox_id == mailbox_id,
                SensorSession.ended_at.is_(None),
                SensorSession.last_seen_at >= cutoff,
            )
        )
    ).all()
    return len(rows)


async def has_enrolled_sensor(session: AsyncSession, *, mailbox_id: UUID) -> bool:
    from envelock.models import SensorDevice

    row = (
        await session.execute(
            select(SensorDevice.id)
            .where(SensorDevice.mailbox_id == mailbox_id, SensorDevice.revoked_at.is_(None))
            .limit(1)
        )
    ).first()
    return row is not None


# ── Silent access (C11) ──────────────────────────────────────────────────────
@dataclass(frozen=True, slots=True)
class ReadVerdict:
    attested: bool
    live_sessions: int
    alerted: bool
    alert_id: UUID | None
    findings: list[dict]


async def is_attested(
    session: AsyncSession,
    *,
    mailbox_id: UUID,
    message_ref: str,
    around: datetime,
) -> bool:
    """Did a sensor on this mailbox vouch for this read?

    Either it named this exact message, or it reported that the owner was
    actively reading at that moment without being able to say which message.
    """
    from envelock.models import AttestedRead

    window = timedelta(seconds=ATTESTATION_WINDOW_SECONDS)
    ref = normalize_message_ref(message_ref)
    refs = [ACTIVITY_REF] if ref == ACTIVITY_REF else [ref, ACTIVITY_REF]
    row = (
        await session.execute(
            select(AttestedRead.id)
            .where(
                AttestedRead.mailbox_id == mailbox_id,
                AttestedRead.message_ref.in_(refs),
                AttestedRead.read_at >= around - window,
                AttestedRead.read_at <= around + window,
            )
            .limit(1)
        )
    ).first()
    return row is not None


async def evaluate_read(
    session: AsyncSession,
    *,
    mailbox,  # noqa: ANN001 — models.Mailbox
    message_ref: str,
    owned_domains: frozenset[str],
    now: datetime | None = None,
    deliver: bool = True,
) -> ReadVerdict:
    """Run C11 for one message that was just seen to become read.

    Called by the IMAP poller when it notices a read, and by the legacy
    `/sensor/flag-changed` endpoint. The detection itself stays pure
    (detections/identity.py); this gathers the two facts it needs — was this
    read vouched for, and was any covered device signed in — and runs the event
    through the real pipeline so an alert, if raised, is escalated like any
    other.
    """
    from envelock.core.enums import IdentityEventKind, SourceMechanism
    from envelock.core.events import DeviceContext, IdentityEvent, NetworkContext
    from envelock.platform.pipeline import analyse_event

    at = now or now_utc()
    ref = normalize_message_ref(message_ref)
    attested = await is_attested(session, mailbox_id=mailbox.id, message_ref=ref, around=at)

    event = IdentityEvent(
        tenant_id=mailbox.tenant_id,
        mailbox_id=mailbox.id,
        occurred_at=at,
        ingested_at=at,
        source=SourceMechanism.IMAP_FLAGS,
        kind=IdentityEventKind.FLAG_CHANGED,
        target=ref,
        after="seen",
        sensor_attested=attested,
        network=NetworkContext(),
        device=DeviceContext(),
    )

    recipients = []
    if deliver:
        from envelock.channels.mail.forward_runner import _recipients

        recipients = await _recipients(session, mailbox.tenant_id)

    result = await analyse_event(
        session,
        event,
        tenant_id=mailbox.tenant_id,
        owned_domains=owned_domains,
        recipients=recipients,
    )
    if deliver and result.alert_id is not None:
        from envelock.notify.dispatch import deliver_pending

        await deliver_pending(session, alert_id=result.alert_id)

    live = await live_session_count(session, mailbox_id=mailbox.id, now=at)
    return ReadVerdict(
        attested=attested,
        live_sessions=live,
        alerted=result.alert_id is not None,
        alert_id=result.alert_id,
        findings=[
            {"service": f.service, "tier": f.tier.value, "summary": f.summary}
            for f in result.findings
        ],
    )


__all__ = [
    "ACTIVITY_REF",
    "ATTESTATION_WINDOW_SECONDS",
    "CLIENTS",
    "HEARTBEAT_SECONDS",
    "MAX_TRACKED_UNSEEN",
    "PAIRING_TTL",
    "SESSION_STALE_SECONDS",
    "ReadVerdict",
    "evaluate_read",
    "has_enrolled_sensor",
    "is_attested",
    "is_live",
    "live_session_count",
    "mint_pairing_code",
    "mint_token",
    "network_changed",
    "normalize_message_ref",
    "pairing_code_hash",
    "token_matches",
    "token_prefix",
]
