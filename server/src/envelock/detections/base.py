"""Detection framework.

A detection is a pure function of `DetectionContext` → findings. It declares the
capabilities it needs; the platform reports it as inactive by name on mailboxes
that cannot supply them (PRD P4) rather than silently skipping it.

Detections must never branch on `event.source` — see server/README.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol, runtime_checkable

from envelock.core.capabilities import Capability
from envelock.core.enums import AlertTier
from envelock.core.events import Event, IdentityEvent, MailEvent


@dataclass(frozen=True, slots=True)
class CounterpartyState:
    """What we already know about the other side. Supplied by the caller so
    detections stay pure and unit-testable."""

    registrable_domain: str
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    message_count: int = 0
    known_bank_ids: frozenset[str] = frozenset()
    known_dkim_domains: frozenset[str] = frozenset()
    known_mail_clients: frozenset[str] = frozenset()
    seen_invoice_numbers: frozenset[str] = frozenset()
    typical_amount: float | None = None
    median_reply_seconds: int | None = None
    verified_phone: str | None = None
    is_trusted: bool = False


@dataclass(frozen=True, slots=True)
class ThreadMessage:
    """A prior message in the same stored thread — what A8's real check
    compares against (sender/reply-to/DKIM continuity inside the conversation)."""

    sender_address: str
    reply_to_address: str | None
    dkim: str | None  # pass|fail|none as stored on Message


@dataclass(frozen=True, slots=True)
class DetectionContext:
    event: Event
    tenant_id: str
    capabilities: frozenset[Capability]
    #: The tenant's effective plan. Decides which detections run at all —
    #: Channel 2 (the "C" suite: sign-in anomalies, silent access, mailbox
    #: tampering) is what Complete sells over Essential. `None` means "do not
    #: gate", used by tests and by the coverage endpoints that describe what a
    #: CONNECTION can do rather than what a tenant has bought.
    plan: str | None = None
    #: Domains the tenant owns — used to tell inbound from internal.
    owned_domains: frozenset[str] = frozenset()
    #: Counterparty domains seen before, for A3 similarity comparison.
    known_counterparties: frozenset[str] = frozenset()
    counterparty: CounterpartyState | None = None
    #: Prior messages sharing this message's thread key (oldest first, capped).
    thread_history: tuple[ThreadMessage, ...] = ()
    #: Live sensor sessions at `event.occurred_at`, for C11.
    active_sessions: int = 0
    #: Known device fingerprints for this mailbox, for C10.
    known_devices: frozenset[str] = frozenset()
    #: Prior sign-in, for C7/C8 travel analysis.
    previous_session: PreviousSession | None = None
    #: Stylometric baseline for the sending address, for A9.
    sender_baseline: dict[str, float] = field(default_factory=dict)
    #: Threat-feed domains, for B1/B7.
    malicious_domains: frozenset[str] = frozenset()
    #: sha256 -> "clean" | "malicious", from the shared cascade cache (B4).
    attachment_verdicts: dict[str, str] = field(default_factory=dict)
    #: Registration age of the sending domain in days, for B9.
    sender_domain_age_days: int | None = None
    #: Whether the mailbox has MFA enabled, for C13.
    mfa_enabled: bool | None = None
    #: Display names of the tenant's own people (mailbox owners), for exec /
    #: staff impersonation (a sender using a colleague's name from an outside
    #: address — classic CEO fraud). Lower-cased.
    internal_names: frozenset[str] = frozenset()
    #: Bank identifiers in this message that were confirmed as fraud before:
    #: identifier -> {"scheme", "other_tenants", "own"} (see platform.fraud_accounts).
    fraud_accounts: dict[str, dict] = field(default_factory=dict)
    now: datetime | None = None

    @property
    def mail(self) -> MailEvent | None:
        return self.event if isinstance(self.event, MailEvent) else None

    @property
    def identity(self) -> IdentityEvent | None:
        return self.event if isinstance(self.event, IdentityEvent) else None


@dataclass(frozen=True, slots=True)
class PreviousSession:
    """Prior sign-in for the same mailbox — powers impossible travel (C7)."""

    at: datetime
    country: str | None
    latitude: float | None
    longitude: float | None
    ip: str | None = None
    asn: int | None = None


@dataclass(frozen=True, slots=True)
class FindingResult:
    service: str
    tier: AlertTier
    score: int
    summary: str
    evidence: dict = field(default_factory=dict)


@runtime_checkable
class Detection(Protocol):
    # Read-only: every detection is a frozen dataclass, and a plain annotation
    # here declared a *settable* attribute that none of them could satisfy.
    @property
    def service(self) -> str: ...
    @property
    def requires(self) -> frozenset[Capability]: ...

    def evaluate(self, ctx: DetectionContext) -> list[FindingResult]: ...


_REGISTRY: dict[str, Detection] = {}
_LOADED = False


def register(detection: Detection) -> Detection:
    _REGISTRY[detection.service] = detection
    return detection


def ensure_loaded() -> None:
    """Import every detection module exactly once.

    Without this the registry reflects import order rather than the catalogue,
    which means a mailbox can run a subset of the suite while reporting full
    coverage — the precise failure P4 exists to prevent.
    """
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    import envelock.detections  # noqa: F401  (registers every detection)


def registry() -> dict[str, Detection]:
    ensure_loaded()
    return dict(_REGISTRY)


def active_for(
    capabilities: frozenset[Capability], plan: str | None = None
) -> list[Detection]:
    """Detections that both the connection CAN run and the plan INCLUDES.

    `plan` defaults to None meaning "no plan gating", which is what the
    coverage endpoints want when they are describing what a connection is
    capable of. The pipeline passes the real plan, because that is where the
    work actually happens and a gate that only hides a button is not a gate.
    """
    from envelock.billing.features import detection_included

    ensure_loaded()
    return [
        d
        for d in _REGISTRY.values()
        if d.requires <= capabilities
        and (plan is None or detection_included(d.service, plan))
    ]


def inactive_for(capabilities: frozenset[Capability]) -> list[str]:
    """Named, not hidden. This list is shown to the customer (E7).

    Deliberately NOT plan-aware: this list means "your connection cannot do
    this". Folding the plan in here would tell someone their mailbox was
    incapable of something they had simply not bought — see
    `plan_locked_detections` for the other, separate list.
    """
    ensure_loaded()
    return sorted(d.service for d in _REGISTRY.values() if not d.requires <= capabilities)


def plan_locked_detections(capabilities: frozenset[Capability], plan: str) -> list[str]:
    """Detections this connection COULD run, that the plan does not include.

    The honest complement of `inactive_for`: these are not broken and not
    unsupported — they are bought separately, and saying so is what turns a
    silent gap into an upgrade prompt.
    """
    from envelock.billing.features import detection_included

    ensure_loaded()
    return sorted(
        d.service
        for d in _REGISTRY.values()
        if d.requires <= capabilities and not detection_included(d.service, plan)
    )


def run_all(ctx: DetectionContext) -> list[FindingResult]:
    findings: list[FindingResult] = []
    for detection in active_for(ctx.capabilities, ctx.plan):
        findings.extend(detection.evaluate(ctx))
    return findings
