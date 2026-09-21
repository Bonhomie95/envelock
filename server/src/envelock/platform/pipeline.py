"""The analysis pipeline: event → context → detections → risk → alert → notify.

This is where the parts meet. Detections stay pure; everything that touches the
database or an external service happens here, which keeps the detection suite
unit-testable and the pipeline the only place that needs integration tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.capabilities import capabilities_for, protection_level
from envelock.core.enums import AlertTier, MailDirection, SourceMechanism
from envelock.core.events import Event, MailEvent
from envelock.detections import cascade as casc
from envelock.detections.base import (
    CounterpartyState,
    DetectionContext,
    FindingResult,
    PreviousSession,
    inactive_for,
    run_all,
)
from envelock.models import (
    BankRecord,
    Counterparty,
    Mailbox,
    Message,
    SenderProfile,
    SensorSession,
)
from envelock.obs.metrics import observe_analysis
from envelock.platform.alerts import raise_alert
from envelock.platform.graph import GRAPH
from envelock.risk.engine import RiskAssessment, assess
from envelock.util.domains import registrable_domain
from envelock.util.payments import (
    extract_amounts,
    extract_bank_identifiers,
    extract_invoice_numbers,
    largest_amount,
)

#: The payment-fraud family. Only these alerts carry a money-at-risk figure: a
#: phishing-link alert may also arrive in a mail quoting a sum, and counting
#: that as "money we stopped leaving" would inflate the one number the customer
#: is most likely to check against their own records.
_MONEY_SERVICES = frozenset({"A1", "A2", "A3", "A4", "A5", "A13", "A14"})


@dataclass(frozen=True, slots=True)
class PipelineResult:
    findings: list[FindingResult]
    assessment: RiskAssessment | None
    alert_id: UUID | None
    protection_level: str
    inactive_detections: list[str]
    latency_seconds: float
    #: The message was already ingested (same rfc_message_id on this mailbox) and
    #: was skipped — no re-analysis, no duplicate alert. The two live sources
    #: (IMAP poll + a forwarded copy) legitimately deliver the same message twice.
    duplicate: bool = False
    #: The stored Message row for this event (None for duplicates and
    #: non-persisted runs) — enforcement links its rewritten URLs to it.
    message_id: UUID | None = None

    @property
    def alerted(self) -> bool:
        return self.alert_id is not None


async def _counterparty_state(
    session: AsyncSession, *, tenant_id: UUID, domain: str
) -> CounterpartyState | None:
    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == tenant_id,
                Counterparty.registrable_domain == domain,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        return None

    banks = (
        (
            await session.execute(
                select(BankRecord).where(
                    BankRecord.counterparty_id == row.id, BankRecord.is_active.is_(True)
                )
            )
        )
        .scalars()
        .all()
    )
    return CounterpartyState(
        registrable_domain=row.registrable_domain,
        first_seen_at=_aware(row.first_seen_at),
        last_seen_at=_aware(row.last_seen_at),
        message_count=row.message_count,
        known_bank_ids=frozenset(b.identifier for b in banks),
        known_dkim_domains=frozenset(row.known_dkim_domains or []),
        known_mail_clients=frozenset(row.known_mail_clients or []),
        seen_invoice_numbers=frozenset(row.seen_invoice_numbers or []),
        typical_amount=float(row.typical_amount) if row.typical_amount else None,
        median_reply_seconds=row.median_reply_seconds,
        verified_phone=row.verified_phone,
        is_trusted=row.is_trusted,
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def build_context(
    session: AsyncSession,
    event: Event,
    *,
    tenant_id: UUID,
    owned_domains: frozenset[str],
    attachment_verdicts: dict[str, str] | None = None,
    sender_domain_age_days: int | None = None,
) -> DetectionContext:
    """Load everything the detections need. They never query anything themselves."""
    mailbox_id = getattr(event, "mailbox_id", None)
    sources: set[SourceMechanism] = {event.source}
    active_sessions = 0
    known_devices: set[str] = set()
    previous: PreviousSession | None = None
    mfa_enabled: bool | None = None

    if mailbox_id is not None:
        mailbox = await session.get(Mailbox, mailbox_id)
        if mailbox is not None:
            sources |= {SourceMechanism(s) for s in (mailbox.sources or []) if s}

        sessions = (
            (
                await session.execute(
                    select(SensorSession)
                    .where(SensorSession.mailbox_id == mailbox_id)
                    .order_by(SensorSession.last_seen_at.desc())
                    .limit(50)
                )
            )
            .scalars()
            .all()
        )
        # Live means still heartbeating, not merely "never marked ended".
        # Nothing ever set `ended_at`, so a device that heartbeated once counted
        # as signed in forever — which permanently suppressed C11 (it fires only
        # when nobody is signed in) the moment a mailbox installed the very
        # sensor that makes C11 possible.
        from envelock.platform.sensor import is_live

        active_sessions = sum(
            1 for s in sessions if s.ended_at is None and is_live(s.last_seen_at)
        )
        known_devices = {s.device_fingerprint for s in sessions if s.device_fingerprint}
        if sessions:
            latest = sessions[0]
            previous = PreviousSession(
                at=_aware(latest.last_seen_at) or datetime.now(UTC),
                country=latest.country,
                # Resolved at heartbeat (channels/identity/geo.py). These were
                # hardcoded None, which meant C7's haversine always
                # short-circuited and impossible-travel could never fire.
                latitude=latest.latitude,
                longitude=latest.longitude,
                ip=latest.ip,
                asn=latest.asn,
            )

        # C13 asks "was this mailbox's account holding a second factor when it
        # was signed into?". `mfa_enabled` was declared and never assigned, so
        # the answer was always None and the detection never fired. The mailbox
        # address IS the user's login, which is where the answer lives.
        if mailbox is not None:
            from envelock.models import User

            mfa_enabled = (
                await session.execute(
                    select(User.mfa_enabled).where(
                        User.tenant_id == tenant_id, User.email == mailbox.address
                    )
                )
            ).scalar_one_or_none()

    counterparty = None
    baseline: dict[str, float] = {}
    thread_history: tuple = ()
    #: The cross-tenant graph plus anything the free reputation feeds flag on this
    #: message's sender domain (user requirement #3).
    malicious_domains: set[str] = set(GRAPH.known_bad())
    if isinstance(event, MailEvent) and event.direction is MailDirection.INBOUND:
        sender_domain = registrable_domain(event.sender.domain)
        counterparty = await _counterparty_state(
            session, tenant_id=tenant_id, domain=sender_domain
        )
        # Prior messages in this stored thread — A8's REAL check. The old A8
        # only caught a forged reply (Re: subject, no chain); the named attack
        # is the opposite: the attacker replies INSIDE the genuine thread from
        # a compromised account, chain intact, SPF/DKIM passing. thread_key was
        # persisted on every Message since day one and read by nothing.
        if mailbox_id is not None and (event.references or event.in_reply_to):
            from envelock.detections.base import ThreadMessage

            tkey = event.references[0] if event.references else event.in_reply_to
            prior = (
                (
                    await session.execute(
                        select(Message)
                        .where(
                            Message.mailbox_id == mailbox_id,
                            Message.thread_key == tkey,
                        )
                        .order_by(Message.received_at.asc())
                        .limit(10)
                    )
                )
                .scalars()
                .all()
            )
            thread_history = tuple(
                ThreadMessage(
                    sender_address=m.sender_address,
                    reply_to_address=m.reply_to_address,
                    dkim=m.dkim,
                )
                for m in prior
            )

        # Check the FROM domain against free public blocklists. A hit adds it to the
        # malicious set so B1 (URLs) and B7 (sender reputation) fire on it.
        if sender_domain and sender_domain not in owned_domains:
            from envelock.channels.external.reputation import check_sender_domain

            rep = await check_sender_domain(sender_domain)
            if rep.listed:
                malicious_domains.add(sender_domain)

            # How old is the sender's domain? B9 and A7's newly-registered
            # escalation both read this, and no caller ever supplied it — an
            # RdapClient existed but was wired only to the pre-signup demo, so
            # "first payment mail from a domain registered last week" (the
            # classic BEC infrastructure signal) never fired. Looked up only
            # for FIRST-CONTACT senders (the case where it matters), cached in
            # the shared client, bounded, and best-effort.
            if (
                sender_domain_age_days is None
                and (counterparty is None or counterparty.message_count == 0)
            ):
                from envelock.config import get_settings as _gs

                if _gs().scan_registration_dates:
                    import asyncio as _asyncio

                    from envelock.workers.watchers import get_rdap_client

                    try:
                        rdap = get_rdap_client()
                        data = await _asyncio.wait_for(
                            rdap.lookup(sender_domain), timeout=3.0
                        )
                        if data:
                            sender_domain_age_days = rdap.age_days(
                                data.get("registered_at")
                            )
                    except Exception:  # noqa: BLE001, S110 — enrichment, never blocking
                        pass

        # Feature 1, delivery-time rung: run the message's LINK domains through
        # the same free blocklists, and the full URLs through Safe Browsing when
        # a key is configured. A hit lands in malicious_domains so B1 fires on
        # the URL itself. Capped per message; every lookup is cached; the click
        # redirector re-checks live regardless of what happens here.
        if event.urls:
            from envelock.config import get_settings as _settings
            from envelock.detections.cascade import Verdict, get_url_cascade
            from envelock.platform.links import url_host

            cfg = _settings()
            cap = max(cfg.url_check_max_per_message, 0)
            link_regs: list[str] = []
            for url in event.urls:
                reg = registrable_domain(url_host(url))
                if reg and reg not in owned_domains and reg not in link_regs:
                    link_regs.append(reg)
            if cfg.domain_reputation_enabled:
                from envelock.channels.external.reputation import check_sender_domain

                for reg in link_regs[:cap]:
                    if reg in malicious_domains:
                        continue
                    rep = await check_sender_domain(reg)
                    if rep.listed:
                        malicious_domains.add(reg)
            cascade = get_url_cascade()
            if cascade.safebrowsing:
                for url in event.urls[:cap]:
                    reg = registrable_domain(url_host(url))
                    if not reg or reg in owned_domains or reg in malicious_domains:
                        continue
                    verdict = await cascade.check(url)
                    if verdict.verdict is Verdict.MALICIOUS:
                        malicious_domains.add(reg)
        profile = (
            await session.execute(
                select(SenderProfile).where(
                    SenderProfile.tenant_id == tenant_id,
                    SenderProfile.address == event.sender.address,
                )
            )
        ).scalar_one_or_none()
        if profile is not None:
            baseline = profile.features or {}

    known = {
        row
        for (row,) in (
            await session.execute(
                select(Counterparty.registrable_domain).where(
                    Counterparty.tenant_id == tenant_id
                )
            )
        ).all()
    }

    # The tenant's own people's names — so we can catch a sender using a
    # colleague's name from an outside address (CEO/staff impersonation).
    internal_names: set[str] = set()
    if isinstance(event, MailEvent) and event.direction is MailDirection.INBOUND:
        name_rows = (
            await session.execute(
                select(Mailbox.display_name).where(
                    Mailbox.tenant_id == tenant_id, Mailbox.display_name.isnot(None)
                )
            )
        ).all()
        internal_names = {n.strip().lower() for (n,) in name_rows if n and n.strip()}

    caps = capabilities_for(frozenset(sources))
    return DetectionContext(
        event=event,
        tenant_id=str(tenant_id),
        capabilities=caps,
        owned_domains=owned_domains,
        known_counterparties=frozenset(known),
        internal_names=frozenset(internal_names),
        counterparty=counterparty,
        thread_history=thread_history,
        active_sessions=active_sessions,
        known_devices=frozenset(known_devices),
        previous_session=previous,
        sender_baseline=baseline,
        malicious_domains=frozenset(malicious_domains),
        attachment_verdicts=attachment_verdicts or {},
        sender_domain_age_days=sender_domain_age_days,
        mfa_enabled=mfa_enabled,
        now=datetime.now(UTC),
    )


async def learn(
    session: AsyncSession,
    event: MailEvent,
    *,
    tenant_id: UUID,
    flagged: bool = False,
) -> None:
    """Update counterparty state and the stylometric baseline.

    Learning happens *after* detection so a fraudulent message cannot poison the
    baseline it was judged against. Ordering alone was not enough, though —
    see `flagged`.

    `flagged` means the message raised an alert at MEDIUM or above. Such a
    message is still *observed* (it counts toward `message_count` and moves
    `last_seen_at`, because it did happen) but nothing about it becomes a
    baseline: not its DKIM domain, not its bank details, not its writing style.
    """
    if event.direction is not MailDirection.INBOUND:
        return
    domain = registrable_domain(event.sender.domain)
    if not domain or domain in {""}:
        return

    row = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == tenant_id,
                Counterparty.registrable_domain == domain,
            )
        )
    ).scalar_one_or_none()

    now = event.occurred_at
    if row is None:
        row = Counterparty(
            tenant_id=tenant_id,
            registrable_domain=domain,
            display_name=event.sender.display,
            first_seen_at=now,
            last_seen_at=now,
            message_count=1,
            known_dkim_domains=[],
            known_mail_clients=[],
        )
        session.add(row)
        await session.flush()
    else:
        row.message_count += 1
        row.last_seen_at = now

    # Everything above is observation — it records that the message arrived.
    # Everything below is trust: it decides what "normal" looks like for this
    # counterparty from now on. A flagged message must contribute to the first
    # and nothing to the second.
    #
    # This guard is new, and its absence inverted the flagship detection. The
    # comment below has always said bank details are "only learned from messages
    # we did not flag", but that described an intention, not the code: `learn`
    # was called unconditionally and had no notion of whether anything fired. So
    # a fraudster impersonating a vendor the tenant had never been emailed by
    # before was the *first* message for that counterparty, and their account
    # became the trusted baseline — after which every genuine invoice from the
    # real vendor raised "the bank details do not match the account on file".
    # The one message that must never teach us anything was the one it learned
    # from, and the resulting alert pointed at the victim rather than the
    # attacker.
    if flagged:
        return

    dkim = event.authentication.dkim_domain
    if dkim and dkim not in (row.known_dkim_domains or []):
        row.known_dkim_domains = [*(row.known_dkim_domains or []), dkim]

    _learn_text = " ".join(
        filter(
            None,
            [event.subject, event.body_text,
             *(a.extracted_text for a in event.attachments if a.extracted_text)],
        )
    )

    # A13 baselines: invoice numbers (duplicate-billing fraud) and the typical
    # amount (gross-anomaly fraud). The detection read these fields since day
    # one; nothing ever wrote them, so it could not fire on any input.
    invoices = extract_invoice_numbers(_learn_text)
    if invoices:
        seen = list(row.seen_invoice_numbers or [])
        merged = seen + [i for i in sorted(invoices) if i not in seen]
        row.seen_invoice_numbers = merged[-200:]  # bounded per vendor
    amounts = extract_amounts(_learn_text)
    if amounts:
        largest = max(amounts)
        row.typical_amount = (
            largest
            if row.typical_amount is None
            # EMA rather than a stored history: drifts with the real relationship,
            # cheap to keep, and a single outlier can't rewrite "normal".
            else 0.8 * float(row.typical_amount) + 0.2 * largest
        )

    # Bank details are learned only when the vendor has no ACTIVE record —
    # otherwise A1 could never fire. (The filter matters: after a legitimate
    # bank change retires the old record, an unfiltered query still found the
    # retired row, never learned the new account, and left the vendor
    # unprotected forever.)
    existing = (
        (
            await session.execute(
                select(BankRecord).where(
                    BankRecord.counterparty_id == row.id,
                    BankRecord.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    if not existing:
        for bank in extract_bank_identifiers(_learn_text):
            session.add(
                BankRecord(
                    tenant_id=tenant_id,
                    counterparty_id=row.id,
                    scheme=bank.scheme,
                    identifier=bank.identifier,
                    country=bank.country,
                    first_seen_at=now,
                )
            )

    from envelock.detections.content import style_features

    features = style_features(event.body_text or "")
    if features:
        profile = (
            await session.execute(
                select(SenderProfile).where(
                    SenderProfile.tenant_id == tenant_id,
                    SenderProfile.address == event.sender.address,
                )
            )
        ).scalar_one_or_none()
        if profile is None:
            session.add(
                SenderProfile(
                    tenant_id=tenant_id,
                    address=event.sender.address,
                    sample_count=1,
                    features=features,
                )
            )
        else:
            # Running mean keeps the baseline stable and cheap to update.
            n = profile.sample_count + 1
            baseline = dict(profile.features or {})
            for key, value in features.items():
                baseline[key] = ((baseline.get(key, value) * (n - 1)) + value) / n
            profile.features = baseline
            profile.sample_count = n


def _llm_min_confidence() -> float:
    from envelock.config import get_settings

    return get_settings().llm_min_confidence


async def analyse_event(
    session: AsyncSession,
    event: Event,
    *,
    tenant_id: UUID,
    owned_domains: frozenset[str],
    recipients: list | None = None,
    persist: bool = True,
    attachment_verdicts: dict[str, str] | None = None,
    sender_domain_age_days: int | None = None,
) -> PipelineResult:
    # Idempotency: the same message reaches us twice whenever a mailbox is on both
    # a live IMAP poll and a forwarding rule (and on any poll overlap). Keyed on
    # (mailbox_id, rfc_message_id), a message we have already stored is skipped
    # before any analysis — no duplicate alert, no double-counted counterparty
    # learning. Messages without an rfc_message_id fall through (nothing to key on).
    if (
        persist
        and isinstance(event, MailEvent)
        and event.rfc_message_id
        and event.mailbox_id is not None
    ):
        seen = (
            await session.execute(
                select(Message.id).where(
                    Message.mailbox_id == event.mailbox_id,
                    Message.rfc_message_id == event.rfc_message_id,
                )
            )
        ).first()
        if seen is not None:
            return PipelineResult(
                findings=[],
                assessment=None,
                alert_id=None,
                protection_level=protection_level(
                    capabilities_for(frozenset({event.source}))
                ).value,
                inactive_detections=[],
                latency_seconds=0.0,
                duplicate=True,
            )

    # Attachment cascade (B4's real teeth). `analyse_attachments` existed with
    # zero callers, so `ctx.attachment_verdicts` was always empty and the
    # "known malware → CRITICAL" branch could never fire on any ingest path.
    # Running it here covers every caller at once; after the duplicate check so
    # a re-delivered message costs nothing.
    if (
        persist
        and attachment_verdicts is None
        and isinstance(event, MailEvent)
        and event.attachments
    ):
        attachment_verdicts = await analyse_attachments(
            casc.get_attachment_cascade(), event, protected_mailbox=event.remediable
        )

    ctx = await build_context(
        session,
        event,
        tenant_id=tenant_id,
        owned_domains=owned_domains,
        attachment_verdicts=attachment_verdicts,
        sender_domain_age_days=sender_domain_age_days,
    )

    findings = run_all(ctx)
    assessment = assess(findings)

    # AI cascade (last rung): only the ambiguous payment/impersonation band reaches
    # the LLM judge, capped per mailbox. It can confirm/escalate a verdict and
    # annotate the alert; it never lowers a rule tier. Off unless a provider is set.
    ai_verdict = None
    rule_tier = assessment.tier if assessment is not None else None
    if persist:
        from envelock.llm.cascade import refine

        assessment, ai_verdict = await refine(
            session, event, assessment, tenant_id=tenant_id, context=ctx
        )

    message_id: UUID | None = None
    if persist and isinstance(event, MailEvent):
        # E13 metadata-only: analyse the subject, then do not keep it. Bodies and
        # attachment bytes are never persisted by any path, so the subject is the
        # only message content that would otherwise reach a durable row.
        from envelock.models import Tenant

        tenant_row = await session.get(Tenant, tenant_id)
        metadata_only = bool(tenant_row and tenant_row.metadata_only)

        message = Message(
            tenant_id=tenant_id,
            mailbox_id=event.mailbox_id,
            rfc_message_id=event.rfc_message_id,
            thread_key=event.references[0] if event.references else event.rfc_message_id,
            direction=event.direction.value,
            sender_address=event.sender.address,
            sender_display=event.sender.display,
            reply_to_address=event.reply_to.address if event.reply_to else None,
            subject=None if metadata_only else event.subject,
            sent_at=event.sent_at,
            received_at=event.occurred_at,
            source=event.source.value,
            remediable=event.remediable,
            spf=event.authentication.spf.value,
            dkim=event.authentication.dkim.value,
            dmarc=event.authentication.dmarc.value,
            attachment_hashes=[a.sha256 for a in event.attachments],
            risk_score=assessment.score if assessment else 0,
            source_ref=event.source_ref,
        )
        session.add(message)
        await session.flush()
        message_id = message.id

    if persist and isinstance(event, MailEvent):
        # The daily usage rollup — every read path (quality metrics, the COGS
        # fall-through rate) SUMs this table, and nothing ever wrote it: the
        # dashboard's "single number that predicts COGS" was permanently null.
        from uuid import uuid4 as _uuid4

        from sqlalchemy.dialects.postgresql import insert as _pg_insert

        from envelock.models import UsageMeter

        stats = dict(_LAST_CASCADE_STATS)
        _LAST_CASCADE_STATS.update({"cache": 0, "static": 0, "detonated": 0})
        from envelock.config import get_settings as _meter_settings

        url_checks = min(
            len(event.urls), _meter_settings().url_check_max_per_message
        ) if event.urls else 0
        today = datetime.now(UTC).date()
        increments = {
            "messages_analysed": 1,
            "attachments_seen": len(event.attachments),
            "attachments_cache_hit": stats["cache"],
            "attachments_static_resolved": stats["static"],
            "attachments_detonated": stats["detonated"],
            "url_lookups_free": url_checks,
        }
        stmt = (
            _pg_insert(UsageMeter)
            .values(
                id=_uuid4(),
                tenant_id=tenant_id,
                day=today,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                **increments,
            )
            .on_conflict_do_update(
                index_elements=[UsageMeter.tenant_id, UsageMeter.day],
                set_={
                    k: getattr(UsageMeter, k) + v for k, v in increments.items()
                },
            )
        )
        await session.execute(stmt)

    alert_id: UUID | None = None
    if persist and assessment is not None and assessment.is_alertable:
        # The counterparty is the sender's registrable domain — captured so that
        # confirming the alert can feed the E8 graph (see alerts.resolve). Only an
        # *external* sender is a counterparty: never record the tenant's own
        # domain, or resolving an internal-mail alert would report a legitimate
        # customer domain to the cross-tenant graph as fraudulent.
        counterparty_domain = None
        if isinstance(event, MailEvent):
            sender_reg = registrable_domain(event.sender.domain)
            if sender_reg and sender_reg not in owned_domains:
                counterparty_domain = sender_reg
        # AI autoflag: the judge independently confirmed fraud at or above the
        # confidence bar. The tier promotion (if any) already happened in refine;
        # this marks the alert so the UI can show *why* it moved.
        ai_flagged = (
            ai_verdict is not None
            and ai_verdict.is_fraud
            and ai_verdict.confidence >= _llm_min_confidence()
        )
        # The sum that was about to move. Captured only for the payment-fraud
        # family: a phishing-link alert also sits in a mail that may quote a
        # figure, and counting it as "money we stopped leaving" would be a
        # number we cannot defend in front of the customer who paid us for it.
        amount_at_risk: float | None = None
        amount_currency: str | None = None
        if isinstance(event, MailEvent) and (set(assessment.services) & _MONEY_SERVICES):
            found = largest_amount(
                f"{event.subject or ''}\n{event.body_text or ''}"
            )
            if found is not None:
                amount_at_risk, amount_currency = found

        alert = await raise_alert(
            session,
            tenant_id=tenant_id,
            mailbox_id=getattr(event, "mailbox_id", None),
            assessment=assessment,
            findings=findings,
            message_id=message_id,
            recipients=recipients or [],
            counterparty_domain=counterparty_domain,
            ai_verdict=ai_verdict.verdict if ai_verdict is not None else None,
            ai_flagged=ai_flagged,
            amount_at_risk=amount_at_risk,
            amount_currency=amount_currency,
        )
        alert_id = alert.id

    if persist and ai_verdict is not None:
        # Every judge call leaves an audit row — flagged or not — so "why did the
        # AI (not) act?" is always answerable, and human dispositions can label it
        # later (see alerts.resolve).
        from envelock.models import LlmVerdictRecord

        session.add(
            LlmVerdictRecord(
                tenant_id=tenant_id,
                mailbox_id=getattr(event, "mailbox_id", None),
                message_id=message_id,
                alert_id=alert_id,
                verdict=ai_verdict.verdict,
                confidence=ai_verdict.confidence,
                rationale=ai_verdict.rationale,
                escalated=(
                    assessment is not None
                    and rule_tier is not None
                    and assessment.tier is not rule_tier
                ),
                rule_tier=rule_tier.value if rule_tier is not None else None,
                final_tier=assessment.tier.value if assessment is not None else None,
                provider=ai_verdict.provider,
                model=ai_verdict.model,
                input_tokens=ai_verdict.input_tokens,
                output_tokens=ai_verdict.output_tokens,
                cost_micros=ai_verdict.cost_micros,
            )
        )

    if persist and isinstance(event, MailEvent):
        # HIGH and CRITICAL only — the tiers that mean "probable attack" and
        # "money at risk now" (PRD §8). Deliberately NOT MEDIUM: §8's own worked
        # example of MEDIUM is "first contact discussing payment", which is every
        # new supplier a company ever emails. Suppressing learning there would
        # mean no vendor is ever learned on first contact, so A1 would have no
        # baseline to compare against and could never fire — the detection would
        # be switched off by the guard meant to protect it.
        #
        # The attack this closes is a fraudster posing as an unknown vendor, and
        # `risk/engine.py` already forces that case to CRITICAL (payment
        # instructions from an unverified payee plus a deception signal, or
        # first-contact plus urgency), so it lands above this line, not below.
        flagged = assessment is not None and assessment.tier in (
            AlertTier.HIGH,
            AlertTier.CRITICAL,
        )
        await learn(session, event, tenant_id=tenant_id, flagged=flagged)

    latency = (datetime.now(UTC) - event.ingested_at).total_seconds()

    # The single most useful pair of numbers an operator has: how much mail we
    # actually looked at, and what we concluded. Recorded here rather than at the
    # call sites so every ingest path — IMAP poll, forwarded copy, backfill,
    # provider API — is counted the same way and none can be forgotten.
    observe_analysis(
        source=str(getattr(event.source, "value", event.source)),
        seconds=max(latency, 0.0),
        findings=[f.service for f in findings],
        tier=(assessment.tier.value if assessment is not None and alert_id else None),
    )

    return PipelineResult(
        findings=findings,
        assessment=assessment,
        alert_id=alert_id,
        protection_level=protection_level(ctx.capabilities).value,
        inactive_detections=inactive_for(ctx.capabilities),
        latency_seconds=round(max(latency, 0.0), 3),
        message_id=message_id,
    )


async def analyse_attachments(
    cascade: casc.AttachmentCascade,
    event: MailEvent,
    *,
    payloads: dict[str, bytes] | None = None,
    protected_mailbox: bool = True,
) -> dict[str, str]:
    """Run the cascade and return sha256 → verdict for the detection context.

    Also tallies which layer resolved each file so the caller can meter usage —
    the fall-through rate is the number that predicts COGS (PRD §12.12D)."""
    verdicts: dict[str, str] = {}
    stats = {"cache": 0, "static": 0, "detonated": 0}
    for att in event.attachments:
        result = await cascade.analyse(
            sha256=att.sha256,
            filename=att.filename,
            payload=(payloads or {}).get(att.sha256) or att.raw or b"",
            declared_mime=att.declared_mime,
            protected_mailbox=protected_mailbox,
        )
        verdicts[att.sha256] = result.verdict.value
        layer = result.layer.value if hasattr(result.layer, "value") else str(result.layer)
        if layer == "cache":
            stats["cache"] += 1
        elif layer == "static":
            stats["static"] += 1
        elif layer == "detonation":
            stats["detonated"] += 1
    _LAST_CASCADE_STATS.update(stats)
    return verdicts


#: Layer tallies from the most recent analyse_attachments call in this task —
#: consumed by the usage meter right after (single-threaded per event).
_LAST_CASCADE_STATS: dict[str, int] = {"cache": 0, "static": 0, "detonated": 0}
