"""The cascade entry point the pipeline calls after rule scoring.

Order of operations, cheapest first:
  1. Is the cascade even on? (`ENVELOCK_LLM_PROVIDER` != none)   — a dict lookup
  2. Does the rule verdict warrant a judge? (the gate)          — in-memory
  3. Is this mailbox under its monthly cap?                     — one indexed query
  4. Only then call the provider.

Policy: the judge can **confirm or escalate** a verdict (a confident fraud verdict
on a High promotes it to Critical and attaches the callback), and it annotates the
alert with a plain-language rationale. It never lowers a rule tier — recall on real
payment fraud (§15.4, >95% target) must not depend on a model's confidence.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from envelock.config import get_settings
from envelock.core.enums import AlertTier
from envelock.core.events import MailEvent
from envelock.llm.base import LlmVerdict, Transport
from envelock.llm.gate import should_escalate
from envelock.llm.judge import Judge
from envelock.llm.providers import get_provider
from envelock.models import LlmUsage
from envelock.risk.engine import RiskAssessment

logger = logging.getLogger("envelock.llm")

_ORDER = {
    AlertTier.LOW: 0, AlertTier.MEDIUM: 1, AlertTier.HIGH: 2, AlertTier.CRITICAL: 3,
}
_BY_RANK = {v: k for k, v in _ORDER.items()}


def _promote(tier: AlertTier) -> AlertTier:
    return _BY_RANK[min(3, _ORDER[tier] + 1)]


async def _reserve_call(
    session: AsyncSession, tenant_id: UUID, mailbox_id: UUID | None, period: str
) -> LlmUsage | None:
    """Atomically claim one judge call against the monthly cap.

    The old shape was check-then-increment with a multi-second LLM round trip in
    between — every concurrent run for the same mailbox passed the check in that
    window, and the Python-side `calls = calls + 1` lost concurrent updates, so
    the cap leaked AND spend under-reported. One atomic upsert-increment closes
    both: the counter is claimed BEFORE the call, in SQL. Returns the usage row
    when under cap; None at the cap (the losing claim stays counted — a skipped
    attempt costing one counter tick is the cheap side of that trade).
    """
    from uuid import uuid4 as _uuid4

    from sqlalchemy.dialects.postgresql import insert as pg_insert

    cap = get_settings().llm_max_calls_per_mailbox_month
    now = datetime.now(UTC)
    stmt = (
        pg_insert(LlmUsage)
        .values(
            id=_uuid4(),
            tenant_id=tenant_id,
            mailbox_id=mailbox_id,
            period=period,
            calls=1,
            cost_micros=0,
            created_at=now,
            updated_at=now,
        )
        .on_conflict_do_update(
            index_elements=[LlmUsage.mailbox_id, LlmUsage.period],
            set_={"calls": LlmUsage.calls + 1, "updated_at": now},
        )
        .returning(LlmUsage.id, LlmUsage.calls)
    )
    claimed = (await session.execute(stmt)).first()
    if claimed is None or claimed.calls > cap:
        return None
    return await session.get(LlmUsage, claimed.id)


def _trusted_facts(event, context) -> dict[str, str]:  # noqa: ANN001
    """Context WE computed, rendered for the judge outside the untrusted fence.

    Without these the judge was blind to everything that changes the verdict:
    whether SPF/DKIM passed, whether the sender is a five-year vendor or a
    first-contact stranger, whether the links are already on a feed, how old
    the sending domain is. Values are enum states, counts and hard-truncated
    filenames — never attacker-authored free text."""
    facts: dict[str, str] = {}
    auth = getattr(event, "authentication", None)
    if auth is not None:
        facts["email_authentication"] = (
            f"SPF={auth.spf.value} DKIM={auth.dkim.value} DMARC={auth.dmarc.value}"
        )
    reply_to = getattr(event, "reply_to", None)
    sender = getattr(event, "sender", None)
    if (
        reply_to is not None
        and sender is not None
        and reply_to.address
        and reply_to.address.lower() != sender.address.lower()
    ):
        facts["reply_to_differs_from_sender"] = "yes"
    cp = getattr(context, "counterparty", None) if context is not None else None
    if cp is None or cp.message_count == 0:
        facts["sender_relationship"] = "first contact — never corresponded before"
    else:
        facts["sender_relationship"] = (
            f"known correspondent, {cp.message_count} prior message(s), "
            + ("bank details on file" if cp.known_bank_ids else "no bank details on file")
        )
    urls = tuple(getattr(event, "urls", ()) or ())
    if urls:
        bad_domains: frozenset[str] = (
            getattr(context, "malicious_domains", frozenset()) if context else frozenset()
        )
        flagged = sum(1 for u in urls if any(d and d in u for d in bad_domains))
        facts["links"] = f"{len(urls)} link(s), {flagged} on threat feeds"
    attachments = tuple(getattr(event, "attachments", ()) or ())
    if attachments:
        facts["attachments"] = ", ".join(a.filename[:60] for a in attachments[:5])
    age = getattr(context, "sender_domain_age_days", None) if context else None
    if age is not None:
        facts["sender_domain_age_days"] = str(age)
    return facts


async def refine(
    session: AsyncSession,
    event,  # noqa: ANN001 — Event
    assessment: RiskAssessment | None,
    *,
    tenant_id: UUID,
    context=None,  # noqa: ANN001 — DetectionContext, for the trusted-facts block
    transport: Transport | None = None,
    provider=None,  # noqa: ANN001 — test injection
) -> tuple[RiskAssessment | None, LlmVerdict | None]:
    """Maybe run the LLM judge and fold its verdict into the assessment. Returns the
    (possibly promoted) assessment and the verdict (None when the cascade didn't run
    or the provider failed)."""
    if not isinstance(event, MailEvent):
        return assessment, None
    prov = provider if provider is not None else get_provider(transport)
    if prov is None or not prov.configured:
        return assessment, None
    if not should_escalate(assessment):
        return assessment, None

    mailbox_id = getattr(event, "mailbox_id", None)
    period = datetime.now(UTC).strftime("%Y-%m")
    from envelock.obs.metrics import observe_llm

    usage = await _reserve_call(session, tenant_id, mailbox_id, period)
    if usage is None:
        logger.info("llm cascade: mailbox %s at monthly cap", mailbox_id)
        observe_llm("capped")
        return assessment, None

    verdict = await Judge(prov).evaluate(
        sender=event.sender.address,
        subject=event.subject or "",
        body=_analyzable_body(event),
        signals=list(assessment.services) if assessment else [],
        facts=_trusted_facts(event, context),
    )
    if verdict is None:
        observe_llm("error")
        return assessment, None
    observe_llm(verdict.verdict)

    # Cost lands on the already-claimed row (COGS is the number that predicts
    # spend — always record it).
    usage.cost_micros = (usage.cost_micros or 0) + verdict.cost_micros

    # Apply the verdict — escalate only, never demote.
    minc = get_settings().llm_min_confidence
    if (
        assessment is not None
        and verdict.escalate
        and verdict.confidence >= minc
        and assessment.tier is not AlertTier.CRITICAL
    ):
        new_tier = _promote(assessment.tier)
        # Client-facing: plain reason only — no confidence %, no model name. The
        # numbers stay internal (in the verdict + finding evidence).
        reason = verdict.rationale or "our fraud review found signs of a payment scam."
        client_line = f"Our fraud check agrees this looks like a scam: {reason}"
        assessment = replace(
            assessment,
            tier=new_tier,
            requires_callback=assessment.requires_callback or new_tier is AlertTier.CRITICAL,
            rationale=(*assessment.rationale, client_line),
            body=assessment.body + "\n" + client_line,
        )
    elif assessment is not None and verdict.rationale:
        # Not escalating, but a short plain note still adds context on the alert.
        note = f"Note: {verdict.rationale}"
        assessment = replace(assessment, body=assessment.body + "\n" + note)

    return assessment, verdict


def _analyzable_body(event: MailEvent) -> str:
    parts = [event.body_text or ""]
    for att in event.attachments:
        if att.extracted_text:
            parts.append(att.extracted_text)
    return "\n".join(p for p in parts if p)


__all__ = ["refine"]
