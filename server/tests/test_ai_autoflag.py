"""AI autoflagging: the judge's verdict is persisted, marks the alert, and is
labeled by the human disposition — the audit trail and the training corpus."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail.parser import parse_message
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.models import Alert, LlmVerdictRecord, Mailbox, Tenant
from envelock.platform.pipeline import analyse_event
from tests.test_llm_cascade import _HIGH_BAND, _FakeProvider

_RANK = {AlertTier.LOW: 0, AlertTier.MEDIUM: 1, AlertTier.HIGH: 2, AlertTier.CRITICAL: 3}


def _arm(monkeypatch, verdict: dict) -> None:
    """Point the pipeline's cascade at a fake provider (no network, no key)."""
    from envelock.llm import cascade

    monkeypatch.setattr(cascade, "get_provider", lambda transport=None: _FakeProvider(verdict))


async def _persisted_event(session):
    """A real tenant + mailbox (the pipeline persists rows with FKs) carrying the
    same ambiguous High-band message the cascade tests use."""
    tid = uuid4()
    session.add(Tenant(id=tid, name="Acme"))
    await session.flush()
    mb = Mailbox(tenant_id=tid, address="pay@acme.com", sources=[SourceMechanism.IMAP_IDLE.value])
    session.add(mb)
    await session.flush()
    event = parse_message(
        _HIGH_BAND.encode(),
        tenant_id=tid,
        mailbox_id=mb.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=frozenset({"acme.com"}),
        remediable=True,
    )
    return tid, event


@pytest.mark.asyncio
async def test_confident_fraud_autoflags_alert_and_persists_verdict(
    session, monkeypatch
) -> None:
    _arm(monkeypatch, {"verdict": "fraud", "confidence": 0.95, "rationale": "impersonated vendor"})
    tid, event = await _persisted_event(session)
    result = await analyse_event(
        session, event, tenant_id=tid, owned_domains=frozenset({"acme.com"})
    )
    assert result.alert_id is not None

    alert = await session.get(Alert, result.alert_id)
    assert alert.ai_flagged is True
    assert alert.ai_verdict == "fraud"

    row = (
        await session.execute(
            select(LlmVerdictRecord).where(LlmVerdictRecord.alert_id == alert.id)
        )
    ).scalar_one()
    assert row.verdict == "fraud"
    assert row.confidence == pytest.approx(0.95)
    # The record carries the before/after picture: promoted exactly one step.
    assert row.escalated is True
    assert _RANK[AlertTier(row.final_tier)] == _RANK[AlertTier(row.rule_tier)] + 1
    assert row.final_tier == alert.tier
    assert row.message_id == result.message_id
    assert row.human_disposition is None  # not labeled yet


@pytest.mark.asyncio
async def test_disposition_labels_the_verdict_row(session, monkeypatch) -> None:
    from envelock.platform import alerts as alert_svc

    _arm(monkeypatch, {"verdict": "fraud", "confidence": 0.9, "rationale": "scam"})
    tid, event = await _persisted_event(session)
    result = await analyse_event(
        session, event, tenant_id=tid, owned_domains=frozenset({"acme.com"})
    )
    assert result.alert_id is not None
    await session.commit()

    resolved = await alert_svc.resolve(
        session, alert_id=result.alert_id, tenant_id=tid, actor_id=uuid4(), dismissed=True
    )
    assert resolved is not None
    row = (
        await session.execute(
            select(LlmVerdictRecord).where(LlmVerdictRecord.alert_id == result.alert_id)
        )
    ).scalar_one()
    assert row.human_disposition == "dismissed"  # the label: a false positive
    assert row.labeled_at is not None


@pytest.mark.asyncio
async def test_benign_verdict_annotates_but_never_flags(session, monkeypatch) -> None:
    _arm(monkeypatch, {"verdict": "benign", "confidence": 0.99, "rationale": "routine invoice"})
    tid, event = await _persisted_event(session)
    result = await analyse_event(
        session, event, tenant_id=tid, owned_domains=frozenset({"acme.com"})
    )
    # The rules still alerted (High band) — the AI must not flag or demote.
    assert result.alert_id is not None
    alert = await session.get(Alert, result.alert_id)
    assert alert.ai_flagged is False
    assert alert.ai_verdict == "benign"

    # But the verdict is still recorded — "why did the AI not act?" is answerable.
    row = (
        await session.execute(
            select(LlmVerdictRecord).where(LlmVerdictRecord.alert_id == alert.id)
        )
    ).scalar_one()
    assert row.verdict == "benign" and row.escalated is False
    assert row.rule_tier == row.final_tier == alert.tier  # untouched by the AI
