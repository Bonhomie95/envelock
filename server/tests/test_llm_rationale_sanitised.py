"""#10 — the model's rationale is shown only on a confirmed-fraud verdict, and
only with phone numbers and URLs stripped.

The rationale is written from attacker-controlled email text and then printed to
the customer as our own finding. A benign/suspicious verdict used to append a
`Note: ...` line to the alert body, and nothing stripped an injected callback
number or link, so "vendor confirmed, call +1 555 0100" could ride out on it.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.core.enums import AlertTier
from envelock.llm.cascade import _plain_rationale, refine
from tests.test_llm_cascade import _FakeProvider, _high_band_assessment


def test_plain_rationale_strips_urls_and_phone_numbers() -> None:
    cleaned = _plain_rationale("Confirmed by vendor, call +1 (555) 010-0100 or https://evil.example/x")
    assert "555" not in cleaned
    assert "evil.example" not in cleaned
    assert "[removed]" in cleaned


@pytest.mark.asyncio
async def test_benign_verdict_adds_no_line_to_the_alert_body(session) -> None:
    event, assessment = _high_band_assessment()
    assert assessment is not None
    before = assessment.body
    provider = _FakeProvider(
        {"verdict": "benign", "confidence": 0.9, "rationale": "Looks routine, see https://ok.example"}
    )
    refined, verdict = await refine(
        session, event, assessment, tenant_id=uuid4(), provider=provider
    )
    assert verdict is not None and not verdict.is_fraud
    assert refined.body == before  # no annotation from a non-fraud verdict
    assert refined.tier is assessment.tier  # and no demotion


@pytest.mark.asyncio
async def test_fraud_rationale_is_sanitised_before_it_reaches_the_customer(session) -> None:
    event, assessment = _high_band_assessment()
    assert assessment is not None
    if assessment.tier is AlertTier.CRITICAL:
        pytest.skip("rules already Critical; escalation path not exercised")
    provider = _FakeProvider(
        {
            "verdict": "fraud",
            "confidence": 0.95,
            "rationale": "Scam: call +44 20 7946 0000 and visit http://evil.example/pay",
        }
    )
    refined, verdict = await refine(
        session, event, assessment, tenant_id=uuid4(), provider=provider
    )
    # The stored and client-facing rationale carry no phone number or URL.
    assert "7946" not in verdict.rationale and "evil.example" not in verdict.rationale
    ai_line = next(r for r in refined.rationale if "fraud check" in r)
    assert "7946" not in ai_line and "evil.example" not in ai_line
    assert "evil.example" not in refined.body and "7946" not in refined.body
