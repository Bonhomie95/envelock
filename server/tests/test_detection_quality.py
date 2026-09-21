"""Measure detection quality against a labelled corpus.

Why this exists: before it, nothing in the repo could answer "did that change
make detection better or worse?" Detections had unit tests asserting that a
given synthetic context produces a given finding, which proves the function
runs — not that the product catches fraud or leaves ordinary mail alone. So
every change to `risk/engine.py`, `detections/` or `util/payments.py` was made
on reasoning alone, and a confident-but-wrong refactor would have degraded the
product silently until a customer noticed.

This runs whole messages through the real pipeline, in sequence, and scores the
result the way you would judge the product:

* **recall**    — of the frauds, how many did we raise at HIGH or CRITICAL?
* **precision** — of everything we raised, how much was actually fraud?

Precision is the number that decides whether the product survives a real inbox
(PRD P5: alert fatigue is the failure mode that kills it), so the corpus is
deliberately ~half benign, including the near-misses that a naive detector gets
wrong: the same account reformatted, urgency with no payment, long digit runs in
a logistics mail, a real new supplier's first invoice.

The floors below are a ratchet, not a target. Raise them when you improve the
detector; never lower one to make a red build green — that is the one move that
turns this file from a safety net into decoration.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest
from corpus.cases import CASES, Case

from envelock.channels.mail.parser import parse_message
from envelock.core.enums import AlertTier, MailboxClass, SourceMechanism
from envelock.models import Mailbox, Tenant
from envelock.platform.pipeline import analyse_event

pytestmark = pytest.mark.asyncio

OWNED = frozenset({"acme.com"})

#: A case counts as "raised" at these tiers. HIGH means "probable attack" and
#: CRITICAL means "money at risk now" (PRD §8) — the two that demand action.
#: MEDIUM is explicitly "needs a human glance" and is not counted as a positive,
#: because counting it would let the detector score well by hedging everything
#: into MEDIUM and telling the customer nothing.
ALERTING = (AlertTier.HIGH, AlertTier.CRITICAL)

#: Current measured performance is 100% on both. These floors sit just below so
#: a single regression fails the build while leaving room for a corpus that
#: grows faster than the detector.
MIN_RECALL = 0.80
MIN_PRECISION = 0.80


@dataclass
class Outcome:
    case: Case
    tier: AlertTier | None
    raised: bool

    @property
    def correct(self) -> bool:
        return self.raised == (self.case.label == "fraud")


async def _run_case(session, case: Case) -> Outcome:
    """Replay a case's messages in order; the verdict is on the last one."""
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name=f"Corpus {case.id}"))
    await session.flush()
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=MailboxClass.PROTECTED.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mailbox)
    await session.flush()

    result = None
    for raw in case.messages:
        event = parse_message(
            raw,
            tenant_id=tenant_id,
            mailbox_id=mailbox.id,
            source=SourceMechanism.IMAP_IDLE,
            owned_domains=OWNED,
            remediable=True,
        )
        result = await analyse_event(
            session, event, tenant_id=tenant_id, owned_domains=OWNED
        )
    await session.commit()

    assert result is not None, f"case {case.id} has no messages"
    tier = result.assessment.tier if result.assessment else None
    return Outcome(case=case, tier=tier, raised=tier in ALERTING)


async def test_detection_quality_against_the_corpus(session, capsys) -> None:
    outcomes = [await _run_case(session, case) for case in CASES]

    scored = [o for o in outcomes if not o.case.known_gap]
    gaps = [o for o in outcomes if o.case.known_gap]

    tp = sum(1 for o in scored if o.case.label == "fraud" and o.raised)
    fn = sum(1 for o in scored if o.case.label == "fraud" and not o.raised)
    fp = sum(1 for o in scored if o.case.label == "benign" and o.raised)
    tn = sum(1 for o in scored if o.case.label == "benign" and not o.raised)

    recall = tp / (tp + fn) if (tp + fn) else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0

    lines = [
        "",
        "detection quality",
        "─────────────────",
        f"  corpus            {len(CASES)} cases "
        f"({sum(1 for c in CASES if c.label == 'fraud')} fraud, "
        f"{sum(1 for c in CASES if c.label == 'benign')} benign)",
        f"  scored            {len(scored)}   (known gaps excluded: {len(gaps)})",
        f"  recall            {recall:.0%}   ({tp} caught, {fn} missed)",
        f"  precision         {precision:.0%}   ({tp} real, {fp} false alarms)",
        f"  confusion         tp={tp} fp={fp} tn={tn} fn={fn}",
        "",
    ]
    for o in outcomes:
        mark = "gap " if o.case.known_gap else ("ok  " if o.correct else "MISS")
        tier = o.tier.value if o.tier else "none"
        lines.append(f"  [{mark}] {o.case.id:38s} {o.case.label:6s} → {tier}")
    if gaps:
        lines += ["", "  known gaps (reported, not scored):"]
        lines += [f"    · {o.case.id}: {o.case.gap_note}" for o in gaps]
    lines.append("")

    with capsys.disabled():
        print("\n".join(lines))

    misses = [o for o in scored if not o.correct]
    detail = "\n".join(
        f"  {o.case.id} ({o.case.label}) → {o.tier.value if o.tier else 'none'}: {o.case.why}"
        for o in misses
    )
    assert recall >= MIN_RECALL, f"recall {recall:.0%} below floor:\n{detail}"
    assert precision >= MIN_PRECISION, f"precision {precision:.0%} below floor:\n{detail}"


async def test_known_gaps_are_still_gaps(session) -> None:
    """A known gap that starts passing must be promoted, not left labelled.

    Without this the corpus rots the other way: a case marked `known_gap` gets
    fixed by some unrelated change, nobody notices, and the flag stays — quietly
    excluding a case that now works from the score it should be improving.
    """
    for case in (c for c in CASES if c.known_gap):
        outcome = await _run_case(session, case)
        if outcome.correct:
            pytest.fail(
                f"'{case.id}' is marked known_gap but now behaves correctly "
                f"(→ {outcome.tier.value if outcome.tier else 'none'}). "
                "Remove known_gap=True so it counts toward the score."
            )
