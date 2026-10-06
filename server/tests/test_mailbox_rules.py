"""Server-side rule watch → C1 (external forward) / C2 (finance-hiding)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.core.enums import SourceMechanism
from envelock.db import get_sessionmaker
from envelock.db_rls import system_scope
from envelock.models import Finding, Mailbox, MailboxCredential, Tenant
from envelock.workers.mailbox_rules import _gmail_rules, _graph_rules

OWNED = frozenset({"cyberlex.store"})


# ── pure parsing ──────────────────────────────────────────────────────────────
def test_graph_rule_parsing() -> None:
    rules = _graph_rules(
        [
            {
                "id": "r1", "displayName": "fwd",
                "actions": {"forwardTo": [{"emailAddress": {"address": "evil@attacker.com"}}]},
            },
            {
                "id": "r2", "displayName": "cleanup",
                "actions": {"delete": True},
                "conditions": {"subjectContains": ["invoice", "payment"]},
            },
        ]
    )
    assert rules[0].forward_to == "evil@attacker.com"
    assert rules[1].forward_to is None
    assert "delete" in rules[1].blob and "invoice" in rules[1].blob


def test_gmail_rule_parsing() -> None:
    rules = _gmail_rules(
        [{"id": "f1", "criteria": {"query": "invoice"}, "action": {"addLabelIds": ["TRASH"]}}],
        {"enabled": True, "emailAddress": "sink@evil.com"},
    )
    assert any("delete" in r.blob and "invoice" in r.blob for r in rules)
    assert any(r.forward_to == "sink@evil.com" for r in rules)


# ── end to end ────────────────────────────────────────────────────────────────
class _GraphRulesTransport:
    def __init__(self, rules: list[dict]) -> None:
        self._rules = rules

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        return {"value": self._rules} if "messageRules" in url else {}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return b""


@pytest.fixture
async def graph_mailbox(client):  # noqa: ANN001, ARG001 — client builds the schema
    tid, mid = uuid4(), uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(Tenant(id=tid, name="Cyberlex", plan="complete", payment_method_ok=True))
            await session.flush()
            session.add(
                Mailbox(
                    id=mid, tenant_id=tid, address="admin@cyberlex.store",
                    mailbox_class="protected", sources=[SourceMechanism.GRAPH_API.value],
                    is_active=True,
                )
            )
            session.add(
                MailboxCredential(
                    mailbox_id=mid, tenant_id=tid, kind="oauth_token",
                    ciphertext=b"x", wrapped_dek=b"y", key_id="k",
                )
            )
            await session.commit()
    return tid, mid


async def _run(mid, rules):  # noqa: ANN001, ANN202
    from envelock.workers.mailbox_rules import watch_rules

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mb = await session.get(Mailbox, mid)
            cred = (
                await session.execute(
                    select(MailboxCredential).where(MailboxCredential.mailbox_id == mid)
                )
            ).scalar_one()
            res = await watch_rules(
                session, mb, cred, provider="microsoft", access_token="t",  # noqa: S106
                owned=OWNED, recipients=[], transport=_GraphRulesTransport(rules),
            )
            await session.commit()
            return res


async def test_c1_and_c2_fire_then_idempotent(graph_mailbox) -> None:  # noqa: ANN001
    tid, mid = graph_mailbox
    rules = [
        {
            "id": "r1", "displayName": "fwd",
            "actions": {"forwardTo": [{"emailAddress": {"address": "boss@attacker.com"}}]},
        },
        {
            "id": "r2", "displayName": "cleanup",
            "actions": {"delete": True},
            "conditions": {"subjectContains": ["invoice"]},
        },
    ]
    res = await _run(mid, rules)
    assert res["rules_alerted"] >= 2, res

    with system_scope("test"):
        async with get_sessionmaker()() as session:
            services = {
                f.service: f.tier
                for f in (await session.execute(select(Finding))).scalars().all()
            }
    assert services.get("C1") == "critical"
    assert services.get("C2") == "critical"

    # Same rules again → nothing new.
    assert (await _run(mid, rules))["rules_new"] == 0
