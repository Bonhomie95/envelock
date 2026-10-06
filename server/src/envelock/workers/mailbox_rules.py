"""Server-side rule / forwarding watch — the data source for C1 and C2.

The headline account-takeover move is a mailbox rule that quietly forwards mail
to an outside address, or deletes/hides the finance mail an attacker is
impersonating. The capability model always advertised this on Graph/Gmail
(READ_SERVER_RULES), but nothing read the rules, so C1/C2 could never fire.

This reads the inbox rules (Graph) or filters + auto-forwarding (Gmail) each
sync, and raises C1 (external forward) / C2 (finance-hiding) for any rule it has
not seen before — a baseline of seen ids on the credential keeps it to NEW rules,
not every rule on every poll. Read-only; detection stays in detections/identity.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from envelock.channels.mail.api_fetch import (
    gmail_auto_forwarding,
    gmail_filters,
    graph_message_rules,
)
from envelock.core.enums import SourceMechanism
from envelock.models import Mailbox, MailboxCredential
from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.mailboxrules")

#: Upper bound on remembered rule ids, so a mailbox churning filters can't bloat
#: the column. Rules beyond this simply get re-evaluated — harmless.
MAX_TRACKED_RULES = 500

#: Microsoft folder ids whose names we can't resolve cheaply; moving mail to any
#: folder as a rule action is treated as a hide for C2's purposes.
_GRAPH_HIDE_FOLDERS = ("deleteditems", "junkemail", "archive")


class _Rule:
    __slots__ = ("rule_id", "name", "forward_to", "blob")

    def __init__(self, rule_id: str, name: str, forward_to: str | None, blob: str) -> None:
        self.rule_id = rule_id
        self.name = name
        self.forward_to = forward_to  # external forward address, if any
        self.blob = blob  # name + actions + conditions, for the C2 keyword match


def _graph_rules(raw: list[dict]) -> list[_Rule]:
    out: list[_Rule] = []
    for r in raw:
        actions = r.get("actions") or {}
        conds = r.get("conditions") or {}
        name = r.get("displayName") or "(unnamed rule)"
        fwd: str | None = None
        for key in ("forwardTo", "redirectTo", "forwardAsAttachmentTo"):
            for rcp in actions.get(key) or []:
                addr = ((rcp.get("emailAddress") or {}).get("address") or "").strip()
                if addr:
                    fwd = addr
                    break
            if fwd:
                break
        action_words: list[str] = []
        if actions.get("delete") or actions.get("permanentDelete"):
            action_words.append("delete")
        if actions.get("markAsRead"):
            action_words.append("mark as read")
        if actions.get("moveToFolder"):
            action_words.append("archive")  # hiding into a folder
        cond_text = " ".join(
            str(v)
            for v in (
                *(conds.get("subjectContains") or []),
                *(conds.get("bodyContains") or []),
                *(conds.get("bodyOrSubjectContains") or []),
                *(conds.get("senderContains") or []),
                *(conds.get("headerContains") or []),
            )
        )
        blob = f"{name} {' '.join(action_words)} {cond_text}"
        out.append(_Rule(str(r.get("id") or name), name, fwd, blob))
    return out


def _gmail_rules(filters: list[dict], auto_fwd: dict) -> list[_Rule]:
    out: list[_Rule] = []
    for f in filters:
        action = f.get("action") or {}
        crit = f.get("criteria") or {}
        fwd = (action.get("forward") or "").strip() or None
        add = {str(x).upper() for x in (action.get("addLabelIds") or [])}
        remove = {str(x).upper() for x in (action.get("removeLabelIds") or [])}
        action_words: list[str] = []
        if "TRASH" in add:
            action_words.append("delete")
        if "SPAM" in add:
            action_words.append("junk")
        if "INBOX" in remove:
            action_words.append("archive")
        cond_text = " ".join(
            str(v)
            for v in (
                crit.get("from"), crit.get("to"), crit.get("subject"),
                crit.get("query"), crit.get("hasTheWord"),
            )
            if v
        )
        name = f"filter {f.get('id') or ''}".strip()
        blob = f"{name} {' '.join(action_words)} {cond_text}"
        out.append(_Rule(str(f.get("id") or cond_text), name, fwd, blob))
    # Mailbox-level auto-forwarding is a single "rule".
    if auto_fwd.get("enabled") and (auto_fwd.get("emailAddress") or "").strip():
        addr = auto_fwd["emailAddress"].strip()
        out.append(
            _Rule(f"autoforward:{addr.lower()}", "auto-forwarding", addr, f"auto-forwarding {addr}")
        )
    return out


async def watch_rules(
    session: AsyncSession,
    mailbox: Mailbox,
    cred: MailboxCredential,
    *,
    provider: str,
    access_token: str,
    owned: frozenset[str],
    recipients: list | None = None,
    transport=None,  # noqa: ANN001 — api_fetch.HttpTransport
) -> dict:
    """Fetch current rules, raise C1/C2 for newly-seen ones, advance the baseline."""
    try:
        if provider == "google":
            rules = _gmail_rules(
                await gmail_filters(access_token=access_token, transport=transport),
                await gmail_auto_forwarding(access_token=access_token, transport=transport),
            )
            source = SourceMechanism.GMAIL_API
        else:
            rules = _graph_rules(
                await graph_message_rules(access_token=access_token, transport=transport)
            )
            source = SourceMechanism.GRAPH_API
    except Exception as exc:  # noqa: BLE001 — a failed read is not evidence of a rule
        logger.info("rule watch skipped for %s: %s", mailbox.id, exc)
        return {"rules_new": 0, "rules_alerted": 0}

    seen = set(cred.rule_ids or [])
    current_ids = [r.rule_id for r in rules]
    new_rules = [r for r in rules if r.rule_id not in seen]
    cred.rule_ids = current_ids[:MAX_TRACKED_RULES]

    alerted = 0
    for rule in new_rules:
        # C1: an external forward address. C2: a finance-hiding action. A rule can
        # be both — emit one event per signal so each detection sees what it reads.
        if rule.forward_to and "@" in rule.forward_to:
            dest = registrable_domain(rule.forward_to)
            if dest and dest not in owned:
                alerted += await _emit_rule_changed(
                    session, mailbox, source=source, owned=owned, recipients=recipients,
                    name=rule.name, after=rule.forward_to,
                )
        alerted += await _emit_rule_changed(
            session, mailbox, source=source, owned=owned, recipients=recipients,
            name=rule.name, after=rule.blob,
        )
    return {"rules_new": len(new_rules), "rules_alerted": alerted}


async def _emit_rule_changed(
    session: AsyncSession,
    mailbox: Mailbox,
    *,
    source: SourceMechanism,
    owned: frozenset[str],
    recipients: list | None,
    name: str,
    after: str,
) -> int:
    from envelock.core.enums import IdentityEventKind
    from envelock.core.events import DeviceContext, IdentityEvent, NetworkContext
    from envelock.platform.pipeline import analyse_event

    at = datetime.now(UTC)
    event = IdentityEvent(
        tenant_id=mailbox.tenant_id,
        mailbox_id=mailbox.id,
        occurred_at=at,
        ingested_at=at,
        source=source,
        kind=IdentityEventKind.RULE_CHANGED,
        target=name[:255],
        after=after[:2000],
        network=NetworkContext(),
        device=DeviceContext(),
    )
    result = await analyse_event(
        session, event, tenant_id=mailbox.tenant_id,
        owned_domains=owned, recipients=recipients or [],
    )
    if result.alert_id is not None:
        from envelock.notify.dispatch import deliver_pending

        await deliver_pending(session, alert_id=result.alert_id)
        return 1
    return 0


__all__ = ["watch_rules"]
