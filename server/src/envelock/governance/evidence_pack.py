"""The per-alert evidence pack — one PDF a customer can hand to an insurer, a
bank or the police.

Funds-transfer-fraud claims turn on whether the business followed a
verification procedure. Everything that proves it already exists as rows —
the message's headers and authentication results, what changed, who called the
supplier on which number and what they said, when the message was quarantined,
who resolved it — so the pack assembles those rows and nothing else. No
figure in it is estimated or rephrased.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from io import BytesIO
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.models import (
    Alert,
    AuditEvent,
    Finding,
    Mailbox,
    Message,
    PaymentVerification,
    Tenant,
    User,
)

_ACTIONS = {
    "alert.raised": "Alert raised",
    "alert.viewed": "Alert viewed",
    "alert.acknowledged": "Acknowledged",
    "alert.resolved": "Resolved as confirmed fraud",
    "alert.dismissed": "Dismissed (not fraud)",
    "alert.escalated": "Escalated",
    "message.quarantined": "Message quarantined",
    "message.quarantine_requested": "Quarantine requested",
    "payment.verified_by_call": "Supplier called on the number on file",
    "payment.verification_sms_sent": "Confirmation text sent to the number on file",
    "payment.verified_by_sms": "Supplier answered the confirmation text",
}

_OUTCOME = {
    "confirmed": "Supplier confirmed the change",
    "denied": "Supplier said they did NOT make this change",
    "no_answer": "No answer",
    "pending": "Awaiting answer",
    "expired": "Expired unanswered",
}


def reference(alert: Alert) -> str:
    return "ENV-" + alert.id.hex[:6].upper()


def _ts(value: datetime | None) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


async def collect(session: AsyncSession, alert: Alert) -> dict:
    """Everything the pack shows, as plain data (also what the fingerprint covers)."""
    tenant = await session.get(Tenant, alert.tenant_id)
    mailbox = await session.get(Mailbox, alert.mailbox_id) if alert.mailbox_id else None
    findings = list((await session.execute(
        select(Finding).where(Finding.alert_id == alert.id).order_by(Finding.score.desc())
    )).scalars().all())
    message_ids = {f.message_id for f in findings if f.message_id}
    message = await session.get(Message, next(iter(message_ids))) if message_ids else None
    verifications = list((await session.execute(
        select(PaymentVerification)
        .where(PaymentVerification.alert_id == alert.id)
        .order_by(PaymentVerification.created_at)
    )).scalars().all())
    targets = [alert.id] + ([message.id] if message else [])
    audit = list((await session.execute(
        select(AuditEvent)
        .where(AuditEvent.tenant_id == alert.tenant_id,
               or_(*[AuditEvent.target_id == t for t in targets]))
        .order_by(AuditEvent.created_at)
    )).scalars().all())
    actor_ids = {a.actor_id for a in audit if a.actor_id} | {
        v.recorded_by for v in verifications if v.recorded_by
    }
    names: dict[UUID, str] = {}
    if actor_ids:
        for u in (await session.execute(select(User).where(User.id.in_(actor_ids)))).scalars():
            names[u.id] = u.email

    return {
        "reference": reference(alert),
        "workspace": tenant.name if tenant else "",
        "generated_at": _ts(datetime.now(UTC)),
        "alert": {
            "tier": alert.tier,
            "title": alert.title,
            "state": alert.state,
            "raised_at": _ts(alert.created_at),
            "supplier": alert.counterparty_domain,
            "amount": (
                f"{alert.amount_currency} {alert.amount_at_risk:,.2f}"
                if alert.amount_at_risk is not None and alert.amount_currency
                else None
            ),
            "acknowledged_at": _ts(alert.acknowledged_at) if alert.acknowledged_at else None,
            "resolved_at": _ts(alert.resolved_at) if alert.resolved_at else None,
        },
        "message": {
            "mailbox": mailbox.address if mailbox else None,
            "from": message.sender_address if message else None,
            "display_name": message.sender_display if message else None,
            "reply_to": message.reply_to_address if message else None,
            "subject": message.subject if message else None,
            "sent_at": _ts(message.sent_at) if message and message.sent_at else None,
            "received_at": _ts(message.received_at) if message else None,
            "message_id": message.rfc_message_id if message else None,
            "spf": message.spf if message else None,
            "dkim": message.dkim if message else None,
            "dmarc": message.dmarc if message else None,
            "attachments": list(message.attachment_hashes or []) if message else [],
            "quarantined_at": (
                _ts(message.quarantined_at) if message and message.quarantined_at else None
            ),
        },
        "findings": [
            {"code": f.service, "tier": f.tier, "summary": f.summary,
             "accounts": [
                 f"{i.get('scheme', '').upper()} {i.get('identifier')}"
                 for i in ((f.evidence or {}).get("new_identifiers") or [])
                 + ((f.evidence or {}).get("fraud_accounts") or [])
             ]}
            for f in findings
        ],
        "verifications": [
            {"when": _ts(v.responded_at or v.created_at),
             "channel": "Phone call" if v.channel == "call" else "Text message",
             "phone": v.phone, "outcome": _OUTCOME.get(v.status, v.status),
             "by": names.get(v.recorded_by) if v.recorded_by else
                   ("The supplier" if v.channel == "sms" and v.responded_at else None),
             "note": v.note, "account": v.account_masked}
            for v in verifications
        ],
        "timeline": [
            {"when": _ts(a.created_at), "what": _ACTIONS.get(a.action, a.action),
             "by": names.get(a.actor_id) if a.actor_id else "Envelock"}
            for a in audit
        ],
    }


def fingerprint(data: dict) -> str:
    """SHA-256 of the record's contents (minus the generation time), printed on
    the pack so two copies can be shown to hold the same facts."""
    body = {k: v for k, v in data.items() if k != "generated_at"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def render(data: dict) -> bytes:
    from xml.sax.saxutils import escape

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=16, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=11, spaceBefore=10,
                        spaceAfter=4, textColor=colors.HexColor("#111827"),
                        keepWithNext=1)
    body = ParagraphStyle("b", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, textColor=colors.HexColor("#6b7280"))
    cell = ParagraphStyle("c", parent=body, fontSize=8, leading=10.5)

    def p(text: object, style: ParagraphStyle = body) -> Paragraph:
        return Paragraph(escape(str(text)) if text not in (None, "") else "—", style)

    def kv(rows: list[tuple[str, object]]) -> Table:
        t = Table([[p(k, small), p(v)] for k, v in rows], colWidths=[40 * mm, 130 * mm])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return t

    def grid(head: list[str], rows: list[list[object]], widths: list[float]) -> Table:
        t = Table([[p(h, small) for h in head]] + [[p(c, cell) for c in r] for r in rows],
                  colWidths=[w * mm for w in widths], repeatRows=1)
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
        ]))
        return t

    a, m = data["alert"], data["message"]
    story: list = [
        p("ENVELOCK — FRAUD EVIDENCE RECORD", small),
        Paragraph(escape(f"{data['reference']} · {a['title']}"), h1),
        p(f"Workspace: {data['workspace']} · Generated {data['generated_at']}", small),
        Spacer(1, 6),
        Paragraph("Summary", h2),
        kv([("Severity", a["tier"].upper()), ("Status", a["state"]),
            ("Raised", a["raised_at"]), ("Supplier", a["supplier"]),
            ("Amount requested", a["amount"]), ("Acknowledged", a["acknowledged_at"]),
            ("Closed", a["resolved_at"])]),
        Paragraph("The message", h2),
        kv([("Mailbox", m["mailbox"]), ("From", m["from"]), ("Display name", m["display_name"]),
            ("Reply-To", m["reply_to"]), ("Subject", m["subject"]), ("Sent", m["sent_at"]),
            ("Received", m["received_at"]), ("Message-ID", m["message_id"]),
            ("SPF / DKIM / DMARC", f"{m['spf']} / {m['dkim']} / {m['dmarc']}"),
            ("Attachments (SHA-256)", "\n".join(m["attachments"]) or None),
            ("Quarantined", m["quarantined_at"])]),
        Paragraph("What Envelock found", h2),
        grid(["Check", "Severity", "Finding", "Account(s)"],
             [[f["code"], f["tier"], f["summary"], "\n".join(f["accounts"])]
              for f in data["findings"]] or [["—", "—", "—", "—"]],
             [13, 16, 86, 55]),
        Paragraph("Verification with the supplier", h2),
        p("Only ever through the phone number on file for the supplier — never a "
          "number or address taken from the message.", small),
        Spacer(1, 3),
        grid(["When", "How", "Number", "Outcome", "Recorded by", "Note"],
             [[v["when"], v["channel"], v["phone"], v["outcome"], v["by"], v["note"]]
              for v in data["verifications"]] or [["—", "Not verified", "—", "—", "—", "—"]],
             [25, 17, 28, 33, 43, 24]),
        Paragraph("Timeline", h2),
        grid(["When", "Event", "By"],
             [[t["when"], t["what"], t["by"]] for t in data["timeline"]] or [["—", "—", "—"]],
             [40, 90, 40]),
        Spacer(1, 10),
        p(f"Record fingerprint (SHA-256 of the facts above): {fingerprint(data)}", small),
        p("Produced from Envelock's records as they stood at generation time. "
          "Message bodies are not retained by Envelock and are not included.", small),
    ]
    buf = BytesIO()
    SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
        topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"{data['reference']} evidence record", author="Envelock",
    ).build(story)
    return buf.getvalue()


__all__ = ["collect", "fingerprint", "reference", "render"]
