"""The alert as a person reads it.

An alert is only worth sending if the reader knows what to do within a few
seconds. The old body was the alert title, a paragraph, and a link — which
leaves the two questions that actually matter unanswered: *which message is
this about?* and *do I need to do anything?*

So the report answers them in a fixed order, and always the same order, because
someone who gets these weekly should be able to find the answer without reading:

    Why am I getting this alert?   one sentence
    User affected                  whose mailbox
    Email details                  sent to / from / when / subject
    Analysis                       what we found, one line each
    What should I do?              the action — including "nothing"

"What should I do?" is the section this module exists for. It is derived from
the tier, which is *defined* by required action (PRD §8), so it can state
plainly whether the message was moved, flagged, or left alone. An alert that
says "we already took it out of the inbox" is a different thing from one that
says "you need to check this", and a reader must never have to guess which they
are holding.

Both a plain-text and an HTML rendering are produced. Text is not a fallback
afterthought: it is what SMS-adjacent clients, terminal mail readers and
screen-reader users get, so it carries the same sections in the same order.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime

from envelock.core.enums import AlertTier

__all__ = ["AlertReport", "render_html", "render_text", "report_for_alert"]


@dataclass(frozen=True, slots=True)
class AlertReport:
    """Everything the reader needs, already decided."""

    tier: AlertTier
    title: str
    #: The mailbox this happened to.
    mailbox_address: str
    #: One line per detection that fired.
    findings: tuple[str, ...] = ()
    #: Message facts. Any of these can be missing: a subject is absent under
    #: metadata-only mode (E13), and an alert can be raised by a channel that
    #: has no single message behind it.
    sender: str | None = None
    subject: str | None = None
    received_at: datetime | None = None
    #: True when the message was moved out of the inbox. Only Critical does
    #: this, and saying so is what turns "be alarmed" into "nothing to do".
    quarantined: bool = False
    #: Set when the message was left in place but marked.
    flagged_in_place: bool = False
    #: E3 — the number on file with us, never the one in the email.
    callback_phone: str | None = None
    url: str = "https://app.envelock.org/alerts"
    #: Free-form extra context, shown under Analysis.
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def why(self) -> str:
        """One sentence: what happened, in the reader's terms."""
        return {
            AlertTier.CRITICAL: (
                "Envelock detected a change to payment details or account access "
                "on a message sent to one of your mailboxes."
            ),
            AlertTier.HIGH: (
                "Envelock detected a probable attack on a message sent to one of "
                "your mailboxes."
            ),
            AlertTier.MEDIUM: (
                "Envelock found something suspicious on a message sent to one of "
                "your mailboxes, and a person should take a look."
            ),
            AlertTier.LOW: (
                "Envelock recorded something worth knowing about a message sent to "
                "one of your mailboxes."
            ),
        }[self.tier]

    @property
    def action(self) -> str:
        """What to do — the whole point, and never ambiguous.

        Every branch either names a concrete step or says "nothing", because
        "you may wish to review this" is what teaches people to ignore alerts.
        """
        if self.callback_phone:
            # A payment is at stake and there is a number on file. Everything
            # else is secondary to making that call.
            moved = (
                " We have already moved the message out of the inbox, so nobody "
                "can act on it by mistake in the meantime."
                if self.quarantined
                else ""
            )
            return (
                f"Call {self.callback_phone} and confirm the details with the "
                "supplier before paying anything. This is the number on file with "
                "us — do not use a number from the email itself." + moved
            )
        if self.quarantined:
            return (
                "Nothing. Envelock has already moved this message out of the "
                "inbox, so the person it was sent to will not see it. Open the "
                "alert only if you think that was wrong."
            )
        if self.flagged_in_place:
            return (
                "Check this before acting on it. The message is still in the "
                "mailbox with a warning attached — we have not removed it."
            )
        if self.tier is AlertTier.LOW:
            return "Nothing. This is recorded for context; no action is expected."
        return (
            "Take a look, and confirm the sender is who they claim before acting "
            "on anything in the message. Nothing has been moved or changed."
        )


def _facts(report: AlertReport) -> list[tuple[str, str]]:
    """The message details, skipping what we genuinely do not have.

    Printing "Subject: None" would be worse than omitting the row: it reads as
    a bug rather than as a deliberate privacy setting.
    """
    rows: list[tuple[str, str]] = [("Sent to", report.mailbox_address)]
    if report.sender:
        rows.append(("From", report.sender))
    if report.received_at is not None:
        rows.append(("Date", report.received_at.strftime("%Y-%m-%d %H:%M UTC")))
    if report.subject:
        rows.append(("Subject", report.subject))
    return rows


def render_text(report: AlertReport) -> str:
    out: list[str] = [
        report.title,
        "",
        "WHY AM I GETTING THIS ALERT?",
        report.why,
        "",
        "USER AFFECTED",
        report.mailbox_address,
        "",
        "EMAIL DETAILS",
    ]
    width = max((len(label) for label, _ in _facts(report)), default=0)
    out += [f"  {label.ljust(width)}  {value}" for label, value in _facts(report)]

    if report.findings or report.notes:
        out += ["", "ANALYSIS"]
        out += [f"  - {line}" for line in (*report.findings, *report.notes)]

    out += [
        "",
        "WHAT SHOULD I DO?",
        report.action,
        "",
        f"Full details: {report.url}",
    ]
    return "\n".join(out)


#: Inline styles only: every mail client strips <style> blocks, and half of them
#: strip classes too. Ugly source, reliable rendering.
_WRAP = (
    "font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;"
    "max-width:600px;color:#111827;line-height:1.5;"
)
_H = "margin:20px 0 6px;font-size:13px;font-weight:700;color:#111827;"
_P = "margin:0;font-size:14px;color:#374151;"
_LABEL = "padding:2px 12px 2px 0;font-size:13px;color:#6b7280;vertical-align:top;"
_VALUE = "padding:2px 0;font-size:13px;color:#111827;"

_BANNER = {
    AlertTier.CRITICAL: ("#b91c1c", "Action needed now"),
    AlertTier.HIGH: ("#c2410c", "Probable attack"),
    AlertTier.MEDIUM: ("#a16207", "Worth a look"),
    AlertTier.LOW: ("#4b5563", "For your records"),
}


def render_html(report: AlertReport) -> str:
    e = html.escape
    colour, banner = _BANNER[report.tier]

    rows = "".join(
        f'<tr><td style="{_LABEL}">{e(label)}</td>'
        f'<td style="{_VALUE}">{e(value)}</td></tr>'
        for label, value in _facts(report)
    )

    analysis = ""
    if report.findings or report.notes:
        items = "".join(
            f'<li style="margin:0 0 6px;">{e(line)}</li>'
            for line in (*report.findings, *report.notes)
        )
        analysis = (
            f'<div style="{_H}">Analysis</div>'
            f'<ul style="margin:0;padding-left:18px;font-size:14px;color:#374151;">{items}</ul>'
        )

    # The action sits in a tinted box because it is the one part a reader who
    # skims must not miss.
    return (
        f'<div style="{_WRAP}">'
        f'<div style="background:{colour};color:#fff;padding:12px 16px;'
        f'font-size:15px;font-weight:700;">{e(banner)}</div>'
        f'<div style="background:#f3f4f6;padding:8px 16px;font-size:14px;'
        f'color:#111827;">{e(report.title)}</div>'
        f'<div style="padding:16px;">'
        f'<div style="{_H}">Why am I getting this alert?</div>'
        f'<p style="{_P}">{e(report.why)}</p>'
        f'<div style="{_H}">User affected</div>'
        f'<p style="{_P}">{e(report.mailbox_address)}</p>'
        f'<div style="{_H}">Email details</div>'
        f'<table style="border-collapse:collapse;margin:0;">{rows}</table>'
        f"{analysis}"
        f'<div style="{_H}">What should I do?</div>'
        f'<div style="background:#f9fafb;border-left:3px solid {colour};'
        f'padding:10px 12px;font-size:14px;color:#111827;">{e(report.action)}</div>'
        f'<p style="margin:20px 0 0;font-size:12px;">'
        f'<a href="{e(report.url)}" style="color:#1d4ed8;">Open this alert in Envelock</a>'
        f"</p>"
        f"</div></div>"
    )


async def report_for_alert(session, alert, *, url_base: str | None = None):  # noqa: ANN001, ANN201
    """Build the report for a stored alert, or None if we cannot.

    Loads the mailbox it happened to, the findings that fired, and — through the
    findings — the message itself. Returns None rather than a half-filled report
    when there is no mailbox: a report that cannot say *whose* mailbox this is
    would fail at the one job it has.
    """
    from sqlalchemy import select

    from envelock.core.enums import MailboxClass
    from envelock.models import Finding, Mailbox, Message

    if alert.mailbox_id is None:
        return None
    mailbox = await session.get(Mailbox, alert.mailbox_id)
    if mailbox is None:
        return None

    findings = (
        (
            await session.execute(
                select(Finding).where(Finding.alert_id == alert.id).order_by(Finding.score.desc())
            )
        )
        .scalars()
        .all()
    )

    message = None
    for f in findings:
        if f.message_id is not None:
            message = await session.get(Message, f.message_id)
            if message is not None:
                break

    tier = AlertTier(alert.tier)
    protected = mailbox.mailbox_class == MailboxClass.PROTECTED.value
    # Mirrors what the poller actually does (workers/imap_fetch). Saying "we
    # moved it" when we did not would be worse than saying nothing at all.
    quarantined = protected and tier is AlertTier.CRITICAL
    flagged = protected and tier is AlertTier.HIGH

    sender = None
    if message is not None:
        sender = (
            f'"{message.sender_display}" <{message.sender_address}>'
            if message.sender_display
            else message.sender_address
        )

    # The AI judge's plain-language line reached the dashboard but never the
    # email — the report was built from Finding rows alone, and `notes` had no
    # writer. Surface the verdict rationale here (plain words only, no
    # confidence/model, PRD §16).
    notes: list[str] = []
    if getattr(alert, "ai_flagged", False):
        from envelock.models import LlmVerdictRecord

        verdict_row = (
            (
                await session.execute(
                    select(LlmVerdictRecord)
                    .where(LlmVerdictRecord.alert_id == alert.id)
                    .order_by(LlmVerdictRecord.created_at.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
        if verdict_row is not None and verdict_row.rationale:
            notes.append(
                f"Our fraud check independently confirmed this: {verdict_row.rationale}"
            )
        else:
            notes.append("Our fraud check independently confirmed this alert.")

    base = (url_base or "https://app.envelock.org").rstrip("/")
    return AlertReport(
        tier=tier,
        title=alert.title,
        mailbox_address=mailbox.address,
        findings=tuple(f.summary for f in findings[:5]),
        notes=tuple(notes),
        sender=sender,
        subject=message.subject if message is not None else None,
        received_at=message.received_at if message is not None else None,
        quarantined=quarantined,
        flagged_in_place=flagged,
        callback_phone=alert.callback_phone if alert.requires_callback else None,
        url=f"{base}/alerts/{alert.id}",
    )
