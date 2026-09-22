"""The monthly "what we caught, and why" digest.

A security product that works is invisible. That is the point of it and it is
also its commercial problem: a customer whose month was quiet has no evidence
they were protected, only an invoice, and the renewal conversation starts from
there. Every alert already carries a plain-English reason — written by the AI
analyst where one was consulted, by the detection itself where it was not — and
those sentences are the best sales asset the company owns, because a customer
reads them and recognises their own suppliers and their own invoices.

So once a month each workspace gets the month back in its own words: what was
caught, what it was worth, and one line each on why. Nothing is invented for it.
Every figure here is read from rows the product wrote while doing its job.

Three rules this module holds to, all of them learned the hard way by other
people's digest emails:

* **Never send an empty one.** A digest with nothing in it is an advert, and it
  teaches the reader to filter the sender — which is how the *next* one, the one
  reporting a real fraud, ends up unread in Junk.
* **Never inflate.** Prevented-loss counts confirmed frauds only, is reported per
  currency, and says out loud how many incidents carried no figure.
* **Never include message content.** Counterparty domains and our own alert
  titles, nothing else. The digest crosses into a mail system we do not control.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.core.enums import AlertTier
from envelock.models import Alert, LlmVerdictRecord, Tenant

__all__ = ["Digest", "DigestItem", "build_digest", "render_html", "render_text"]

#: Highest tier first, then most recent. A reader who stops after three lines
#: should have read the three that mattered.
_RANK = {
    AlertTier.CRITICAL.value: 0,
    AlertTier.HIGH.value: 1,
    AlertTier.MEDIUM.value: 2,
    AlertTier.LOW.value: 3,
}


@dataclass(frozen=True, slots=True)
class DigestItem:
    """One caught attack, as the reader will recognise it."""

    tier: str
    title: str
    counterparty: str | None
    reason: str | None
    amount: float | None
    currency: str | None
    ai: bool
    at: datetime


@dataclass(frozen=True, slots=True)
class Digest:
    tenant_name: str
    period_start: datetime
    period_end: datetime
    #: Everything analysed, so the quiet months still show the work done.
    messages_analysed: int
    alerts_raised: int
    critical: int
    confirmed: int
    #: [{"currency": "GBP", "amount": 48250.0}], never summed across currencies.
    prevented_by_currency: list[dict] = field(default_factory=list)
    unpriced_incidents: int = 0
    ai_consulted: int = 0
    items: list[DigestItem] = field(default_factory=list)
    #: Inbound payment requests checked this month, and what they asked for:
    #: [{"currency": "USD", "amount": 48250.0}] — per currency, never summed across.
    payment_requests: int = 0
    payments_checked_by_currency: list[dict] = field(default_factory=list)

    @property
    def worth_sending(self) -> bool:
        """A month with nothing in it does not get an email. See the module note.
        Payment requests checked count as something: "we checked $48,250 of
        payment requests and all of it was fine" is the quiet month's proof."""
        return self.alerts_raised > 0 or self.payment_requests > 0

    @property
    def headline(self) -> str:
        """The one line the owner reads: money checked, frauds stopped."""
        parts = []
        if self.payments_checked_by_currency:
            money = " and ".join(
                _money(r["amount"], r["currency"]) for r in self.payments_checked_by_currency[:2]
            )
            parts.append(f"{money} in payment requests checked")
        elif self.payment_requests:
            parts.append(
                f"{self.payment_requests} payment "
                f"{'request' if self.payment_requests == 1 else 'requests'} checked"
            )
        if self.confirmed:
            parts.append(f"{self.confirmed} {'fraud' if self.confirmed == 1 else 'frauds'} stopped")
        elif self.critical:
            parts.append(
                f"{self.critical} critical {'alert' if self.critical == 1 else 'alerts'}"
            )
        if not parts:
            parts.append(f"{self.alerts_raised} caught this month")
        return "; ".join(parts)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


async def build_digest(
    session: AsyncSession,
    *,
    tenant_id: UUID,
    since: datetime,
    until: datetime | None = None,
) -> Digest | None:
    """Assemble one workspace's month. None when the tenant no longer exists."""
    tenant = await session.get(Tenant, tenant_id)
    if tenant is None:
        return None
    until = until or datetime.now(UTC)

    alerts = list(
        (
            await session.execute(
                select(Alert)
                .where(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= since,
                    Alert.created_at < until,
                )
                .order_by(Alert.created_at.desc())
            )
        )
        .scalars()
        .all()
    )

    # The AI's own sentence, where there was one. This is the line that makes the
    # digest worth opening, so it is read from the recorded verdicts rather than
    # regenerated — the customer must see exactly what the product told them at
    # the time, not a fresh opinion formed a month later.
    rationales: dict[UUID, str] = {}
    if alerts:
        rows = (
            (
                await session.execute(
                    select(LlmVerdictRecord).where(
                        LlmVerdictRecord.alert_id.in_([a.id for a in alerts])
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            if row.rationale and row.alert_id is not None:
                rationales.setdefault(row.alert_id, row.rationale)

    from envelock.platform.alerts import prevented_loss

    prevented = prevented_loss(alerts)

    notable = sorted(
        (a for a in alerts if a.tier in (AlertTier.CRITICAL.value, AlertTier.HIGH.value)),
        key=lambda a: (_RANK.get(a.tier, 9), -(_aware(a.created_at) or until).timestamp()),
    )[:8]

    messages = await _count_messages(session, tenant_id=tenant_id, since=since, until=until)
    requests, checked = await _payments_checked(
        session, tenant_id=tenant_id, since=since, until=until
    )

    return Digest(
        tenant_name=tenant.name,
        period_start=since,
        period_end=until,
        messages_analysed=messages,
        alerts_raised=len(alerts),
        critical=sum(1 for a in alerts if a.tier == AlertTier.CRITICAL.value),
        confirmed=sum(1 for a in alerts if a.state == "resolved"),
        prevented_by_currency=prevented["by_currency"],
        unpriced_incidents=prevented["unpriced_incidents"],
        ai_consulted=sum(1 for a in alerts if a.ai_flagged),
        payment_requests=requests,
        payments_checked_by_currency=checked,
        items=[
            DigestItem(
                tier=a.tier,
                title=a.title,
                counterparty=a.counterparty_domain,
                reason=rationales.get(a.id),
                amount=a.amount_at_risk,
                currency=a.amount_currency,
                ai=bool(a.ai_flagged),
                at=_aware(a.created_at) or until,
            )
            for a in notable
        ],
    )


async def _count_messages(
    session: AsyncSession, *, tenant_id: UUID, since: datetime, until: datetime
) -> int:
    from sqlalchemy import func

    from envelock.models import Message

    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Message)
                .where(
                    Message.tenant_id == tenant_id,
                    Message.created_at >= since,
                    Message.created_at < until,
                )
            )
        ).scalar_one()
        or 0
    )


async def _payments_checked(
    session: AsyncSession, *, tenant_id: UUID, since: datetime, until: datetime
) -> tuple[int, list[dict]]:
    """(payment requests with an amount, total per currency, largest first)."""
    from sqlalchemy import func

    from envelock.models import Message

    rows = (
        await session.execute(
            select(Message.payment_currency, func.count(), func.sum(Message.payment_amount))
            .where(
                Message.tenant_id == tenant_id,
                Message.created_at >= since,
                Message.created_at < until,
                Message.payment_amount.is_not(None),
            )
            .group_by(Message.payment_currency)
        )
    ).all()
    count = sum(int(n) for _, n, _ in rows)
    totals = sorted(
        ({"currency": cur, "amount": float(total or 0)} for cur, _, total in rows if cur),
        key=lambda r: -r["amount"],
    )
    return count, totals


def _money(amount: float, currency: str) -> str:
    symbol = {"USD": "$", "EUR": "€", "GBP": "£", "NGN": "₦"}.get(currency)
    body = f"{amount:,.2f}".removesuffix(".00")
    return f"{symbol}{body}" if symbol else f"{currency} {body}"


def _prevented_line(d: Digest) -> str | None:
    """One sentence, or none. Never a zero — "we saved you nothing" is not a
    sentence any product should put in front of a customer, and an absent figure
    is the honest rendering of "no confirmed fraud carried an amount"."""
    if not d.prevented_by_currency:
        return None
    parts = [_money(row["amount"], row["currency"]) for row in d.prevented_by_currency]
    total = " and ".join(parts) if len(parts) <= 2 else ", ".join(parts[:-1]) + f" and {parts[-1]}"
    tail = ""
    if d.unpriced_incidents:
        tail = (
            f" A further {d.unpriced_incidents} confirmed "
            f"{'incident' if d.unpriced_incidents == 1 else 'incidents'} named no amount."
        )
    return f"{total} was stopped from going to the wrong account.{tail}"


def _period(d: Digest) -> str:
    return f"{d.period_start:%-d %B} – {d.period_end:%-d %B %Y}"


def render_text(d: Digest) -> str:
    lines = [
        f"Envelock — {d.tenant_name}",
        _period(d),
        "",
        d.headline[0].upper() + d.headline[1:] + ".",
        "",
    ]
    prevented = _prevented_line(d)
    if prevented:
        lines += [prevented, ""]
    lines += [
        f"Messages analysed: {d.messages_analysed:,}",
        f"Alerts raised: {d.alerts_raised} ({d.critical} critical)",
        f"Confirmed by your team: {d.confirmed}",
    ]
    if d.ai_consulted:
        lines.append(f"AI analyst confirmed: {d.ai_consulted}")
    lines.append("")

    if d.items:
        lines += ["WHAT WE CAUGHT", ""]
        for item in d.items:
            head = f"[{item.tier.upper()}] {item.title}"
            if item.amount is not None and item.currency:
                head += f" — {_money(item.amount, item.currency)}"
            lines.append(head)
            if item.counterparty:
                lines.append(f"  Sender: {item.counterparty}")
            if item.reason:
                lines.append(f"  Why: {item.reason}")
            lines.append(f"  {item.at:%-d %b %H:%M} UTC")
            lines.append("")

    lines += [
        "Every alert above is in your dashboard with its full working.",
        "",
        "You are receiving this because you administer an Envelock workspace.",
    ]
    return "\n".join(lines)


def render_html(d: Digest) -> str:
    e = html.escape

    def row(item: DigestItem) -> str:
        colour = "#b91c1c" if item.tier == AlertTier.CRITICAL.value else "#b45309"
        amount = (
            f'<span style="font-weight:600;white-space:nowrap;">'
            f"{e(_money(item.amount, item.currency))}</span>"
            if item.amount is not None and item.currency
            else ""
        )
        # Escaped once, at the join — escaping the counterparty here as well
        # produced "&amp;lt;" in the rendered mail, which is safe but reads as
        # gibberish to the customer.
        meta = []
        if item.counterparty:
            meta.append(item.counterparty)
        meta.append(f"{item.at:%-d %b %H:%M} UTC")
        if item.ai:
            meta.append("AI confirmed")
        reason = (
            f'<div style="font-size:13px;color:#374151;margin-top:6px;'
            f'line-height:1.6;">{e(item.reason)}</div>'
            if item.reason
            else ""
        )
        return (
            f'<tr><td style="padding:14px 0;border-bottom:1px solid #e5e7eb;">'
            f'<div style="display:flex;justify-content:space-between;gap:12px;">'
            f'<span style="font-size:11px;font-weight:700;letter-spacing:.06em;'
            f'color:{colour};">{e(item.tier.upper())}</span>{amount}</div>'
            f'<div style="font-size:14px;font-weight:600;color:#111827;'
            f'margin-top:6px;">{e(item.title)}</div>'
            f"{reason}"
            f'<div style="font-size:11px;color:#9ca3af;margin-top:8px;">'
            f'{e(" · ".join(meta))}</div></td></tr>'
        )

    prevented = _prevented_line(d)
    prevented_block = (
        f'<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;'
        f'padding:18px;margin-bottom:24px;font-size:15px;color:#14532d;'
        f'line-height:1.6;">{e(prevented)}</div>'
        if prevented
        else ""
    )

    stats = [
        ("Messages analysed", f"{d.messages_analysed:,}"),
        ("Alerts raised", str(d.alerts_raised)),
        ("Critical", str(d.critical)),
        ("Confirmed by your team", str(d.confirmed)),
    ]
    stat_cells = "".join(
        f'<td style="padding:0 8px 0 0;"><div style="font-size:11px;color:#6b7280;'
        f'letter-spacing:.06em;">{e(label.upper())}</div>'
        f'<div style="font-size:22px;font-weight:700;color:#111827;'
        f'margin-top:2px;">{e(value)}</div></td>'
        for label, value in stats
    )

    items = "".join(row(i) for i in d.items)
    items_block = (
        f'<div style="font-size:11px;font-weight:700;letter-spacing:.08em;'
        f'color:#6b7280;margin:28px 0 4px;">WHAT WE CAUGHT</div>'
        f'<table role="presentation" width="100%" style="border-collapse:collapse;">'
        f"{items}</table>"
        if items
        else ""
    )

    return (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Envelock — {e(d.tenant_name)}</title></head>"
        '<body style="margin:0;background:#f6f7f9;'
        'font-family:-apple-system,Segoe UI,Arial,sans-serif;">'
        '<div style="max-width:640px;margin:0 auto;padding:32px 16px;">'
        '<div style="background:#fff;border:1px solid #e5e7eb;border-radius:8px;'
        'padding:28px;">'
        f'<div style="font-size:13px;color:#6b7280;">{e(_period(d))}</div>'
        f'<div style="font-size:20px;font-weight:700;color:#111827;margin:4px 0 6px;">'
        f"{e(d.tenant_name)} — your month in email fraud</div>"
        f'<div style="font-size:16px;font-weight:600;color:#c2410c;margin:0 0 24px;">'
        f"{e(d.headline[0].upper() + d.headline[1:])}.</div>"
        f"{prevented_block}"
        f'<table role="presentation" style="border-collapse:collapse;width:100%;">'
        f"<tr>{stat_cells}</tr></table>"
        f"{items_block}"
        '<div style="font-size:12px;color:#6b7280;margin-top:28px;line-height:1.6;">'
        "Every alert above is in your dashboard with its full working.</div>"
        "</div>"
        '<div style="font-size:11px;color:#9ca3af;margin-top:16px;text-align:center;">'
        "You are receiving this because you administer an Envelock workspace."
        "</div></div></body></html>"
    )
