"""Account-lifecycle email: the messages a customer needs in order not to be
surprised by their own account.

These are not alerts. An alert says "something is happening in your mail"; these
say "something changed in your account with us" — your password, your plan, your
payment, your access. The difference matters operationally: an alert can be
noisy and still be doing its job, whereas one of these arriving wrongly, or not
arriving at all, is a support ticket or a silent lapse in protection.

Everything here funnels through `notify_admins`, which owns the one question
each of these had to answer separately before: *who* gets told. That is always
the people with a console to act in — owners and admins, active only.
"""

from __future__ import annotations

import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from envelock.config import get_settings

logger = logging.getLogger("envelock.notify.account")


async def admin_recipients(session: AsyncSession, tenant_id: UUID) -> list[str]:
    """Owners and admins with an active login — the people who can act on this.

    Members are deliberately excluded: they see only their own mailbox, and a
    billing or password-policy message to them is noise they cannot act on.
    """
    from envelock.models import User

    return list(
        (
            await session.execute(
                select(User.email).where(
                    User.tenant_id == tenant_id,
                    User.is_admin.is_(True),
                    User.status == "active",
                )
            )
        )
        .scalars()
        .all()
    )


def app_url(path: str = "") -> str:
    return f"{get_settings().web_base_url.rstrip('/')}{path}"


#: Display names, written out rather than derived with `.capitalize()`. That
#: call lowercases everything after the first letter, so any plan later named
#: with more than one word or an internal capital would silently render wrong —
#: and it has no answer at all for a plan we don't recognise.
_PLAN_NAMES = {
    "guard": "Guard",
    "solo": "Solo",
    "essential": "Essential",
    "complete": "Complete",
}


def plan_label(plan: str | None) -> str:
    """A plan named the way a sentence needs it: "the Complete plan".

    Bare "Complete" reads as a status word rather than a product — "Complete is
    active" looks like a progress message. The article and the noun are what
    make it a name. An unrecognised or missing plan degrades to "your plan",
    which is always true and never wrong.
    """
    name = _PLAN_NAMES.get((plan or "").strip().lower())
    return f"the {name} plan" if name else "your plan"


def plan_title(plan: str | None) -> str:
    """`plan_label` at the start of a sentence or heading: "The Complete plan".

    Only the first character is touched — `str.capitalize()` would flatten the
    plan's own capital ("The complete plan").
    """
    label = plan_label(plan)
    return label[:1].upper() + label[1:]


async def notify_admins(
    session: AsyncSession,
    tenant_id: UUID,
    *,
    subject: str,
    heading: str,
    paragraphs: list[str],
    text: str,
    cta_label: str | None = None,
    cta_url: str | None = None,
    footnote: str | None = None,
    preheader: str | None = None,
) -> int:
    """Send one account email to every admin. Returns how many actually went.

    Never raises. A billing webhook or a password change must not fail because
    the mail relay is down — the state change already happened and is the thing
    that matters; the email is the courtesy. Failures are logged, not surfaced.
    """
    from envelock.notify.mail import is_configured, send_mail
    from envelock.notify.templates import branded_email

    if not is_configured():
        logger.info("account email %r not sent: no SMTP relay configured", subject)
        return 0

    html_body = branded_email(
        heading=heading,
        paragraphs=paragraphs,
        cta_label=cta_label,
        cta_url=cta_url,
        footnote=footnote,
        preheader=preheader,
    )
    sent = 0
    try:
        recipients = await admin_recipients(session, tenant_id)
    except Exception as exc:  # noqa: BLE001 — see docstring
        logger.warning("could not list admins for tenant %s: %s", tenant_id, exc)
        return 0
    for address in recipients:
        try:
            result = await send_mail(
                to=address, subject=subject, body=text, html_body=html_body
            )
        except Exception as exc:  # noqa: BLE001 — see docstring
            logger.warning("account email to %s failed: %s", address, exc)
            continue
        if result.sent:
            sent += 1
    return sent


__all__ = ["admin_recipients", "app_url", "notify_admins"]
