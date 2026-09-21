"""Transactional email — the messages that are not alerts.

Password resets, invitations and the like. They share everything that makes an
alert land (DKIM signing, the relay fallback, async delivery) and differ only in
what they say, so this reuses `EmailSender`'s machinery rather than hand-rolling
a second SMTP path — which is exactly what the password-reset flow was doing, in
blocking `smtplib`, inside an async endpoint, with a silent `return` when the
host looked unconfigured.

The one rule here that matters: **`send` returns whether it actually sent.** The
reset flow told every user "a link has been sent to your email" whether or not
anything left the building, so on a deployment with no relay the whole feature
appeared to work and silently did nothing. A caller that cannot tell the
difference cannot tell the truth.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

from envelock.config import get_settings

logger = logging.getLogger("envelock.mail")


@dataclass(frozen=True, slots=True)
class MailResult:
    sent: bool
    #: Machine-readable, for a caller that has to choose a different route.
    #: "sent" | "not_configured" | "failed"
    reason: str
    detail: str = ""

    @property
    def deliverable(self) -> bool:
        """Whether this deployment can send transactional mail at all."""
        return self.reason != "not_configured"


def is_configured() -> bool:
    """Whether a real relay is set up.

    `localhost` is treated as unconfigured deliberately: it is the default in
    `.env.example`, almost never a real relay, and a deployment that has not been
    given one should be told so rather than silently swallowing mail.
    """
    settings = get_settings()
    host = (settings.smtp_host or "").strip()
    return bool(host and host != "localhost" and settings.smtp_from)


async def send_mail(
    *, to: str, subject: str, body: str, html_body: str | None = None
) -> MailResult:
    """Send one transactional message. Never raises.

    `body` is always the text part and is never optional: it is what terminal
    mail readers, screen readers and anything stripping HTML will show, so a
    caller that passes `html_body` still has to write the text version properly.
    """
    if not is_configured():
        logger.warning(
            "transactional email to %s not sent: no SMTP relay configured", to
        )
        return MailResult(
            False,
            "not_configured",
            "no SMTP relay is configured on this deployment",
        )

    settings = get_settings()
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = to
    # Transactional, not bulk — keep it out of bulk filtering heuristics, and
    # tell well-behaved autoresponders not to reply to it.
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    # Reuse the alert sender's DKIM signing and relay fallback rather than
    # duplicating them: we of all companies have to pass our own D5 posture check.
    from envelock.notify.senders import EmailSender

    sender = EmailSender()
    try:
        await sender._deliver(message)  # noqa: SLF001 — same package, shared transport
    except (smtplib.SMTPException, OSError, RuntimeError) as exc:
        if sender.has_fallback:
            try:
                await sender._deliver_via_relay(message)  # noqa: SLF001
            except Exception as relay_exc:  # noqa: BLE001
                logger.warning(
                    "transactional email to %s failed on primary and relay: %s / %s",
                    to, exc, relay_exc,
                )
                return MailResult(False, "failed", f"{exc}; relay: {relay_exc}")
            return MailResult(True, "sent", "delivered via relay fallback")
        logger.warning("transactional email to %s failed: %s", to, exc)
        return MailResult(False, "failed", str(exc))
    except Exception as exc:  # noqa: BLE001 — mail must never break the caller
        logger.warning("transactional email to %s failed: %s", to, exc)
        return MailResult(False, "failed", str(exc))

    return MailResult(True, "sent")


__all__ = ["MailResult", "is_configured", "send_mail"]
