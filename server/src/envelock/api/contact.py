"""The public contact form.

An unauthenticated endpoint that sends mail to an address we own, on behalf of
someone who typed their own address into a box. That shape is a spam relay and
a reputation bonfire unless three things are true, so all three are here:

* **The topic is an enum, not free text**, and it only ever reaches the subject
  line. A caller cannot steer delivery.
* **The reply-to is the visitor's address, and the From is always ours.**
  Sending as the visitor would fail our own SPF/DKIM and teach mail providers
  that envelock.org forges senders — we of all companies cannot afford that.
* **Turnstile plus the rate limiter.** The bucket is applied by path prefix in
  `security/middleware.py`; the CAPTCHA is checked here.
"""

from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field

from envelock.config import get_settings

logger = logging.getLogger("envelock.contact")

router = APIRouter(prefix="/api/v1", tags=["contact"])

#: Shown in the dropdown, in this order. The key is what the caller sends and
#: what `contact_topic_emails` routes on. `label` is the human sentence in the
#: dropdown; `tag` is the short, stable token in the subject line — a mail
#: filter matching "[Billing]" should not break because the dropdown wording
#: was later softened to "Billing or payment".
TOPICS: dict[str, dict[str, str]] = {
    "account": {"label": "Account", "tag": "Account"},
    "billing": {"label": "Billing or payment", "tag": "Billing"},
    "bug": {"label": "Something is broken", "tag": "Bug"},
    "suggestion": {"label": "Suggestion", "tag": "Suggestion"},
    "complaint": {"label": "Complaint", "tag": "Complaint"},
    "security": {"label": "Security concern", "tag": "Security"},
    "other": {"label": "Something else", "tag": "Other"},
}

TopicId = Literal["account", "billing", "bug", "suggestion", "complaint", "security", "other"]


class ContactRequest(BaseModel):
    topic: TopicId
    email: EmailStr
    name: str = Field(default="", max_length=120)
    subject: str = Field(min_length=3, max_length=200)
    message: str = Field(min_length=10, max_length=5000)
    #: Turnstile solution. Optional in the model because a deployment with no
    #: secret configured does not render the widget; `verify` decides.
    captcha_token: str | None = None


@router.get("/contact/options")
async def contact_options() -> dict:
    """Topics and, if enabled, the public CAPTCHA site key.

    The site key is public by design — it identifies the widget, it does not
    authorise anything. The secret never appears here.
    """
    settings = get_settings()
    return {
        "topics": [{"id": k, "label": v["label"]} for k, v in TOPICS.items()],
        "captcha_site_key": settings.turnstile_site_key,
    }


@router.post("/contact", status_code=status.HTTP_202_ACCEPTED)
async def submit_contact(req: ContactRequest, request: Request) -> dict:
    from envelock.notify.mail import is_configured, send_mail
    from envelock.notify.templates import branded_email
    from envelock.security import turnstile

    client_ip = request.client.host if request.client else None
    if not await turnstile.verify(req.captcha_token, remote_ip=client_ip):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "the anti-spam check did not pass — please try again",
        )

    if not is_configured():
        # Truthful failure. Returning 202 here would tell someone their
        # complaint had been received when it had gone nowhere.
        logger.error("contact form submission dropped: no SMTP relay configured")
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "we can't take messages through this form right now — please email "
            "us directly",
        )

    settings = get_settings()
    topic = TOPICS.get(req.topic, TOPICS["other"])
    label, tag = topic["label"], topic["tag"]
    to = settings.contact_topic_map.get(req.topic, settings.contact_email)
    who = f"{req.name} <{req.email}>" if req.name else req.email

    text = (
        f"Topic: {label}\n"
        f"From: {who}\n"
        f"Subject: {req.subject}\n\n"
        f"{req.message}\n"
    )
    result = await send_mail(
        to=to,
        subject=f"[{tag}] {req.subject}",
        body=text,
        html_body=branded_email(
            heading=f"[{tag}] {req.subject}",
            preheader=f"From {who}",
            paragraphs=[f"From: {who}", req.message],
            footnote="Sent from the contact form on envelock.org.",
        ),
        reply_to=req.email,
    )
    if not result.sent:
        logger.error("contact form send failed (%s)", result.reason)
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "we couldn't send that just now — please try again shortly",
        )

    # Acknowledgement to the sender, so a complaint does not vanish into
    # silence. Best effort: their message is already delivered, which is the
    # part that matters, so a failure here is logged and not surfaced.
    try:
        await send_mail(
            to=req.email,
            subject=f"We received your message — {req.subject}",
            body=(
                "Thanks — we've got your message and will come back to you.\n\n"
                f"Topic: {label}\nSubject: {req.subject}\n\n"
                "For reference, this is what you sent:\n\n"
                f"{req.message}\n"
            ),
            html_body=branded_email(
                heading="We received your message",
                preheader="We'll come back to you.",
                paragraphs=[
                    "Thanks — we've got your message and will come back to you.",
                    f"Topic: {label}",
                    f"Subject: {req.subject}",
                ],
                footnote="This is a copy for your records; no reply is needed.",
            ),
        )
    except Exception as exc:  # noqa: BLE001 — see comment above
        logger.warning("contact acknowledgement to %s failed: %s", req.email, exc)

    return {"received": True}
