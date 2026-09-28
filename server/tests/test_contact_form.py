"""The public contact form.

An unauthenticated endpoint that emails an address the caller names is a spam
relay unless it is held down, so what is pinned here is the holding-down: the
topic cannot steer delivery, the From stays ours, a failure is reported as a
failure rather than swallowed, and the CAPTCHA is actually consulted.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def relay(monkeypatch):
    """A working relay that records what was sent."""
    from envelock.notify import mail

    sent: list[dict] = []

    async def _send(*, to, subject, body, html_body=None, reply_to=None):  # noqa: ANN001, ANN202
        sent.append(
            {"to": to, "subject": subject, "body": body, "reply_to": reply_to}
        )
        return mail.MailResult(True, "sent")

    monkeypatch.setattr(mail, "is_configured", lambda: True)
    monkeypatch.setattr(mail, "send_mail", _send)
    return sent


def _payload(**over) -> dict:
    base = {
        "topic": "billing",
        "email": "someone@customer.example",
        "name": "A Customer",
        "subject": "Charged twice this month",
        "message": "I think my card was charged two times for September.",
    }
    base.update(over)
    return base


def test_options_lists_topics_and_never_leaks_the_secret(client: TestClient) -> None:
    r = client.get("/api/v1/contact/options")
    assert r.status_code == 200
    body = r.json()
    ids = {t["id"] for t in body["topics"]}
    assert {"billing", "bug", "complaint", "suggestion"} <= ids
    # The SITE key is public and identifies the widget. The SECRET must never
    # appear on a public endpoint, under any name.
    assert "captcha_site_key" in body
    assert not any("secret" in k.lower() for k in body)


def test_a_message_reaches_us_with_the_topic_in_the_subject(client, relay) -> None:
    r = client.post("/api/v1/contact", json=_payload())
    assert r.status_code == 202, r.text

    # Two emails: ours, then the acknowledgement to the sender.
    assert len(relay) == 2
    to_us, ack = relay
    assert to_us["subject"].startswith("[Billing] ")
    assert "Charged twice this month" in to_us["subject"]
    # Reply-To carries the visitor so a reply reaches them; sending AS them
    # would fail our own SPF/DKIM and teach providers we forge senders.
    assert to_us["reply_to"] == "someone@customer.example"
    assert ack["to"] == "someone@customer.example"


def test_an_unknown_topic_is_refused_rather_than_routed(client, relay) -> None:
    """The topic is an enum, so a caller cannot invent one — which is what stops
    it being used to steer delivery or inject a header."""
    r = client.post("/api/v1/contact", json=_payload(topic="../admin"))
    assert r.status_code == 422
    assert relay == []


def test_a_failed_send_is_reported_not_swallowed(client, monkeypatch) -> None:
    """Returning 202 on a dropped message tells someone their complaint was
    received when it went nowhere. That is worse than an error."""
    from envelock.notify import mail

    monkeypatch.setattr(mail, "is_configured", lambda: False)
    r = client.post("/api/v1/contact", json=_payload())
    assert r.status_code == 503


def test_a_rejected_captcha_stops_the_message(client, relay, monkeypatch) -> None:
    from envelock.security import turnstile

    async def _deny(token, *, remote_ip=None):  # noqa: ANN001, ANN202
        return False

    monkeypatch.setattr(turnstile, "verify", _deny)
    r = client.post("/api/v1/contact", json=_payload(captcha_token="bad"))  # noqa: S106
    assert r.status_code == 400
    assert relay == []


def test_the_captcha_is_off_when_no_secret_is_configured(client, relay) -> None:
    """A deployment without a Turnstile secret must still accept messages —
    otherwise enabling the widget becomes a prerequisite for having a contact
    form at all, and dev/staging would silently reject everything."""
    from envelock.security import turnstile

    assert turnstile.is_configured() is False
    r = client.post("/api/v1/contact", json=_payload(captcha_token=None))
    assert r.status_code == 202
    assert len(relay) == 2
