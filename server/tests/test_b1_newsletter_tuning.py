"""B1 link-phishing noise control (pure).

A legitimate newsletter linking to big-brand domains trips only "soft" reasons
(a brand name in a URL, a shortener). Alerting MEDIUM on those every send is the
false-positive treadmill P5 forbids, so soft-only findings must stay quiet
UNLESS the message is actually about payment or sign-in. A "hard" reason (bare
IP, threat feed, embedded credentials) still fires on its own.
"""

from __future__ import annotations

from uuid import uuid4

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import SourceMechanism
from envelock.detections.base import DetectionContext, run_all

OWNED = frozenset({"acme.com"})


def _ctx(raw: str) -> DetectionContext:
    event = parse_message(
        raw.encode(), tenant_id=uuid4(), mailbox_id=uuid4(),
        source=SourceMechanism.IMAP_IDLE, owned_domains=OWNED, remediable=True,
    )
    return DetectionContext(
        event=event,
        tenant_id="t",
        capabilities=capabilities_for(frozenset({SourceMechanism.IMAP_IDLE})),
        owned_domains=OWNED,
    )


def _b1(raw: str):  # noqa: ANN202
    return [f for f in run_all(_ctx(raw)) if f.service == "B1"]


NEWSLETTER = """\
From: News <news@news.example.com>
To: user@acme.com
Subject: Your October product newsletter
Message-ID: <n1@news.example.com>
Content-Type: text/plain

Here is what's new this month. Read more at
https://www.microsoft.com/en/whats-new and sign up at
https://login.microsoftonline.com/signup — thanks for reading!
"""

NEWSLETTER_BUT_PAYMENT = """\
From: News <news@news.example.com>
To: user@acme.com
Subject: Your invoice is ready
Message-ID: <n2@news.example.com>
Content-Type: text/plain

Please pay the attached invoice via https://www.microsoft.com/pay today.
"""

BARE_IP = """\
From: News <news@news.example.com>
To: user@acme.com
Subject: hello
Message-ID: <n3@news.example.com>
Content-Type: text/plain

Click http://203.0.113.10/account to continue.
"""


def test_soft_only_newsletter_is_silent() -> None:
    assert _b1(NEWSLETTER) == [], "brand-bait links on a newsletter must not alert"


def test_soft_reasons_fire_with_payment_context() -> None:
    hits = _b1(NEWSLETTER_BUT_PAYMENT)
    assert hits, "a brandish link in a payment message is exactly what B1 is for"


def test_hard_reason_fires_without_context() -> None:
    hits = _b1(BARE_IP)
    assert hits, "a bare-IP link is dangerous on its own, newsletter or not"
