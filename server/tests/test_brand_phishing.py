"""Brand phishing that the 2026-11-08 end-to-end run under-rated (pure).

Two messages from that run, forwarded in exactly as sent:

* A "Microsoft 365 Security" password lure from microsoft365-verify-login.com
  rated MEDIUM, on its bare-IP link alone. The display name, the credential
  lure and a link domain dressed up as Microsoft together are a probable attack.
* "Billing" <billing@gemini.com> linking to gemini-statement-portal.com raised
  nothing. A link to a copy of the sender's own domain is the landing page of a
  spoofed sender.

The controls are the mail these checks must leave alone: a brand's real mail
linking to its own family of domains, images on a brand's CDN, a partner
newsletter that names Microsoft and links to the real microsoft.com, and a
known vendor's invoice or an Amazon order as a mail gateway stores it. Safe
Links moves every link onto outlook.com. Proofpoint, Mimecast and Google's
wrapper carry the link, and the brand it names, inside their own URL.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from urllib.parse import quote, urlsplit
from uuid import uuid4

import pytest

from envelock.channels.mail.parser import parse_message
from envelock.core.capabilities import capabilities_for
from envelock.core.enums import AlertTier, SourceMechanism
from envelock.detections.base import CounterpartyState, DetectionContext, run_all
from envelock.risk.engine import RiskAssessment, assess

OWNED = frozenset({"northwind-e2e.com"})

#: 05-credential-phish.eml from the e2e run.
CREDENTIAL_PHISH = b"""\
From: "Microsoft 365 Security" <no-reply@microsoft365-verify-login.com>
To: finance@northwind-e2e.com
Subject: Action required: your mailbox password expires today
Date: Sun, 08 Nov 2026 03:10:26 -0600
Message-ID: <179412902605.5233.9180730763589722797@e2e.test>
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<p>Your password for finance@northwind-e2e.com expires in 2 hours.</p><p><a href="https://microsoft365-verify-login.com/owa/auth?u=finance">Keep my current password</a></p><p><a href="http://185.234.72.10/login.php">Mailbox settings</a></p>
"""  # noqa: E501 — the e2e message verbatim, one HTML line

#: 06-hostile-headers.eml from the e2e run.
STATEMENT_PHISH = b"""\
From: "Billing" <billing@gemini.com>
Reply-To: "
To: ,
 :'\xc3\xa9,);\\[
Subject: Statement ready
Message-ID: <hostile-e2e@gemini.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary=B

--B
Content-Type: text/html; charset=utf-8

<a href="https://gemini-statement-portal.com/pay">View statement</a>
--B--
"""

#: How Gmail stamps a message on delivery, above everything the sender wrote.
_GMAIL = (
    "mx.google.com; dkim=pass header.i=@{d}; spf=pass smtp.mailfrom={d}; "
    "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from={d}"
)


def _assess(
    raw: bytes,
    source: SourceMechanism = SourceMechanism.FORWARD_INGEST,
    counterparty: CounterpartyState | None = None,
) -> RiskAssessment | None:
    # No owned_domains: every sender here is outside, and claude/sad-easley-46e85c
    # drops that parameter (direction comes from the channel there).
    event = parse_message(
        raw, tenant_id=uuid4(), mailbox_id=uuid4(), source=source, remediable=True
    )
    ctx = DetectionContext(
        event=event,
        tenant_id="t",
        capabilities=capabilities_for(frozenset({source})),
        owned_domains=OWNED,
        known_counterparties=frozenset({"acme-supplies.com"}),
        counterparty=counterparty,
    )
    return assess(run_all(ctx))


def _tier(assessment: RiskAssessment | None) -> AlertTier | None:
    return assessment.tier if assessment is not None else None


#: Defender rewrites every link in a Microsoft 365 mailbox onto outlook.com.
_SAFELINKS = "https://eur01.safelinks.protection.outlook.com/?url={}&data=05"


def _proofpoint_v2(url: str) -> str:
    """Proofpoint v2 spells `%` as `-` and `/` as `_`, so it escapes those two first."""
    spelled = quote(url, safe="/").replace("-", "%2D").replace("_", "%5F")
    return (
        "https://urldefense.proofpoint.com/v2/url?u="
        + spelled.translate(str.maketrans("%/", "-_"))
        + "&d=DwMFaQ&c=AbC&r=DeF&m=GhI&s=JkL&e="
    )


#: How each mail gateway rewrites a link in the mailbox it protects. Mimecast keeps
#: only the destination's domain; the others keep the whole link. Google's is the
#: shape Calendar gives the links in an invitation.
_GATEWAYS: dict[str, Callable[[str], str]] = {
    "safe-links": lambda u: _SAFELINKS.format(quote(u, safe="")),
    "proofpoint-v2": _proofpoint_v2,
    "proofpoint-v3": lambda u: f"https://urldefense.com/v3/__{u}__;!!AbCdEf!GhIjKl$",
    "mimecast": lambda u: (
        f"https://url.us.m.mimecastprotect.com/s/AbCdEfGh?domain={urlsplit(u).hostname}"
    ),
    "google": lambda u: f"https://www.google.com/url?q={quote(u, safe=':/')}&sa=D&source=calendar",
}


def _through(gateway: str) -> Callable[[bytes], bytes]:
    """`raw` as a mailbox behind `gateway` stores it: every href rewritten."""
    wrap = _GATEWAYS[gateway]
    return lambda raw: re.sub(
        rb'href="([^"]+)"', lambda m: b'href="%s"' % wrap(m[1].decode()).encode(), raw
    )


def _delivered(*gateways: str) -> pytest.MarkDecorator:
    return pytest.mark.parametrize(
        "delivered", [lambda raw: raw, *map(_through, gateways)], ids=["as-sent", *gateways]
    )


_DELIVERED = _delivered(*_GATEWAYS)
#: Mimecast keeps only the domain, so a brand name in the path is out of sight behind it.
_WHOLE_LINK = _delivered(*(g for g in _GATEWAYS if g != "mimecast"))


@_DELIVERED
def test_brand_credential_phish_is_high(delivered: Callable[[bytes], bytes]) -> None:
    assessment = _assess(delivered(CREDENTIAL_PHISH))
    assert _tier(assessment) is AlertTier.HIGH, assessment
    assert "Microsoft 365 Security" in assessment.title


@_DELIVERED
def test_brand_credential_phish_is_high_without_its_bare_ip_link(
    delivered: Callable[[bytes], bytes],
) -> None:
    """The brand-dressed link carries it alone: the attacker needs no IP link."""
    raw = CREDENTIAL_PHISH.replace(
        b'<p><a href="http://185.234.72.10/login.php">Mailbox settings</a></p>', b""
    )
    assert b"185.234" not in raw
    assert _tier(_assess(delivered(raw))) is AlertTier.HIGH


@_DELIVERED
def test_link_to_a_copy_of_the_senders_domain_is_flagged(
    delivered: Callable[[bytes], bytes],
) -> None:
    assessment = _assess(delivered(STATEMENT_PHISH))
    assert assessment is not None and assessment.is_alertable, assessment
    assert assessment.tier is AlertTier.MEDIUM
    assert "gemini-statement-portal.com" in assessment.title


def _statement(link: str, stamp: str = "") -> bytes:
    return (
        f"{stamp}From: \"Billing\" <billing@gemini.com>\nTo: finance@northwind-e2e.com\n"
        "Subject: Statement ready\nMessage-ID: <s-1@gemini.com>\n"
        f'Content-Type: text/html; charset=utf-8\n\n<a href="{link}">View statement</a>\n'
    ).encode()


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            _statement(
                "https://geminipay.com/pay",
                "Authentication-Results: mx.example; spf=fail smtp.mailfrom=gemini.com; "
                "dmarc=fail header.from=gemini.com\n",
            ),
            id="host-says-unverified-run-together-copy",
        ),
        pytest.param(_statement("https://gemіni.com/pay"), id="homoglyph-copy-no-stamp"),
    ],
)
def test_other_copies_of_the_senders_domain_are_flagged(raw: bytes) -> None:
    assessment = _assess(raw, SourceMechanism.IMAP_IDLE)
    assert assessment is not None and "B1" in assessment.services, assessment
    assert assessment.is_alertable


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(
            b'From: GitHub <noreply@github.com>\nTo: finance@northwind-e2e.com\n'
            b"Subject: [acme/app] comment\nMessage-ID: <g-1@github.com>\n"
            b"Content-Type: text/html; charset=utf-8\n\n<p>jane commented</p>"
            b'<a href="https://raw.githubusercontent.com/acme/app/main/x.txt">x.txt</a>\n',
            id="github-raw-link",
        ),
        pytest.param(
            b'From: "Microsoft" <no-reply@microsoft.com>\nTo: finance@northwind-e2e.com\n'
            b"Subject: Sign in\nMessage-ID: <m-1@microsoft.com>\n"
            b"Content-Type: text/html; charset=utf-8\n\n<p>Sign in to Microsoft 365.</p>"
            b'<a href="https://www.microsoft365.com/">Open</a>\n',
            id="microsoft365-link",
        ),
    ],
)
def test_a_host_that_stamps_nothing_spares_a_brands_own_family(raw: bytes) -> None:
    """No Authentication-Results at all: GitHub's and Microsoft's real mail look
    exactly as unverified as a spoof, so their run-together family domains stay out."""
    assessment = _assess(raw, SourceMechanism.IMAP_IDLE)
    assert assessment is None or not assessment.is_alertable, assessment


def test_a_verified_sender_linking_to_its_own_domain_family_is_quiet() -> None:
    """Microsoft's real mail links to microsoft365.com and microsoftonline.com.
    Once the host verifies the sender, a family domain is presumed theirs."""
    notice = b"""\
From: "Microsoft 365 Message center" <o365mc@microsoft.com>
To: finance@northwind-e2e.com
Subject: Sign in to review your Microsoft 365 renewal
Message-ID: <mc-1@microsoft.com>
Content-Type: text/html; charset=utf-8

<p>Sign in to the admin center to review your subscription.</p>
<a href="https://www.microsoft365.com/">Microsoft 365</a>
<a href="https://login.microsoftonline.com/">Sign in</a>
<a href="https://admin.microsoft.com/billing">Billing</a>
"""
    stamp = _GMAIL.format(d="microsoft.com").encode()
    for source in (SourceMechanism.GMAIL_API, SourceMechanism.IMAP_IDLE):
        assessment = _assess(b"Authentication-Results: " + stamp + b"\n" + notice, source)
        assert assessment is None or not assessment.is_alertable, (source, assessment)


def test_images_on_a_senders_cdn_domain_are_not_links() -> None:
    """GitHub mail shows avatars from githubusercontent.com. An image is not a
    link anyone follows, so it is not judged as one, verified sender or not."""
    raw = b"""\
From: GitHub <noreply@github.com>
To: finance@northwind-e2e.com
Subject: [acme/app] New comment
Message-ID: <c-1@github.com>
Content-Type: text/html; charset=utf-8

<img src="https://avatars.githubusercontent.com/u/1?s=60&v=4">
<p>jane commented on your pull request.</p>
<a href="https://github.com/acme/app/pull/1">View it on GitHub</a>
"""
    assert _assess(raw) is None


@pytest.mark.parametrize(
    "link",
    [
        pytest.param("https://admin.microsoft.com/", id="plain"),
        pytest.param(
            _SAFELINKS.format(quote("https://admin.microsoft.com/", safe="")), id="safe-links"
        ),
    ],
)
def test_partner_newsletter_naming_microsoft_is_not_high(link: str) -> None:
    """An IT partner's newsletter names Microsoft, asks readers to sign in and
    links to the real microsoft.com. Not one of its links is dressed as Microsoft."""
    raw = f"""\
From: "Acme IT | Microsoft 365 News" <news@acme-it.example>
To: finance@northwind-e2e.com
Subject: Turn on MFA this month
Message-ID: <n-1@acme-it.example>
Content-Type: text/plain

Sign in to the Microsoft 365 admin center and turn on MFA:
{link}
""".encode()
    assessment = _assess(raw)
    assert _tier(assessment) not in (AlertTier.HIGH, AlertTier.CRITICAL), assessment
    assert assessment is None or "A5" not in assessment.services


def test_benign_newsletter_from_the_e2e_run_is_quiet() -> None:
    """08-benign-newsletter.eml: makenotion.com linking to notion.so."""
    raw = b"""\
From: "Notion" <team@makenotion.com>
To: finance@northwind-e2e.com
Subject: What's new in Notion this month
Message-ID: <179412902605.5233.1050629092864099780@e2e.test>
Content-Type: text/plain; charset=utf-8

Here's a roundup of this month's product updates. Read more at https://www.notion.so/releases
"""
    assert _assess(raw) is None


#: How Exchange Online stamps mail it verified, above everything the sender wrote.
_EXCHANGE = (
    "Authentication-Results: spf=pass (sender IP is 203.0.113.5) smtp.mailfrom={d}; "
    "dkim=pass (signature was verified) header.d={d};dmarc=pass action=none "
    "header.from={d};compauth=pass reason=100\n"
)


def _known_vendor(domain: str) -> CounterpartyState:
    """A year of history: 30 messages, the last a week ago."""
    now = datetime.now(UTC)
    return CounterpartyState(
        registrable_domain=domain,
        first_seen_at=now - timedelta(days=365),
        last_seen_at=now - timedelta(days=7),
        message_count=30,
        known_dkim_domains=frozenset({domain}),
    )


def _vendor_invoice(link: str, prose: str, subject: str = "Invoice 4471") -> bytes:
    return (
        _EXCHANGE.format(d="acme-supplies.com")
        + 'From: "Acme Supplies Billing" <billing@acme-supplies.com>\n'
        + f"To: finance@northwind-e2e.com\nSubject: {subject}\n"
        "Message-ID: <inv-4471@acme-supplies.com>\nContent-Type: text/html; charset=utf-8\n\n"
        f'<p>{prose}</p><p><a href="{link}">View invoice 4471</a></p>\n'
        '<p><a href="https://www.linkedin.com/company/acme-supplies">Follow us</a></p>\n'
    ).encode()


def _on_microsoft_365(raw: bytes, vendor: str) -> RiskAssessment | None:
    return _assess(raw, SourceMechanism.GRAPH_API, _known_vendor(vendor))


@_DELIVERED
def test_a_known_vendors_invoice_on_microsoft_365_is_quiet(
    delivered: Callable[[bytes], bytes],
) -> None:
    """Safe Links moves the vendor's links onto outlook.com. That is Microsoft's own
    domain, not one "not owned by" Outlook, and the links inside it go to the
    vendor's portal and its LinkedIn page. Behind any gateway, the brand a wrapped
    link names is its destination's, and LinkedIn's page is LinkedIn's own."""
    raw = _vendor_invoice(
        "https://portal.acme-supplies.com/invoices/4471",
        "Invoice 4471 is attached; payment due in 30 days.",
    )
    assessment = _on_microsoft_365(delivered(raw), "acme-supplies.com")
    assert assessment is None or "B1" not in assessment.services, assessment


@_DELIVERED
def test_an_amazon_order_confirmation_is_quiet(delivered: Callable[[bytes], bytes]) -> None:
    """Amazon shows its pictures from m.media-amazon.com, a name that reads as
    dressed up as Amazon. A picture is not a link, and the order link is amazon.com."""
    raw = _EXCHANGE.format(d="amazon.com").encode() + b"""\
From: "Amazon.com" <auto-confirm@amazon.com>
To: finance@northwind-e2e.com
Subject: Your Amazon.com order #112-4471-0000001
Message-ID: <o-4471@amazon.com>
Content-Type: text/html; charset=utf-8

<img src="https://m.media-amazon.com/images/G/01/x-locale/cs/te/logo.png" alt="amazon">
<p>Thanks for your order. Order total: $42.17. Payment method: Visa ending in 4471.</p>
<a href="https://www.amazon.com/gp/css/order-details?orderID=112-4471-0000001">View order</a>
<img src="https://m.media-amazon.com/images/I/41abc.jpg" alt="USB-C cable">
"""
    assessment = _on_microsoft_365(delivered(raw), "amazon.com")
    assert assessment is None or "B1" not in assessment.services, assessment


@_WHOLE_LINK
@pytest.mark.parametrize(
    ("prose", "subject"),
    [
        pytest.param("Invoice 4471 is attached; payment due in 30 days.", "Invoice 4471",
                     id="payment"),
        pytest.param("Sign in to view your statement.", "Your account", id="sign-in"),
    ],
)
def test_a_brand_name_on_someone_elses_domain_still_alerts(
    delivered: Callable[[bytes], bytes], prose: str, subject: str
) -> None:
    """The same vendor and wording, linking to a page that names Microsoft on a
    domain that is neither Microsoft's nor the vendor's."""
    raw = _vendor_invoice("https://pay.example/microsoft/invoice", prose, subject)
    assessment = _on_microsoft_365(delivered(raw), "acme-supplies.com")
    assert assessment is not None and "B1" in assessment.services, assessment
    assert assessment.tier is AlertTier.MEDIUM, assessment
