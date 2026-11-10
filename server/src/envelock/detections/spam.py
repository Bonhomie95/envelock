"""Spam: mail nobody asked for, scored on every inbound message from outside.

Gmail and Microsoft filter spam; a small or private host often does not, so this
runs on every mailbox whatever its provider. Two filters beat none. A spam
verdict never raises an alert, which would bury the alerts that matter: the
pipeline moves the message to the mailbox's own Junk folder, which every mail
client already knows how to show. The fraud checks judge the same message as
before, so a scam that is also spam still alerts.

Scored like a small SpamAssassin: each sign adds weight and JUNK_AT or more is
spam. Content alone gets there only on several distinct phrases of one family
(two for extortion, three for the other scams, never for a sales pitch or an
account lure), so one unlucky sentence in real mail does not move it; a
blocklisted server plus one more sign does. Newsletter software's mail
(`MailEvent.bulk`) is spared the signs of marketing style, which real newsletters
share with spam. Who the sender is (a correspondent, a supplier, someone the
customer rescued from Junk) is the pipeline's call, not this module's.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from envelock.core.enums import AuthResult
from envelock.detections.base import DetectionContext, FindingResult
from envelock.detections.content import _SHORTENERS, _host_of
from envelock.detections.impersonation import _strip_tags
from envelock.util.domains import is_free_mail, registrable_domain
from envelock.util.payments import normalise_text

JUNK_AT = 5.0


@dataclass(frozen=True, slots=True)
class SpamVerdict:
    score: float
    #: Codes, not prose: stored on the message so "why was this junked?" has an
    #: answer, and never any of the message's own words (E13).
    reasons: tuple[str, ...]

    @property
    def is_spam(self) -> bool:
        return self.score >= JUNK_AT


def _rx(*alternatives: str) -> re.Pattern[str]:
    return re.compile(r"\b(?:" + "|".join(alternatives) + r")\b", re.IGNORECASE)


_NUM = r"(?:\d+(?:[.,]\d+)?|one|two|three|four|five|six|seven|eight|nine|ten|fifteen|twenty|fifty)"

#: (code, phrases, first hit, each further distinct phrase, cap)
_FAMILIES: tuple[tuple[str, re.Pattern[str], float, float, float], ...] = (
    (
        "advance_fee",
        _rx(
            r"next\s+of\s+kin",
            r"(?:unclaimed|dormant|abandoned)\s+(?:funds?|account|deposit|inheritance|consignment|sum)",
            r"inheritance\s+(?:funds?|claim|transfer|sum)",
            r"compensation\s+funds?",
            r"consignment\s+box",
            r"diplomatic\s+(?:agent|courier|bag)",
            r"atm\s+(?:master\s*)?card\s+(?:payment|delivery|worth|valued|containing)",
            r"(?:won|winner\s+of|winning)\s+(?:the\s+|a\s+|our\s+)?(?:[\w-]+\s+){0,3}?"
            r"(?:lottery|lotto|sweepstakes?|jackpot|cash\s+prize|grand\s+prize)",
            r"lottery\s+(?:board|commission|winner|award|program(?:me)?|claims?)",
            r"claim\s+(?:your|the)\s+(?:prize|winnings|jackpot|inheritance|funds?|compensation)",
            r"(?:dear|attention)\W+(?:beneficiary|lucky\s+winner|winner)",
            r"(?:my|our)\s+late\s+(?:client|husband|father|wife|customer|brother)",
            rf"{_NUM}\s+million\s+(?:united\s+states\s+|us\s+)?(?:dollars|usd|pounds|euros)",
            r"percentage\s+of\s+(?:the|this)\s+(?:sum|funds?|money|total)",
        ),
        3.0, 1.0, 5.0,
    ),
    (
        "extortion",
        _rx(
            r"(?:i|we)\s+(?:have\s+)?(?:hacked|infected|compromised|gained\s+(?:full\s+)?access\s+to)\s+"
            r"(?:your|ur)\s+(?:device|computer|phone|account|e-?mail|system|operating\s+system|webcam|camera)",
            r"(?:recorded|captured|filmed)\s+(?:you|a\s+video\s+of\s+you|your\s+screen)",
            r"(?:adult|porn(?:ographic)?|xxx)\s+(?:sites?|websites?|videos?|content|material)",
            r"(?:send|share|forward|release|leak)\s+(?:it|the\s+video|the\s+recording|this\s+video|"
            r"the\s+(?:photos?|pictures?))\s+to\s+(?:all\s+)?(?:of\s+)?(?:your\s+)?"
            r"(?:contacts|friends|family|colleagues)",
            r"i\s+know\s+(?:your|ur)\s+password",
        ),
        3.5, 1.5, 5.5,
    ),
    (
        "pharma_adult",
        _rx(
            r"viagra", r"cialis", r"levitra", r"sildenafil", r"tadalafil",
            r"online\s+pharmacy", r"male\s+enhancement", r"penis\s+enlargement",
            r"(?:diet|weight\s+loss|slimming)\s+pills",
            r"lose\s+\d+\s*(?:lbs|pounds|kg|kilos)\s+in\s+\d+\s+(?:days|weeks)",
            r"hot\s+singles", r"lonely\s+(?:wives|women|housewives)",
            r"(?:sexy|horny)\s+(?:girls|singles|women)",
            r"casino\s+bonus", r"free\s+spins", r"online\s+casino",
        ),
        3.0, 1.0, 5.0,
    ),
    (
        "crypto_scheme",
        _rx(
            r"double\s+your\s+(?:money|bitcoin|btc|investment|crypto|income)",
            r"guaranteed\s+(?:returns?|profits?|income|roi)",
            r"\d{1,3}\s?%\s+(?:daily|weekly|monthly)\s+(?:returns?|profits?|roi|interest|income)",
            r"risk[\s-]free\s+(?:investment|returns?|profits?|trading)",
            r"(?:trading|crypto|forex)\s+(?:bot|signals|account\s+manager)",
            r"binary\s+options",
            r"(?:crypto(?:currency)?|bitcoin)\s+(?:investment|mining)\s+(?:platform|opportunity|plan)",
        ),
        3.0, 1.0, 5.0,
    ),
    (
        "sales_pitch",
        _rx(
            r"(?:first|1st|top)\s+page\s+(?:of|on)\s+google",
            r"(?:seo|search\s+engine\s+optimi[sz]ation)\s+(?:services?|experts?|packages?|audit|"
            r"ranking|agency|company)",
            r"rank(?:ing)?\s+(?:your|ur)\s+(?:website|site|business)",
            r"(?:website|web)\s+(?:re-?design|design|development)\s+services?",
            r"(?:boost|increase|improve|double)\s+(?:your\s+)?(?:website\s+|online\s+)?"
            r"(?:traffic|rankings?|sales|leads)",
            r"lead\s+generation\s+(?:services?|campaigns?|agency)",
            r"(?:guest|sponsored)\s+posts?",
            r"backlinks?",
            r"(?:e-?mail|contact|attendees?|buyers?|mailing|decision[\s-]makers?)\s+lists?\s+"
            r"(?:of|for|available|purchase|includes?)",
            r"(?:i|we)\s+(?:came\s+across|noticed|was\s+checking|were\s+checking|visited|went\s+through)\s+"
            r"(?:your|ur)\s+(?:website|site|business|company|profile|page)",
            r"(?:mobile\s+app|app|software|website)\s+development\s+(?:services?|company|agency|team)",
            r"virtual\s+assistant\s+services?",
            r"(?:reply|respond)\s+(?:with\s+)?\W?(?:no|stop|unsubscribe|remove|not\s+interested)\W?\s+"
            r"(?:to|if)",
        ),
        2.0, 1.0, 4.0,
    ),
    (
        "account_lure",
        _rx(
            r"(?:mailbox|e-?mail\s+account|inbox)\s+(?:is\s+(?:almost\s+)?full|quota|"
            r"storage\s+(?:is\s+)?full|has\s+exceeded)",
            r"(?:account|mailbox|e-?mail)\s+(?:will\s+be\s+|has\s+been\s+)?"
            r"(?:suspended|deactivated|terminated|closed|disabled)",
            r"verify\s+your\s+(?:account|e-?mail|mailbox|identity)",
            r"password\s+(?:will\s+)?(?:expires?|expir(?:y|ation))",
            r"(?:pending|undelivered|held|blocked)\s+(?:incoming\s+)?(?:messages|e-?mails)",
            r"(?:package|parcel|shipment)\s+(?:could\s+not|couldn'?t|cannot|can'?t)\s+be\s+delivered",
            r"(?:re-?)?confirm\s+your\s+(?:billing|payment)\s+(?:details|information)",
        ),
        2.0, 1.0, 3.5,
    ),
)

_RE_SUBJECT = re.compile(r"^\s*re\s*:", re.IGNORECASE)
#: An address in a Received header's `from` part: `[1.2.3.4]`, `(1.2.3.4)`, `[IPv6:…]`.
_RCVD_IP = re.compile(r"[\[(](?:ipv6:)?([0-9a-f:.]{7,45})[\])]", re.IGNORECASE)


def connecting_ip(received: tuple[str, ...]) -> str | None:
    """The public address that handed the message to the mailbox's host.

    Received headers are added top-down as the message travels, so the first
    public address from the top sits in a header the receiving host wrote. The
    sender can forge only the headers below it, which are never read.
    """
    for header in received[:6]:
        sent_from = re.split(r"\bby\b", header, maxsplit=1, flags=re.IGNORECASE)[0]
        for candidate in _RCVD_IP.findall(sent_from):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                return str(ip)
    return None


def _shouting(subject: str) -> bool:
    letters = [c for c in subject if c.isalpha()]
    caps = len(letters) >= 12 and sum(c.isupper() for c in letters) >= 0.75 * len(letters)
    return caps or "!!" in subject or "$$" in subject


def score_spam(ctx: DetectionContext, findings: list[FindingResult]) -> SpamVerdict:
    mail = ctx.mail
    if mail is None:
        return SpamVerdict(0.0, ())
    score = 0.0
    reasons: list[str] = []

    def add(code: str, weight: float) -> None:
        nonlocal score
        score += weight
        reasons.append(code)

    services = {f.service for f in findings}
    sender = registrable_domain(mail.sender.domain)
    free_sender = is_free_mail(sender)
    auth = mail.authentication

    if ctx.sending_ip_listed:
        add("ip_listed", 4.0)
    if mail.upstream_spam:
        add("upstream_spam", 3.5)
    if "B7" in services:
        add("sender_listed", 5.0)
    if any(registrable_domain(_host_of(u)) in ctx.malicious_domains for u in mail.urls):
        add("link_listed", 3.0)
    if auth.dmarc is AuthResult.FAIL:
        add("dmarc_fail", 2.5)
    if auth.spf is AuthResult.FAIL:
        add("spf_fail", 1.5)
    elif auth.spf is AuthResult.SOFTFAIL:
        add("spf_softfail", 0.5)
    if auth.dkim is AuthResult.FAIL:
        add("dkim_fail", 1.0)
    age = ctx.sender_domain_age_days
    if age is not None and not free_sender:
        if age <= 7:
            add("new_domain", 2.5)
        elif age <= 30:
            add("new_domain", 1.5)

    subject = mail.subject or ""
    visible = mail.body_text or _strip_tags(mail.body_html or "")
    text = normalise_text(f"{subject}\n{visible}")
    styled = not mail.bulk  # marketing style counts only outside newsletter software
    pitched = False
    for code, pattern, first, more, cap in _FAMILIES:
        if code == "sales_pitch" and not styled:
            continue
        hits = {m.group(0).lower() for m in pattern.finditer(text)}
        if hits:
            add(code, min(first + more * (len(hits) - 1), cap))
            pitched = pitched or code == "sales_pitch"
    if pitched and free_sender:
        add("webmail_pitch", 1.0)
    if reply_to := mail.reply_to:
        theirs = registrable_domain(reply_to.domain)
        if theirs and theirs != sender and is_free_mail(theirs):
            add("reply_to_webmail", 2.0)

    if styled and _shouting(subject):
        add("shouting", 1.0)
    if _RE_SUBJECT.match(subject) and not mail.in_reply_to and not mail.references:
        add("fake_reply", 1.0)
    if not mail.recipients_to and not mail.recipients_cc:
        add("undisclosed", 1.0)
    if styled and mail.body_html and "<img" in mail.body_html.lower() and len(visible.strip()) < 40:
        add("image_only", 1.5)
    if styled and any(_host_of(u) in _SHORTENERS for u in mail.urls):
        add("shortener", 1.0)

    return SpamVerdict(round(score, 1), tuple(reasons))


__all__ = ["JUNK_AT", "SpamVerdict", "connecting_ip", "score_spam"]
