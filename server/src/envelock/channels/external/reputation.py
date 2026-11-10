"""Sender-domain reputation via free feeds (user requirement #3).

When mail arrives, we check the FROM domain against public blocklists so a domain
already known for phishing/spam is flagged even before our own cross-tenant graph
has seen it. Everything here is free and needs no API key:

* **DNSBL domain lists** — Spamhaus DBL and SURBL answer a normal DNS query:
  `<domain>.dbl.spamhaus.org` resolving to `127.0.1.x` means listed. (Spamhaus DBL
  is free for low-volume/non-commercial use — audit the terms before high volume,
  per the README licensing note.)
* **DNSBL IP lists** — Spamhaus ZEN and SpamCop, for the server that handed the
  message to the mailbox's host (`detections/spam.py`). Same terms note.
* **Google Safe Browsing** — used for URLs elsewhere; if a key is set we also check
  the domain's root URL here.

Results are cached briefly so a burst of mail from one sender is one lookup, and
every failure mode (no resolver, timeout, NXDOMAIN) resolves to "not listed"
rather than raising.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field

from envelock.config import get_settings
from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.reputation")

#: Answers that mean the list refused to answer, never a listing: Spamhaus's
#: 127.255.255.x, and SURBL's and URIBL's 127.0.0.1 ("your queries are blocked").
#: Read as listings, a list that blocked this server would call EVERY sender bad.
_REFUSALS = {
    "127.255.255.252": "does not know this zone name",
    "127.255.255.254": "refuses queries sent through a public DNS resolver",
    "127.255.255.255": "refuses this server: too many queries",
    "127.0.0.1": "blocks queries from this server",
}
#: When each zone's refusal was last logged, so a refusing list is one warning an
#: hour, not one per message.
_WARNED: dict[str, float] = {}


def _refusal(code: str) -> bool:
    return code.startswith("127.255.") or code in _REFUSALS


def _meaning(code: str) -> str:
    return _REFUSALS.get(code, f"refused the query ({code})")


def _query_zone(zone: str) -> str:
    """Where a zone is asked. With a Spamhaus DQS key, a Spamhaus zone is asked of
    DQS (`<key>.zen.dq.spamhaus.net`). Results still name the public zone, so the
    key never reaches a log line or a customer's screen."""
    key = get_settings().spamhaus_dqs_key.get_secret_value().strip()
    if key and zone.endswith(".spamhaus.org"):
        return f"{key}.{zone.removesuffix('.spamhaus.org')}.dq.spamhaus.net"
    return zone


def _answers(name: str, *, lifetime: float = 5.0) -> list[str]:
    """The A records for a DNSBL query; none for NXDOMAIN (not listed), a timeout
    or no resolver."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = lifetime
        return [str(rdata) for rdata in resolver.resolve(name, "A")]
    except Exception:  # noqa: BLE001 — every failure mode is "not listed"
        return []


def _warn_refused(zone: str, code: str) -> None:
    now = time.monotonic()
    if now - _WARNED.get(zone, -3600.0) < 3600:
        return
    _WARNED[zone] = now
    fix = " — set ENVELOCK_SPAMHAUS_DQS_KEY" if zone.endswith(".spamhaus.org") else ""
    logger.warning("dnsbl %s %s; its answers are ignored%s", zone, _meaning(code), fix)


@dataclass(frozen=True, slots=True)
class ReputationResult:
    domain: str
    listed: bool
    sources: tuple[str, ...] = ()
    codes: tuple[str, ...] = ()


@dataclass
class _CacheEntry:
    result: ReputationResult
    at: float


@dataclass
class DomainReputation:
    """Cached DNSBL reputation checker. One instance is shared process-wide."""

    _cache: dict[str, _CacheEntry] = field(default_factory=dict)

    def _cached(self, reg: str) -> ReputationResult | None:
        entry = self._cache.get(reg)
        if entry is None:
            return None
        ttl = get_settings().reputation_cache_seconds
        if (time.monotonic() - entry.at) > ttl:
            self._cache.pop(reg, None)
            return None
        return entry.result

    def _dnsbl_listed(self, reg: str, zone: str) -> str | None:
        """Return the return-code (127.0.1.x) if `reg` is listed in `zone`, else
        None. A listing is any answer in 127.0.0.0/8 that is not a refusal."""
        codes = _answers(f"{reg}.{_query_zone(zone)}")
        listed = [c for c in codes if c.startswith("127.") and not _refusal(c)]
        if not listed and (refused := next((c for c in codes if _refusal(c)), None)):
            _warn_refused(zone, refused)
        return listed[0] if listed else None

    def check(self, domain: str) -> ReputationResult:
        reg = registrable_domain(domain)
        if not reg:
            return ReputationResult(domain=domain, listed=False)
        return self._lookup(reg, reg, reg, get_settings().dnsbl_domain_zone_list)

    def check_ip(self, ip: str) -> ReputationResult:
        """The same for a sending server: `4.3.2.1.zen.spamhaus.org` for 1.2.3.4,
        and an IPv6 address's reversed nibbles (ZEN lists both; SpamCop only IPv4,
        and answers an IPv6 query "not listed")."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return ReputationResult(domain=ip, listed=False)
        query = addr.reverse_pointer.rsplit(".", 2)[0]  # drop in-addr.arpa / ip6.arpa
        return self._lookup(f"ip:{addr}", str(addr), query, get_settings().dnsbl_ip_zone_list)

    def _lookup(self, key: str, label: str, query: str, zones: list[str]) -> ReputationResult:
        cached = self._cached(key)
        if cached is not None:
            return cached
        sources: list[str] = []
        codes: list[str] = []
        if get_settings().domain_reputation_enabled:
            for zone in zones:
                code = self._dnsbl_listed(query, zone)
                if code:
                    sources.append(zone)
                    codes.append(code)
        result = ReputationResult(
            domain=label, listed=bool(sources), sources=tuple(sources), codes=tuple(codes)
        )
        self._cache[key] = _CacheEntry(result=result, at=time.monotonic())
        return result


#: Process-wide singleton so the cache is shared across requests.
REPUTATION = DomainReputation()


async def check_sender_domain(domain: str) -> ReputationResult:
    """Async wrapper — the DNS lookups are blocking, so run them off the loop."""
    import asyncio

    return await asyncio.to_thread(REPUTATION.check, domain)


async def check_sending_ip(ip: str) -> ReputationResult:
    """`check_sender_domain` for the server that delivered the message."""
    import asyncio

    return await asyncio.to_thread(REPUTATION.check_ip, ip)


def probe() -> tuple[bool, str]:
    """Whether each IP blocklist answers this server, asked for its test entry
    127.0.0.2 (RFC 5782: listed on every one). For the ops status page: a list that
    refuses is otherwise silent, the filter just quietly losing its best sign."""
    settings = get_settings()
    if not settings.domain_reputation_enabled:
        return True, "off (ENVELOCK_DOMAIN_REPUTATION_ENABLED=false)"
    ok = True
    parts: list[str] = []
    for zone in settings.dnsbl_ip_zone_list:
        codes = _answers(f"2.0.0.127.{_query_zone(zone)}", lifetime=1.5)
        if any(c.startswith("127.") and not _refusal(c) for c in codes):
            parts.append(f"{zone}: answering")
            continue
        ok = False
        parts.append(f"{zone}: {_meaning(codes[0]) if codes else 'no answer'}")
    key = settings.spamhaus_dqs_key.get_secret_value().strip()
    parts.append("Spamhaus DQS key set" if key else "no Spamhaus DQS key")
    return ok, " · ".join(parts)


async def probe_blocklists() -> tuple[bool, str]:
    import asyncio

    return await asyncio.to_thread(probe)


__all__ = [
    "DomainReputation",
    "REPUTATION",
    "ReputationResult",
    "check_sender_domain",
    "check_sending_ip",
    "probe",
    "probe_blocklists",
]
