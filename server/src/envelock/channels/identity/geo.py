"""Where a sign-in came from — the missing input for C7, C9 and C14.

Three detections were written correctly and could never fire, because nothing
ever put a latitude on a session. `build_context` hardcoded `latitude=None`, so
the haversine in C7 (impossible travel) always short-circuited, C14
(counterparty travel) with it, and C9 could not classify a VPN exit it had no
network facts about. This module is that input.

Design notes:

* **Failure is silent and safe.** A lookup that times out or is not configured
  returns an empty `GeoFacts`, which lands the detections back exactly where they
  were — off — rather than raising inside an ingest path.
* **Results are cached in-process.** A sensor heartbeat fires far more often than
  a person changes network, and the free tiers of every provider are rate
  limited. The cache is bounded so a long-running worker cannot grow without end.
* **Private and reserved addresses are never sent to a third party.** A LAN
  address carries no location and leaking a customer's internal addressing to an
  IP-intelligence vendor would be a needless disclosure.
* **VPN-ness is a signal, not a defeat.** We record that an address belongs to a
  VPN, proxy, hosting range or Tor exit and let C9 say so; we never pretend to
  see through it (PRD §7.2).
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

logger = logging.getLogger("envelock.geo")

@dataclass(frozen=True, slots=True)
class GeoFacts:
    """What we could learn about an address. All fields optional by design —
    a partial answer is still useful, and an empty one is not an error."""

    ip: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    asn_name: str | None = None
    is_vpn: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_tor: bool = False

    @property
    def located(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    @property
    def anonymised(self) -> bool:
        """Behind something that hides the real origin. C9's whole subject."""
        return self.is_vpn or self.is_proxy or self.is_tor


#: Bounded so a worker that runs for weeks cannot grow without limit. Small: the
#: working set is "the addresses this tenant's people are signing in from".
_CACHE_MAX = 4096
_cache: dict[str, GeoFacts] = {}


EMPTY = GeoFacts()


def is_public_ip(value: str | None) -> bool:
    """Whether this address is worth (and safe) sending to a lookup service."""
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value.strip().split("%")[0])
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _remember(ip: str, facts: GeoFacts) -> GeoFacts:
    if len(_cache) >= _CACHE_MAX:
        # Cheap eviction: drop the oldest insertion. A true LRU is not worth the
        # bookkeeping for a cache this small and this tolerant of a miss.
        _cache.pop(next(iter(_cache)), None)
    _cache[ip] = facts
    return facts


def reset_cache() -> None:
    """Test hook — the cache is process-global."""
    _cache.clear()


def _parse_ipinfo(ip: str, body: dict) -> GeoFacts:
    """ipinfo.io's shape. `loc` is "lat,lng"; `org` is "AS15169 Google LLC".

    Privacy flags only exist on paid plans; their absence must not be read as
    "definitely not a VPN", which is why they default to False and C9 treats a
    False as "no evidence" rather than "clean".
    """
    latitude = longitude = None
    loc = body.get("loc")
    if isinstance(loc, str) and "," in loc:
        try:
            lat_text, lon_text = loc.split(",", 1)
            latitude, longitude = float(lat_text), float(lon_text)
        except ValueError:
            latitude = longitude = None

    asn = None
    asn_name = None
    org = body.get("org")
    if isinstance(org, str) and org.startswith("AS"):
        head, _, rest = org.partition(" ")
        try:
            asn = int(head[2:])
        except ValueError:
            asn = None
        asn_name = rest or None
    elif isinstance(org, str):
        asn_name = org

    privacy = body.get("privacy") or {}
    return GeoFacts(
        ip=ip,
        country=(body.get("country") or None),
        city=(body.get("city") or None),
        latitude=latitude,
        longitude=longitude,
        asn=asn,
        asn_name=asn_name,
        is_vpn=bool(privacy.get("vpn")),
        is_proxy=bool(privacy.get("proxy")),
        is_hosting=bool(privacy.get("hosting")),
        is_tor=bool(privacy.get("tor")),
    )


async def lookup(
    ip: str | None,
    *,
    timeout: float = 3.0,  # noqa: ASYNC109 — an HTTP client budget, not a task deadline
) -> GeoFacts:
    """Locate `ip`. Never raises; returns `EMPTY` when it cannot answer.

    The timeout is deliberately short: this runs inside a sensor heartbeat, and a
    slow intelligence provider must degrade the detection, never the request.
    """
    if not is_public_ip(ip):
        return EMPTY
    assert ip is not None
    ip = ip.strip()

    cached = _cache.get(ip)
    if cached is not None:
        return cached

    from envelock.config import get_settings

    token = get_settings().ipinfo_token
    if token is None or not token.get_secret_value():
        # Not configured. Cache the miss so an unconfigured deployment does not
        # re-check the setting on every heartbeat.
        return _remember(ip, EMPTY)

    try:
        import httpx

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(
                f"https://ipinfo.io/{ip}/json",
                headers={"Authorization": f"Bearer {token.get_secret_value()}"},
            )
        if response.status_code != 200:
            logger.debug("geo lookup for %s returned %s", ip, response.status_code)
            return _remember(ip, EMPTY)
        facts = _parse_ipinfo(ip, response.json())
    except Exception as exc:  # noqa: BLE001 — a location is never worth an exception here
        logger.debug("geo lookup for %s failed: %s", ip, exc)
        return _remember(ip, EMPTY)

    return _remember(ip, facts)


__all__ = ["EMPTY", "GeoFacts", "is_public_ip", "lookup", "reset_cache"]
