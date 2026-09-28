"""Domain-control verification via DNS (PRD signup funnel).

A tenant must prove they control a domain before we connect a mailbox on it —
otherwise anyone could sign up with someone else's company address and start
receiving that company's fraud alerts (or map their coverage). Two proofs, both
standard:

* **TXT** — add `_envelock.<domain>  TXT  "envelock-verify=<token>"`.
* **CNAME** — point `_envelock.<domain>  CNAME  <token>.verify.envelock.org`.

The check is a live DNS resolution; nothing here trusts anything the client sends.
"""

from __future__ import annotations

import logging

from envelock.util.domains import registrable_domain

logger = logging.getLogger("envelock.dnsverify")

_TXT_PREFIX = "envelock-verify="
_VERIFY_HOST = "verify.envelock.org"

#: Queried directly rather than through whatever the host's /etc/resolv.conf
#: points at. Three independent operators, so one being slow or wrong does not
#: decide the answer.
_PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8", "9.9.9.9")

#: Per-resolver budget. The old single 8s lifetime meant one unreachable
#: resolver cost 8s for TXT and 8s again for CNAME — 16s before we could say
#: "not yet". Several short attempts beat one long one.
_LOOKUP_TIMEOUT = 2.5


def _authoritative_nameservers(domain: str) -> list[str]:
    """IPs of the domain's own nameservers.

    Asking them directly is the whole point: a recursive resolver that has
    already been asked for `_envelock.<domain>` caches the NXDOMAIN for the
    zone's negative TTL — often 5 to 60 minutes — so it keeps answering "not
    there" long after the customer has added the record. The authoritative
    servers have no such cache, so a record shows up the moment it is saved.
    """
    try:
        import dns.resolver

        reg = registrable_domain(domain) or domain
        probe = dns.resolver.Resolver(configure=False)
        probe.nameservers = list(_PUBLIC_RESOLVERS)
        probe.lifetime = _LOOKUP_TIMEOUT
        ips: list[str] = []
        for ns in probe.resolve(reg, "NS"):
            name = str(getattr(ns, "target", ns)).rstrip(".")
            try:
                ips.extend(str(a) for a in probe.resolve(name, "A"))
            except Exception as exc:  # noqa: BLE001 — one unresolvable NS is not fatal
                logger.debug("nameserver %s did not resolve: %s", name, exc)
                continue
            if len(ips) >= 3:  # three is plenty; don't walk a 10-NS delegation
                break
        return ips
    except Exception as exc:  # noqa: BLE001
        logger.debug("could not find authoritative nameservers for %s: %s", domain, exc)
        return []


def _resolver_chain(host: str) -> list:
    """Resolvers to try, in order: the zone's own nameservers (never stale),
    then the public recursives, then whatever the host is configured with."""
    import dns.resolver

    chain = []
    for ips in (_authoritative_nameservers(host), list(_PUBLIC_RESOLVERS)):
        if not ips:
            continue
        r = dns.resolver.Resolver(configure=False)
        r.nameservers = ips
        r.lifetime = _LOOKUP_TIMEOUT
        chain.append(r)
    try:
        system = dns.resolver.Resolver()  # reads /etc/resolv.conf
        system.lifetime = _LOOKUP_TIMEOUT
        chain.append(system)
    except Exception as exc:  # noqa: BLE001 — a host with no resolv.conf still has the above
        logger.debug("no system resolver available: %s", exc)
    return chain


def _rdata_values(answers, rdtype: str) -> list[str]:
    out: list[str] = []
    for rdata in answers:
        if rdtype == "TXT":
            # TXT rdata is one or more quoted chunks; join them.
            out.append(b"".join(rdata.strings).decode("utf-8", "ignore"))
        elif hasattr(rdata, "target"):
            out.append(str(rdata.target).rstrip("."))
        else:
            out.append(str(rdata))
    return out


def txt_record_value(token: str) -> str:
    return f"{_TXT_PREFIX}{token}"


def challenge_host(domain: str) -> str:
    return f"_envelock.{registrable_domain(domain) or domain}"


def cname_target(token: str) -> str:
    return f"{token}.{_VERIFY_HOST}"


def _resolve(host: str, rdtype: str) -> list[str]:
    """Resolve a DNS record. Returns [] on any failure (NXDOMAIN, timeout, no
    resolver) rather than raising — an unverifiable domain is simply not verified."""
    return _resolve_status(host, rdtype)[1]


def verify_txt(domain: str, token: str) -> bool:
    want = txt_record_value(token)
    host = challenge_host(domain)
    return any(want == v.strip().strip('"') for v in _resolve(host, "TXT"))


def verify_cname(domain: str, token: str) -> bool:
    want = cname_target(token).lower()
    host = challenge_host(domain)
    return any(v.lower().rstrip(".") == want for v in _resolve(host, "CNAME"))


def verify(domain: str, token: str, *, method: str = "txt") -> bool:
    """Confirm the tenant controls `domain`. Accepts either proof regardless of the
    stated method, so a customer who added the wrong record type still passes."""
    if not token:
        return False
    return verify_txt(domain, token) or verify_cname(domain, token)


def _resolve_status(host: str, rdtype: str) -> tuple[str, list[str]]:
    """Like `_resolve`, but tells apart a DEFINITIVE 'the record is not there'
    (NXDOMAIN / NoAnswer from a working resolver) from a TRANSIENT failure
    (timeout, no resolver, network down). Returns ('ok'|'absent'|'unknown', values).

    This distinction is the whole safety of re-verification: a transient DNS blip
    must never be read as 'the customer deleted their record' and used to revoke.

    Walks `_resolver_chain`: the first resolver that returns records wins, so the
    usual path is one fast authoritative answer. A definitive 'not there' is only
    reported once a resolver has said so without any other resolver contradicting
    it — a timeout never downgrades to 'absent'."""
    conclusive = False
    for resolver in _resolver_chain(host):
        try:
            answers = resolver.resolve(host, rdtype)
        except Exception as exc:  # noqa: BLE001
            name = type(exc).__name__
            # NXDOMAIN (no such name) and NoAnswer (name exists, no such record)
            # are authoritative "it's not there". Everything else — Timeout,
            # NoNameservers, a missing dnspython — is inconclusive and must NOT
            # trigger revocation, so keep trying the rest of the chain.
            if name in {"NXDOMAIN", "NoAnswer"}:
                conclusive = True
            else:
                logger.debug("dns %s/%s via %r inconclusive: %s", host, rdtype, resolver, exc)
            continue
        values = _rdata_values(answers, rdtype)
        if values:
            return ("ok", values)
        conclusive = True
    return ("absent", []) if conclusive else ("unknown", [])


def verification_status(domain: str, token: str, *, method: str = "txt") -> str:
    """Tri-state control check for the re-verification job: 'present' (a matching
    record is live), 'absent' (a working resolver says no matching record exists),
    or 'unknown' (couldn't determine — never revoke on this).

    'absent' requires BOTH proofs to resolve definitively without a match, so a
    single transient lookup keeps the domain verified until we can actually tell."""
    if not token:
        return "unknown"
    want_txt = txt_record_value(token)
    want_cname = cname_target(token).lower()
    host = challenge_host(domain)

    txt_status, txt_vals = _resolve_status(host, "TXT")
    if any(want_txt == v.strip().strip('"') for v in txt_vals):
        return "present"
    cname_status, cname_vals = _resolve_status(host, "CNAME")
    if any(v.lower().rstrip(".") == want_cname for v in cname_vals):
        return "present"

    # No match found. Only call it a real deletion if BOTH lookups were conclusive.
    if txt_status in {"ok", "absent"} and cname_status in {"ok", "absent"}:
        return "absent"
    return "unknown"


def deliverability_status(domain: str) -> str:
    """Whether an email domain plausibly EXISTS and can receive mail:
    'ok' (has MX, or an A/AAAA host mail can fall back to), 'absent' (a working
    resolver says the domain / its records don't exist — a typo like
    `test@hjsbcjsjs.com`), or 'unknown' (couldn't determine — never block on this).

    Used at registration to reject made-up domains before ownership verification.
    Fails OPEN: a transient DNS hiccup returns 'unknown' so real signups aren't
    blocked by our own resolver being briefly unreachable."""
    reg = registrable_domain(domain) or domain
    if not reg:
        return "unknown"
    hosts = list(dict.fromkeys(h for h in (domain, reg) if h))  # dedupe, keep order
    statuses: list[str] = []
    for host in hosts:
        for rdtype in ("MX", "A", "AAAA"):
            status, vals = _resolve_status(host, rdtype)
            if vals:
                return "ok"
            statuses.append(status)
    # Only 'absent' when every lookup was conclusive (NXDOMAIN/NoAnswer), never on
    # a timeout/resolver failure.
    return "absent" if all(s in {"ok", "absent"} for s in statuses) else "unknown"


__all__ = [
    "challenge_host",
    "cname_target",
    "deliverability_status",
    "txt_record_value",
    "verification_status",
    "verify",
    "verify_cname",
    "verify_txt",
]
