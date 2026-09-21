"""Attachment and URL cascades — free layers first, metered last (PRD §12.12).

The fall-through rate is the single number that predicts COGS, so it is metered
at every layer rather than inferred.
"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum

from envelock.config import get_settings

logger = logging.getLogger("envelock.cascade")


class Layer(IntEnum):
    CACHE = 0
    STATIC = 1
    REPUTATION = 2
    DETONATION = 3


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CascadeResult:
    sha256: str
    verdict: Verdict
    layer: Layer
    reasons: tuple[str, ...] = ()
    cost_micros: int = 0

    @property
    def reached_paid_layer(self) -> bool:
        return self.layer >= Layer.REPUTATION


@dataclass
class CascadeMetrics:
    seen: int = 0
    cache_hits: int = 0
    static_resolved: int = 0
    reputation_calls: int = 0
    detonations: int = 0
    cost_micros: int = 0

    @property
    def fallthrough_rate(self) -> float:
        """Target < 5% (PRD §15.4)."""
        return self.detonations / self.seen if self.seen else 0.0

    def payload(self) -> dict:
        return {
            "attachments_seen": self.seen,
            "cache_hits": self.cache_hits,
            "static_resolved": self.static_resolved,
            "reputation_calls": self.reputation_calls,
            "detonations": self.detonations,
            "fallthrough_rate": round(self.fallthrough_rate, 4),
            "target": 0.05,
            "within_target": self.fallthrough_rate <= 0.05,
            "external_cost_micros": self.cost_micros,
        }


#: Entries kept before the oldest are evicted. Sized so the working set of a busy
#: tenant fits comfortably while the map stays a few megabytes: this lives in a
#: long-running process that is not restarted for weeks.
MAX_CACHE_ENTRIES = 50_000


class VerdictCache:
    """Layer 0. Shared across tenants and keyed only by hash, so it holds no
    customer data. Clean verdicts expire because clean-today can be
    flagged-tomorrow; malicious verdicts do not expire.

    Bounded, LRU, and that matters: this was a plain dict with expiry only on
    *read*. Malicious entries never expired and nothing was ever evicted, so the
    map only ever grew for the life of the process — an unbounded allocation in
    the one process that also serves every customer request. An
    `OrderedDict` gives eviction in the same lookup that already happens.
    """

    def __init__(
        self, *, clean_ttl_days: int | None = None, max_entries: int = MAX_CACHE_ENTRIES
    ) -> None:
        self._ttl = timedelta(
            days=clean_ttl_days or get_settings().attachment_cache_ttl_clean_days
        )
        self._max = max_entries
        self._entries: OrderedDict[str, tuple[Verdict, datetime]] = OrderedDict()

    def get(self, sha256: str, *, now: datetime | None = None) -> Verdict | None:
        entry = self._entries.get(sha256)
        if entry is None:
            return None
        verdict, stored_at = entry
        if verdict is Verdict.MALICIOUS:
            self._entries.move_to_end(sha256)
            return verdict
        if (now or datetime.now(UTC)) - stored_at > self._ttl:
            del self._entries[sha256]
            return None
        self._entries.move_to_end(sha256)
        return verdict

    def put(self, sha256: str, verdict: Verdict, *, now: datetime | None = None) -> None:
        self._entries[sha256] = (verdict, now or datetime.now(UTC))
        self._entries.move_to_end(sha256)
        # Evict least-recently-used. A malicious verdict can be evicted like any
        # other: losing it costs one re-check at the next layer, whereas an
        # unbounded map costs the process.
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


# ── Layer 1: static triage, free and self-hosted ─────────────────────────────
_EXECUTABLE_MAGIC = {
    b"MZ": "Windows executable",
    b"\x7fELF": "Linux executable",
    b"\xca\xfe\xba\xbe": "Mach-O executable",
}
_RISKY_EXT = (
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".wsf", ".hta", ".lnk", ".iso", ".img", ".vhd", ".ps1", ".msi", ".one",
)
_MACRO_MAGIC = b"\xd0\xcf\x11\xe0"
_PDF_ACTIONS = (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/EmbeddedFile")


@dataclass(frozen=True, slots=True)
class StaticVerdict:
    verdict: Verdict
    reasons: tuple[str, ...]


def static_triage(
    *, filename: str, payload: bytes, declared_mime: str | None = None
) -> StaticVerdict:
    """YARA and ClamAV plug in here; these checks need no dependency at all and
    already resolve the common cases."""
    name = filename.lower()
    reasons: list[str] = []
    verdict = Verdict.UNKNOWN

    for magic, label in _EXECUTABLE_MAGIC.items():
        if payload.startswith(magic):
            reasons.append(f"{label} content")
            verdict = Verdict.MALICIOUS
            break

    if name.endswith(_RISKY_EXT):
        reasons.append("executable or script extension")
        verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if declared_mime and declared_mime.startswith("image/") and payload[:2] in (b"MZ", b"PK"):
        reasons.append("claims to be an image but is not")
        verdict = Verdict.MALICIOUS

    if payload.startswith(_MACRO_MAGIC) or name.endswith((".docm", ".xlsm", ".pptm")):
        reasons.append("macro-capable Office document")
        verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if payload.startswith(b"%PDF"):
        hits = [a.decode() for a in _PDF_ACTIONS if a in payload[:200_000]]
        if hits:
            reasons.append(f"PDF with active content ({', '.join(hits)})")
            verdict = max(verdict, Verdict.SUSPICIOUS, key=_severity)

    if not reasons and payload:
        verdict = Verdict.CLEAN
        reasons.append("no static indicators")

    return StaticVerdict(verdict, tuple(reasons))


_SEVERITY = {Verdict.CLEAN: 0, Verdict.UNKNOWN: 1, Verdict.SUSPICIOUS: 2, Verdict.MALICIOUS: 3}


def _severity(v: Verdict) -> int:
    return _SEVERITY[v]


class AttachmentCascade:
    """Layer 0 → 1 → 2 → 3, stopping as soon as a verdict is reached."""

    def __init__(
        self,
        *,
        cache: VerdictCache | None = None,
        detonation_enabled: bool | None = None,
    ) -> None:
        settings = get_settings()
        self.cache = cache or VerdictCache()
        self.detonation_enabled = (
            settings.detonation_enabled if detonation_enabled is None else detonation_enabled
        )
        self.reputation_available = settings.virustotal_api_key is not None
        self.metrics = CascadeMetrics()

    async def analyse(
        self,
        *,
        sha256: str,
        filename: str,
        payload: bytes,
        declared_mime: str | None = None,
        protected_mailbox: bool = True,
    ) -> CascadeResult:
        from envelock.obs.metrics import observe_cascade

        self.metrics.seen += 1

        cached = self.cache.get(sha256)
        if cached is not None:
            self.metrics.cache_hits += 1
            observe_cascade(kind="attachment", layer="cache")
            return CascadeResult(sha256, cached, Layer.CACHE, ("shared verdict cache",))

        static = static_triage(filename=filename, payload=payload, declared_mime=declared_mime)
        if static.verdict in (Verdict.MALICIOUS, Verdict.CLEAN):
            self.metrics.static_resolved += 1
            self.cache.put(sha256, static.verdict)
            observe_cascade(kind="attachment", layer="static")
            return CascadeResult(sha256, static.verdict, Layer.STATIC, static.reasons)

        if self.reputation_available:
            reputation = await self._reputation(sha256)
            if reputation is not None:
                # Metered only when the lookup actually resolved something —
                # a hash lookup is not a detonation, far cheaper.
                self.metrics.reputation_calls += 1
                self.metrics.cost_micros += 100
                self.cache.put(sha256, reputation)
                observe_cascade(kind="attachment", layer="reputation")
                return CascadeResult(
                    sha256, reputation, Layer.REPUTATION, ("hash reputation",), 100
                )

        # Only unknown, risky, Protected-bound files would reach the metered
        # layer — but no detonation provider is implemented yet, so nothing is
        # sandboxed and NOTHING is metered. When a provider lands, restore the
        # per-detonation metering here alongside it.
        if self.detonation_enabled and protected_mailbox:
            verdict = await self._detonate(payload)
            if verdict is not Verdict.UNKNOWN:
                self.metrics.detonations += 1
                self.metrics.cost_micros += 5000
                self.cache.put(sha256, verdict)
                return CascadeResult(
                    sha256, verdict, Layer.DETONATION, ("dynamic analysis",), 5000
                )

        observe_cascade(kind="attachment", layer="fallthrough")
        return CascadeResult(
            sha256,
            static.verdict,
            Layer.STATIC,
            static.reasons + ("detonation not enabled",),
        )

    async def _reputation(self, sha256: str) -> Verdict | None:
        """VirusTotal hash lookup. Returns None when the sample is unknown (404),
        the API errors, or no key is configured — the cascade degrades, never
        blocks. (This was a `return None` stub that still METERED a lookup per
        attachment; now the lookup is real and metering happens only on a real
        call.)"""
        settings = get_settings()
        key = (
            settings.virustotal_api_key.get_secret_value()
            if settings.virustotal_api_key
            else ""
        )
        if not key:
            return None
        try:
            import httpx

            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{sha256}",
                    headers={"x-apikey": key},
                )
            if resp.status_code == 404:
                return None  # unknown sample — fall through
            if resp.status_code != 200:
                return None
            stats = (
                (resp.json().get("data") or {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            if malicious >= 3:
                return Verdict.MALICIOUS
            if malicious >= 1 or suspicious >= 3:
                return Verdict.SUSPICIOUS
            # Known to VT with a clean sheet across engines.
            if int(stats.get("harmless") or 0) + int(stats.get("undetected") or 0) > 0:
                return Verdict.CLEAN
            return None
        except Exception:  # noqa: BLE001 — reputation is best-effort
            return None

    async def _detonate(self, payload: bytes) -> Verdict:
        """No sandbox provider is implemented yet — answer UNKNOWN and meter
        NOTHING (see `analyse`): billing 5000 micros per attachment for a
        function that always shrugs was fiction in the COGS ledger."""
        return Verdict.UNKNOWN


# ── URL cascade ──────────────────────────────────────────────────────────────
_SHORTENERS = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
     "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "tiny.cc"}
)
_IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


@dataclass
class UrlMetrics:
    checked: int = 0
    free_hits: int = 0
    paid_calls: int = 0

    def payload(self) -> dict:
        return {
            "urls_checked": self.checked,
            "free_resolved": self.free_hits,
            "paid_calls": self.paid_calls,
            "paid_rate": round(self.paid_calls / self.checked, 4) if self.checked else 0.0,
        }


@dataclass(frozen=True, slots=True)
class UrlVerdict:
    url: str
    verdict: Verdict
    source: str
    reasons: tuple[str, ...] = ()


class UrlCascade:
    """Google Safe Browsing is free and is the primary. Redirect unwrapping and
    brand-similarity are entirely self-built."""

    def __init__(self, *, feed_domains: frozenset[str] = frozenset()) -> None:
        settings = get_settings()
        self.safebrowsing = bool(
            settings.safebrowsing_api_key
            and settings.safebrowsing_api_key.get_secret_value()
        )
        self.urlhaus = settings.urlhaus_enabled
        self.feed_domains = feed_domains
        self.metrics = UrlMetrics()
        self._cache: dict[str, UrlVerdict] = {}

    async def check(self, url: str) -> UrlVerdict:
        if url in self._cache:
            return self._cache[url]

        self.metrics.checked += 1
        from envelock.util.domains import registrable_domain

        host = url.split("//", 1)[-1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
        reg = registrable_domain(host)
        reasons: list[str] = []

        if reg in self.feed_domains:
            self.metrics.free_hits += 1
            verdict = UrlVerdict(url, Verdict.MALICIOUS, "threat feed", ("on a threat feed",))
            self._cache[url] = verdict
            return verdict

        if _IP_HOST.match(host):
            reasons.append("bare IP address instead of a hostname")
        if reg in _SHORTENERS:
            reasons.append("link shortener hides the destination")
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            reasons.append("credentials embedded in the URL")

        if reasons:
            self.metrics.free_hits += 1
            verdict = UrlVerdict(url, Verdict.SUSPICIOUS, "static", tuple(reasons))
        elif self.safebrowsing:
            # This branch used to increment the counter and return UNKNOWN
            # without making a call, so a deployment with a Safe Browsing key
            # configured got exactly the same protection as one without — while
            # the cost view reported paid lookups that never happened.
            self.metrics.paid_calls += 1
            verdict = await self._safebrowsing(url)
        else:
            verdict = UrlVerdict(url, Verdict.UNKNOWN, "static", ("no reputation source",))

        self._cache[url] = verdict
        return verdict

    #: Google's Lookup API takes up to 500 URLs per request; we check one at a
    #: time because the cascade is called per-URL and the result is cached.
    _SAFEBROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def _safebrowsing(
        self,
        url: str,
        *,
        timeout: float = 4.0,  # noqa: ASYNC109 — an HTTP client budget, not a task deadline
    ) -> UrlVerdict:
        """Ask Google Safe Browsing about one URL.

        Any failure returns UNKNOWN rather than raising: a reputation service
        being slow must degrade this one signal, never fail the analysis of a
        message that has a dozen other signals to offer.
        """
        from envelock.config import get_settings

        key = get_settings().safebrowsing_api_key
        if key is None or not key.get_secret_value():
            return UrlVerdict(url, Verdict.UNKNOWN, "static", ("no reputation source",))

        body = {
            "client": {"clientId": "envelock", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            import httpx

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    self._SAFEBROWSING_URL,
                    # The key rides a HEADER, not `?key=`. httpx logs the full
                    # request URL at INFO, so a query-string key is written to
                    # the application log verbatim on every lookup — and then
                    # into whatever ships those logs. Google accepts either
                    # form; only one of them keeps the secret out of the log.
                    headers={"X-Goog-Api-Key": key.get_secret_value()},
                    json=body,
                )
            if response.status_code != 200:
                logger.debug("safe browsing returned %s", response.status_code)
                return UrlVerdict(url, Verdict.UNKNOWN, "safebrowsing", ("lookup failed",))
            matches = (response.json() or {}).get("matches") or []
        except Exception as exc:  # noqa: BLE001 — one signal, never the whole analysis
            logger.debug("safe browsing lookup failed: %s", exc)
            return UrlVerdict(url, Verdict.UNKNOWN, "safebrowsing", ("lookup failed",))

        if not matches:
            # An explicit clean answer, which is different from "we didn't look".
            return UrlVerdict(url, Verdict.CLEAN, "safebrowsing", ())

        threats = tuple(
            sorted({str(m.get("threatType", "")).lower().replace("_", " ") for m in matches if m})
        )
        return UrlVerdict(
            url,
            Verdict.MALICIOUS,
            "safebrowsing",
            tuple(f"Google Safe Browsing lists this as {t}" for t in threats if t),
        )


_URL_CASCADE: UrlCascade | None = None


_ATTACHMENT_CASCADE: AttachmentCascade | None = None


def get_attachment_cascade() -> AttachmentCascade:
    """Process-wide attachment cascade so the verdict cache and metrics are
    shared by every ingest path and the cost/status views — a per-request
    instance reported zeros forever."""
    global _ATTACHMENT_CASCADE  # noqa: PLW0603
    if _ATTACHMENT_CASCADE is None:
        _ATTACHMENT_CASCADE = AttachmentCascade()
    return _ATTACHMENT_CASCADE


def get_url_cascade() -> UrlCascade:
    """Process-wide URL cascade so its verdict cache and metrics are shared by
    delivery-time analysis, the click-time redirector, and the cost view."""
    global _URL_CASCADE  # noqa: PLW0603
    if _URL_CASCADE is None:
        _URL_CASCADE = UrlCascade()
    return _URL_CASCADE


def reset_url_cascade() -> None:
    """Drop the singleton (tests; settings changes)."""
    global _URL_CASCADE  # noqa: PLW0603
    _URL_CASCADE = None


def rewrite_for_click(url: str, *, token: str, base: str) -> str:
    """Feature 1 — links weaponised after delivery are the standard evasion, so
    the destination is re-checked at click time. The original URL travels only
    in the token's DB row, never in the rewritten link itself."""
    return f"{base}/r/{token}"
