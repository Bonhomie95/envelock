"""Extraction of payment identifiers from message text (A1).

Deliberately dependency-free regex + checksum validation: this runs on every
inbound message, so it must be fast and must not call anything metered.
"""

from __future__ import annotations

import re
import string
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BankIdentifier:
    """A payment identifier found in a message. Defined here rather than in the
    detection framework: payments has no business importing detections, and the
    reverse direction created an import cycle."""

    scheme: str  # iban|swift|ach|sortcode|account|crypto
    identifier: str
    country: str | None = None

#: Zero-width, soft-hyphen and bidi-control characters. They render as nothing,
#: so a human reads "bank" and "GB29NWBK…" exactly as intended while every regex
#: below sees a different string. Removing them is not cosmetic — leaving them in
#: was a complete bypass of A1 that costs an attacker one keystroke.
_INVISIBLE = re.compile("[­​-‏ -‮⁠-⁤﻿]")


def normalise_text(text: str) -> str:
    """Fold a message body into the one form the payment patterns are written for.

    Three separate bypasses closed here, all verified against the live code:

    * ``GB29NWBK6016133<ZWSP>19268 19`` extracted **nothing** — a zero-width
      space inside the account number, invisible in every mail client.
    * ``…our ba<ZWSP>nk: 60-16-13`` made `has_payment_context` false, which
      switches off sort-code, ACH and bare-account extraction entirely.
    * Fullwidth digits (``ＧＢ２９…``) extracted nothing. NFKC folds them back.

    NFKC also maps NBSP and the other exotic spaces onto U+0020; the explicit Zs
    pass catches anything NFKC leaves behind.
    """
    if not text:
        return ""
    out = unicodedata.normalize("NFKC", text)
    out = _INVISIBLE.sub("", out)
    # Tab/vertical-tab/form-feed are category Cc, not Zs, so the comprehension
    # below misses them — and an IBAN pasted out of a spreadsheet is tab
    # separated. Newlines are deliberately left alone: they are a real structural
    # boundary, and folding them would let an anchor run across lines and staple
    # two unrelated numbers into one candidate.
    out = out.replace("\t", " ").replace("\v", " ").replace("\f", " ")
    return "".join(" " if unicodedata.category(ch) == "Zs" else ch for ch in out)


#: An IBAN *candidate*: the country/check prefix, then anything that could be
#: part of the account, including the spaces every printed invoice puts every
#: four characters. Deliberately permissive — `valid_iban`'s mod-97 is what
#: decides, and being strict here is what broke the common case.
#:
#: The old pattern required rigid groups of exactly four and could not span a
#: trailing short group, so the standard human rendering
#: ``GB29 NWBK 6016 1331 9268 19`` did not match as an IBAN at all. Worse, the
#: leftover digits then matched `_SORTCODE_RE`, so the flagship detection stored
#: "926819" as the vendor's account. The same account typed the other way stored
#: the full IBAN — two identifiers for one account, which is exactly the
#: "bank details changed" signal A1 exists to raise. It produced both false
#: alarms on reformatted invoices and silent misses on real ones.
_IBAN_ANCHOR = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,40}")
#: SWIFT/BIC only counts when explicitly labelled. An unlabelled 8-letter
#: uppercase token matches ordinary words — "ATTACHED" parses as a structurally
#: valid BIC (bank ATTA, country CH, location ED) and would fire A1 on a routine
#: invoice. Real remittance details always carry the label.
_SWIFT_RE = re.compile(
    r"\b(?:SWIFT|BIC|SWIFT[\s/-]*BIC)\b\s*(?:CODE)?\s*[:\-]?\s*"
    r"([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"
)
_SORTCODE_RE = re.compile(r"\b(\d{2}[-\s]?\d{2}[-\s]?\d{2})\b")
_ACH_RE = re.compile(r"\b(\d{9})\b")
_ACCOUNT_RE = re.compile(r"\b(\d{8,17})\b")
_BTC_RE = re.compile(r"\b(bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")

#: Presence of these near an identifier is what makes it a *payment instruction*
#: rather than an incidental number. Drives A1 precision.
PAYMENT_CONTEXT = re.compile(
    r"\b(bank|account|acct|iban|swift|bic|routing|sort\s?code|beneficiary|"
    r"remit|remittance|wire|transfer|payment|invoice|payable|deposit|"
    # The gift-card BEC ("buy iTunes cards, urgent, tell no one") carries no
    # bank identifier at all — without this vocabulary, A2/A7/A14 all gated on
    # has_payment_context and the entire scam class fired NOTHING.
    r"gift\s?cards?|itunes|google\s?play|steam\s?card|voucher|prepaid\s?card|"
    r"zelle|venmo|cash\s?app|paypal|western\s?union|moneygram|crypto|bitcoin|usdt)\b",
    re.IGNORECASE,
)

#: A14 — urgency and pressure. Weak alone, strong as a multiplier on A1.
URGENCY = re.compile(
    r"\b(urgent|immediately|asap|today|right away|expedite|"
    r"confidential|do not (?:tell|inform|discuss)|keep this between|"
    r"new account|updated? (?:bank|account|payment)|changed? our bank)\b",
    re.IGNORECASE,
)

_MOD97 = {c: str(i + 10) for i, c in enumerate(string.ascii_uppercase)}

#: ISO 3166-1 alpha-2. Positions 5-6 of a BIC must be a real country.
ISO_COUNTRIES = frozenset((
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT",
    "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
    "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
    "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
    "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
    "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK",
    "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
    "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
    "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR",
    "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
    "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
    "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
    "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
    "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
    "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
    "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF",
    "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW",
    "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
))


def valid_iban(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if len(v) < 15 or len(v) > 34:
        return False
    rearranged = v[4:] + v[:4]
    digits = "".join(_MOD97.get(c, c) for c in rearranged)
    if not digits.isdigit():
        return False
    return int(digits) % 97 == 1


def _normalise(value: str) -> str:
    return re.sub(r"[\s-]", "", value).upper()


def normalise_identifier(scheme: str, value: str) -> str:
    """Canonical form for a bank identifier, BY SCHEME — the one the extractor
    stores, so registry writes and mail-side extraction always compare equal.

    The registry write paths used a bare `.replace(" ","").upper()`: a sort code
    entered as 60-16-13 never matched the extracted 601613, an ETH address was
    uppercased away from the extractor's lowercase form, and a base58 BTC
    address was corrupted outright — every genuine invoice from such a vendor
    then raised a false "details do not match" CRITICAL.
    """
    v = (value or "").strip()
    scheme = (scheme or "").lower()
    if scheme == "crypto":
        stripped = re.sub(r"\s", "", v)
        return stripped.lower() if stripped.lower().startswith("0x") else stripped
    return _normalise(v)


def _find_ibans(upper: str) -> list[tuple[int, int, str]]:
    """Every validated IBAN in `upper`, as (start, stop, compressed) spans.

    Matches permissively, then shrinks the candidate from the right until the
    mod-97 check passes — the tail of an anchor match is usually the next words
    of the sentence, not part of the account number. Returning the span lets the
    caller blank it out so the remaining patterns cannot re-match fragments of an
    IBAN as a sort code or a bare account.
    """
    spans: list[tuple[int, int, str]] = []
    for match in _IBAN_ANCHOR.finditer(upper):
        chunk = match.group(0)
        # (character, offset-within-chunk) for every non-space character.
        packed = [(ch, i) for i, ch in enumerate(chunk) if ch != " "]
        for end in range(len(packed), 14, -1):
            candidate = "".join(ch for ch, _ in packed[:end])
            if valid_iban(candidate):
                stop = match.start() + packed[end - 1][1] + 1
                spans.append((match.start(), stop, candidate))
                break
    return spans


def extract_bank_identifiers(text: str) -> list[BankIdentifier]:
    """Pull every plausible payment identifier out of a body or attachment.

    Returns normalised identifiers so `NG12ABCD...` and `NG12 ABCD ...` compare
    equal — otherwise a reformatted invoice would look like a bank change.
    """
    if not text:
        return []

    text = normalise_text(text)
    upper = text.upper()
    found: dict[str, BankIdentifier] = {}

    # IBANs first, and blank each match out of the working copy afterwards. An
    # IBAN contains long digit runs that `_SORTCODE_RE` and `_ACCOUNT_RE` will
    # happily match, so leaving it in place manufactures phantom identifiers for
    # the same account.
    masked = list(upper)
    for start, stop, iban in _find_ibans(upper):
        found[iban] = BankIdentifier("iban", iban, country=iban[:2])
        masked[start:stop] = " " * (stop - start)
    remainder = "".join(masked)

    for match in _SWIFT_RE.finditer(upper):
        norm = _normalise(match.group(1))
        # Avoid re-capturing the leading segment of an IBAN we already have.
        if any(norm in k for k in found):
            continue
        if norm[4:6] not in ISO_COUNTRIES:
            continue
        found.setdefault(norm, BankIdentifier("swift", norm, country=norm[4:6]))

    for match in _BTC_RE.finditer(text):
        found.setdefault(match.group(1), BankIdentifier("crypto", match.group(1)))
    for match in _ETH_RE.finditer(text):
        norm = match.group(1).lower()
        found.setdefault(norm, BankIdentifier("crypto", norm))

    # Bare account/routing numbers only count with payment context nearby,
    # otherwise every order number and phone number becomes a false positive.
    if PAYMENT_CONTEXT.search(text):
        for match in _SORTCODE_RE.finditer(remainder):
            norm = _normalise(match.group(1))
            if len(norm) == 6:
                found.setdefault(norm, BankIdentifier("sortcode", norm))
        for match in _ACH_RE.finditer(remainder):
            found.setdefault(match.group(1), BankIdentifier("ach", match.group(1)))
        for match in _ACCOUNT_RE.finditer(remainder):
            norm = match.group(1)
            if norm not in found and len(norm) >= 10:
                found.setdefault(norm, BankIdentifier("account", norm))

    return list(found.values())


def has_payment_context(text: str) -> bool:
    return bool(text) and bool(PAYMENT_CONTEXT.search(normalise_text(text)))


def urgency_score(text: str) -> int:
    """0..3. A14."""
    return min(3, len(URGENCY.findall(text or "")))


_INVOICE_RE = re.compile(r"\b(?:invoice|inv|bill)\s*#?\s*([A-Z0-9][A-Z0-9\-/]{2,20})\b", re.I)
_AMOUNT_RE = re.compile(
    r"(?:USD|EUR|GBP|NGN|TWD|SGD|CNY|\$|€|£|₦)\s?([\d,]+(?:\.\d{2})?)", re.I
)
#: Same shape, but keeping the currency marker. `extract_amounts` throws it away
#: because A13's baseline only compares magnitudes within one vendor. The
#: prevented-loss rollup cannot: adding £ to ₦ produces a headline number that is
#: not true in any currency, so the marker has to survive extraction.
_AMOUNT_CCY_RE = re.compile(
    r"(USD|EUR|GBP|NGN|TWD|SGD|CNY|\$|€|£|₦)\s?([\d,]+(?:\.\d{2})?)", re.I
)

#: Symbol → ISO, so "$1,000" and "USD 1,000" in the same thread do not land in
#: two different buckets.
_CCY_CANON = {
    "$": "USD", "€": "EUR", "£": "GBP", "₦": "NGN",
}


def extract_invoice_numbers(text: str) -> set[str]:
    """Invoice references in the text, uppercased — the A13 duplicate-billing key."""
    return {m.group(1).upper() for m in _INVOICE_RE.finditer(normalise_text(text))}


def extract_amounts(text: str) -> list[float]:
    """Currency-marked amounts in the text — the A13 anomaly baseline."""
    out: list[float] = []
    for m in _AMOUNT_RE.finditer(normalise_text(text)):
        try:
            out.append(float(m.group(1).replace(",", "")))
        except ValueError:
            continue
    return out


def largest_amount(text: str) -> tuple[float, str] | None:
    """The biggest currency-marked sum in the text, with its currency.

    "Biggest" rather than "first" deliberately: a fraudulent remittance mail
    routinely carries several figures — a VAT line, a previous balance, a
    reference number that happens to be money-shaped — and the one that matters
    is the one being asked for. Comparison is within a single currency only, for
    the same reason the marker is kept at all; a message that quotes two
    currencies returns whichever currency holds the largest single figure rather
    than attempting a conversion we have no rate for.

    Returns None when the message names no amount, which is the common case and
    must stay distinguishable from "the amount was zero".
    """
    by_ccy: dict[str, float] = {}
    for m in _AMOUNT_CCY_RE.finditer(normalise_text(text)):
        marker = m.group(1).upper()
        ccy = _CCY_CANON.get(marker, marker)
        try:
            value = float(m.group(2).replace(",", ""))
        except ValueError:
            continue
        if value > by_ccy.get(ccy, 0.0):
            by_ccy[ccy] = value
    if not by_ccy:
        return None
    ccy = max(by_ccy, key=lambda k: by_ccy[k])
    return by_ccy[ccy], ccy
