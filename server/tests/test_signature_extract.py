"""Signature-block extraction for C5 (pure, no DB)."""

from __future__ import annotations

from envelock.util.signature import extract_signature, signature_bank_ids

DELIMITED = """\
Hi Sam, the invoice is attached — let me know if anything looks off.

Thanks,
Dana

--
Dana Okoro
Finance, Northwind Ltd
Account: GB33BUKB20201555555555
"""

REPLY_WITH_HISTORY = """\
Sounds good, speak soon.

Dana
Account GB33BUKB20201555555555

On Mon, 6 Oct 2026, Sam wrote:
> here is the old thread
> Account GB94BARC10201530093459
"""


def test_delimiter_wins() -> None:
    sig = extract_signature(DELIMITED)
    assert "Dana Okoro" in sig
    assert "invoice is attached" not in sig  # the body above is not the signature
    assert signature_bank_ids(sig) == frozenset({"GB33BUKB20201555555555"})


def test_fallback_stops_at_quoted_history() -> None:
    sig = extract_signature(REPLY_WITH_HISTORY)
    # The quoted thread's account must not leak into the signature's id set,
    # or every reply would look like a signature change.
    assert signature_bank_ids(sig) == frozenset({"GB33BUKB20201555555555"})


def test_empty_is_no_signature() -> None:
    assert extract_signature("") == ""
    assert extract_signature(None) == ""
    assert signature_bank_ids("") == frozenset()
