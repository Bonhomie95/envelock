"""Payment extractor fixes (#9): inflected payment words, and the two-digit-year
date that read as a sort code.

7b9b9e5 anchored PAYMENT_CONTEXT at both ends and dropped bare "account", which
left "banking details have changed" and "future payments" matching nothing — so
once "account" was gone, a sort-code change worded that way extracted no
identifiers at all. Separately, a separated date like 30-10-26 still parsed as a
sort code, which is the very false positive 7b9b9e5 set out to kill.
"""

from __future__ import annotations

from envelock.util.payments import extract_bank_identifiers, has_payment_context


def test_inflected_payment_words_are_context() -> None:
    for phrase in (
        "Our banking details have changed.",
        "Please redirect future payments.",
        "See the attached invoices.",
        "We are now wiring to a new beneficiary.",
        "Updated remittances below.",
    ):
        assert has_payment_context(phrase), phrase


def test_bank_change_worded_with_banking_extracts_the_sort_code() -> None:
    text = "Our banking details have changed. Please pay to Sort 60 16 13, Acc 31926819."
    ids = {b.identifier for b in extract_bank_identifiers(text)}
    assert "601613" in ids


def test_labelled_sort_code_that_looks_like_a_date_still_counts() -> None:
    ids = {b.identifier for b in extract_bank_identifiers("Our sort code is 30-10-26.")}
    assert "301026" in ids


def test_dated_invoice_is_not_a_sort_code() -> None:
    text = "Invoice dated 30-10-26 is attached, payment due on receipt."
    ids = {b.identifier for b in extract_bank_identifiers(text)}
    assert "301026" not in ids


def test_unseparated_six_digits_still_a_sort_code() -> None:
    # Only the separated date shape is dropped; a plain 601613 beside bank context
    # is still a sort code.
    ids = {b.identifier for b in extract_bank_identifiers("Bank sort code 601613.")}
    assert "601613" in ids
