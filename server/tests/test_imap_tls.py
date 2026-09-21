"""Certificate handling for IMAP: describing one, and trusting one on purpose.

This is the code that decides whether a mailbox which works in Thunderbird can
work here. Two failure directions, both expensive:

* too permissive → we accept a certificate we should not, and a product whose
  job is stopping credentials reaching the wrong server hands over a mailbox
  password;
* too strict → a working mailbox is declared broken and the customer is sent to
  fix something that was never wrong.

The pin is the interesting part. It is narrower than normal verification, not
looser: normal verification asks "would some authority vouch for this name?",
a pin asks "is this the exact certificate the customer looked at?" — which an
attacker holding a valid certificate for another name cannot satisfy.
"""

from __future__ import annotations

import hashlib
import ssl
from datetime import UTC, datetime, timedelta

import pytest

from envelock.channels.mail.imap_tls import (
    CertificateInfo,
    CertificatePinError,
    fingerprint_of,
    host_matches_san,
    unverified_context,
    verify_pin,
)


# ── Name matching (RFC 6125) ─────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("mail.example.com", "mail.example.com", True),
        ("mail.example.com", "imap.example.com", False),
        ("MAIL.Example.COM", "mail.example.com", True),
        ("mail.example.com.", "mail.example.com", True),
        ("mail.example.com", "mail.example.com.", True),
        # A wildcard covers exactly one label...
        ("mail.example.com", "*.example.com", True),
        ("imap.example.com", "*.example.com", True),
        # ...never spans a dot...
        ("a.b.example.com", "*.example.com", False),
        # ...and does not cover the bare domain, which surprises people.
        ("example.com", "*.example.com", False),
        # ...nor an empty label.
        (".example.com", "*.example.com", False),
        # The case that started this: a customer's domain on shared hosting.
        ("mail.mycompany.com", "server47.hostingprovider.net", False),
        ("mail.mycompany.com", "*.hostingprovider.net", False),
    ],
)
def test_certificate_name_matching(host: str, pattern: str, expected: bool) -> None:
    assert host_matches_san(host, pattern) is expected


# ── What we tell the customer ────────────────────────────────────────────────
def _info(**over) -> CertificateInfo:  # noqa: ANN003
    base = {
        "sha256": "a" * 64,
        "subject": "CN=server47.hostingprovider.net",
        "issuer": "CN=Some CA",
        "names": ("server47.hostingprovider.net",),
        "not_before": "2026-01-01",
        "not_after": "2027-01-01",
        "host": "mail.mycompany.com",
        "expired": False,
        "self_signed": False,
    }
    return CertificateInfo(**(base | over))


def test_a_mismatch_names_both_sides_so_the_customer_can_act() -> None:
    """The summary has to contain what they connected to AND what it covers.

    Naming only one of the two leaves them unable to tell whether the server is
    wrong or the certificate is — the single decision this screen exists for.
    """
    info = _info()
    assert not info.matches_host
    assert "server47.hostingprovider.net" in info.summary
    assert "mail.mycompany.com" in info.summary


def test_expiry_is_reported_ahead_of_a_name_mismatch() -> None:
    """An expired certificate is the more urgent fact, and renewing it usually
    fixes the name too. Leading with the name would send them down a longer road."""
    info = _info(expired=True)
    assert "expired" in info.summary.lower()


def test_a_self_signed_certificate_that_matches_still_warns() -> None:
    info = _info(names=("mail.mycompany.com",), self_signed=True)
    assert info.matches_host
    assert "self-signed" in info.summary


def test_a_good_certificate_says_so_plainly() -> None:
    info = _info(names=("mail.mycompany.com",))
    assert info.matches_host
    assert "looks correct" in info.summary


# ── The pin ──────────────────────────────────────────────────────────────────
class _FakeSock:
    def __init__(self, der: bytes | None) -> None:
        self._der = der

    def getpeercert(self, binary_form: bool = False) -> bytes | None:  # noqa: FBT001, FBT002, ARG002
        return self._der


def test_the_approved_certificate_is_accepted() -> None:
    der = b"the exact bytes the customer looked at"
    verify_pin(_FakeSock(der), fingerprint_of(der))  # does not raise


def test_any_other_certificate_is_refused() -> None:
    """The whole point. A different certificate — even a perfectly valid one
    issued for another name — is not the one that was approved."""
    approved = fingerprint_of(b"approved")
    with pytest.raises(CertificatePinError):
        verify_pin(_FakeSock(b"a machine-in-the-middle's certificate"), approved)


def test_a_server_offering_no_certificate_is_refused() -> None:
    with pytest.raises(CertificatePinError):
        verify_pin(_FakeSock(None), "b" * 64)


def test_pin_comparison_ignores_formatting_the_customer_might_paste() -> None:
    """Fingerprints get copied from `openssl`, which prints them colon-separated
    and uppercase. Refusing that formatting would look like a wrong fingerprint."""
    der = b"cert"
    hexed = hashlib.sha256(der).hexdigest()
    colonised = ":".join(hexed[i : i + 2] for i in range(0, len(hexed), 2)).upper()
    verify_pin(_FakeSock(der), colonised)  # does not raise


# ── The context used for pinned connections ──────────────────────────────────
def test_the_unverified_context_still_refuses_obsolete_tls() -> None:
    """It skips certificate judgement because a pin replaces it — but there is
    no reason to also accept TLS 1.0, and a context this permissive is exactly
    the one worth checking."""
    ctx = unverified_context()
    assert ctx.verify_mode is ssl.CERT_NONE
    assert ctx.check_hostname is False
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2


def test_fingerprint_is_stable_and_lowercase_hex() -> None:
    """It is stored in a 64-character column and compared as a string, so drift
    in case or length would silently stop every pinned mailbox connecting."""
    fp = fingerprint_of(b"anything")
    assert len(fp) == 64
    assert fp == fp.lower()
    assert fingerprint_of(b"anything") == fp


# ── The real parser, against a certificate we generate here ──────────────────
def _self_signed(names: list[str], *, days: int = 30) -> bytes:
    """A real DER certificate, so the parser is exercised rather than mocked."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_parsing_a_real_certificate_reports_the_mismatch() -> None:
    from envelock.channels.mail.imap_tls import _parse

    der = _self_signed(["server47.hostingprovider.net", "*.hostingprovider.net"])
    info = _parse(der, "mail.mycompany.com")
    assert info is not None
    assert info.sha256 == fingerprint_of(der)
    assert info.self_signed is True
    assert info.expired is False
    assert not info.matches_host
    assert "server47.hostingprovider.net" in info.names


def test_parsing_a_real_certificate_that_does_match() -> None:
    from envelock.channels.mail.imap_tls import _parse

    der = _self_signed(["mail.mycompany.com"])
    info = _parse(der, "mail.mycompany.com")
    assert info is not None
    assert info.matches_host


def test_an_expired_certificate_is_seen_as_expired() -> None:
    from envelock.channels.mail.imap_tls import _parse

    der = _self_signed(["mail.mycompany.com"], days=-1)
    info = _parse(der, "mail.mycompany.com")
    assert info is not None
    assert info.expired is True


# ── The trust store itself ───────────────────────────────────────────────────
def test_verification_is_strict() -> None:
    ctx = __import__(
        "envelock.channels.mail.imap_tls", fromlist=["verifying_context"]
    ).verifying_context()
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    assert ctx.minimum_version is ssl.TLSVersion.TLSv1_2


def test_an_empty_platform_trust_store_falls_back_rather_than_failing_everything() -> None:
    """A host with no CA bundle would reject every server, correct ones included.

    That failure is indistinguishable from a genuinely bad certificate, which
    makes the real signal unreadable and tempts someone into "fixing" it by
    disabling verification. A python.org macOS build has an empty store until
    `Install Certificates.command` is run, and slim containers often ship
    without `ca-certificates`, so this is not a hypothetical.
    """
    from envelock.channels.mail.imap_tls import verifying_context

    ctx = verifying_context()
    # Whichever source it came from, we must end up able to verify somebody.
    assert ctx.cert_store_stats()["x509_ca"] > 0, (
        "no CA certificates loaded — every IMAP connection would fail"
    )


def test_the_fallback_bundle_is_a_declared_dependency() -> None:
    """It is load-bearing for connectivity, so it must not be transitive: a
    dependency resolution that dropped it would break IMAP on any host with an
    empty system store, and nothing would explain why."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    deps = tomllib.loads((root / "pyproject.toml").read_text())["project"]["dependencies"]
    assert any(d.startswith("certifi") for d in deps)
