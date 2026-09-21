"""TLS for IMAP: inspecting a certificate, and trusting a specific one on purpose.

The problem this solves is the most common reason a mailbox connects in
Thunderbird and not here. A desktop client shows a warning and lets the person
continue; we use Python's default TLS context, which verifies the chain *and*
the hostname and then simply fails. Shared hosting very often presents a
certificate naming `serverNN.provider.net` while the customer connects to
`mail.theircompany.com`, so a working mailbox looks broken.

Refusing outright is not the answer, and neither is turning verification off.
Turning it off would mean any machine-in-the-middle could offer any certificate
and silently collect mailbox passwords — from a product whose entire purpose is
to stop exactly that.

So we do what SSH does. When verification fails, the customer is shown precisely
*what* was presented — the names it covers, who issued it, when it expires, and
its SHA-256 — and can approve **that one certificate** for **that one mailbox**.
From then on the connection is checked against that fingerprint. The difference
from disabling verification is total:

* a blanket `CERT_NONE` accepts *any* certificate, forever, silently;
* a pin accepts *exactly the bytes the customer looked at*, and a
  machine-in-the-middle presenting anything else is refused — including one
  holding a perfectly valid certificate for another name.

The pin is checked **before any credential is sent**. A mismatched pin closes
the socket while the password is still in memory and has not touched the wire.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import socket
import ssl
from dataclasses import dataclass

logger = logging.getLogger("envelock.imap.tls")

__all__ = [
    "CertificateInfo",
    "CertificatePinError",
    "fingerprint_of",
    "host_matches_san",
    "inspect_certificate",
    "unverified_context",
    "verify_pin",
    "verifying_context",
]


class CertificatePinError(Exception):
    """The server's certificate is not the one the customer approved.

    Deliberately not an `ssl.SSLError`: this is not a handshake problem. The
    handshake succeeded and the peer is simply not who we agreed to talk to,
    which is the case worth shouting about.
    """


def host_matches_san(host: str, pattern: str) -> bool:
    """Does `host` match one `dNSName` from a certificate?

    RFC 6125 wildcards, which are narrower than people assume: `*.example.com`
    covers `mail.example.com` but NOT `example.com` itself, and never spans a
    dot, so it does not cover `a.b.example.com` either.

    Being wrong in the permissive direction here would tell a customer their
    certificate is fine when it is not; in the strict direction, it sends them
    to fix something that was never broken.
    """
    host = host.lower().rstrip(".")
    pattern = pattern.lower().rstrip(".")
    if pattern.startswith("*."):
        head, _, tail = host.partition(".")
        return bool(head) and tail == pattern[2:]
    return pattern == host


def fingerprint_of(der: bytes) -> str:
    """The SHA-256 of a DER certificate, lowercase hex — what we pin on."""
    return hashlib.sha256(der).hexdigest()


def verifying_context() -> ssl.SSLContext:
    """Strict TLS: verify the chain AND the hostname.

    This has to be passed explicitly. `imaplib.IMAP4_SSL(host, port)` with no
    context does *not* verify anything — it builds one with
    `ssl._create_stdlib_context()`, whose `verify_mode` is `CERT_NONE` and whose
    `check_hostname` is False. So the obvious-looking call silently accepts any
    certificate from anyone, which for this product means sending a customer's
    mailbox password to whatever answered on that port.

    `imapclient`, used on the polling path, defaults to
    `ssl.create_default_context()` and does verify. That asymmetry is worse than
    either behaviour on its own: a mailbox connects (unverified), is stored, and
    then fails every poll afterwards (verified) — looking protected while
    ingesting nothing.
    """
    ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    # If the platform trust store is empty, verification would reject *every*
    # server — including correctly configured ones — and the failure looks
    # identical to a genuinely bad certificate. That is worse than not
    # verifying: it makes the real signal unreadable and invites someone to
    # "fix" it by turning verification off.
    #
    # An empty store is not exotic. A python.org build on macOS has one until
    # `Install Certificates.command` is run, and slim container images routinely
    # ship without `ca-certificates`.
    if ctx.cert_store_stats()["x509_ca"] == 0:
        try:
            import certifi

            ctx.load_verify_locations(cafile=certifi.where())
            logger.warning(
                "system CA store is empty; verifying IMAP certificates against "
                "certifi instead. Install ca-certificates on this host."
            )
        except Exception:  # noqa: BLE001
            # Nothing to verify against, and we will not silently stop
            # verifying. Connections will fail loudly, which is the correct
            # outcome for a host that cannot authenticate anyone.
            logger.error(
                "no CA certificates available: IMAP connections cannot verify "
                "any server. Install ca-certificates on this host."
            )

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def unverified_context() -> ssl.SSLContext:
    """A context that completes a handshake without judging the certificate.

    Used for two things only, neither of which trusts the peer: *looking* at a
    certificate in order to describe it to the customer, and completing the
    handshake for a pinned connection whose fingerprint is checked immediately
    afterwards by `verify_pin`. Never use it without one of those follow-ups.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Even unverified, refuse obsolete protocol versions: there is no reason to
    # negotiate TLS 1.0 with anyone in 2026.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def verify_pin(sock: ssl.SSLSocket, expected_sha256: str) -> None:
    """Raise unless the peer presented exactly the approved certificate.

    Call this immediately after the handshake and **before** sending anything —
    the whole value of a pin is that a wrong peer never sees the password.
    """
    der = sock.getpeercert(binary_form=True)
    if not der:
        raise CertificatePinError("the server presented no certificate")
    actual = fingerprint_of(der)
    # Constant-time: the fingerprint is public, but comparing secrets and
    # non-secrets the same way keeps the habit from decaying.
    if not hmac.compare_digest(actual, expected_sha256.lower().replace(":", "")):
        raise CertificatePinError(
            "the server's certificate has changed since it was approved "
            f"(expected {expected_sha256[:16]}…, got {actual[:16]}…)"
        )


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """What a certificate says, in the terms a person needs to decide about it."""

    sha256: str
    subject: str
    issuer: str
    #: Every dNSName the certificate is valid for.
    names: tuple[str, ...]
    not_before: str
    not_after: str
    #: The host we asked for, so the UI can say "you connected to X".
    host: str
    expired: bool
    self_signed: bool

    @property
    def matches_host(self) -> bool:
        return any(host_matches_san(self.host, n) for n in self.names)

    @property
    def summary(self) -> str:
        """One line saying what is wrong with it, or that nothing is."""
        if self.expired:
            return f"This certificate expired on {self.not_after}."
        if not self.matches_host:
            covers = ", ".join(self.names[:3]) or "no host names"
            return (
                f"This certificate is for {covers} — not “{self.host}”, "
                "which is the server you entered."
            )
        if self.self_signed:
            return "This certificate is self-signed: no authority vouches for it."
        return "This certificate looks correct for this server."

    def as_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "names": list(self.names),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "host": self.host,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "matches_host": self.matches_host,
            "summary": self.summary,
        }


def _parse(der: bytes, host: str) -> CertificateInfo | None:
    try:
        from cryptography import x509
    except ImportError:  # pragma: no cover — cryptography is a hard dependency
        return None

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 — an unparseable certificate is still a failure to report
        return None

    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = list(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        # Certificates predating SAN put the name in CN. Rare, but a customer
        # stuck on one deserves the same explanation as everyone else.
        names = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                 if isinstance(a.value, str)]

    from datetime import UTC, datetime

    now = datetime.now(UTC)
    return CertificateInfo(
        sha256=fingerprint_of(der),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        names=tuple(names),
        not_before=cert.not_valid_before_utc.date().isoformat(),
        not_after=cert.not_valid_after_utc.date().isoformat(),
        host=host,
        expired=not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc),
        self_signed=cert.issuer == cert.subject,
    )


def inspect_certificate(
    host: str, port: int, *, timeout: float = 8.0, starttls: bool = False
) -> CertificateInfo | None:
    """Fetch and describe the certificate a server presents, without trusting it.

    Returns None if the server cannot be reached at all — that is a different
    problem with a different fix, and conflating the two is how someone ends up
    editing a certificate setting to fix a firewall.
    """
    ctx = unverified_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            if starttls:
                # Walk the plaintext greeting and issue STARTTLS by hand: we
                # want the certificate even when the IMAP layer would go on to
                # reject it.
                raw.settimeout(timeout)
                stream = raw.makefile("rwb")
                stream.readline()  # greeting
                stream.write(b"a001 STARTTLS\r\n")
                stream.flush()
                if not stream.readline().upper().startswith(b"A001 OK"):
                    return None
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
                return _parse(der, host) if der else None
    except Exception:  # noqa: BLE001 — unreachable is not our answer to give here
        return None
