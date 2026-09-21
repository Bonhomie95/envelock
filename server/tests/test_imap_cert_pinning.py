"""Certificate pinning end to end, over a real TLS socket.

The other pinning tests check the pieces. This one runs a genuine TLS IMAP
server holding a certificate for the wrong name — the exact shared-hosting
situation a customer hits — and drives the real connect path against it.

Three things have to be true, and only a real handshake can show them:

1. **Without a pin it fails**, and fails *as a certificate problem*, not as some
   generic connection error. If it were misclassified the customer would be sent
   to check a firewall that is fine.
2. **With the right pin it connects**, which is the entire feature: a mailbox
   that works in Thunderbird now works here.
3. **With any other certificate it still refuses.** This is what separates a pin
   from switching verification off. The connection is not "trusted now" — it is
   trusted *for exactly these bytes*.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SERVER_PW = "the-app-password"  # noqa: S105 — a fixture, never leaves this file


def _self_signed_pem(common_name: str) -> tuple[str, str, bytes]:
    """Returns (cert_path, key_path, der). Named for a host we will NOT dial."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    tmp = Path(tempfile.mkdtemp())
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path), cert.public_bytes(serialization.Encoding.DER)


class TinyTlsImapServer(threading.Thread):
    """Enough IMAP4rev1 to complete a sign-in, wrapped in TLS."""

    daemon = True

    def __init__(self, cert_path: str, key_path: str) -> None:
        super().__init__()
        self.logins: list[tuple[str, str]] = []
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(cert_path, key_path)
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                raw, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(raw,), daemon=True).start()

    def _serve(self, raw: socket.socket) -> None:
        try:
            conn = self._ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError):
            # A client that refused our certificate hangs up here. That is the
            # behaviour under test, not an error.
            raw.close()
            return
        try:
            stream = conn.makefile("rwb")
            stream.write(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n")
            stream.flush()
            while True:
                line = stream.readline()
                if not line:
                    return
                parts = line.decode(errors="replace").strip().split(" ", 2)
                tag, cmd = parts[0], (parts[1].upper() if len(parts) > 1 else "")
                rest = parts[2] if len(parts) > 2 else ""
                if cmd == "CAPABILITY":
                    stream.write(b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n")
                    stream.write(f"{tag} OK done\r\n".encode())
                elif cmd == "LOGIN":
                    user, _, pw = rest.partition(" ")
                    user, pw = user.strip('"'), pw.strip('"')
                    self.logins.append((user, pw))
                    ok = pw == SERVER_PW
                    stream.write(
                        f"{tag} OK signed in\r\n".encode()
                        if ok
                        else f"{tag} NO [AUTHENTICATIONFAILED] bad password\r\n".encode()
                    )
                elif cmd == "LOGOUT":
                    stream.write(b"* BYE\r\n" + f"{tag} OK done\r\n".encode())
                    stream.flush()
                    return
                else:
                    stream.write(f"{tag} OK\r\n".encode())
                stream.flush()
        except (OSError, ssl.SSLError):
            return
        finally:
            with contextlib_suppress():
                conn.close()

    def stop(self) -> None:
        self._stop.set()
        with contextlib_suppress():
            self._sock.close()


def contextlib_suppress():  # noqa: ANN201
    import contextlib

    return contextlib.suppress(Exception)


@pytest.fixture
def bad_cert_server(monkeypatch):  # noqa: ANN001, ANN201
    """A TLS IMAP server whose certificate names a host we will not be dialling."""
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS", "true")
    get_settings.cache_clear()

    cert_path, key_path, der = _self_signed_pem("server47.hostingprovider.net")
    server = TinyTlsImapServer(cert_path, key_path)
    server.start()
    try:
        yield server, der
    finally:
        server.stop()
        get_settings.cache_clear()


def _candidate(port: int):  # noqa: ANN202
    from envelock.channels.mail.imap_discovery import Candidate

    # We dial 127.0.0.1; the certificate says server47.hostingprovider.net.
    return Candidate("127.0.0.1", port, "ssl", "test", 10)


def test_without_a_pin_it_fails_as_a_certificate_problem(bad_cert_server) -> None:  # noqa: ANN001
    """Not merely "it failed" — the *classification* is what routes the customer
    to the right fix. Reported as a network problem, they would go and check a
    firewall that was never the issue."""
    from envelock.channels.mail.imap_errors import ImapErrorCode
    from envelock.channels.mail.imap_probe import probe_sync

    server, _ = bad_cert_server
    result = probe_sync(
        [_candidate(server.port)], email="pay@socketco.example", password=SERVER_PW
    )
    assert not result.ok
    assert result.failure is not None
    assert result.failure.code is ImapErrorCode.CERTIFICATE_ERROR
    assert not server.logins, "the password must not be sent to an unverified server"


def test_with_the_approved_certificate_it_connects(bad_cert_server) -> None:  # noqa: ANN001
    """The whole point of the feature: a mailbox that works in Thunderbird and
    failed here now connects, without verification being switched off."""
    from envelock.channels.mail.imap_probe import probe_sync
    from envelock.channels.mail.imap_tls import fingerprint_of

    server, der = bad_cert_server
    result = probe_sync(
        [_candidate(server.port)],
        email="pay@socketco.example",
        password=SERVER_PW,
        pin_sha256=fingerprint_of(der),
    )
    assert result.ok, result.failure
    assert server.logins[-1] == ("pay@socketco.example", SERVER_PW)


def test_a_pin_for_a_different_certificate_is_still_refused(bad_cert_server) -> None:  # noqa: ANN001
    """What separates a pin from disabling verification.

    The server here holds a certificate that a customer somewhere may well have
    approved — but not *this* one. Trust is scoped to exact bytes, so this
    connection is refused and the password is never sent.
    """
    from envelock.channels.mail.imap_probe import probe_sync
    from envelock.channels.mail.imap_tls import fingerprint_of

    server, _ = bad_cert_server
    _, _, other_der = _self_signed_pem("someone-elses-server.example")

    result = probe_sync(
        [_candidate(server.port)],
        email="pay@socketco.example",
        password=SERVER_PW,
        pin_sha256=fingerprint_of(other_der),
    )
    assert not result.ok
    assert not server.logins, "the password must not reach a server we did not approve"


def test_the_password_never_reaches_a_server_with_a_changed_certificate(
    bad_cert_server,  # noqa: ANN001
) -> None:
    """The ordering guarantee, stated on its own because it is the security
    property: the pin is checked after the handshake but before authentication,
    so a substituted server learns nothing."""
    from envelock.channels.mail.imap_probe import probe_sync

    server, _ = bad_cert_server
    probe_sync(
        [_candidate(server.port)],
        email="pay@socketco.example",
        password=SERVER_PW,
        pin_sha256="f" * 64,  # nothing will ever match this
    )
    assert server.logins == []


def test_the_probe_uses_a_verifying_context_not_imaplibs_default() -> None:
    """A regression guard for a real vulnerability, not a style preference.

    `imaplib.IMAP4_SSL(host, port)` with no context builds one via
    `ssl._create_stdlib_context()` — `verify_mode=CERT_NONE`,
    `check_hostname=False`. The call looks correct and verifies nothing, so
    every mailbox password went to whatever answered on that port, from a
    product whose purpose is preventing exactly that.

    Worse, `imapclient` on the polling path *does* verify, so the two halves
    disagreed: a mailbox with a bad certificate connected, was stored, and then
    failed every poll — appearing protected while ingesting nothing.

    This asserts the property directly, because the mistake is invisible at the
    call site.
    """
    import ssl

    from envelock.channels.mail.imap_tls import verifying_context

    stdlib = ssl._create_stdlib_context()  # noqa: SLF001 — quoting the bug
    assert stdlib.verify_mode is ssl.CERT_NONE
    assert stdlib.check_hostname is False

    ours = verifying_context()
    assert ours.verify_mode is ssl.CERT_REQUIRED
    assert ours.check_hostname is True


def test_the_polling_path_and_the_connect_path_agree() -> None:
    """They must reach the same verdict about the same server.

    When they disagreed, "connected" and "actually usable" came apart, which is
    the failure mode a customer cannot diagnose: the dashboard says the mailbox
    is fine and no mail ever arrives.
    """
    import ssl

    from imapclient.tls import wrap_socket  # noqa: F401 — imported to assert it exists

    from envelock.channels.mail.imap_tls import verifying_context

    # imapclient falls back to ssl.create_default_context(SERVER_AUTH).
    theirs = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    ours = verifying_context()
    assert (ours.verify_mode, ours.check_hostname) == (
        theirs.verify_mode,
        theirs.check_hostname,
    )
