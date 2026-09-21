"""The imapclient / Python 3.14 shim.

Python 3.14 renamed `imaplib.IMAP4`'s read buffer to `_file` and left `file` as
a read-only property. `imapclient` 3.1 still assigns `file`, so on 3.14 every
non-implicit-TLS connection dies with:

    AttributeError: property 'file' of 'IMAP4WithTimeout' object has no setter

This is nastier than a normal dependency break because it is *partial*. Port 993
keeps working (`IMAP4_TLS` inherits the stdlib's correct `open()`), while
STARTTLS on 143 fails — so a deployment can test one mailbox, see it connect,
and ship something that cannot poll a large share of ISP mail. It reached
production here exactly that way.

These tests run on every interpreter. On 3.13 and earlier the shim is inert and
that is what gets asserted; on 3.14+ the repair itself is exercised.
"""

from __future__ import annotations

import imaplib
import inspect

from envelock.channels.mail import imap_compat


def test_the_shim_matches_the_interpreter_it_is_running_on() -> None:
    """`is_needed()` must reflect the real reason, not a version number.

    Keyed to the actual attribute, so a backport, a patch release, or a fixed
    `imapclient` changes the answer on its own rather than needing this file
    edited.
    """
    attr = inspect.getattr_static(imaplib.IMAP4, "file", None)
    read_only_property = isinstance(attr, property) and attr.fset is None
    assert imap_compat.is_needed() is read_only_property


def test_installing_is_idempotent() -> None:
    """It is called from the client factory, so it runs on every connection.
    Patching repeatedly would stack wrappers around wrappers."""
    imap_compat.install()
    assert imap_compat.install() is False


def test_the_buffer_is_assigned_under_the_name_this_python_uses() -> None:
    """The single line the whole shim exists for."""

    class Fake:
        pass

    obj = Fake()
    imap_compat._set_buffer(obj, "buffer")  # noqa: SLF001
    if imap_compat.is_needed():
        assert obj._file == "buffer"  # noqa: SLF001
        assert not hasattr(obj, "file")
    else:
        assert obj.file == "buffer"


def test_starttls_keeps_imapclients_capability_guard() -> None:
    """The guard must survive the patch.

    Without it we would send STARTTLS to a server that never advertised it, and
    a plaintext session that merely *looks* upgraded is precisely the failure
    this codebase refuses everywhere else — a mailbox password on the wire in
    the clear.
    """
    from imapclient import IMAPClient
    from imapclient.exceptions import CapabilityError

    imap_compat.install()

    class NoStarttls:
        ssl = False
        _starttls_done = False

        def has_capability(self, name: str) -> bool:  # noqa: ARG002
            return False

    try:
        IMAPClient.starttls(NoStarttls())
    except CapabilityError:
        pass  # the guard fired, which is the point
    except Exception as exc:  # noqa: BLE001
        msg = f"expected CapabilityError from the guard, got {type(exc).__name__}: {exc}"
        raise AssertionError(msg) from exc
    else:
        raise AssertionError("STARTTLS was attempted on a server that does not offer it")


def test_a_plain_connection_works_on_this_interpreter() -> None:
    """End to end against a real socket, which is the only way to catch this.

    Constructing an IMAPClient with ssl=False is what broke; a mocked client
    would have sailed through on 3.14 and told us nothing.
    """
    import socket
    import threading

    from imapclient import IMAPClient

    imap_compat.install()

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve() -> None:
        try:
            conn, _ = srv.accept()
            conn.sendall(b"* OK [CAPABILITY IMAP4rev1] ready\r\n")
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                tag = data.split()[0]
                conn.sendall(b"* CAPABILITY IMAP4rev1\r\n" + tag + b" OK done\r\n")
        except OSError:
            return

    threading.Thread(target=serve, daemon=True).start()
    try:
        client = IMAPClient("127.0.0.1", port=port, ssl=False, timeout=5, use_uid=True)
        assert client is not None
    finally:
        srv.close()
