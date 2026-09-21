"""Make `imapclient` work on Python 3.14.

Python 3.14 renamed `imaplib.IMAP4`'s read buffer from `file` to `_file` and
left `file` behind as a **read-only property**, so any assignment to it now
raises:

    AttributeError: property 'file' of 'IMAP4WithTimeout' object has no setter

`imapclient` 3.1 still assigns it in two places, and both are on the STARTTLS
path — which is a large share of ISP and custom-domain mail, not an edge case:

* `imap4.IMAP4WithTimeout.open()` — every non-implicit-TLS connection;
* `IMAPClient.starttls()` — the upgrade itself.

Implicit TLS (port 993) is unaffected, because `imapclient.tls.IMAP4_TLS` does
not override `open()` and inherits the stdlib's already-correct version. That
asymmetry is what makes this so easy to miss: a deployment tests one mailbox on
993, sees it work, and ships a product that cannot poll anyone on 143.

The patch is deliberately narrow. It applies only where `file` really is a
read-only property, so on Python 3.13 and earlier nothing is touched, and it
replicates the original method bodies exactly apart from the attribute name.
Delete this module once `imapclient` releases a version that handles 3.14 —
`is_needed()` will tell you when that has happened.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("envelock.imap.compat")

_installed = False


def is_needed() -> bool:
    """Whether this Python makes `imaplib.IMAP4.file` read-only."""
    import imaplib
    import inspect

    attr = inspect.getattr_static(imaplib.IMAP4, "file", None)
    return isinstance(attr, property) and attr.fset is None


def _set_buffer(imap_obj: object, fileobj: object) -> None:
    """Assign the read buffer under whichever name this Python expects."""
    import imaplib
    import inspect

    attr = inspect.getattr_static(imaplib.IMAP4, "file", None)
    if isinstance(attr, property):
        imap_obj._file = fileobj  # type: ignore[attr-defined]  # noqa: SLF001
    else:
        imap_obj.file = fileobj  # type: ignore[attr-defined]


def install() -> bool:
    """Patch `imapclient` if this Python needs it. Returns whether it did.

    Idempotent, and safe to call from anywhere that is about to use the
    library.
    """
    global _installed  # noqa: PLW0603 — one process-wide patch, applied once
    if _installed or not is_needed():
        return False

    from imapclient import IMAPClient, tls
    from imapclient.imap4 import IMAP4WithTimeout
    from imapclient.imapclient import require_capability

    def open_(self, host: str = "", port: int = 143, timeout: float | None = None) -> None:  # noqa: ANN001
        # imapclient's original, with the buffer assigned under the right name.
        self.host = host
        self.port = port
        self.sock = self._create_socket(timeout)  # noqa: SLF001
        _set_buffer(self, self.sock.makefile("rb"))

    def _starttls(self, ssl_context=None):  # noqa: ANN001, ANN202
        from imapclient import exceptions

        if self.ssl or self._starttls_done:  # noqa: SLF001
            raise exceptions.IMAPClientAbortError("TLS session already established")
        typ, data = self._imap._simple_command("STARTTLS")  # noqa: SLF001
        self._checkok("starttls", typ, data)  # noqa: SLF001
        self._starttls_done = True  # noqa: SLF001
        self._imap.sock = tls.wrap_socket(self._imap.sock, ssl_context, self.host)  # noqa: SLF001
        _set_buffer(self._imap, self._imap.sock.makefile("rb"))  # noqa: SLF001
        return data[0]

    # Re-apply imapclient's own capability guard. Without it we would send
    # STARTTLS to servers that never advertised it — and a plaintext session
    # that *looks* upgraded is exactly the failure this codebase refuses
    # elsewhere.
    _starttls.__doc__ = IMAPClient.starttls.__doc__
    starttls = require_capability("STARTTLS")(_starttls)

    IMAP4WithTimeout.open = open_
    IMAPClient.starttls = starttls
    _installed = True
    logger.info(
        "applied the imapclient/Python 3.14 compatibility patch "
        "(imaplib.IMAP4.file is read-only on this interpreter)"
    )
    return True


__all__ = ["install", "is_needed"]
