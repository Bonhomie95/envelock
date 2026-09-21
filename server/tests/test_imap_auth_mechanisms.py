"""Signing in the way each server actually wants.

`imaplib.login()` sends the `LOGIN` command and nothing else. Plenty of servers
— Dovecot with `disable_plaintext_auth`, and most corporate mail — advertise
`LOGINDISABLED` and expect a SASL mechanism instead. Thunderbird speaks several,
which is precisely why a mailbox signs in there and fails here.

The order is the design, and these pin it:

* `LOGIN` first where it is allowed, because every server supports it and TLS
  already protects the credential;
* `CRAM-MD5` next — MD5 is dead for signatures, but as an HMAC challenge inside
  TLS it is what these servers ask for, and the password never crosses the wire;
* SASL `PLAIN` last, for servers that refuse `LOGIN` but accept the same
  credential by another route.

What must never happen is a silent downgrade, or a generic "wrong password"
when the truth is "the server does not accept passwords this way" — those have
completely different fixes.
"""

from __future__ import annotations

import imaplib

import pytest

from envelock.channels.mail.imap_probe import _authenticate_password


class FakeImap:
    """Only what `_authenticate_password` touches."""

    def __init__(self, caps: list[str], *, accepts: set[str] | None = None) -> None:
        self.capabilities = tuple(c.encode() for c in caps)
        self.accepts = accepts or set()
        self.calls: list[str] = []

    def login(self, username: str, password: str):  # noqa: ANN201, ARG002
        self.calls.append("LOGIN")
        if "LOGIN" not in self.accepts:
            raise imaplib.IMAP4.error("LOGIN failed")
        return ("OK", [b"signed in"])

    def login_cram_md5(self, username: str, password: str):  # noqa: ANN201, ARG002
        self.calls.append("CRAM-MD5")
        if "CRAM-MD5" not in self.accepts:
            raise imaplib.IMAP4.error("CRAM-MD5 failed")
        return ("OK", [b"signed in"])

    def authenticate(self, mechanism: str, responder):  # noqa: ANN201
        self.calls.append(mechanism)
        if mechanism not in self.accepts:
            raise imaplib.IMAP4.error(f"{mechanism} failed")
        # Exercise the responder so a broken payload cannot pass unnoticed.
        self.payload = responder(b"")
        return ("OK", [b"signed in"])


def test_login_is_preferred_when_the_server_allows_it() -> None:
    """Every server supports it, and TLS already protects the credential. Trying
    something exotic first would be slower and no safer."""
    client = FakeImap(["IMAP4REV1", "AUTH=CRAM-MD5"], accepts={"LOGIN", "CRAM-MD5"})
    typ, _ = _authenticate_password(client, "u@x.com", "pw")
    assert typ == "OK"
    assert client.calls == ["LOGIN"]


def test_logindisabled_skips_straight_to_cram_md5() -> None:
    """The case that locks us out while Thunderbird sails through. Sending LOGIN
    to a server that advertised LOGINDISABLED only earns a rejection."""
    client = FakeImap(
        ["IMAP4REV1", "LOGINDISABLED", "AUTH=CRAM-MD5"], accepts={"CRAM-MD5"}
    )
    typ, _ = _authenticate_password(client, "u@x.com", "pw")
    assert typ == "OK"
    assert client.calls == ["CRAM-MD5"], "LOGIN should not have been attempted"


def test_falls_through_to_cram_md5_when_login_fails_without_warning() -> None:
    """A server can refuse LOGIN without ever advertising LOGINDISABLED. Giving
    up there would report a credential problem that does not exist."""
    client = FakeImap(["IMAP4REV1", "AUTH=CRAM-MD5"], accepts={"CRAM-MD5"})
    typ, _ = _authenticate_password(client, "u@x.com", "pw")
    assert typ == "OK"
    assert client.calls == ["LOGIN", "CRAM-MD5"]


def test_sasl_plain_is_the_last_resort() -> None:
    client = FakeImap(["IMAP4REV1", "LOGINDISABLED", "AUTH=PLAIN"], accepts={"PLAIN"})
    typ, _ = _authenticate_password(client, "u@x.com", "pw")
    assert typ == "OK"
    assert client.calls == ["PLAIN"]


def test_the_plain_payload_is_a_correctly_framed_sasl_message() -> None:
    """SASL PLAIN is authzid NUL authcid NUL password. Getting the framing wrong
    fails in a way that looks exactly like a wrong password."""
    client = FakeImap(["IMAP4REV1", "LOGINDISABLED", "AUTH=PLAIN"], accepts={"PLAIN"})
    _authenticate_password(client, "u@x.com", "s3cret")
    assert client.payload == b"\x00u@x.com\x00s3cret"


def test_a_server_offering_nothing_we_speak_says_so_precisely() -> None:
    """"Wrong password" and "this server will not take a password this way" have
    completely different fixes, so the message must not conflate them."""
    client = FakeImap(["IMAP4REV1", "LOGINDISABLED", "AUTH=GSSAPI", "AUTH=NTLM"])
    with pytest.raises(imaplib.IMAP4.error) as excinfo:
        _authenticate_password(client, "u@x.com", "pw")
    text = str(excinfo.value)
    assert "LOGINDISABLED" in text
    # It names what the server *would* accept, which is what support needs.
    assert "GSSAPI" in text
    assert "NTLM" in text


def test_a_genuinely_wrong_password_still_surfaces_the_server_rejection() -> None:
    """The fallbacks must not bury a real credential failure. LOGIN is allowed
    here and simply fails, so that rejection is the answer."""
    client = FakeImap(["IMAP4REV1"], accepts=set())
    with pytest.raises(imaplib.IMAP4.error):
        _authenticate_password(client, "u@x.com", "wrong")
    # Tried LOGIN, found no SASL mechanism on offer, re-ran LOGIN to surface it.
    assert client.calls == ["LOGIN", "LOGIN"]


def test_capabilities_are_read_case_insensitively() -> None:
    """Servers are inconsistent about case; matching only uppercase would miss
    LOGINDISABLED on the servers that most need this path."""
    client = FakeImap(["imap4rev1", "logindisabled", "auth=cram-md5"], accepts={"CRAM-MD5"})
    typ, _ = _authenticate_password(client, "u@x.com", "pw")
    assert typ == "OK"
    assert client.calls == ["CRAM-MD5"]
