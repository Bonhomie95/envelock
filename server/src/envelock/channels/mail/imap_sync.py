"""Real IMAP fetch + quarantine (Tier 3).

This is the socket-level counterpart to the pure `ImapBroker` scheduler: the
broker decides *when* a mailbox is due, this module does the actual IMAP work —
select the inbox, pull the UIDs we have not seen, and (for Protected mailboxes)
move a flagged message out of the inbox.

Everything here is synchronous (``imapclient`` wraps the stdlib ``imaplib``,
which is blocking); callers run it with ``asyncio.to_thread`` so one slow server
never blocks the event loop. The IMAP client is injected via ``client_factory``
so the fetch/quarantine logic is unit-testable without a live server.

Credentials are only ever handed to this module in the broker/worker process,
decrypted immediately before the connection and never persisted in the clear
(PRD §5.2).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

#: Folder a Protected mailbox's flagged mail is moved into. Created on demand.
QUARANTINE_FOLDER = "Envelock Quarantine"

#: Never pull an unbounded backlog in one poll — protects memory and latency.
DEFAULT_LIMIT = 200

#: First-connect look-back when there is no cursor yet: we do not want to ingest
#: a decade of history, only recent mail. Backfill of older mail is a separate,
#: explicit action (PRD E11).
FIRST_SYNC_TAIL = 50

#: The FETCH item for a message's full source. `BODY.PEEK[]`, never `RFC822`.
#:
#: RFC 3501 §6.4.5: `RFC822` is `BODY[]`, and fetching `BODY[]` from a folder
#: opened read-write "implicitly sets the \Seen flag". The live poll opens the
#: inbox read-write (it has to — it quarantines and rewrites in the same
#: session) and fetched `RFC822`, so every new message in every connected
#: mailbox was marked READ the moment Envelock looked at it. The customer's
#: unread count went to zero and new mail sat unnoticed in their inbox, which is
#: the precise opposite of protecting it. It also made silent-access detection
#: (C11) impossible: C11 asks "who marked this read?", and the answer was always
#: us.
#:
#: `PEEK` returns the same bytes and leaves every flag alone. Servers answer it
#: under the key `BODY[]`.
BODY_FETCH = "BODY.PEEK[]"


def _raw_body(entry: dict) -> bytes | None:
    """The message source from a FETCH response to `BODY_FETCH`.

    `BODY[]` is what a compliant server answers a `BODY.PEEK[]` request with.
    `RFC822` is accepted as well so a server that echoes the older item name
    still works — we only ever *request* PEEK, so reading either is safe.
    """
    for key in (b"BODY[]", "BODY[]", b"RFC822", "RFC822"):
        raw = entry.get(key)
        if raw:
            return bytes(raw)
    return None


class ImapClientLike(Protocol):
    """The slice of ``imapclient.IMAPClient`` this module uses. Declared as a
    Protocol so tests can inject a fake with the same surface."""

    def login(self, username: str, password: str) -> Any: ...
    def oauth2_login(self, username: str, access_token: str) -> Any: ...
    def starttls(self) -> Any: ...
    def select_folder(self, folder: str, readonly: bool = False) -> dict: ...
    def search(self, criteria: Any) -> list[int]: ...
    def fetch(self, messages: Any, data: Any) -> dict: ...
    def folder_exists(self, folder: str) -> bool: ...
    def create_folder(self, folder: str) -> Any: ...
    def append(
        self, folder: str, msg: bytes, flags: Any = (), msg_time: Any = None
    ) -> Any: ...
    def move(self, messages: Any, folder: str) -> Any: ...
    def copy(self, messages: Any, folder: str) -> Any: ...
    def delete_messages(self, messages: Any) -> Any: ...
    def expunge(self, messages: Any = None) -> Any: ...
    def capabilities(self) -> tuple: ...
    def logout(self) -> Any: ...


ClientFactory = Callable[..., ImapClientLike]


@dataclass(frozen=True, slots=True)
class FetchedMessage:
    uid: int
    raw: bytes


@dataclass(slots=True)
class FetchResult:
    messages: list[FetchedMessage] = field(default_factory=list)
    uidvalidity: int | None = None
    highest_uid: int | None = None
    ok: bool = True
    error: str | None = None
    #: True when the failure was the server rejecting the credentials (not a
    #: transient network/TLS error) — the caller uses this to prompt a reconnect
    #: rather than retrying a password the server will keep refusing.
    auth_failed: bool = False


class _AuthError(Exception):
    """Raised inside ``_open`` when the server rejects the login, so ``fetch_new``
    can distinguish a bad password from a transient connection failure."""


def _default_client_factory(
    *, host: str, port: int, security: str, timeout: float, pin_sha256: str | None = None
) -> ImapClientLike:
    """Real ``imapclient.IMAPClient``. Imported lazily so the module (and the
    tests that inject a fake) do not require the dependency at import time.

    With `pin_sha256` set, the certificate is checked against that exact
    fingerprint rather than the public CA chain. This path matters as much as
    the one in `imap_probe`: connecting once and then failing every poll
    afterwards would be worse than never connecting, because the mailbox would
    look protected while quietly ingesting nothing.
    """
    from imapclient import IMAPClient

    from envelock.channels.mail.imap_compat import install as install_imapclient_shim

    # Python 3.14 made imaplib.IMAP4.file read-only; imapclient 3.1 still
    # assigns it on the STARTTLS path. No-op on older interpreters.
    install_imapclient_shim()

    ssl = security == "ssl"
    if pin_sha256 and ssl:
        from envelock.channels.mail.imap_tls import unverified_context, verify_pin

        client = IMAPClient(
            host,
            port=port,
            ssl=True,
            ssl_context=unverified_context(),
            timeout=timeout,
            use_uid=True,
        )
        # Before any credential is sent.
        verify_pin(client.socket(), pin_sha256)
        return client
    if ssl:
        # Pass the context explicitly. imapclient's own default would be
        # `ssl.create_default_context()`, which is correct but does not cope
        # with an empty platform trust store — and if this path and the connect
        # path disagree about a server, a mailbox connects and then never polls.
        from envelock.channels.mail.imap_tls import verifying_context

        return IMAPClient(
            host,
            port=port,
            ssl=True,
            ssl_context=verifying_context(),
            timeout=timeout,
            use_uid=True,
        )
    return IMAPClient(host, port=port, ssl=False, timeout=timeout, use_uid=True)


class _BlockedHostError(Exception):
    """The target resolves somewhere we refuse to dial (see imap_probe)."""


def _assert_peer_public(client) -> None:  # noqa: ANN001 — ImapClientLike
    """Re-check the address we ACTUALLY connected to, before any credential.

    `check_host_allowed` resolves the name and approves the answer; the client
    then resolves it again to dial. A record with a short TTL can answer
    publicly for the check and 169.254.169.254 for the connection — the classic
    DNS-rebinding window. The socket knows the truth, so ask it. This runs
    before `login()`, so a rebound host never receives the mailbox password.
    """
    import contextlib as _ctx
    import ipaddress as _ip

    from envelock.config import get_settings

    if get_settings().imap_allow_private_hosts:
        # Same opt-in the pre-connect guard honours: a self-hosted mail server
        # on the LAN (and the suite's loopback server) is deliberately allowed.
        return

    peer = None
    with _ctx.suppress(Exception):
        peer = client.socket().getpeername()
    if not peer:
        return  # a test double, or a transport without a peer — nothing to check
    try:
        addr = _ip.ip_address(str(peer[0]).split("%")[0])
    except (ValueError, IndexError):
        return
    if (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        with _ctx.suppress(Exception):
            client.logout()
        raise _BlockedHostError(
            f"the mail server resolved to {addr} at connect time, which we will "
            "not talk to. If this is genuinely your mail server, it must be "
            "reachable on a public address."
        )


def _open(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    timeout: float,
    client_factory: ClientFactory | None,
    pin_sha256: str | None = None,
) -> ImapClientLike:
    """Connect and authenticate. `password` uses IMAP LOGIN; `access_token` uses
    SASL XOAUTH2 — the only way in for providers that have switched password
    authentication off (Microsoft 365).

    `pin_sha256` is a certificate this mailbox's owner approved; see
    `imap_tls`."""
    if client_factory is None:
        # Only guard real connections; an injected factory is a test double.
        from envelock.channels.mail.imap_probe import check_host_allowed

        blocked = check_host_allowed(host, port)
        if blocked is not None:
            raise _BlockedHostError(blocked.message)

        # Refuse an unencrypted session before a socket is opened. Anything that
        # is not "ssl" or "starttls" reaches `client.login()` over a plaintext
        # connection, which sends the mailbox password in the clear — on connect
        # and again on every poll thereafter. The STARTTLS branch below already
        # refuses to degrade for the same reason.
        from envelock.config import get_settings

        if security not in ("ssl", "starttls") and not get_settings().imap_allow_plaintext:
            raise _BlockedHostError(
                "refusing to connect without encryption — this would send the "
                "mailbox password across the internet in clear text. Use SSL/TLS "
                "(usually port 993) or STARTTLS (usually port 143)."
            )

    factory = client_factory or _default_client_factory
    if client_factory is None:
        client = factory(
            host=host, port=port, security=security, timeout=timeout, pin_sha256=pin_sha256
        )
    else:
        # Test doubles keep the original signature.
        client = factory(host=host, port=port, security=security, timeout=timeout)
    if client_factory is None:
        # Closes the DNS-rebinding window between check_host_allowed and this
        # connection. Before STARTTLS and before login: nothing secret has been
        # sent yet.
        _assert_peer_public(client)
    if security == "starttls":
        # Deliberately NOT suppressed. Falling through to a plaintext session
        # would put the mailbox password on the wire in the clear.
        if pin_sha256 and client_factory is None:
            from envelock.channels.mail.imap_tls import unverified_context, verify_pin

            client.starttls(unverified_context())
            verify_pin(client.socket(), pin_sha256)
        else:
            from envelock.channels.mail.imap_tls import verifying_context

            client.starttls(verifying_context())
    try:
        if access_token is not None:
            client.oauth2_login(username, access_token)
        else:
            client.login(username, password or "")
    except Exception as exc:  # noqa: BLE001
        # imapclient raises LoginError on a rejected credential; match by name so
        # we do not hard-depend on its exception class here.
        name = type(exc).__name__.lower()
        if "login" in name or "auth" in name:
            with contextlib.suppress(Exception):
                client.logout()
            raise _AuthError(str(exc)) from exc
        raise
    return client


def fetch_new(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    since_uid: int | None = None,
    uidvalidity: int | None,
    folder: str = "INBOX",
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    pin_sha256: str | None = None,
    access_token: str | None = None,
) -> FetchResult:
    """Pull messages newer than ``since_uid`` from ``folder``.

    Returns every new message plus the server's current UIDVALIDITY and the
    highest UID seen (the caller persists both as the next cursor). Any socket,
    TLS, or auth failure comes back as ``ok=False`` with a reason rather than an
    exception, so one broken mailbox never aborts a whole poll cycle.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host,
            port=port,
            security=security,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            client_factory=client_factory,
            pin_sha256=pin_sha256,
        )
        info = client.select_folder(folder, readonly=False)
        server_uidvalidity = _as_int(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY"))

        # A UIDVALIDITY change invalidates every stored UID (RFC 3501): the server
        # has renumbered the folder, so our cursor is meaningless. Restart from the
        # recent tail rather than trusting a stale, now-ambiguous UID.
        cursor = since_uid
        if uidvalidity is not None and server_uidvalidity != uidvalidity:
            cursor = None

        if cursor is None:
            all_uids = sorted(_as_int_list(client.search(["ALL"])))
            wanted = all_uids[-FIRST_SYNC_TAIL:]
        else:
            # ``cursor:*`` always returns at least the highest message even when
            # none are strictly greater, so filter to strictly-new UIDs ourselves.
            candidates = sorted(_as_int_list(client.search(["UID", f"{cursor + 1}:*"])))
            wanted = [u for u in candidates if u > cursor]

        wanted = wanted[-limit:]
        if not wanted:
            highest = since_uid if cursor is not None else None
            return FetchResult(
                messages=[], uidvalidity=server_uidvalidity, highest_uid=highest, ok=True
            )

        raw_by_uid = client.fetch(wanted, [BODY_FETCH])
        messages: list[FetchedMessage] = []
        for uid in wanted:
            raw = _raw_body(raw_by_uid.get(uid) or {})
            if raw:
                messages.append(FetchedMessage(uid=int(uid), raw=raw))

        highest_uid = max((m.uid for m in messages), default=since_uid)
        return FetchResult(
            messages=messages,
            uidvalidity=server_uidvalidity,
            highest_uid=highest_uid,
            ok=True,
        )
    except _AuthError as exc:
        return FetchResult(ok=False, error=f"login rejected: {exc}", auth_failed=True)
    except _BlockedHostError as exc:
        return FetchResult(ok=False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 — any failure is a poll failure, reported not raised
        return FetchResult(ok=False, error=_reason(exc))
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


@dataclass(frozen=True, slots=True)
class ReadMessage:
    """A message that was unread at the last poll and is read now."""

    uid: int
    #: RFC 5322 Message-ID as the server has it, or None if the header is absent.
    message_id: str | None


@dataclass(slots=True)
class ReadWatch:
    #: The unread UIDs now — the baseline for the next poll.
    unseen: list[int] = field(default_factory=list)
    became_read: list[ReadMessage] = field(default_factory=list)
    uidvalidity: int | None = None
    ok: bool = True
    error: str | None = None


def _message_id_from(entry: dict) -> str | None:
    """Pull the Message-ID out of a `BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]` reply.

    Servers echo the section name back in slightly different spellings (quoted
    field names, different case), so match on the prefix rather than one key.
    """
    raw = None
    for key, value in entry.items():
        name = key.decode("ascii", "ignore") if isinstance(key, bytes) else str(key)
        if name.upper().startswith("BODY[HEADER"):
            raw = value
            break
    if not raw:
        return None
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    # Unfold continuation lines, then find the header.
    text = text.replace("\r\n ", " ").replace("\r\n\t", " ").replace("\n ", " ")
    for line in text.splitlines():
        head, sep, value = line.partition(":")
        if sep and head.strip().lower() == "message-id":
            return value.strip() or None
    return None


def watch_reads(
    *,
    host: str,
    port: int = 993,
    security: str = "ssl",
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    previous_unseen: list[int] | None,
    previous_uidvalidity: int | None,
    max_tracked: int = 5000,
    folder: str = "INBOX",
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    pin_sha256: str | None = None,
) -> ReadWatch:
    """Which messages were read since the last look? — the question C11 asks.

    Compare the inbox's unread set with the one remembered from last time. A
    UID that has left it has either been read or been moved/deleted, so each is
    checked: still present with `\\Seen` means read; absent means it went
    somewhere else (including our own quarantine and rewrite, which run earlier
    in the same poll), which is not a read and not reported.

    Opened with EXAMINE (read-only) and fetched with PEEK: the one thing this
    must never do is mark mail as read while asking who read it.

    Limits worth knowing, and stated rather than hidden: a message that arrives
    and is read within one poll interval is never seen unread, and re-reading an
    already-read message changes no flag at all. Flags can only show a first
    read of mail that was sitting unread.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host, port=port, security=security, username=username,
            password=password, access_token=access_token,
            timeout=timeout, client_factory=client_factory, pin_sha256=pin_sha256,
        )
        info = client.select_folder(folder, readonly=True)
        uidvalidity = _as_int(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY"))
        unseen = sorted(_as_int_list(client.search(["UNSEEN"])))[-max_tracked:]
        watch = ReadWatch(unseen=unseen, uidvalidity=uidvalidity)

        # No baseline, or the server renumbered the folder: remember, report
        # nothing. Diffing against another epoch's UIDs would be noise.
        if previous_unseen is None or (
            previous_uidvalidity is not None and uidvalidity != previous_uidvalidity
        ):
            return watch

        now_unseen = set(unseen)
        left = sorted(u for u in previous_unseen if u not in now_unseen)
        if not left:
            return watch

        data = client.fetch(
            left, ["FLAGS", "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]"]
        ) or {}
        for uid in left:
            entry = data.get(uid) or {}
            if not entry:
                continue  # gone: moved or deleted, not read
            flags = entry.get(b"FLAGS") or entry.get("FLAGS") or ()
            if not any(_flag_name(f).lower() == "\\seen" for f in flags):
                continue
            watch.became_read.append(
                ReadMessage(uid=int(uid), message_id=_message_id_from(entry))
            )
        return watch
    except _AuthError as exc:
        return ReadWatch(ok=False, error=f"login rejected: {exc}")
    except Exception as exc:  # noqa: BLE001
        return ReadWatch(ok=False, error=_reason(exc))
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def fetch_since(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    since_date=None,  # noqa: ANN001 — datetime.date
    folder: str = "INBOX",
    limit: int = DEFAULT_LIMIT,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    pin_sha256: str | None = None,
) -> FetchResult:
    """Pull messages received on or after ``since_date`` — onboarding backfill (E11).

    Distinct from ``fetch_new``: it searches by date rather than a UID cursor, so it
    can reach back over history the day a mailbox is connected. The caller runs each
    returned message through the pipeline to seed A9 stylometry and A12 baselines,
    then does NOT advance the live cursor from this (a subsequent poll owns that).
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host, port=port, security=security, username=username,
            password=password, access_token=access_token,
            timeout=timeout, client_factory=client_factory, pin_sha256=pin_sha256,
        )
        info = client.select_folder(folder, readonly=True)
        server_uidvalidity = _as_int(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY"))
        # IMAP SINCE takes a date; the server returns everything on/after it.
        criteria = ["SINCE", since_date.strftime("%d-%b-%Y")]
        wanted = sorted(_as_int_list(client.search(criteria)))[-limit:]
        if not wanted:
            return FetchResult(messages=[], uidvalidity=server_uidvalidity, ok=True)
        raw_by_uid = client.fetch(wanted, [BODY_FETCH])
        messages: list[FetchedMessage] = []
        for uid in wanted:
            raw = _raw_body(raw_by_uid.get(uid) or {})
            if raw:
                messages.append(FetchedMessage(uid=int(uid), raw=raw))
        return FetchResult(messages=messages, uidvalidity=server_uidvalidity, ok=True)
    except _AuthError as exc:
        return FetchResult(ok=False, error=f"login rejected: {exc}", auth_failed=True)
    except Exception as exc:  # noqa: BLE001
        return FetchResult(ok=False, error=_reason(exc))
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def quarantine_message(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    uid: int = 0,
    folder: str = "INBOX",
    quarantine_folder: str = QUARANTINE_FOLDER,
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    pin_sha256: str | None = None,
) -> bool:
    """Move a single message out of the inbox into the quarantine folder.

    Uses IMAP MOVE where the server advertises it, else COPY + delete + EXPUNGE —
    the fallback works on servers as old as 1998, which is the whole point of the
    Tier 3 path. Returns True only if the message actually left the inbox.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host,
            port=port,
            security=security,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            client_factory=client_factory,
            pin_sha256=pin_sha256,
        )
        client.select_folder(folder, readonly=False)
        if not client.folder_exists(quarantine_folder):
            with contextlib.suppress(Exception):
                client.create_folder(quarantine_folder)

        caps = ()
        with contextlib.suppress(Exception):
            caps = client.capabilities()
        has_move = any(_cap_eq(c, "MOVE") for c in caps)

        if has_move:
            client.move([uid], quarantine_folder)
        else:
            client.copy([uid], quarantine_folder)
            client.delete_messages([uid])
            client.expunge([uid])
        return True
    except Exception:  # noqa: BLE001 — quarantine failure is reported by the caller, never fatal
        return False
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


def replace_message(
    *,
    host: str,
    port: int,
    security: str,
    username: str,
    password: str | None = None,
    access_token: str | None = None,
    uid: int = 0,
    raw: bytes = b"",
    folder: str = "INBOX",
    timeout: float = 30.0,
    client_factory: ClientFactory | None = None,
    pin_sha256: str | None = None,
) -> bool:
    """Swap a delivered message for our protected copy (banner + rewritten links).

    IMAP has no in-place edit, so this is APPEND-then-delete: the modified copy
    is APPENDed with the original's flags and INTERNALDATE (read/unread state and
    the timestamp survive; threading survives because the copy keeps its
    Message-ID), then the original is deleted and expunged. The APPEND happens
    FIRST — if anything fails, the customer still has the original message; a
    delete-first order could lose mail, which is never acceptable.

    Returns True only when the copy is in place and the original is gone.
    """
    client: ImapClientLike | None = None
    try:
        client = _open(
            host=host,
            port=port,
            security=security,
            username=username,
            password=password,
            access_token=access_token,
            timeout=timeout,
            client_factory=client_factory,
            pin_sha256=pin_sha256,
        )
        client.select_folder(folder, readonly=False)

        flags: tuple = ()
        internaldate = None
        with contextlib.suppress(Exception):
            entry = (client.fetch([uid], ["FLAGS", "INTERNALDATE"]) or {}).get(uid) or {}
            raw_flags = entry.get(b"FLAGS") or entry.get("FLAGS") or ()
            # \Recent is session state the server owns — APPENDing it is an error
            # on strict servers.
            flags = tuple(
                f for f in raw_flags if _flag_name(f).lower() != "\\recent"
            )
            internaldate = entry.get(b"INTERNALDATE") or entry.get("INTERNALDATE")

        client.append(folder, raw, flags, internaldate)
        client.delete_messages([uid])
        client.expunge([uid])
        return True
    except Exception:  # noqa: BLE001 — enforcement failure is reported by the caller, never fatal
        return False
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.logout()


# ── helpers ───────────────────────────────────────────────────────────────────
def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _as_int_list(values: Any) -> list[int]:
    out: list[int] = []
    for v in values or []:
        iv = _as_int(v)
        if iv is not None:
            out.append(iv)
    return out


def _flag_name(flag: Any) -> str:
    if isinstance(flag, bytes):
        return flag.decode("ascii", "ignore")
    return str(flag)


def _cap_eq(cap: Any, name: str) -> bool:
    if isinstance(cap, bytes):
        cap = cap.decode("ascii", "ignore")
    return str(cap).upper() == name


def _reason(exc: Exception) -> str:
    name = type(exc).__name__
    text = str(exc).strip()
    return f"{name}: {text}" if text else name


__all__ = [
    "QUARANTINE_FOLDER",
    "fetch_since",
    "FetchedMessage",
    "FetchResult",
    "fetch_new",
    "quarantine_message",
    "replace_message",
    "ReadMessage",
    "ReadWatch",
    "watch_reads",
]
