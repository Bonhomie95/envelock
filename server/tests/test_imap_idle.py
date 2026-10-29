"""IMAP IDLE over a real socket: new mail is analysed the moment it lands.

Before IDLE was wired in, a Protected mailbox was only as fast as the poll
interval. The server here speaks just enough IMAP4rev1 + IDLE (RFC 2177) for the
real `imapclient` code path, and delivers a message mid-IDLE the way a mail
server does — so the test measures arrival → alert, not a mocked callback.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import threading
import time
from uuid import uuid4

import pytest

from envelock.channels.mail import imap_sync

FRAUD = (
    b'From: "Gemini Accounts" <billing@gemini-invoices.net>\r\n'
    b"To: pay@idleco.example\r\n"
    b"Subject: URGENT: updated bank details for invoice 4471\r\n"
    b"Date: Mon, 1 Sep 2025 09:00:00 +0000\r\n"
    b"Message-ID: <inv-4471-idle@gemini-invoices.net>\r\n"
    b"\r\n"
    b"Our bank has changed. Please remit to IBAN GB33BUKB20201555555555,\r\n"
    b"account 55555555, sort code 20-20-15. Same day please.\r\n"
)


class IdleImapServer(threading.Thread):
    """LOGIN, CAPABILITY, SELECT/EXAMINE, UID SEARCH/FETCH/MOVE, LIST, CREATE,
    IDLE/DONE, LOGOUT — and `deliver()`, which announces `* N EXISTS` to every
    connection sitting in IDLE, exactly as a real server does."""

    daemon = True

    def __init__(self, *, idle: bool = True) -> None:
        super().__init__()
        self.caps = "IMAP4rev1 MOVE" + (" IDLE" if idle else "")
        self.messages: dict[int, bytes] = {}
        self.next_uid = 1001
        self.moved: list[int] = []
        self.idling: list[socket.socket] = []
        #: Whether each IDLE session had its folder open read-only (EXAMINE).
        self.idle_read_only: list[bool] = []
        self.conns: list[socket.socket] = []
        self._lock = threading.Lock()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]

    def deliver(self, raw: bytes) -> None:
        with self._lock:
            self.messages[self.next_uid] = raw
            self.next_uid += 1
            for conn in self.idling:
                with contextlib.suppress(OSError):
                    conn.sendall(f"* {len(self.messages)} EXISTS\r\n".encode())

    def drop_all(self) -> None:
        with self._lock:
            for conn in self.conns:
                with contextlib.suppress(OSError):
                    conn.shutdown(socket.SHUT_RDWR)

    def stop(self) -> None:
        self._sock.close()
        self.drop_all()

    def run(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            with self._lock:
                self.conns.append(conn)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _uids(self, spec: str) -> list[int]:
        out: list[int] = []
        for part in spec.split(","):
            lo, _, hi = part.partition(":")
            top = max(self.messages, default=0) if hi == "*" else int(hi or lo)
            out += [u for u in sorted(self.messages) if int(lo) <= u <= max(top, int(lo))]
        return out

    def _serve(self, conn: socket.socket) -> None:  # noqa: C901 — a flat dispatch reads best
        def send(data: bytes) -> None:
            with self._lock:
                conn.sendall(data)

        send(f"* OK [CAPABILITY {self.caps}] ready\r\n".encode())
        buffer, idle_tag, read_only = b"", None, False
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
                while b"\r\n" in buffer:
                    raw, buffer = buffer.split(b"\r\n", 1)
                    line = raw.decode("utf-8", "replace")
                    if idle_tag is not None:
                        if line.strip().upper() == "DONE":
                            with self._lock:
                                self.idling.remove(conn)
                            send(f"{idle_tag} OK IDLE terminated\r\n".encode())
                            idle_tag = None
                        continue
                    tag, _, rest = line.partition(" ")
                    command, _, args = rest.partition(" ")
                    command, upper = command.upper(), args.upper()
                    if command == "CAPABILITY":
                        send(f"* CAPABILITY {self.caps}\r\n{tag} OK done\r\n".encode())
                    elif command in ("LOGIN", "NOOP", "CREATE"):
                        send(f"{tag} OK done\r\n".encode())
                    elif command in ("SELECT", "EXAMINE"):
                        read_only = command == "EXAMINE"
                        mode = "READ-ONLY" if read_only else "READ-WRITE"
                        send(
                            f"* {len(self.messages)} EXISTS\r\n"
                            f"* OK [UIDVALIDITY 7] ok\r\n"
                            f"* OK [UIDNEXT {self.next_uid}] ok\r\n"
                            f"{tag} OK [{mode}] done\r\n".encode()
                        )
                    elif command == "LIST":
                        found = '"INBOX"' in upper or '"*"' in upper
                        listing = '* LIST () "/" "INBOX"\r\n' if found else ""
                        send(f"{listing}{tag} OK done\r\n".encode())
                    elif command == "UID" and upper.startswith("SEARCH"):
                        crit = args.split()[1:]
                        everything = crit[0].upper() == "ALL"
                        uids = sorted(self.messages) if everything else self._uids(crit[1])
                        send(f"* SEARCH {' '.join(map(str, uids))}\r\n{tag} OK done\r\n".encode())
                    elif command == "UID" and upper.startswith("FETCH"):
                        out = b""
                        order = sorted(self.messages)
                        for uid in self._uids(args.split()[1]):
                            body = self.messages[uid]
                            out += (
                                f"* {order.index(uid) + 1} FETCH (UID {uid} BODY[] "
                                f"{{{len(body)}}}\r\n".encode() + body + b")\r\n"
                            )
                        send(out + f"{tag} OK done\r\n".encode())
                    elif command == "UID" and upper.startswith("MOVE"):
                        for uid in self._uids(args.split()[1]):
                            self.moved.append(uid)
                            self.messages.pop(uid, None)
                        send(f"{tag} OK done\r\n".encode())
                    elif command == "IDLE":
                        send(b"+ idling\r\n")
                        idle_tag = tag
                        with self._lock:
                            self.idling.append(conn)
                            self.idle_read_only.append(read_only)
                    elif command == "LOGOUT":
                        send(f"* BYE\r\n{tag} OK done\r\n".encode())
                        return
                    else:
                        send(f"{tag} BAD unsupported\r\n".encode())
        except OSError:
            return
        finally:
            with self._lock:
                for group in (self.idling, self.conns):
                    if conn in group:
                        group.remove(conn)
            conn.close()


def _wait(condition, timeout: float = 5.0) -> bool:  # noqa: ANN001
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def server(monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
    # Loopback and plaintext are refused in normal operation; a self-hosted
    # deployment opts in, and so does this test (same as test_imap_socket_e2e).
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "true"
    os.environ["ENVELOCK_IMAP_ALLOW_PLAINTEXT"] = "true"
    from envelock.config import get_settings

    get_settings.cache_clear()
    # A short look-up interval so stopping the IDLE thread takes ms, not 10 s.
    monkeypatch.setattr(imap_sync, "IDLE_CHECK_SECONDS", 0.3)
    srv = IdleImapServer()
    srv.start()
    yield srv
    srv.stop()
    os.environ["ENVELOCK_IMAP_ALLOW_PRIVATE_HOSTS"] = "false"
    os.environ["ENVELOCK_IMAP_ALLOW_PLAINTEXT"] = "false"
    get_settings.cache_clear()


def _watch(srv: IdleImapServer, stop: threading.Event, on_new_mail) -> dict:  # noqa: ANN001
    outcome: dict = {}

    def run() -> None:
        try:
            outcome["result"] = imap_sync.idle_watch(
                host="127.0.0.1", port=srv.port, security="none", username="u",
                password="p",  # noqa: S106 — the test server accepts any login
                on_new_mail=on_new_mail, max_seconds=60, stop=stop,
            )
        except Exception as exc:  # noqa: BLE001 — the test inspects it
            outcome["error"] = exc
        outcome["ended_at"] = time.monotonic()

    outcome["thread"] = threading.Thread(target=run, daemon=True)
    outcome["thread"].start()
    return outcome


def test_idle_reports_new_mail_the_moment_it_lands(server: IdleImapServer) -> None:
    stop, arrived = threading.Event(), threading.Event()
    run = _watch(server, stop, arrived.set)
    assert _wait(lambda: server.idling), "the client never entered IDLE"

    sent = time.monotonic()
    server.deliver(FRAUD)
    assert arrived.wait(2), "new mail was not reported while in IDLE"
    assert time.monotonic() - sent < 1.0

    stop.set()
    run["thread"].join(3)
    assert run.get("result") is True and "error" not in run
    assert server.idle_read_only == [True], "IDLE must only listen (EXAMINE)"
    assert _wait(lambda: not server.conns), "the IDLE connection was not closed"


def test_a_server_without_idle_is_left_to_the_poll(server: IdleImapServer) -> None:
    server.caps = "IMAP4rev1 MOVE"
    run = _watch(server, threading.Event(), lambda: None)
    run["thread"].join(3)
    assert run.get("result") is False and "error" not in run


def test_a_dropped_idle_connection_raises_instead_of_spinning(server: IdleImapServer) -> None:
    run = _watch(server, threading.Event(), lambda: None)
    assert _wait(lambda: server.idling)
    dropped = time.monotonic()
    server.drop_all()
    run["thread"].join(3)
    assert isinstance(run.get("error"), ConnectionError), run
    assert run["ended_at"] - dropped < 1.0


async def _seed(port: int, *, mailbox_class: str) -> tuple:
    from conftest import platform_sessionmaker as get_sessionmaker

    from envelock.core.enums import SourceMechanism
    from envelock.models import Domain, Mailbox, MailboxCredential, Tenant
    from envelock.security.crypto import seal

    tenant_id, mailbox_id = uuid4(), uuid4()
    async with get_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name="IdleCo", plan="complete", payment_method_ok=True))
        await session.flush()
        session.add(
            Domain(
                id=uuid4(), tenant_id=tenant_id, name="idleco.example",
                registrable_domain="idleco.example",
                verification_token="tok",  # noqa: S106 — a DNS proof token, not a credential
            )
        )
        session.add(
            Mailbox(
                id=mailbox_id, tenant_id=tenant_id, address="pay@idleco.example",
                mailbox_class=mailbox_class,
                sources=[SourceMechanism.IMAP_IDLE.value], is_active=True,
            )
        )
        sealed = seal(b"p", aad=str(mailbox_id).encode())
        session.add(
            MailboxCredential(
                mailbox_id=mailbox_id, tenant_id=tenant_id, kind="imap_password",
                imap_host="127.0.0.1", imap_port=port, imap_security="none",
                imap_last_uid=1000, imap_uidvalidity=7,
                ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
        await session.commit()
    return tenant_id, mailbox_id


async def _alert_count(mailbox_id) -> int:  # noqa: ANN001
    from conftest import platform_sessionmaker as get_sessionmaker
    from sqlalchemy import func, select

    from envelock.models import Alert

    async with get_sessionmaker()() as session:
        return int(
            (
                await session.execute(
                    select(func.count()).select_from(Alert).where(Alert.mailbox_id == mailbox_id)
                )
            ).scalar_one()
        )


async def test_new_mail_is_analysed_seconds_after_it_lands(
    db: None, server: IdleImapServer
) -> None:
    """The whole real-time path: the worker's reconcile holds IDLE on the
    Protected mailbox, mail lands, and the alert exists — and the message is
    quarantined — within seconds, not at the next poll."""
    from envelock.core.enums import MailboxClass
    from envelock.workers import imap_fetch

    _, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    try:
        await imap_fetch._reconcile_idle()
        assert list(imap_fetch._IDLE) == [mailbox_id]
        for _ in range(250):
            if server.idling:
                break
            await asyncio.sleep(0.02)
        assert server.idling, "the worker never entered IDLE"

        landed = time.monotonic()
        server.deliver(FRAUD)
        while await _alert_count(mailbox_id) == 0:
            assert time.monotonic() - landed < 10, "no alert 10 s after the mail landed"
            await asyncio.sleep(0.05)
        latency = time.monotonic() - landed
        print(f"\nIDLE arrival -> alert: {latency:.2f}s")  # noqa: T201 — the measured number
        assert latency < 5
        for _ in range(100):
            if server.moved:
                break
            await asyncio.sleep(0.05)
        assert server.moved == [1001], "a Critical must still be quarantined"
    finally:
        imap_fetch._release_idle()
        await asyncio.sleep(0.5)  # let the IDLE thread see its stop flag and log out


async def test_monitored_mailboxes_are_not_held_in_idle(
    db: None, server: IdleImapServer
) -> None:
    from envelock.core.enums import MailboxClass
    from envelock.workers import imap_fetch

    await _seed(server.port, mailbox_class=MailboxClass.MONITORED.value)
    try:
        await imap_fetch._reconcile_idle()
        assert imap_fetch._IDLE == {}
    finally:
        imap_fetch._release_idle()


async def test_a_poll_and_an_idle_wakeup_never_sync_one_mailbox_twice(
    db: None, server: IdleImapServer
) -> None:
    """Both can fire for the same arrival. Unserialised, both fetch the same UID
    and both act on it — two quarantine moves, or two banner rewrites."""
    from envelock.core.enums import MailboxClass
    from envelock.workers.imap_fetch import _sync_one

    _, mailbox_id = await _seed(server.port, mailbox_class=MailboxClass.PROTECTED.value)
    server.deliver(FRAUD)
    first, second = await asyncio.gather(_sync_one(mailbox_id), _sync_one(mailbox_id))
    assert first and second and first["ok"] and second["ok"], (first, second)
    assert sorted([first["fetched"], second["fetched"]]) == [0, 1]
    assert server.moved == [1001]
    assert await _alert_count(mailbox_id) == 1
