"""Feature 1 — link safety: rewriting, write-back enforcement, click-time redirect.

Covers the full chain: URL selection → token minting → protected-copy building
→ IMAP replace → the /r/{token} redirector's three verdict paths → the worker
doing all of it end-to-end against a fake IMAP server.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail import enforce, imap_sync
from envelock.channels.mail.enforce import Banner, build_protected_copy, is_processed
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.models import (
    Domain,
    LinkClick,
    LinkToken,
    Mailbox,
    MailboxCredential,
    Message,
    Tenant,
)
from envelock.platform.links import mint_link_tokens, rewritable_urls
from envelock.security.crypto import seal
from envelock.workers.imap_fetch import sync_mailbox

BASE = "http://localhost:8010"


# ── URL selection ─────────────────────────────────────────────────────────────
def test_rewritable_urls_filters_owned_unsubscribe_and_own_redirector():
    urls = [
        "https://evil.example.com/pay",
        "https://acme.com/portal",  # tenant's own domain — never rewritten
        "https://news.example.com/unsubscribe?u=1",  # unsubscribe — never
        f"{BASE}/r/sometoken",  # already ours — never
        "https://evil.example.com/pay",  # duplicate — once
    ]
    out = rewritable_urls(urls, owned_domains=frozenset({"acme.com"}), redirect_base=BASE)
    assert out == ["https://evil.example.com/pay"]


# ── Protected-copy building ───────────────────────────────────────────────────
_RAW_MULTIPART = (
    b"From: vendor@partner.com\r\n"
    b"To: pay@acme.com\r\n"
    b"Subject: invoice\r\n"
    b"Message-ID: <keepme@partner.com>\r\n"
    b'Content-Type: multipart/alternative; boundary="b1"\r\n\r\n'
    b"--b1\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Pay at https://evil.example.com/pay please.\r\n"
    b"--b1\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b'<html><body><a href="https://evil.example.com/pay">pay</a></body></html>\r\n'
    b"--b1--\r\n"
)


def test_build_protected_copy_rewrites_links_and_injects_banner():
    link_map = {"https://evil.example.com/pay": "tok123"}
    banner = Banner(severity="critical", title="Bank detail changed", lines=("A1 fired",))
    out = build_protected_copy(
        _RAW_MULTIPART, link_map=link_map, redirect_base=BASE, banner=banner
    )

    text = out.decode("utf-8", "replace")
    assert "evil.example.com" not in text.replace("=\r\n", "")  # gone from both parts
    assert f"{BASE}/r/tok123" in text.replace("=\r\n", "")
    assert "Bank detail changed" in text
    assert "Message-ID: <keepme@partner.com>" in text  # threading survives
    assert is_processed(out)
    assert not is_processed(_RAW_MULTIPART)


def test_build_protected_copy_without_banner_only_rewrites():
    out = build_protected_copy(
        _RAW_MULTIPART,
        link_map={"https://evil.example.com/pay": "tok9"},
        redirect_base=BASE,
        banner=None,
    )
    text = out.decode("utf-8", "replace").replace("=\r\n", "")
    assert f"{BASE}/r/tok9" in text
    assert "Protected by Envelock" not in text.split("/r/tok9")[0].split("\r\n\r\n")[0]


# ── IMAP replace ──────────────────────────────────────────────────────────────
class FakeImap:
    def __init__(self, messages: dict[int, bytes]) -> None:
        self.messages = dict(messages)
        self.appended: list[tuple[str, bytes, tuple]] = []
        self.folders = {"INBOX"}
        self.moved: list[tuple[int, str]] = []
        self.uidvalidity = 7

    def login(self, u, p):  # noqa: ANN001
        pass

    def oauth2_login(self, u, t):  # noqa: ANN001
        pass

    def starttls(self):
        pass

    def logout(self):
        pass

    def select_folder(self, folder, readonly=False):  # noqa: ANN001
        return {b"UIDVALIDITY": self.uidvalidity}

    def search(self, criteria):  # noqa: ANN001
        uids = sorted(self.messages)
        if criteria and criteria[0] == "UID":
            lo = int(str(criteria[1]).split(":", 1)[0])
            hits = [u for u in uids if u >= lo]
            return hits or ([uids[-1]] if uids else [])
        return uids

    def fetch(self, messages, data):  # noqa: ANN001
        out = {}
        for uid in messages:
            if uid not in self.messages:
                continue
            entry = {}
            # The poller asks for BODY.PEEK[] (never RFC822, which marks mail
            # read); a real server answers it under the name BODY[].
            if "BODY.PEEK[]" in data:
                entry[b"BODY[]"] = self.messages[uid]
            if "RFC822" in data:
                entry[b"RFC822"] = self.messages[uid]
            if "FLAGS" in data:
                entry[b"FLAGS"] = (b"\\Seen", b"\\Recent")
            if "INTERNALDATE" in data:
                entry[b"INTERNALDATE"] = None
            out[uid] = entry
        return out

    def folder_exists(self, folder):  # noqa: ANN001
        return folder in self.folders

    def create_folder(self, folder):  # noqa: ANN001
        self.folders.add(folder)

    def capabilities(self):
        return (b"IMAP4REV1", b"MOVE")

    def move(self, messages, folder):  # noqa: ANN001
        for uid in messages:
            if uid in self.messages:
                self.moved.append((uid, folder))
                del self.messages[uid]

    def copy(self, messages, folder):  # noqa: ANN001
        for uid in messages:
            self.moved.append((uid, folder))

    def delete_messages(self, messages):  # noqa: ANN001
        for uid in messages:
            self.messages.pop(uid, None)

    def expunge(self, messages=None):  # noqa: ANN001
        pass

    def append(self, folder, msg, flags=(), msg_time=None):  # noqa: ANN001
        self.appended.append((folder, bytes(msg), tuple(flags)))
        self.messages[max(self.messages, default=0) + 1000] = bytes(msg)


def _factory(client):  # noqa: ANN001
    def factory(*, host, port, security, timeout):  # noqa: ANN001
        return client

    return factory


def test_replace_message_appends_first_then_deletes():
    client = FakeImap({5: _RAW_MULTIPART})
    ok = imap_sync.replace_message(
        host="imap.test", port=993, security="ssl", username="u",
        password="p",  # noqa: S106 — test fixture, not a credential
        uid=5, raw=b"new-bytes", client_factory=_factory(client),
    )
    assert ok is True
    assert client.appended[0][0] == "INBOX"
    assert client.appended[0][1] == b"new-bytes"
    # \Recent must not be replayed into APPEND; \Seen must survive.
    assert client.appended[0][2] == (b"\\Seen",)
    assert 5 not in client.messages  # original gone


# ── Worker end-to-end: clean mail gets its links rewritten ────────────────────
async def _protected_mailbox(session):  # noqa: ANN001
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="Acme", plan="complete", payment_method_ok=True))
    await session.flush()
    session.add(Domain(tenant_id=tenant_id, name="acme.com", registrable_domain="acme.com"))
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=MailboxClass.PROTECTED.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mailbox)
    await session.flush()
    sealed = seal(b"app-password", aad=str(mailbox.id).encode())
    session.add(
        MailboxCredential(
            mailbox_id=mailbox.id,
            tenant_id=tenant_id,
            kind="imap_password",
            imap_host="imap.acme.com",
            imap_port=993,
            imap_security="ssl",
            ciphertext=sealed.ciphertext,
            wrapped_dek=sealed.wrapped_dek,
            key_id=sealed.key_id,
        )
    )
    await session.flush()
    return mailbox


_CLEAN_WITH_LINK = (
    b"From: jane@partner.com\r\n"
    b"To: pay@acme.com\r\n"
    b"Subject: notes\r\n"
    b"Message-ID: <clean1@partner.com>\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Doc is at https://docs.partner.com/spec - thanks!\r\n"
)


@pytest.mark.asyncio
async def test_worker_rewrites_links_in_clean_mail(session):
    mailbox = await _protected_mailbox(session)
    client = FakeImap({11: _CLEAN_WITH_LINK})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory(client))

    assert summary["ok"] is True
    assert summary["alerted"] == 0
    assert summary["rewritten"] == 1
    # The copy on the "server" carries the rewritten link and our stamp.
    appended = client.appended[0][1].decode("utf-8", "replace").replace("=\r\n", "")
    assert "/r/" in appended
    assert "docs.partner.com" not in appended
    assert enforce.PROCESSED_HEADER in appended
    # And a LinkToken row exists pointing back at the original URL.
    tokens = (
        (await session.execute(select(LinkToken).where(LinkToken.tenant_id == mailbox.tenant_id)))
        .scalars()
        .all()
    )
    assert [t.original_url for t in tokens] == ["https://docs.partner.com/spec"]
    msg_ids = {t.message_id for t in tokens}
    stored = (
        (await session.execute(select(Message.id).where(Message.tenant_id == mailbox.tenant_id)))
        .scalars()
        .all()
    )
    assert msg_ids == set(stored)


@pytest.mark.asyncio
async def test_worker_skips_our_own_copies(session):
    mailbox = await _protected_mailbox(session)
    processed = build_protected_copy(
        _CLEAN_WITH_LINK, link_map={}, redirect_base=BASE, banner=None
    )
    client = FakeImap({12: processed})

    summary = await sync_mailbox(session, mailbox, client_factory=_factory(client))

    assert summary["ok"] is True
    assert summary["rewritten"] == 0
    assert client.appended == []  # nothing re-written, no APPEND loop


# ── Feature 2 end-to-end: the changed-bank-detail attack through the worker ──
_BANK_CHANGE = (
    b"From: accounts@partner.com\r\n"
    b"To: pay@acme.com\r\n"
    b"Subject: Re: Invoice 2296-002 - new bank details\r\n"
    b"Message-ID: <bankchange@partner.com>\r\n"
    b"Content-Type: text/plain\r\n\r\n"
    b"Please note our new bank account for this invoice payment:\r\n"
    b"IBAN GB33BUKB20201555555555. Kindly remit at your earliest.\r\n"
)


@pytest.mark.asyncio
async def test_worker_flags_and_quarantines_a_changed_bank_detail(session):
    """The differentiator: the REAL vendor address, clean links, valid headers —
    only the IBAN differs from the ledger. Must go Critical and leave the inbox."""
    from datetime import UTC, datetime

    from envelock.models import Alert, BankRecord, Counterparty

    mailbox = await _protected_mailbox(session)
    now = datetime.now(UTC)
    cp = Counterparty(
        tenant_id=mailbox.tenant_id,
        registrable_domain="partner.com",
        first_seen_at=now,
        last_seen_at=now,
        message_count=14,
        known_dkim_domains=["partner.com"],
        known_mail_clients=[],
        verified_phone="+886-2-5555-0100",
    )
    session.add(cp)
    await session.flush()
    session.add(
        BankRecord(
            tenant_id=mailbox.tenant_id,
            counterparty_id=cp.id,
            scheme="iban",
            identifier="GB94BARC10201530093459",
            first_seen_at=now,
            is_active=True,
        )
    )
    await session.flush()

    client = FakeImap({21: _BANK_CHANGE})
    summary = await sync_mailbox(session, mailbox, client_factory=_factory(client))

    assert summary["ok"] is True
    assert summary["alerted"] == 1
    assert summary["quarantined"] == 1
    assert summary["alerts"][0]["tier"] == "critical"

    alert = (
        (await session.execute(select(Alert).where(Alert.tenant_id == mailbox.tenant_id)))
        .scalars()
        .one()
    )
    assert alert.tier == "critical"
    # The callback number comes from the LEDGER, never from the current email —
    # the whole attack is that the attacker supplies the "verification" number.
    assert alert.requires_callback is True
    assert alert.callback_phone == "+886-2-5555-0100"


# ── The redirector endpoint ───────────────────────────────────────────────────
def _mint_token_sync() -> str:
    """Seed a LinkToken via its own event loop (suite pattern for client tests)."""
    import asyncio

    async def _mint() -> str:
        from conftest import platform_sessionmaker as get_sessionmaker

        from envelock.db import dispose

        async with get_sessionmaker()() as session:
            tenant_id = uuid4()
            session.add(Tenant(id=tenant_id, name="Acme", plan="complete", payment_method_ok=True))
            await session.flush()
            mapping = await mint_link_tokens(
                session,
                ["https://destination.example.com/page"],
                tenant_id=tenant_id,
                mailbox_id=None,
                message_id=None,
            )
            await session.commit()
            token = mapping["https://destination.example.com/page"]
        await dispose()
        return token

    return asyncio.run(_mint())


def _click_actions() -> list[str]:
    import asyncio

    async def _read() -> list[str]:
        from conftest import platform_sessionmaker as get_sessionmaker

        from envelock.db import dispose

        async with get_sessionmaker()() as session:
            rows = (await session.execute(select(LinkClick))).scalars().all()
            actions = [c.action for c in rows]
        await dispose()
        return actions

    return asyncio.run(_read())


def test_redirector_unknown_url_302s_and_logs_click(client):
    token = _mint_token_sync()
    resp = client.get(f"/r/{token}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://destination.example.com/page"
    assert _click_actions() == ["allowed"]


def test_redirector_blocks_malicious(client, monkeypatch):
    token = _mint_token_sync()

    async def fake_eval(url):  # noqa: ANN001
        return "malicious", ["on a threat feed"]

    monkeypatch.setattr("envelock.api.redirect.evaluate_url", fake_eval)
    resp = client.get(f"/r/{token}", follow_redirects=False)
    assert resp.status_code == 403
    assert "Dangerous link blocked" in resp.text
    assert "destination.example.com" in resp.text
    # No bypass: a block page offers no continue link.
    assert "?go=1" not in resp.text


def test_redirector_interstitial_then_continue(client, monkeypatch):
    token = _mint_token_sync()

    async def fake_eval(url):  # noqa: ANN001
        return "suspicious", ["link shortener hides the destination"]

    monkeypatch.setattr("envelock.api.redirect.evaluate_url", fake_eval)
    warned = client.get(f"/r/{token}", follow_redirects=False)
    assert warned.status_code == 200
    assert "Check before you continue" in warned.text
    assert "?go=1" in warned.text

    through = client.get(f"/r/{token}?go=1", follow_redirects=False)
    assert through.status_code == 302
    assert through.headers["location"] == "https://destination.example.com/page"


def test_redirector_unknown_token_is_a_404_page(client):
    resp = client.get("/r/not-a-real-token")
    assert resp.status_code == 404
    assert "not recognised" in resp.text


# ── Focus mode ────────────────────────────────────────────────────────────────
def test_focus_mode_mounts_core_and_parks_only_the_operator_console(monkeypatch):
    """What `focus_core` may and may not switch off.

    It used to park the billing router. Combined with the client's `/billing`
    route being commented out, that meant the DEFAULT deployment had no path by
    which a customer could pay: a trial starts at registration on the top plan and
    drops to Guard after fifteen days, the upgrade handler receives 402, and it
    sent the customer to a page that did not exist. Billing is core.

    Governance is core for a smaller but equally silent reason: the dashboard
    reads `/api/v1/metrics/quality` from that router, so with it unmounted the
    quality panel 404'd and rendered nothing on every production deployment.

    What `focus_core` legitimately parks is the operator console — a separate app
    on a separate hostname for Envelock's own staff, whose absence costs a
    customer nothing.
    """
    from fastapi.testclient import TestClient

    from envelock.config import get_settings
    from envelock.main import create_app

    monkeypatch.setenv("ENVELOCK_FOCUS_CORE", "true")
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        assert c.get("/health").status_code == 200
        # Core surface answers (401/404-page, not route-missing 404 with no body).
        assert c.get("/r/xyz").status_code == 404
        assert "not recognised" in c.get("/r/xyz").text

        # The revenue path is mounted. 401, not 404: the route exists and is
        # asking for authentication, which is the distinction that matters.
        assert c.post("/api/v1/billing/portal").status_code in (401, 403)
        assert c.post("/api/v1/billing/checkout", json={}).status_code in (401, 403, 422)
        # And the panel the dashboard reads.
        assert c.get("/api/v1/metrics/quality").status_code in (401, 403)

        # The operator console stays parked.
        assert c.post("/api/v1/admin/auth/login", json={}).status_code == 404
    get_settings.cache_clear()


# ── Poll-side seat cap: protection stops when entitlement does ────────────────
def test_entitled_mailboxes_lapsed_trial_and_capacity():
    from datetime import UTC, datetime, timedelta

    from envelock.billing.entitlement import entitled_mailboxes

    now = datetime.now(UTC)
    lapsed = Tenant(
        id=uuid4(), name="Lapsed", plan="complete",
        trial_started_at=now - timedelta(days=30),
        trial_ends_at=now - timedelta(days=15),
        payment_method_ok=False,
    )
    boxes = [Mailbox(id=uuid4(), tenant_id=lapsed.id, address=f"u{i}@x.com") for i in range(2)]
    # Lapsed unpaid → Guard → zero mailboxes keep protection.
    assert entitled_mailboxes(lapsed, boxes) == []

    solo = Tenant(id=uuid4(), name="Solo", plan="solo", payment_method_ok=True)
    a = Mailbox(
        id=uuid4(), tenant_id=solo.id, address="a@x.com", created_at=now - timedelta(days=2)
    )
    b = Mailbox(
        id=uuid4(), tenant_id=solo.id, address="b@x.com", created_at=now - timedelta(days=1)
    )
    # Solo pays for 1 seat but has 2 connected (downgrade): oldest keeps it.
    assert entitled_mailboxes(solo, [b, a]) == [a]


@pytest.mark.asyncio
async def test_poll_cycle_skips_lapsed_trial_tenants(session):
    from datetime import UTC, datetime, timedelta

    from envelock.workers.imap_fetch import run_imap_poll_cycle

    mailbox = await _protected_mailbox(session)
    # Lapse the tenant: trial over, never paid.
    tenant = await session.get(Tenant, mailbox.tenant_id)
    tenant.payment_method_ok = False
    tenant.trial_started_at = datetime.now(UTC) - timedelta(days=30)
    tenant.trial_ends_at = datetime.now(UTC) - timedelta(days=15)
    await session.commit()

    client = FakeImap({31: _CLEAN_WITH_LINK})
    totals = await run_imap_poll_cycle(client_factory=_factory(client))

    assert totals["mailboxes"] == 0  # not polled at all
    assert client.appended == []


# ── Edge fallback (links that survive an origin outage) ──────────────────────
def test_edge_payload_matches_the_worker_vectors(monkeypatch):
    """The Cloudflare worker (deploy/edge/) verifies what this signs. Both sides
    run against the same vectors file, so a drift on either side fails a test."""
    import json
    import pathlib

    from envelock.config import get_settings
    from envelock.platform.links import link_path

    vectors = json.loads(
        (pathlib.Path(__file__).parents[1] / "deploy/edge/test-vectors.json").read_text()
    )
    monkeypatch.setenv("ENVELOCK_LINK_EDGE_SECRET", vectors["secret"])
    get_settings.cache_clear()
    try:
        for case in vectors["cases"]:
            assert "/r/" + link_path(case["token"], case["url"]) == case["path"]
    finally:
        get_settings.cache_clear()


def test_without_an_edge_secret_links_stay_plain(monkeypatch):
    from envelock.config import get_settings
    from envelock.platform.links import link_path

    monkeypatch.delenv("ENVELOCK_LINK_EDGE_SECRET", raising=False)
    get_settings.cache_clear()
    assert link_path("tok", "https://a.example/") == "tok"


def test_the_origin_resolves_a_link_with_its_fallback_segment(client, monkeypatch):
    from envelock.config import get_settings

    monkeypatch.setenv("ENVELOCK_LINK_EDGE_SECRET", "edge-secret")
    get_settings.cache_clear()
    try:
        path = _mint_token_sync()
    finally:
        get_settings.cache_clear()
    assert "/" in path  # token/payload.sig
    resp = client.get(f"/r/{path}", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://destination.example.com/page"
