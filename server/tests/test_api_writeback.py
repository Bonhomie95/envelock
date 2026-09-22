"""Enforcement and real-time push for Gmail- and Graph-connected mailboxes.

Microsoft 365 no longer takes password IMAP, so for most business customers the
API connection is the ONLY connection — and it used to be detection-only: no
quarantine, no protected links, no push. These run the worker against fakes of
the two APIs that keep state the way the real ones do (labels, folders,
subscriptions), so each assertion is about what happened to the mailbox.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from envelock.channels.mail import api_enforce, enforce
from envelock.config import get_settings
from envelock.core.enums import MailboxClass, SourceMechanism
from envelock.models import BankRecord, Counterparty, Domain, Mailbox, Message, Tenant
from envelock.workers import oauth_fetch
from envelock.workers.push_subscriptions import ensure_push

OWNED = "acme.com"


def _bank_change(mid: str) -> bytes:
    return (
        b'From: "Gemini Accounts" <billing@gemini.com>\r\nTo: pay@acme.com\r\n'
        b"Subject: Updated remittance details\r\nMessage-ID: <" + mid.encode()
        + b"@gemini.com>\r\nContent-Type: text/plain\r\n\r\n"
        b"Our bank has changed. Please remit to IBAN GB33BUKB20201555555555\r\n"
        b"from now on. Same-day payment please.\r\n"
    )


def _newsletter(mid: str) -> bytes:
    return (
        b"From: news@shipping-weekly.example\r\nTo: pay@acme.com\r\n"
        b"Subject: This week in freight\r\nMessage-ID: <" + mid.encode()
        + b"@shipping-weekly.example>\r\nContent-Type: text/html\r\n\r\n"
        b'<html><body><p>Read <a href="https://shipping-weekly.example/issue/42">'
        b"issue 42</a>.</p></body></html>\r\n"
    )


# ── Fake Gmail ───────────────────────────────────────────────────────────────
class FakeGmail:
    def __init__(self, messages: dict[str, bytes]) -> None:
        self.msgs = {
            mid: {"raw": raw, "labelIds": ["INBOX", "UNREAD"], "threadId": f"t-{mid}"}
            for mid, raw in messages.items()
        }
        self.labels = [{"id": "INBOX", "name": "INBOX"}]
        self.trashed: list[str] = []
        self.calls: list[tuple[str, str]] = []
        self.watch_calls = 0

    # read side (api_fetch.HttpTransport)
    async def get_json(self, url: str, *, headers: dict) -> dict:
        if "/messages?" in url:
            return {"messages": [
                {"id": m} for m, v in self.msgs.items() if "INBOX" in v["labelIds"]
            ]}
        mid = url.split("/messages/")[1].split("?")[0]
        return {"raw": base64.urlsafe_b64encode(self.msgs[mid]["raw"]).decode()}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # pragma: no cover
        raise AssertionError("gmail never fetches bytes")

    # write side (api_enforce.WriteTransport)
    async def request(self, method: str, url: str, *, headers: dict, json=None):  # noqa: A002
        self.calls.append((method, url))
        if url.endswith("/watch"):
            self.watch_calls += 1
            exp = int((datetime.now(UTC) + timedelta(days=7)).timestamp() * 1000)
            return {"historyId": "1", "expiration": str(exp)}
        if url.endswith("/labels") and method == "GET":
            return {"labels": self.labels}
        if url.endswith("/labels") and method == "POST":
            self.labels.append({"id": "Label_Q", "name": json["name"]})
            return {"id": "Label_Q"}
        if url.endswith("/modify"):
            mid = url.split("/messages/")[1].split("/")[0]
            lbl = self.msgs[mid]["labelIds"]
            lbl[:] = [x for x in lbl if x not in json["removeLabelIds"]] + json["addLabelIds"]
            return {}
        if "format=minimal" in url:
            mid = url.split("/messages/")[1].split("?")[0]
            return {"labelIds": list(self.msgs[mid]["labelIds"]),
                    "threadId": self.msgs[mid]["threadId"]}
        if "/messages?internalDateSource" in url:
            new_id = f"copy-{len(self.msgs)}"
            raw = base64.urlsafe_b64decode(json["raw"] + "===")
            self.msgs[new_id] = {"raw": raw, "labelIds": json["labelIds"],
                                 "threadId": json.get("threadId")}
            return {"id": new_id}
        if url.endswith("/trash"):
            mid = url.split("/messages/")[1].split("/")[0]
            self.msgs[mid]["labelIds"] = ["TRASH"]
            self.trashed.append(mid)
            return {}
        raise AssertionError(f"unexpected gmail call {method} {url}")


# ── Fake Graph ───────────────────────────────────────────────────────────────
class FakeGraph:
    def __init__(self, messages: dict[str, bytes], *, attachment_bytes: int = 0) -> None:
        self.mime = dict(messages)
        self.folder_of = dict.fromkeys(messages, "inbox-id")
        self.folders: list[dict] = []
        self.created: list[dict] = []
        self.deleted: list[str] = []
        self.patched: list[tuple[str, dict]] = []
        self.attachment_bytes = attachment_bytes
        self.subscriptions: dict[str, dict] = {}

    async def get_json(self, url: str, *, headers: dict) -> dict:
        return {"value": [{"id": m} for m, f in self.folder_of.items() if f == "inbox-id"]}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:
        return self.mime[url.split("/messages/")[1].split("/$value")[0]]

    async def request(self, method: str, url: str, *, headers: dict, json=None):  # noqa: A002
        if url.endswith("/subscriptions") and method == "POST":
            sid = f"sub-{len(self.subscriptions)}"
            self.subscriptions[sid] = dict(json)
            return {"id": sid, "expirationDateTime": json["expirationDateTime"]}
        if "/subscriptions/" in url and method == "PATCH":
            sid = url.rsplit("/", 1)[1]
            self.subscriptions[sid]["expirationDateTime"] = json["expirationDateTime"]
            return {"id": sid, "expirationDateTime": json["expirationDateTime"]}
        if "/mailFolders?$filter" in url:
            return {"value": list(self.folders)}
        if url.endswith("/mailFolders") and method == "POST":
            self.folders.append({"id": "q-folder", "displayName": json["displayName"]})
            return {"id": "q-folder"}
        if url.endswith("/move"):
            mid = url.split("/messages/")[1].split("/")[0]
            self.folder_of[mid] = json["destinationId"]
            return {"id": mid}
        if "/messages/" in url and "$select=" in url:
            mid = url.split("/messages/")[1].split("?")[0]
            return {
                "subject": "This week in freight",
                "body": {"contentType": "html", "content":
                         '<html><body><a href="https://shipping-weekly.example/issue/42">'
                         "issue 42</a></body></html>"},
                "from": {"emailAddress": {"address": "news@shipping-weekly.example"}},
                "toRecipients": [{"emailAddress": {"address": "pay@acme.com"}}],
                "receivedDateTime": "2026-09-22T10:00:00Z",
                "sentDateTime": "2026-09-22T09:59:00Z",
                "isRead": False,
                "internetMessageId": f"<{mid}@shipping-weekly.example>",
                "parentFolderId": "inbox-id",
                "hasAttachments": self.attachment_bytes > 0,
            }
        if url.endswith("/attachments"):
            return {"value": [{
                "@odata.type": "#microsoft.graph.fileAttachment", "name": "big.pdf",
                "contentType": "application/pdf", "contentBytes": "AAAA",
                "size": self.attachment_bytes,
            }]}
        if "/mailFolders/" in url and url.endswith("/messages") and method == "POST":
            self.created.append(json)
            return {"id": f"copy-{len(self.created)}"}
        if method == "PATCH":
            self.patched.append((url, json))
            return {}
        if url.endswith("/permanentDelete"):
            mid = url.split("/messages/")[1].split("/")[0]
            self.deleted.append(mid)
            self.folder_of.pop(mid, None)
            return {}
        raise AssertionError(f"unexpected graph call {method} {url}")


# ── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def flags(monkeypatch: pytest.MonkeyPatch):
    def _set(**env: str) -> None:
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()

    yield _set
    get_settings.cache_clear()


async def _mailbox(session, provider: str, *, cls=MailboxClass.PROTECTED) -> Mailbox:  # noqa: ANN001
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="Acme", plan="complete", payment_method_ok=True))
    await session.flush()
    session.add(Domain(tenant_id=tenant_id, name=OWNED, registrable_domain=OWNED))
    src = SourceMechanism.GMAIL_API if provider == "google" else SourceMechanism.GRAPH_API
    mailbox = Mailbox(tenant_id=tenant_id, address="pay@acme.com",
                      mailbox_class=cls.value, sources=[src.value])
    session.add(mailbox)
    await session.flush()
    now = datetime.now(UTC)
    cp = Counterparty(tenant_id=tenant_id, registrable_domain="gemini.com",
                      display_name="Gemini", first_seen_at=now - timedelta(days=400),
                      last_seen_at=now - timedelta(days=1), message_count=40,
                      verified_phone="+18030000000")
    session.add(cp)
    await session.flush()
    session.add(BankRecord(tenant_id=tenant_id, counterparty_id=cp.id, scheme="iban",
                           identifier="GB94BARC10201530093459",
                           first_seen_at=now - timedelta(days=300),
                           verified_at=now - timedelta(days=300)))
    await session.commit()
    return mailbox


@pytest.fixture
def token(monkeypatch: pytest.MonkeyPatch):
    def _use(provider: str) -> None:
        async def _tok(session, mailbox_id):  # noqa: ANN001, ARG001
            return ("access-token", provider)

        monkeypatch.setattr(oauth_fetch, "current_access_token", _tok)
        from envelock.workers import push_subscriptions

        monkeypatch.setattr(push_subscriptions, "current_access_token", _tok)

    return _use


# ── Gmail ────────────────────────────────────────────────────────────────────
async def test_gmail_critical_leaves_the_inbox_under_the_quarantine_label(
    session, token  # noqa: ANN001
) -> None:
    token("google")
    mailbox = await _mailbox(session, "google")
    gmail = FakeGmail({"m1": _bank_change("m1")})

    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )

    assert summary["alerted"] == 1
    assert summary["quarantined"] == 1
    assert "INBOX" not in gmail.msgs["m1"]["labelIds"]
    assert "Label_Q" in gmail.msgs["m1"]["labelIds"]
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id))).scalars().one()
    assert stored.quarantined_at is not None
    assert stored.source_ref == "m1"


async def test_gmail_protected_copy_replaces_the_original_once(
    session, token, flags  # noqa: ANN001
) -> None:
    token("google")
    flags(ENVELOCK_GMAIL_REWRITE_ENABLED="true")
    mailbox = await _mailbox(session, "google")
    gmail = FakeGmail({"n1": _newsletter("n1")})

    first = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert first["rewritten"] == 1
    assert gmail.trashed == ["n1"]
    copy_id = next(m for m in gmail.msgs if m.startswith("copy-"))
    copy = gmail.msgs[copy_id]
    assert "INBOX" in copy["labelIds"] and copy["threadId"] == "t-n1"
    assert b"/r/" in copy["raw"] and b"shipping-weekly.example/issue/42" not in copy["raw"]
    assert enforce.is_processed(copy["raw"])

    # The next cycle sees our copy in the inbox and leaves it alone.
    second = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert second["rewritten"] == 0
    assert len([m for m in gmail.msgs if m.startswith("copy-")]) == 1


async def test_rewrite_stays_off_until_switched_on(session, token) -> None:  # noqa: ANN001
    token("google")
    mailbox = await _mailbox(session, "google")
    gmail = FakeGmail({"n1": _newsletter("n1")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert summary["rewritten"] == 0
    assert not [c for c in gmail.calls if c[0] == "POST"]


async def test_a_monitored_mailbox_is_never_written_to(
    session, token, flags  # noqa: ANN001
) -> None:
    token("google")
    flags(ENVELOCK_GMAIL_REWRITE_ENABLED="true")
    mailbox = await _mailbox(session, "google", cls=MailboxClass.MONITORED)
    gmail = FakeGmail({"m1": _bank_change("m1"), "n1": _newsletter("n1")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert summary["alerted"] == 1
    assert summary["quarantined"] == 0 and summary["rewritten"] == 0
    assert gmail.calls == []


async def test_a_quarantine_click_is_carried_out_on_the_api_mailbox(
    session, token  # noqa: ANN001
) -> None:
    token("google")
    mailbox = await _mailbox(session, "google")
    gmail = FakeGmail({"n1": _newsletter("n1")})
    await oauth_fetch.sync_oauth_mailbox(session, mailbox, transport=gmail, write_transport=gmail)
    stored = (await session.execute(
        select(Message).where(Message.mailbox_id == mailbox.id))).scalars().one()
    stored.quarantine_requested_at = datetime.now(UTC)
    await session.commit()

    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=gmail, write_transport=gmail
    )
    assert summary["quarantined"] == 1
    assert "INBOX" not in gmail.msgs["n1"]["labelIds"]
    await session.refresh(stored)
    assert stored.quarantined_at is not None and stored.quarantine_requested_at is None


# ── Microsoft Graph ──────────────────────────────────────────────────────────
async def test_graph_critical_moves_to_the_quarantine_folder(session, token) -> None:  # noqa: ANN001
    token("microsoft")
    mailbox = await _mailbox(session, "microsoft")
    graph = FakeGraph({"g1": _bank_change("g1")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=graph, write_transport=graph
    )
    assert summary["quarantined"] == 1
    assert graph.folders[0]["displayName"] == api_enforce.QUARANTINE_NAME
    assert graph.folder_of["g1"] == "q-folder"


async def test_graph_protected_copy_is_a_real_message_not_a_draft(
    session, token, flags  # noqa: ANN001
) -> None:
    token("microsoft")
    flags(ENVELOCK_GRAPH_REWRITE_ENABLED="true")
    mailbox = await _mailbox(session, "microsoft")
    graph = FakeGraph({"g2": _newsletter("g2")})
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=graph, write_transport=graph
    )
    assert summary["rewritten"] == 1
    copy = graph.created[0]
    props = {p["id"]: p["value"] for p in copy["singleValueExtendedProperties"]}
    assert props["Integer 0x0E07"] == "1"  # not MSGFLAG_UNSENT → not a draft
    assert props["SystemTime 0x0E06"] == "2026-09-22T10:00:00Z"  # delivery time kept
    assert copy["internetMessageId"] == "<g2@shipping-weekly.example>"  # threading kept
    assert "/r/" in copy["body"]["content"]
    assert "shipping-weekly.example/issue/42" not in copy["body"]["content"]
    header = copy["internetMessageHeaders"][0]
    assert header["name"] == enforce.PROCESSED_HEADER
    assert graph.deleted == ["g2"]
    assert graph.patched and graph.patched[0][1] == {"isRead": False}


async def test_graph_leaves_a_message_it_cannot_copy_faithfully(
    session, token, flags  # noqa: ANN001
) -> None:
    token("microsoft")
    flags(ENVELOCK_GRAPH_REWRITE_ENABLED="true")
    mailbox = await _mailbox(session, "microsoft")
    graph = FakeGraph({"g3": _newsletter("g3")}, attachment_bytes=5 * 1024 * 1024)
    summary = await oauth_fetch.sync_oauth_mailbox(
        session, mailbox, transport=graph, write_transport=graph
    )
    assert summary["rewritten"] == 0
    assert graph.created == [] and graph.deleted == []


# ── Push ─────────────────────────────────────────────────────────────────────
async def test_graph_subscription_is_created_then_renewed(session, token, flags) -> None:  # noqa: ANN001
    token("microsoft")
    flags(ENVELOCK_MS_WEBHOOK_URL="https://api.envelock.test/api/v1/webhooks/graph")
    mailbox = await _mailbox(session, "microsoft")
    graph = FakeGraph({})

    assert await ensure_push(session, mailbox, transport=graph) is True
    sub = graph.subscriptions["sub-0"]
    assert sub["changeType"] == "created"
    assert sub["resource"] == "users/pay@acme.com/mailFolders('inbox')/messages"
    assert mailbox.push_subscription_id == "sub-0"

    # Plenty of time left: nothing to do.
    assert await ensure_push(session, mailbox, transport=graph) is False
    # Under a day left: renewed in place, not a second subscription.
    later = datetime.now(UTC) + timedelta(days=2, hours=12)
    assert await ensure_push(session, mailbox, transport=graph, now=later) is True
    assert list(graph.subscriptions) == ["sub-0"]
    assert mailbox.push_expires_at > later + timedelta(days=2)


async def test_gmail_watch_is_registered(session, token, flags) -> None:  # noqa: ANN001
    token("google")
    flags(ENVELOCK_GOOGLE_PUBSUB_TOPIC="projects/envelock/topics/gmail")
    mailbox = await _mailbox(session, "google")
    gmail = FakeGmail({})
    assert await ensure_push(session, mailbox, transport=gmail) is True
    assert gmail.watch_calls == 1
    assert mailbox.push_subscription_id == "gmail-watch"
    assert mailbox.push_expires_at > datetime.now(UTC) + timedelta(days=6)


async def test_a_push_flags_the_mailbox_and_the_worker_drains_it(
    session, client, monkeypatch  # noqa: ANN001
) -> None:
    """The receiver runs in the API, which can't decrypt tokens: it must flag,
    not fetch — and the worker's fast loop must pick the flag up."""
    from envelock.security.webhook_auth import push_token

    mailbox = await _mailbox(session, "google")
    try:
        data = base64.b64encode(
            json.dumps({"emailAddress": "pay@acme.com", "historyId": 7}).encode()
        ).decode()
        r = client.post(f"/api/v1/webhooks/gmail?token={push_token()}",
                        json={"message": {"data": data}})
        assert r.status_code == 202
        await session.refresh(mailbox)
        assert mailbox.sync_requested_at is not None

        synced: list = []

        async def _fake(session, mb, *, transport=None, write_transport=None):  # noqa: ANN001, ARG001
            synced.append(mb.id)
            return {"ok": True, "fetched": 1}

        monkeypatch.setattr(oauth_fetch, "sync_oauth_mailbox", _fake)
        totals = await oauth_fetch.drain_requested()
        assert synced == [mailbox.id] and totals["mailboxes"] == 1
    finally:
        # End our transaction even on failure: the client fixture's teardown
        # drops tables and would wait forever on an open transaction's lock.
        await session.commit()
