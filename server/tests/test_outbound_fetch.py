"""The Sent-folder readers that feed A12/C5 (no DB).

Proves each provider path actually pulls the owner's sent mail: Graph from the
Sent Items folder, Gmail via `in:sent`, and IMAP by resolving whatever the
server calls its Sent folder.
"""

from __future__ import annotations

import base64

from envelock.channels.mail import imap_sync
from envelock.channels.mail.api_fetch import gmail_fetch_outbound, graph_fetch_outbound


class _GraphTransport:
    def __init__(self) -> None:
        self.listed_url = ""

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        self.listed_url = url
        return {"value": [{"id": "s1"}, {"id": "s2"}]}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return f"raw-of-{url.rsplit('/', 2)[-2]}".encode()


class _GmailTransport:
    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        if "format=raw" in url:
            mid = url.rsplit("/", 1)[-1].split("?", 1)[0]
            raw = base64.urlsafe_b64encode(f"raw-{mid}".encode()).decode()
            return {"raw": raw}
        assert "in%3Asent" in url or "in:sent" in url, f"not a sent query: {url}"
        return {"messages": [{"id": "g1"}, {"id": "g2"}]}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return b""


async def test_graph_outbound_reads_sent_items() -> None:
    t = _GraphTransport()
    out = await graph_fetch_outbound(access_token="t", transport=t)  # noqa: S106
    assert "sentitems" in t.listed_url, t.listed_url
    assert [m.ref for m in out] == ["s1", "s2"]
    assert out[0].raw == b"raw-of-s1"  # fetched from /me/messages/s1/$value


async def test_gmail_outbound_uses_in_sent() -> None:
    out = await gmail_fetch_outbound(access_token="t", transport=_GmailTransport())  # noqa: S106
    assert [m.ref for m in out] == ["g1", "g2"]
    assert out[0].raw == b"raw-g1"


class _FakeImap:
    def __init__(self, folders, messages) -> None:  # noqa: ANN001
        self.folders = set(folders)
        self.messages = dict(messages)  # uid -> raw
        self.selected: str | None = None

    def login(self, username, password) -> None:  # noqa: ANN001
        pass

    def logout(self) -> None:
        pass

    def folder_exists(self, folder: str) -> bool:
        return folder in self.folders

    def select_folder(self, folder: str, readonly: bool = False) -> dict:  # noqa: ARG002
        self.selected = folder
        return {b"UIDVALIDITY": 1}

    def search(self, criteria):  # noqa: ANN001, ARG002
        return sorted(self.messages)

    def fetch(self, messages, data):  # noqa: ANN001, ARG002
        return {uid: {b"BODY[]": self.messages[uid]} for uid in messages}


def _factory_for(client):  # noqa: ANN001, ANN202
    def factory(*, host, port, security, timeout):  # noqa: ANN001, ANN003, ARG001
        return client

    return factory


def test_imap_fetch_sent_resolves_the_sent_folder() -> None:
    client = _FakeImap({"INBOX", "Sent"}, {1: b"older", 2: b"newer"})
    result = imap_sync.fetch_sent(
        host="h", port=993, security="ssl", username="u", password="p",  # noqa: S106
        client_factory=_factory_for(client),
    )
    assert result.ok
    assert client.selected == "Sent"
    # Newest first — C5 reads the latest signature.
    assert [m.raw for m in result.messages] == [b"newer", b"older"]


def test_imap_fetch_sent_is_a_noop_without_a_sent_folder() -> None:
    client = _FakeImap({"INBOX"}, {1: b"x"})
    result = imap_sync.fetch_sent(
        host="h", port=993, security="ssl", username="u", password="p",  # noqa: S106
        client_factory=_factory_for(client),
    )
    assert result.ok
    assert result.messages == []
