"""The wrong-mailbox safeguard: resolve the inbox a token really reads, and
surface a mismatch against the label the customer typed (no DB needed)."""

from __future__ import annotations

from envelock.api.tenants import _mailbox_payload
from envelock.channels.mail.api_fetch import gmail_whoami, graph_whoami
from envelock.models import Mailbox


class _Who:
    def __init__(self, body: dict) -> None:
        self.body = body

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        return self.body

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        return b""


async def test_graph_whoami_prefers_mail_then_upn() -> None:
    assert await graph_whoami(
        access_token="t", transport=_Who({"mail": "Admin@Cyberlex.store"})  # noqa: S106
    ) == "admin@cyberlex.store"
    # No mailbox address → fall back to the UPN (the .onmicrosoft identity).
    assert await graph_whoami(
        access_token="t",  # noqa: S106
        transport=_Who({"mail": None, "userPrincipalName": "admin@cybergrace.onmicrosoft.com"}),
    ) == "admin@cybergrace.onmicrosoft.com"


async def test_gmail_whoami_reads_profile() -> None:
    assert await gmail_whoami(
        access_token="t", transport=_Who({"emailAddress": "Ops@Example.com"})  # noqa: S106
    ) == "ops@example.com"


def test_payload_flags_a_mismatch() -> None:
    wrong = Mailbox(
        address="admin@cyberlex.store",
        connected_address="admin@cybergrace.onmicrosoft.com",
        mailbox_class="protected",
        sources=[],
    )
    p = _mailbox_payload(wrong)
    assert p["address_mismatch"] is True
    assert p["connected_address"] == "admin@cybergrace.onmicrosoft.com"


def test_payload_no_mismatch_when_equal_or_unknown() -> None:
    same = Mailbox(
        address="a@b.com", connected_address="A@B.com", mailbox_class="protected", sources=[]
    )
    assert _mailbox_payload(same)["address_mismatch"] is False
    unknown = Mailbox(
        address="a@b.com", connected_address=None, mailbox_class="protected", sources=[]
    )
    assert _mailbox_payload(unknown)["address_mismatch"] is False
