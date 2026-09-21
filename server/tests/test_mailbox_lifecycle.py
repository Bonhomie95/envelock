"""Changing a mailbox without destroying it, and E13 metadata-only mode."""

from __future__ import annotations

import asyncio
import time

from fastapi.testclient import TestClient
from sqlalchemy import select

from envelock.auth.security import _totp_at
from envelock.db import get_sessionmaker
from envelock.models import Message, Tenant


def _session(client: TestClient, email: str, tenant: str) -> dict[str, str]:
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": pw, "tenant_name": tenant},
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    return {"Authorization": f"Bearer {tokens['access_token']}"}


def test_promoting_a_mailbox_keeps_its_credential_and_history(
    client: TestClient, monkeypatch
) -> None:
    """Monitored → Protected used to mean delete-and-re-add, which threw away the
    stored credential, the sync cursor and the alert history — and made the
    customer re-enter a password in order to buy an upgrade."""
    from envelock.channels.mail import imap_probe

    monkeypatch.setattr(
        imap_probe,
        "try_login",
        lambda candidate, *, username, **_: imap_probe.Attempt(
            candidate, username, ok=True
        ),
    )

    h = _session(client, "it@promote.example", "Promote")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Promote", "domain": "promote.example"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ap@promote.example", "mailbox_class": "monitored"},
        headers=h,
    ).json()

    connected = client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap",
        json={"imap_host": "imap.promote.example", "imap_port": 993, "password": "pw"},
        headers=h,
    ).json()
    assert "imap_poll" in connected["sources"], "Monitored polls"

    promoted = client.patch(
        f"/api/v1/mailboxes/{mb['id']}",
        json={"mailbox_class": "protected"},
        headers=h,
    )
    assert promoted.status_code == 200, promoted.text
    body = promoted.json()
    assert body["mailbox_class"] == "protected"
    # The class IS the IMAP strategy, so the source has to move with it —
    # otherwise a "Protected" mailbox would keep polling and never quarantine.
    assert "imap_idle" in body["sources"]
    assert "imap_poll" not in body["sources"]
    # And the protection level is re-derived, not left stale.
    assert body["protection_level"] in {"standard", "full"}


def test_demoting_moves_the_strategy_back(client: TestClient, monkeypatch) -> None:
    from envelock.channels.mail import imap_probe

    monkeypatch.setattr(
        imap_probe,
        "try_login",
        lambda candidate, *, username, **_: imap_probe.Attempt(
            candidate, username, ok=True
        ),
    )
    h = _session(client, "it@demote.example", "Demote")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Demote", "domain": "demote.example"},
        headers=h,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ap@demote.example", "mailbox_class": "protected"},
        headers=h,
    ).json()
    client.post(
        f"/api/v1/mailboxes/{mb['id']}/connect/imap",
        json={"imap_host": "imap.demote.example", "imap_port": 993, "password": "pw"},
        headers=h,
    )
    body = client.patch(
        f"/api/v1/mailboxes/{mb['id']}",
        json={"mailbox_class": "monitored"},
        headers=h,
    ).json()
    assert "imap_poll" in body["sources"] and "imap_idle" not in body["sources"]


def test_a_mailbox_cannot_be_patched_across_tenants(client: TestClient) -> None:
    a = _session(client, "it@patcha.example", "PatchA")
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "PatchA", "domain": "patcha.example"},
        headers=a,
    )
    mb = client.post(
        "/api/v1/mailboxes",
        json={"address": "ap@patcha.example", "mailbox_class": "monitored"},
        headers=a,
    ).json()

    b = _session(client, "it@patchb.example", "PatchB")
    assert (
        client.patch(
            f"/api/v1/mailboxes/{mb['id']}",
            json={"mailbox_class": "protected"},
            headers=b,
        ).status_code
        == 404
    )


def test_metadata_only_mode_drops_the_subject(client: TestClient) -> None:
    """Bodies and attachment bytes are never persisted by any path, so the
    subject is the one piece of message content that reaches a durable row.
    A regulated buyer asking for metadata-only is asking about exactly that."""
    h = _session(client, "it@metaonly.example", "MetaOnly")
    boot = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "MetaOnly", "domain": "metaonly.example"},
        headers=h,
    ).json()
    client.post(
        "/api/v1/mailboxes",
        json={"address": "pay@metaonly.example", "mailbox_class": "protected"},
        headers=h,
    )

    async def _set_metadata_only(tenant_id: str) -> None:
        async with get_sessionmaker()() as s:
            tenant = await s.get(Tenant, __import__("uuid").UUID(tenant_id))
            tenant.metadata_only = True
            await s.commit()

    asyncio.run(_set_metadata_only(boot["tenant_id"]))

    raw = (
        "From: \"Vendor\" <billing@vendor.test>\r\n"
        "To: pay@metaonly.example\r\n"
        "Subject: Invoice 5512 attached\r\n\r\n"
        "Our usual terms apply.\r\n"
    )
    assert (
        client.post(
            "/api/v1/ingest",
            json={"raw_message": raw, "mailbox_address": "pay@metaonly.example"},
            headers=h,
        ).status_code
        == 202
    )

    async def _subjects() -> list:
        async with get_sessionmaker()() as s:
            return [m.subject for m in (await s.execute(select(Message))).scalars().all()]

    subjects = asyncio.run(_subjects())
    assert subjects, "the message metadata is still recorded"
    assert all(x is None for x in subjects), "no subject may be persisted"
