"""The apology for the \\Seen bug reaches exactly the workspaces it happened to.

Too narrow and a customer never learns why their unread mail looked read; too
broad and we tell someone who connected after the fix about a problem they never
had, which costs trust for nothing. And it must go once: a re-run after a relay
blip retries the workspaces nobody reached, not the ones already told.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import platform_sessionmaker as get_sessionmaker

from envelock.ops import imap_read_notice as notice

pytestmark = pytest.mark.asyncio

FIXED_AT = datetime(2026, 9, 21, 18, 0, tzinfo=UTC)


async def _workspace(
    name: str, *, connected: datetime | None, polled: bool, kind: str = "imap_password"
) -> None:
    from envelock.core.enums import MailboxClass
    from envelock.models import Mailbox, MailboxCredential, Tenant, User

    tenant_id, mailbox_id = uuid4(), uuid4()
    async with get_sessionmaker()() as session:
        session.add(Tenant(id=tenant_id, name=name))
        await session.flush()
        session.add(
            User(
                id=uuid4(),
                tenant_id=tenant_id,
                email=f"it@{name}.example",
                name="IT",
                password_hash="x",  # noqa: S106 — never used to sign in
                role="owner",
                is_admin=True,
                status="active",
            )
        )
        session.add(
            User(
                id=uuid4(),
                tenant_id=tenant_id,
                email=f"staff@{name}.example",
                name="Staff",
                password_hash="x",  # noqa: S106 — never used to sign in
                role="member",
                is_admin=False,
                status="active",
            )
        )
        session.add(
            Mailbox(
                id=mailbox_id,
                tenant_id=tenant_id,
                address=f"pay@{name}.example",
                mailbox_class=MailboxClass.PROTECTED.value,
            )
        )
        await session.flush()
        if connected is not None:
            session.add(
                MailboxCredential(
                    id=uuid4(),
                    mailbox_id=mailbox_id,
                    tenant_id=tenant_id,
                    kind=kind,
                    ciphertext=b"x",
                    wrapped_dek=b"x",
                    created_at=connected,
                    imap_last_polled_at=connected + timedelta(minutes=1) if polled else None,
                )
            )
        await session.commit()


async def _seed() -> None:
    before = FIXED_AT - timedelta(days=10)
    await _workspace("affected", connected=before, polled=True)
    await _workspace("afterfix", connected=FIXED_AT + timedelta(hours=1), polled=True)
    await _workspace("neverpolled", connected=before, polled=False)
    await _workspace("oauthonly", connected=before, polled=True, kind="oauth_token")
    await _workspace("forwardonly", connected=None, polled=False)


async def test_only_workspaces_polled_over_imap_before_the_fix_are_told(db) -> None:  # noqa: ANN001
    await _seed()
    affected = await notice.find_affected(FIXED_AT)
    assert [a.tenant_name for a in affected] == ["affected"]
    only = affected[0]
    assert only.mailboxes == ["pay@affected.example"]
    # Admins run the dashboard; a member would get an email about mailboxes
    # they may not even be able to see.
    assert only.recipients == ["it@affected.example"]


async def test_the_email_names_the_mailboxes_and_what_did_not_happen(db) -> None:  # noqa: ANN001
    await _seed()
    [affected] = await notice.find_affected(FIXED_AT)
    body = notice.compose(affected, FIXED_AT)
    assert "pay@affected.example" in body
    assert "nothing was deleted" in body.lower()
    assert "21 September 2026" in body


async def test_each_workspace_is_told_once_and_a_failure_is_retried(db, monkeypatch) -> None:  # noqa: ANN001
    from envelock.notify import mail

    await _seed()
    outbox: list[str] = []
    relay_up = False

    async def fake_send(*, to: str, subject: str, body: str, html_body=None):  # noqa: ANN001, ANN202
        if not relay_up:
            return mail.MailResult(False, "failed", "relay down")
        outbox.append(to)
        return mail.MailResult(True, "sent")

    monkeypatch.setattr(mail, "send_mail", fake_send)

    # Relay down: nobody reached, so nobody is marked told.
    told, failed = await notice.send(await notice.find_affected(FIXED_AT), FIXED_AT)
    assert (told, failed) == (0, 1)
    assert len(await notice.find_affected(FIXED_AT)) == 1

    relay_up = True
    told, failed = await notice.send(await notice.find_affected(FIXED_AT), FIXED_AT)
    assert (told, failed) == (1, 0)
    assert outbox == ["it@affected.example"]

    # Recorded in the workspace's audit trail, so a re-run sends nothing.
    assert await notice.find_affected(FIXED_AT) == []
