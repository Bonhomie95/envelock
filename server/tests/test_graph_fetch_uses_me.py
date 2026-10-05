"""A delegated OAuth token must read Graph as /me, never /users/{label}.

The mailbox is stored under the address the customer typed (e.g.
admin@cyberlex.store), which need not be the account's real Microsoft UPN
(often the tenant's <name>.onmicrosoft.com). Building /users/admin@cyberlex.store
made Graph answer 403 on every poll — the inbox was never read and no alert
could ever fire. /me resolves to whichever account the delegated token belongs
to, so it is correct whatever label we hold.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from envelock.core.enums import SourceMechanism
from envelock.security.crypto import seal


class _RecordingTransport:
    """Captures every Graph URL the worker requests; returns an empty inbox."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    async def get_json(self, url: str, *, headers: dict) -> dict:  # noqa: ARG002
        self.urls.append(url)
        return {"value": []}

    async def get_bytes(self, url: str, *, headers: dict) -> bytes:  # noqa: ARG002
        self.urls.append(url)
        return b""


@pytest.fixture
async def graph_mailbox(client):  # noqa: ANN001, ARG001 — client builds the schema
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential, Tenant

    tenant_id, mailbox_id = uuid4(), uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            session.add(
                Tenant(
                    id=tenant_id, name="Graph Co", plan="complete",
                    payment_method_ok=True,
                    trial_ends_at=datetime.now(UTC) + timedelta(days=30),
                )
            )
            await session.flush()
            session.add(
                Mailbox(
                    id=mailbox_id, tenant_id=tenant_id,
                    # A label that is NOT the account's real Microsoft UPN — the
                    # exact shape that produced the 403.
                    address="admin@cyberlex.store",
                    mailbox_class="protected",
                    sources=[SourceMechanism.GRAPH_API.value], is_active=True,
                )
            )
            await session.flush()
            token = json.dumps(
                {"access_token": "fake-access", "refresh_token": "r", "scope": "mail"}
            )
            sealed = seal(token.encode(), aad=str(mailbox_id).encode())
            session.add(
                MailboxCredential(
                    mailbox_id=mailbox_id, tenant_id=tenant_id, kind="oauth_token",
                    ciphertext=sealed.ciphertext, wrapped_dek=sealed.wrapped_dek,
                    key_id=sealed.key_id,
                    # Far in the future so no refresh (network) is attempted.
                    token_expires_at=datetime.now(UTC) + timedelta(hours=1),
                )
            )
            await session.commit()
    return mailbox_id


async def test_graph_fetch_hits_me_not_users_label(graph_mailbox, monkeypatch) -> None:  # noqa: ANN001, ARG001
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox
    from envelock.workers import oauth_fetch

    transport = _RecordingTransport()
    with system_scope("test"):
        async with get_sessionmaker()() as session:
            mailbox = await session.get(Mailbox, graph_mailbox)
            result = await oauth_fetch.sync_oauth_mailbox(session, mailbox, transport=transport)

    assert result["ok"] is True, result
    assert transport.urls, "the worker never called Graph"
    listing = transport.urls[0]
    assert "/me/mailFolders/inbox" in listing, listing
    assert "/users/" not in listing, (
        f"delegated fetch used /users/<label> — the 403 bug: {listing}"
    )
