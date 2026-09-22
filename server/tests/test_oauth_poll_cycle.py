"""The OAuth poll cycle actually runs.

`fetch_all_oauth_mailboxes` combined a SYNC context manager into an `async with`
clause:

    async with sessionmaker() as session, system_scope("..."):

Python then requires `__aenter__` on `system_scope`, which is an ordinary
`@contextmanager`, so the loop raised `TypeError` on its first iteration. The
effect was silent and total: every Microsoft 365 and Gmail mailbox connected over
OAuth was never polled, on every cycle, forever. Nothing caught it because the
scheduler logs a failing job and moves on, and no test exercised the loop body —
only `sync_oauth_mailbox` beneath it.

The test that matters is therefore the boring one: put a mailbox in front of the
cycle and require that it reaches the per-mailbox work at all.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from envelock.core.enums import SourceMechanism


@pytest.fixture
async def oauth_mailbox(client):  # noqa: ANN001, ARG001 — client builds the schema
    """A tenant with one OAuth-connected mailbox."""
    from datetime import UTC, datetime, timedelta

    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import Mailbox, MailboxCredential, Tenant

    tenant_id = uuid4()
    mailbox_id = uuid4()
    with system_scope("test fixture"):
        async with get_sessionmaker()() as session:
            # An entitled tenant: the poller drops mailboxes whose trial has
            # lapsed and which have no payment method, which is correct — and
            # would silently make this test pass for the wrong reason.
            session.add(
                Tenant(
                    id=tenant_id,
                    name="OAuth Co",
                    plan="complete",
                    payment_method_ok=True,
                    trial_ends_at=datetime.now(UTC) + timedelta(days=30),
                )
            )
            # Flush before the FK-bearing rows: SQLAlchemy has no relationship to
            # order these for it, so without this the mailbox insert races its
            # own tenant.
            await session.flush()
            session.add(
                Mailbox(
                    id=mailbox_id,
                    tenant_id=tenant_id,
                    address="ap@oauthco.example",
                    sources=[SourceMechanism.GRAPH_API.value],
                    is_active=True,
                )
            )
            await session.flush()
            session.add(
                MailboxCredential(
                    mailbox_id=mailbox_id,
                    tenant_id=tenant_id,
                    kind="oauth_token",
                    ciphertext=b"x",
                    wrapped_dek=b"y",
                    key_id="test",
                    token_expires_at=datetime.now(UTC),
                )
            )
            await session.commit()
    return mailbox_id


async def test_the_cycle_reaches_the_mailbox_instead_of_raising(
    oauth_mailbox, monkeypatch  # noqa: ANN001
) -> None:
    """The regression itself: before the fix this raised TypeError before doing
    any work at all."""
    from envelock.workers import oauth_fetch

    seen: list = []

    async def _fake_sync(session, mailbox, *, transport=None, write_transport=None):  # noqa: ANN001, ARG001
        seen.append(mailbox.id)
        return {"ok": True, "fetched": 2, "alerted": 0}

    monkeypatch.setattr(oauth_fetch, "sync_oauth_mailbox", _fake_sync)

    totals = await oauth_fetch.fetch_all_oauth_mailboxes()

    assert oauth_mailbox in seen, "the cycle never reached the mailbox"
    assert totals["mailboxes"] == 1
    assert totals["fetched"] == 2
    assert totals["errors"] == 0


async def test_one_failing_mailbox_is_counted_not_fatal(
    oauth_mailbox, monkeypatch  # noqa: ANN001, ARG001
) -> None:
    """A provider outage on one tenant must not stop the others being polled."""
    from envelock.workers import oauth_fetch

    async def _boom(session, mailbox, *, transport=None, write_transport=None):  # noqa: ANN001, ARG001
        raise RuntimeError("provider said no")

    monkeypatch.setattr(oauth_fetch, "sync_oauth_mailbox", _boom)

    totals = await oauth_fetch.fetch_all_oauth_mailboxes()
    assert totals["errors"] == 1
    assert totals["fetched"] == 0
