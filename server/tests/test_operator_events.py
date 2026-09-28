"""Live operator notifications.

What is pinned here is the plumbing that decides whether the console is live and
whether it leaks: delivery, cleanup on disconnect, behaviour when a subscriber
stops keeping up, and that publishing can never fail the thing it reports.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from envelock.platform import events


@pytest.mark.asyncio
async def test_a_subscriber_receives_what_is_published() -> None:
    async with events.subscribe() as queue:
        events.publish("tenant.registered", {"email_domain": "acme.com"})
        payload = await asyncio.wait_for(queue.get(), timeout=1)
    assert payload == {
        "event": "tenant.registered",
        "data": {"email_domain": "acme.com"},
    }


@pytest.mark.asyncio
async def test_a_subscriber_is_removed_when_its_connection_ends() -> None:
    """Without this the set grows for every connection ever made, and `publish`
    slows down forever — a leak that only shows up after weeks of uptime."""
    assert events.subscriber_count() == 0
    async with events.subscribe():
        assert events.subscriber_count() == 1
    assert events.subscriber_count() == 0

    # Also when the body raises: a dropped connection unwinds the generator.
    with pytest.raises(RuntimeError):
        async with events.subscribe():
            raise RuntimeError("connection dropped")
    assert events.subscriber_count() == 0


@pytest.mark.asyncio
async def test_a_slow_subscriber_is_told_to_refetch_rather_than_hoarding() -> None:
    """A browser tab suspended for an hour must not be able to pin an hour of
    events in memory. It loses the oldest and is told it is stale, which is
    correct: these events are hints to reload, not a ledger."""
    async with events.subscribe() as queue:
        for i in range(200):  # well past the queue bound
            events.publish("tenant.registered", {"n": i})
        drained = []
        while not queue.empty():
            drained.append(queue.get_nowait())

    assert len(drained) < 200, "the queue is bounded"
    assert any(p["event"] == "stale" for p in drained), drained


def test_publishing_with_nobody_listening_is_a_no_op() -> None:
    """The common case in production: no operator has the console open. It must
    cost nothing and must not raise."""
    assert events.subscriber_count() == 0
    events.publish("tenant.registered", {"email_domain": "acme.com"})


@pytest.mark.asyncio
async def test_registration_announces_a_new_tenant(client: TestClient) -> None:
    """The console's whole reason for the stream. Only the email DOMAIN goes on
    the wire — the console refetches the real record with its own authorisation
    rather than being handed customer data by a broadcast."""
    async with events.subscribe() as queue:
        r = await asyncio.to_thread(
            client.post,
            "/api/v1/auth/register",
            json={
                "email": "owner@eventco.example",
                "password": "tangerine harbour lantern 47",
                "tenant_name": "eventco.example",
            },
        )
        assert r.status_code in (200, 201), r.text
        payload = await asyncio.wait_for(queue.get(), timeout=2)

    assert payload["event"] == "tenant.registered"
    assert payload["data"] == {"email_domain": "eventco.example"}
