"""The CT watcher must never fail quietly.

It is the entire delivery mechanism for the one thing the free Guard tier
advertises — "lookalike domain monitoring" — and its failure looks exactly like
success from every screen: the Activity tab says "no lookalike domains found for
you yet" whether the feed is healthy and the world is quiet, or the feed has been
dead for a week. Nothing in the product could tell those apart, and the watcher
logged nothing at all.

So these assert on the log, which is the only signal there is.
"""

from __future__ import annotations

import asyncio

import pytest

from envelock.workers.watchers import CertTransparencyWatcher


@pytest.mark.asyncio
async def test_a_missing_websockets_package_is_an_error_not_a_silent_exit(
    monkeypatch, logged
) -> None:  # noqa: ANN001
    """`websockets` used to arrive only as a transitive extra of
    `uvicorn[standard]`. Without it the generator simply returned, so the
    scheduler logged "started" and the feed never existed."""
    import builtins

    real_import = builtins.__import__

    def no_websockets(name, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if name == "websockets":
            raise ImportError("no websockets")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_websockets)
    watcher = CertTransparencyWatcher()
    watcher._running = True

    watcher_log = logged("envelock.workers.watchers")
    assert [m async for m in watcher._connect()] == []

    assert "websockets" in watcher_log.text, (
        f"a watcher that cannot run at all said nothing: {watcher_log.messages}"
    )


@pytest.mark.asyncio
async def test_a_lost_feed_says_so_and_does_not_ratchet_its_backoff(monkeypatch, logged) -> None:  # noqa: ANN001
    """Two claims: the outage is logged, and a successful reconnect resets the
    counter. The delay was `min(2**reconnects, 60)` over a counter that only ever
    went up, so after a handful of outages it stayed pinned at the 60s ceiling
    for the life of the process — long after the feed was healthy."""
    attempts: list[int] = []

    class FakeSocket:
        def __init__(self, fail: bool) -> None:
            self.fail = fail

        async def __aenter__(self):  # noqa: ANN204
            if self.fail:
                raise OSError("certstream is down")
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def __aiter__(self):  # noqa: ANN204
            yield '{"data": {"leaf_cert": {"all_domains": ["example.com"]}}}'

    class FakeWebsockets:
        @staticmethod
        def connect(url: str):  # noqa: ANN205
            attempts.append(len(attempts))
            # Fail twice, then connect.
            return FakeSocket(fail=len(attempts) <= 2)

    real_import = __import__

    def fake_import(name, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if name == "websockets":
            return FakeWebsockets
        return real_import(name, *args, **kwargs)

    import builtins

    monkeypatch.setattr(builtins, "__import__", fake_import)
    # Bound before patching: a lambda that calls `asyncio.sleep` reaches the
    # patched name and recurses.
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda _: real_sleep(0))

    watcher = CertTransparencyWatcher(protected_domains=frozenset({"acme.com"}))
    watcher._running = True

    watcher_log = logged("envelock.workers.watchers")
    gen = watcher._connect()
    first = await anext(gen)
    watcher._running = False
    await gen.aclose()

    messages = watcher_log.messages
    assert first["data"]["leaf_cert"]["all_domains"] == ["example.com"]
    assert any("lost the feed" in m for m in messages), f"an outage was not reported: {messages}"
    assert any("reconnected" in m for m in messages), f"the recovery was not reported: {messages}"
    # The whole point: a healthy connection clears the backoff.
    assert watcher.stats.reconnects == 0, (
        "the reconnect counter survived a successful connection, so the backoff "
        "stays at its ceiling forever"
    )
    assert watcher.stats.last_message_at is not None, (
        "nothing recorded that the feed has ever delivered, which is the only "
        "way to tell a dead feed from a quiet one"
    )
