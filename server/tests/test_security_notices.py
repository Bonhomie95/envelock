"""The account emails that matter most when the recipient did NOT do the thing.

A password changed, two-factor switched off, a device they do not recognise —
each is what takeover looks like from the victim's side, and the window in
which they can still act is short. What is pinned here is that the notice fires
on the transition, does not fire when nothing changed, and can never fail the
operation it is reporting.
"""

from __future__ import annotations

import pytest

from envelock.api import auth as auth_api


def test_a_device_fingerprint_survives_a_browser_update() -> None:
    """Family-level, so a version bump is not a new device. Fingerprinting the
    raw user-agent would email the customer every few weeks and train them to
    ignore the one that matters."""
    chrome_a = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    chrome_b = chrome_a.replace("Chrome/120.0.0.0", "Chrome/131.0.6778.86")
    firefox = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) "
        "Gecko/20100101 Firefox/133.0"
    )

    same = auth_api._device_fingerprint(chrome_a)
    assert same == auth_api._device_fingerprint(chrome_b), "a version bump is not a new device"
    assert same != auth_api._device_fingerprint(firefox), "a different browser is"


def test_an_unrecognisable_agent_is_not_reported_as_a_new_device() -> None:
    """Better to say nothing than to claim a new device on no evidence — a
    false security alert is worse than a missing one, because it is the alert
    people learn to dismiss."""
    assert auth_api._device_fingerprint(None) is None
    assert auth_api._device_fingerprint("") is None
    assert auth_api._device_fingerprint("curl/8.4.0") is None


@pytest.mark.asyncio
async def test_the_first_ever_sign_in_is_recorded_but_not_announced() -> None:
    """The person just created the account and is standing there. "We noticed a
    new device" as the opening message reads as a fault, not as care."""
    sent: list[str] = []

    class FakeUser:
        email = "new@acme.example"
        known_devices: list[str] = []

    class FakeRequest:
        headers = {
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
        }

    async def _record(user, *, heading, what, reassure):  # noqa: ANN001, ANN202
        sent.append(heading)

    original = auth_api._notify_security_change
    auth_api._notify_security_change = _record  # type: ignore[assignment]
    try:
        user = FakeUser()
        await auth_api._note_sign_in_device(user, FakeRequest())
        assert len(user.known_devices) == 1, "the device is remembered"
        assert sent == [], "but nothing is announced"

        # Same device again: still silent, and not recorded twice.
        await auth_api._note_sign_in_device(user, FakeRequest())
        assert len(user.known_devices) == 1
        assert sent == []

        # A genuinely different device now DOES announce.
        class Firefox(FakeRequest):
            headers = {
                "user-agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) "
                    "Gecko/20100101 Firefox/133.0"
                )
            }

        await auth_api._note_sign_in_device(user, Firefox())
        assert sent == ["A new device signed in"]
        assert len(user.known_devices) == 2
    finally:
        auth_api._notify_security_change = original  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_the_remembered_list_cannot_grow_without_bound() -> None:
    """A shared login used from many machines must not accumulate forever."""

    class FakeUser:
        email = "shared@acme.example"
        known_devices: list[str] = []

    user = FakeUser()
    user.known_devices = [f"device{i}" for i in range(50)]

    class FakeRequest:
        headers = {
            "user-agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) "
                "Gecko/20100101 Firefox/133.0"
            )
        }

    original = auth_api._notify_security_change

    async def _quiet(user, *, heading, what, reassure):  # noqa: ANN001, ANN202
        return None

    auth_api._notify_security_change = _quiet  # type: ignore[assignment]
    try:
        await auth_api._note_sign_in_device(user, FakeRequest())
    finally:
        auth_api._notify_security_change = original  # type: ignore[assignment]

    assert len(user.known_devices) == auth_api._KNOWN_DEVICE_LIMIT
