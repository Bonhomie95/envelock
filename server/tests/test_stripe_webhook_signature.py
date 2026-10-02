"""The signing-secret side of Stripe webhook verification.

A rejected webhook is a payment that never activates or a cancellation that
never downgrades, so each way the secret can be configured has to actually
verify. Both cases here were silently broken: several `v1` signatures during a
secret roll, and several secrets configured at once.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from envelock.billing.payments import WebhookError, verify_stripe_webhook

OLD = "whsec_old"  # noqa: S105 — test secret
NEW = "whsec_new"  # noqa: S105 — test secret


def _sign(payload: bytes, *secrets: str) -> str:
    t = str(int(time.time()))
    sigs = [
        hmac.new(s.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
        for s in secrets
    ]
    return ",".join([f"t={t}", *(f"v1={s}" for s in sigs)])


PAYLOAD = json.dumps({"id": "evt_1", "type": "checkout.session.completed"}).encode()


@pytest.mark.parametrize("configured", [f"{OLD},{NEW}", f"{OLD}, {NEW}", f" {NEW} , {OLD} "])
def test_any_of_several_configured_secrets_verifies(configured: str) -> None:
    """A deployment may serve more than one endpoint, or be mid-roll. HMAC'ing
    the whole comma-joined string matches nothing and rejects every delivery."""
    for signer in (OLD, NEW):
        event = verify_stripe_webhook(PAYLOAD, _sign(PAYLOAD, signer), configured)
        assert event["id"] == "evt_1"


def test_a_secret_we_were_never_given_is_still_rejected() -> None:
    with pytest.raises(WebhookError, match="signature mismatch"):
        verify_stripe_webhook(PAYLOAD, _sign(PAYLOAD, "whsec_attacker"), f"{OLD},{NEW}")


def test_a_list_of_nothing_is_not_a_secret() -> None:
    with pytest.raises(WebhookError, match="signing secret"):
        verify_stripe_webhook(PAYLOAD, _sign(PAYLOAD, OLD), " , ")
