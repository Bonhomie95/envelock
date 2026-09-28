"""Cloudflare Turnstile verification.

Turnstile is the free, unlimited, no-puzzle CAPTCHA: the visitor is scored from
browser signals rather than asked to identify traffic lights, so on the normal
path they see nothing at all. That matters on a sign-in form — a challenge a
real customer has to solve is a tax on every legitimate login, paid forever, to
stop bots that mostly are not there.

Two rules this module exists to enforce:

* **The token is verified server-side, always.** The widget's client-side
  callback proves nothing: anything the browser sends, an attacker sends too.
* **A missing secret means the check is OFF, not PASSED-BY-DEFAULT in
  production.** A deployment with no secret configured logs it and allows the
  request, which is right for development and for a staging box — but
  `config.py` refuses to boot a production deployment that has the site key
  without the secret, so the widget can never be rendered while unverifiable.
"""

from __future__ import annotations

import logging

from envelock.config import get_settings

logger = logging.getLogger("envelock.turnstile")

_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

#: A verification call must not hold a request open. Cloudflare answers in
#: tens of milliseconds; anything approaching this is an outage, and an outage
#: at the CAPTCHA provider must not take sign-in down with it.
_TIMEOUT = 5.0


def is_configured() -> bool:
    return bool(get_settings().turnstile_secret_key)


async def verify(token: str | None, *, remote_ip: str | None = None) -> bool:
    """True when `token` is a valid, unused Turnstile solution.

    Fails OPEN on a transport error and CLOSED on a rejection. The distinction
    is deliberate: Cloudflare being unreachable is our problem and must not lock
    customers out of their own account, whereas Cloudflare saying "no" is an
    answer and is honoured.
    """
    if not is_configured():
        return True  # not enabled on this deployment
    if not token:
        return False

    import httpx

    secret = get_settings().turnstile_secret_key
    payload = {
        "secret": secret.get_secret_value() if secret else "",
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(_VERIFY_URL, data=payload)
            body = resp.json()
    except Exception as exc:  # noqa: BLE001 — see docstring: fail open
        logger.warning("turnstile verification unreachable, allowing: %s", exc)
        return True
    ok = bool(body.get("success"))
    if not ok:
        # Logged at info, not warning: a failed challenge is the control doing
        # its job, and at warning level a bot flood would bury real problems.
        logger.info("turnstile rejected a token: %s", body.get("error-codes"))
    return ok


__all__ = ["is_configured", "verify"]
