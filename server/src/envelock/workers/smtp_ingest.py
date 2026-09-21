"""SMTP front end for Tier 4 forwarding ingest.

`ForwardingIngest` (channels/mail/ingest.py) is the transport-agnostic core — it
takes a recipient and a raw message and runs it through the pipeline. This module
is the missing transport: a real aiosmtpd server that publishes an endpoint for
MX to point at, and drives `handle_rcpt` / `handle_data`.

Two ways to receive forwarded mail in production:
  * point MX for `ENVELOCK_INGEST_DOMAIN` at this listener, or
  * use a provider inbound-parse webhook that POSTs to `/api/v1/ingest`.
Both feed the identical pipeline; this gives the self-hosted path.

Run it as its own process (it is deliberately separate from the API):
    python -m envelock.workers.smtp_ingest
"""

from __future__ import annotations

import asyncio
import logging

from envelock.channels.mail.forward_runner import build_forwarding_ingest
from envelock.channels.mail.ingest import ForwardingIngest
from envelock.config import get_settings

logger = logging.getLogger("envelock.smtp")


class ForwardingSMTPHandler:
    """aiosmtpd handler that delegates every decision to `ForwardingIngest`.

    Kept thin and free of aiosmtpd types in its logic so it is testable by
    calling `handle_RCPT` / `handle_data` with plain fakes — no socket needed.
    """

    def __init__(self, ingest: ForwardingIngest | None = None) -> None:
        self._ingest = ingest or build_forwarding_ingest()

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):  # noqa: N802, ANN001, ARG002
        # Pin the source: only the customer's known forwarders (or our inbound
        # provider) may submit. The token in the address proves the tenant, not the
        # sender — without this, a leaked token lets anyone inject mail.
        from envelock.security.ipfilter import ingest_ip_allowed

        peer_ip = None
        peer = getattr(session, "peer", None)
        if isinstance(peer, (tuple, list)) and peer:
            peer_ip = peer[0]
        if not ingest_ip_allowed(peer_ip):
            logger.warning("rejected forwarded mail from disallowed source %s", peer_ip)
            return "550 sender not permitted"
        result = await self._ingest.handle_rcpt(address)
        if not result.accepted:
            return result.reason  # e.g. "550 unknown recipient"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):  # noqa: N802, ANN001, ARG002
        content = envelope.content
        raw = content if isinstance(content, bytes) else str(content).encode()
        last = "250 Message accepted"
        for rcpt in envelope.rcpt_tos:
            result = await self._ingest.handle_data(recipient=rcpt, raw=raw)
            last = result.reason
        return last


def build_controller(*, host: str | None = None, port: int | None = None):  # noqa: ANN201
    """Construct (but do not start) the aiosmtpd Controller."""
    from aiosmtpd.controller import Controller

    settings = get_settings()
    return Controller(
        ForwardingSMTPHandler(),
        hostname=host or settings.ingest_smtp_host,
        port=port or settings.ingest_smtp_port,
    )


def _assert_ingest_is_pinned() -> None:
    """Refuse to run the forwarding listener wide open in production.

    `config._check_production_secrets` makes the same demand, but only for the
    IN-APP listener (`ingest_smtp_in_app`). Started as its own process — the
    documented production shape — that flag is false, the boot check never
    fires, and the listener accepts forwarded mail from anywhere on the
    internet. Anyone who learns a tenant's ingest token could then inject mail
    to fabricate alerts or poison detection baselines. The guard belongs where
    the socket opens, not next to one flag.
    """
    settings = get_settings()
    if settings.env != "production":
        return
    if not settings.ingest_allowed_ip_list:
        raise RuntimeError(
            "Refusing to start the forwarding SMTP ingest in production with "
            "ENVELOCK_INGEST_ALLOWED_IPS empty — that accepts forwarded mail "
            "from any source on the internet. Pin your mail provider's egress "
            "ranges first."
        )


async def run_forever(stop: asyncio.Event | None = None) -> None:
    _assert_ingest_is_pinned()
    controller = build_controller()
    controller.start()
    logger.info(
        "smtp ingest listening on %s:%s (domain %s)",
        controller.hostname,
        controller.port,
        get_settings().ingest_domain,
    )
    stop = stop or asyncio.Event()
    try:
        await stop.wait()  # run until asked to stop
    finally:
        controller.stop()
        logger.info("smtp ingest stopped")


def main() -> None:
    logging.basicConfig(level=get_settings().log_level)
    asyncio.run(run_forever())


if __name__ == "__main__":
    main()
