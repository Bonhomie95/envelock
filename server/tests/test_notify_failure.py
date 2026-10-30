"""`deploy/notify_failure.py`: a failed backup mails the operator.

`envelock-backup.service` only ever wrote its failures to the journal, which
nobody reads until the day a restore is needed. It now triggers
`envelock-notify@.service`, which runs this script. These send through a real
local SMTP server (aiosmtpd, already a server dependency).
"""

from __future__ import annotations

import email
import email.policy
import importlib.util
import socket
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _tool():  # noqa: ANN202
    path = ROOT / "deploy" / "notify_failure.py"
    spec = importlib.util.spec_from_file_location("notify_failure", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def relay():  # noqa: ANN201
    from aiosmtpd.controller import Controller

    class Inbox:
        def __init__(self) -> None:
            self.messages: list = []

        async def handle_DATA(self, server, session, envelope):  # noqa: ANN001, ANN201, N802
            self.messages.append(envelope)
            return "250 OK"

    inbox = Inbox()
    controller = Controller(inbox, hostname="127.0.0.1", port=_free_port())
    controller.start()
    try:
        yield controller, inbox
    finally:
        controller.stop()


def _env(tmp_path: Path, **values: str) -> Path:
    env = tmp_path / ".env"
    env.write_text("".join(f"{k}={v}\n" for k, v in values.items()))
    return env


def test_a_failed_unit_is_mailed_to_the_operator(tmp_path, relay) -> None:  # noqa: ANN001
    controller, inbox = relay
    env = _env(
        tmp_path,
        ENVELOCK_SMTP_HOST="127.0.0.1",
        ENVELOCK_SMTP_PORT=str(controller.port),
        ENVELOCK_SMTP_FROM="alerts@envelock.test",
        ENVELOCK_OPS_ALERT_EMAIL="ops@envelock.test",
    )
    assert _tool().main(["envelock-backup.service", "--env-file", str(env)]) == 0
    assert len(inbox.messages) == 1
    envelope = inbox.messages[0]
    assert envelope.rcpt_tos == ["ops@envelock.test"]
    message = email.message_from_bytes(envelope.content, policy=email.policy.default)
    assert message["Subject"].startswith("[Envelock] envelock-backup.service failed on")
    body = message.get_content()
    assert "journalctl -u envelock-backup.service" in body
    assert "restore.sh --list" in body


def test_it_falls_back_to_the_contact_address(tmp_path, relay) -> None:  # noqa: ANN001
    controller, inbox = relay
    env = _env(
        tmp_path,
        ENVELOCK_SMTP_HOST="127.0.0.1",
        ENVELOCK_SMTP_PORT=str(controller.port),
        ENVELOCK_CONTACT_EMAIL="support@envelock.test",
    )
    assert _tool().main(["envelock-backup.service", "--env-file", str(env)]) == 0
    assert inbox.messages[0].rcpt_tos == ["support@envelock.test"]


def test_the_password_never_goes_over_a_connection_without_tls(tmp_path, relay) -> None:  # noqa: ANN001
    """The local relay offers no STARTTLS — the same thing a stripping attacker
    shows us. With credentials configured, nothing may be sent."""
    controller, inbox = relay
    env = _env(
        tmp_path,
        ENVELOCK_SMTP_HOST="127.0.0.1",
        ENVELOCK_SMTP_PORT=str(controller.port),
        ENVELOCK_SMTP_USERNAME="AKIA-ses-user",
        ENVELOCK_SMTP_PASSWORD="ses-secret",  # noqa: S106 — a fixture value
    )
    assert _tool().main(["envelock-backup.service", "--env-file", str(env)]) == 1
    assert inbox.messages == []


def test_no_relay_is_a_failure_not_a_silent_success(tmp_path) -> None:  # noqa: ANN001
    env = _env(tmp_path, ENVELOCK_SMTP_HOST="")
    assert _tool().main(["envelock-backup.service", "--env-file", str(env)]) == 1


def test_the_backup_unit_is_wired_to_the_notifier() -> None:
    backup = (ROOT / "deploy" / "envelock-backup.service").read_text()
    assert "OnFailure=envelock-notify@%n.service" in backup
    notify = (ROOT / "deploy" / "envelock-notify@.service").read_text()
    assert "deploy/notify_failure.py %i" in notify
