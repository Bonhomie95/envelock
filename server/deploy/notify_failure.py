#!/usr/bin/env python3
"""Mail the operator that a systemd unit failed.

    python3 deploy/notify_failure.py envelock-backup.service

Run by `envelock-notify@.service`, which a unit triggers with
`OnFailure=envelock-notify@%n.service`. The backup unit is the reason it exists:
its failures went to the journal and nowhere else, which is where a failed
backup waits, unread, until the day someone needs to restore.

Standard library only, and reads `.env` itself (like make_prod_env.py), so it
works under the system Python even when the app's venv is what broke. It uses
the relay the product already sends alerts through (ENVELOCK_SMTP_*), and sends
to ENVELOCK_OPS_ALERT_EMAIL, else ENVELOCK_CONTACT_EMAIL, else
support@envelock.org. The password is never sent over a connection without TLS.
"""

from __future__ import annotations

import argparse
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
from datetime import UTC, datetime
from email.message import EmailMessage
from pathlib import Path

KEY_LINE = re.compile(r"^(?P<key>ENVELOCK_[A-Z0-9_]+)=(?P<value>.*)$")
DEFAULT_RECIPIENT = "support@envelock.org"


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text().splitlines():
        m = KEY_LINE.match(line.strip())
        if m:
            values[m["key"]] = m["value"].strip().strip("'\"")
    return values


def journal_tail(unit: str, lines: int = 40) -> str:
    """The unit's last log lines, when this user may read them; else nothing."""
    journalctl = shutil.which("journalctl")
    if journalctl is None:
        return ""
    try:
        out = subprocess.run(  # noqa: S603 — fixed argv, unit name from systemd
            [journalctl, "-u", unit, "-n", str(lines), "--no-pager", "-o", "cat"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""
    return out


def build_message(unit: str, env: dict[str, str], *, host: str, log: str) -> EmailMessage:
    to = (
        env.get("ENVELOCK_OPS_ALERT_EMAIL")
        or env.get("ENVELOCK_CONTACT_EMAIL")
        or DEFAULT_RECIPIENT
    )
    msg = EmailMessage()
    msg["From"] = env.get("ENVELOCK_SMTP_FROM") or "alerts@envelock.org"
    msg["To"] = to
    msg["Subject"] = f"[Envelock] {unit} failed on {host}"
    when = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    body = [
        f"{unit} failed on {host} at {when}.",
        "",
        "What failed and why:",
        f"    journalctl -u {unit} -n 80 --no-pager",
    ]
    if unit.startswith("envelock-backup"):
        body += [
            "",
            "Until a backup succeeds, there is no restore point newer than the last",
            "good one:   ~/apps/server/deploy/restore.sh --list",
        ]
    if log:
        body += ["", "Last log lines:", "", log]
    msg.set_content("\n".join(body) + "\n")
    return msg


def send(msg: EmailMessage, env: dict[str, str], *, timeout: float = 20.0) -> None:
    host = env.get("ENVELOCK_SMTP_HOST", "").strip()
    if not host or host == "localhost":
        raise RuntimeError("no SMTP relay configured (ENVELOCK_SMTP_HOST)")
    port = int(env.get("ENVELOCK_SMTP_PORT") or 587)
    user = env.get("ENVELOCK_SMTP_USERNAME") or ""
    password = env.get("ENVELOCK_SMTP_PASSWORD") or ""
    context = ssl.create_default_context()
    if port == 465:
        server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        encrypted = True
    else:
        server = smtplib.SMTP(host, port, timeout=timeout)
        server.ehlo()
        encrypted = server.has_extn("starttls")
        if encrypted:
            server.starttls(context=context)
            server.ehlo()
    with server:
        if user:
            if not encrypted:
                # A relay that does not offer STARTTLS — or an attacker who
                # stripped it — must not get the password in clear text.
                raise RuntimeError(f"{host}:{port} offers no TLS; refusing to send credentials")
            server.login(user, password)
        server.send_message(msg)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("unit", help="the unit that failed (systemd passes %%i)")
    parser.add_argument(
        "--env-file",
        default=str(Path(__file__).resolve().parents[1] / ".env"),
        help="settings to read the relay from (default: the server's .env)",
    )
    args = parser.parse_args(argv)
    env = read_env(Path(args.env_file))
    msg = build_message(args.unit, env, host=socket.gethostname(), log=journal_tail(args.unit))
    try:
        send(msg, env)
    except Exception as exc:  # noqa: BLE001 — report and exit non-zero, in the journal
        print(
            f"notify_failure: could not mail {msg['To']} about {args.unit}: {exc}",
            file=sys.stderr,
        )
        return 1
    print(f"notify_failure: told {msg['To']} that {args.unit} failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
