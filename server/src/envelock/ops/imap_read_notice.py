"""Tell customers the IMAP poller may have marked their new mail as read.

Before the fix, the poller fetched each new message with `RFC822` from a
read-write `SELECT`, which RFC 3501 §6.4.5 defines as setting `\\Seen`. Every
mailbox connected over IMAP therefore had its new mail marked read as Envelock
polled it. Nothing was deleted or altered; unread mail simply stopped looking
unread. The poller now uses `BODY.PEEK[]` (`envelock.channels.mail.imap_sync`).

    # Who would be told — changes nothing, sends nothing:
    python -m envelock.ops.imap_read_notice --fixed-at 2026-09-21T18:00:00Z

    # Send it:
    python -m envelock.ops.imap_read_notice --fixed-at 2026-09-21T18:00:00Z --send

`--fixed-at` is when the fixed build went live. Only mailboxes polled before then
are affected, so a customer who connected afterwards is never told about a
problem they never had. Each workspace is told once: a sent notice is recorded
in its audit trail, and a re-run skips it.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

NOTICE_ACTION = "notice.imap_read_flag"

SUBJECT = "Envelock may have marked some of your new mail as read"


@dataclass
class Affected:
    tenant_id: UUID
    tenant_name: str
    mailboxes: list[str] = field(default_factory=list)
    first_polled: datetime | None = None
    recipients: list[str] = field(default_factory=list)


def compose(affected: Affected, fixed_at: datetime) -> str:
    """The text part. Plain, specific, and honest about what did not happen."""
    since = (
        f" since {affected.first_polled:%-d %B %Y}" if affected.first_polled else ""
    )
    boxes = "\n".join(f"  - {m}" for m in sorted(affected.mailboxes))
    return f"""Hello,

We found and fixed a bug in how Envelock reads mail over IMAP, and it affected
your workspace, {affected.tenant_name}.

What happened: when Envelock checked these mailboxes for new mail{since}, the way
it downloaded each message caused your mail server to mark it as read:

{boxes}

So new mail in them may have appeared as already read — in Outlook, Thunderbird,
webmail or on a phone — before anyone had opened it.

What did not happen: nothing was deleted, changed or sent. Only the read / unread
marker was affected. Messages Envelock quarantined were already reported to you
as alerts, as before.

It was fixed on {fixed_at:%-d %B %Y}. Envelock now downloads mail without
touching its read status, and we have added a test that fails if that ever
regresses.

What you may want to do: skim recent mail in these mailboxes for anything that
looks read but that nobody has actually dealt with — particularly invoices and
payment requests.

We are sorry. You connected your mailboxes to Envelock to make them safer, and
this made them harder to use. If you have any questions, reply to this email.

— The Envelock team
"""


async def find_affected(fixed_at: datetime) -> list[Affected]:
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.models import AuditEvent, Mailbox, MailboxCredential, Tenant, User

    by_tenant: dict[UUID, Affected] = {}
    async with get_sessionmaker()() as session:
        with system_scope("imap read-flag notice"):
            rows = (
                await session.execute(
                    select(Tenant, Mailbox.address, MailboxCredential)
                    .join(Mailbox, Mailbox.tenant_id == Tenant.id)
                    .join(MailboxCredential, MailboxCredential.mailbox_id == Mailbox.id)
                    .where(
                        Tenant.is_active.is_(True),
                        MailboxCredential.kind == "imap_password",
                        MailboxCredential.imap_last_polled_at.is_not(None),
                        MailboxCredential.created_at < fixed_at,
                    )
                )
            ).all()
            for tenant, address, cred in rows:
                entry = by_tenant.setdefault(
                    tenant.id, Affected(tenant_id=tenant.id, tenant_name=tenant.name)
                )
                entry.mailboxes.append(address)
                started = cred.created_at
                if started is not None and started.tzinfo is None:
                    started = started.replace(tzinfo=UTC)
                if started and (entry.first_polled is None or started < entry.first_polled):
                    entry.first_polled = started

            if by_tenant:
                told = set(
                    (
                        await session.execute(
                            select(AuditEvent.tenant_id).where(
                                AuditEvent.action == NOTICE_ACTION,
                                AuditEvent.tenant_id.in_(by_tenant),
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
                for tenant_id in told:
                    by_tenant.pop(tenant_id, None)

            for entry in by_tenant.values():
                entry.recipients = list(
                    (
                        await session.execute(
                            select(User.email).where(
                                User.tenant_id == entry.tenant_id,
                                User.is_admin.is_(True),
                                User.status == "active",
                            )
                        )
                    )
                    .scalars()
                    .all()
                )
    return sorted(by_tenant.values(), key=lambda a: a.tenant_name.lower())


async def send(affected: list[Affected], fixed_at: datetime) -> tuple[int, int]:
    """Send and record. A workspace is marked told only if at least one of its
    admins was actually reached, so a relay outage leaves it for the next run."""
    from envelock.db import get_sessionmaker
    from envelock.db_rls import system_scope
    from envelock.notify.mail import send_mail
    from envelock.platform.alerts import record_audit

    told = failed = 0
    for entry in affected:
        body = compose(entry, fixed_at)
        reached = []
        for to in entry.recipients:
            result = await send_mail(to=to, subject=SUBJECT, body=body)
            if result.sent:
                reached.append(to)
            else:
                print(f"  ! {to}: {result.reason} {result.detail}", file=sys.stderr)
        if not reached:
            failed += 1
            continue
        async with get_sessionmaker()() as session:
            with system_scope("imap read-flag notice"):
                await record_audit(
                    session,
                    tenant_id=entry.tenant_id,
                    action=NOTICE_ACTION,
                    detail={
                        "recipients": reached,
                        "mailboxes": sorted(entry.mailboxes),
                        "fixed_at": fixed_at.isoformat(),
                    },
                )
                await session.commit()
        told += 1
    return told, failed


def _parse_when(value: str) -> datetime:
    when = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return when if when.tzinfo else when.replace(tzinfo=UTC)


async def _main(args: argparse.Namespace) -> int:
    from envelock.notify.mail import is_configured

    fixed_at = _parse_when(args.fixed_at)
    affected = await find_affected(fixed_at)
    if not affected:
        print("No workspace still needs this notice.")
        return 0

    mailboxes = sum(len(a.mailboxes) for a in affected)
    print(
        f"{len(affected)} workspace(s), {mailboxes} mailbox(es) polled before "
        f"{fixed_at:%Y-%m-%d %H:%M} UTC:\n"
    )
    for entry in affected:
        to = ", ".join(entry.recipients) or "NO ACTIVE ADMIN — cannot be told by email"
        print(f"  {entry.tenant_name}")
        print(f"    to:        {to}")
        print(f"    mailboxes: {', '.join(sorted(entry.mailboxes))}")
    if args.show:
        print("\n--- the email, as the first workspace would get it ---\n")
        print(f"Subject: {SUBJECT}\n")
        print(compose(affected[0], fixed_at))

    if not args.send:
        print("\nDry run: nothing sent. Add --send to send.")
        return 0
    if not is_configured():
        print("\nNo SMTP relay is configured here; nothing sent.", file=sys.stderr)
        return 2
    told, failed = await send(affected, fixed_at)
    print(f"\nSent to {told} workspace(s); {failed} could not be reached (re-run to retry).")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--fixed-at",
        required=True,
        help="when the BODY.PEEK fix went live, ISO 8601 (e.g. 2026-09-21T18:00:00Z)",
    )
    parser.add_argument("--send", action="store_true", help="actually send (default: dry run)")
    parser.add_argument("--show", action="store_true", help="print the email text too")
    return asyncio.run(_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
