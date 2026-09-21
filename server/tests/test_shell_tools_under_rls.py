"""The server-shell tools must work on a production database — RLS on.

`bootstrap_staff` and `rotate_credentials` are run by an operator from a shell,
not from a request, so nothing binds a tenant for them. Under row-level
security that meant:

* `bootstrap_staff` — the very first command after install — was refused
  outright ("new row violates row-level security policy"), leaving no way to
  create the first operator.
* `rotate_credentials` saw **zero** credentials and reported "0 remaining on the
  old provider". The procedure then says to drop the old key, which would have
  made every connected mailbox permanently unreadable.

Both are platform-wide by nature and now say so with `system_scope`. These tests
call them with no ambient scope — the way the shell does. The ordinary `session`
fixture runs in system scope under `ENVELOCK_TEST_RLS`, which is exactly why the
existing tests could not see this; they only bite in the RLS CI job.
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from conftest import platform_sessionmaker as get_sessionmaker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select

from envelock.core.enums import MailboxClass
from envelock.models import Mailbox, MailboxCredential, StaffAccount, Tenant
from envelock.security.crypto import _kek_from, _key_id_from

pytestmark = pytest.mark.asyncio


async def test_the_first_operator_can_be_created_from_the_shell(db) -> None:  # noqa: ANN001
    from envelock.security.bootstrap_staff import create

    email = f"ops-{uuid4().hex[:6]}@envelock.org"
    result = await create(email=email, name="Ops", department="leadership")

    assert result["ok"], result
    async with get_sessionmaker()() as s:
        account = (
            await s.execute(select(StaffAccount).where(StaffAccount.email == email))
        ).scalar_one()
    assert account.must_change_password


async def test_rotation_sees_every_tenants_credentials(db) -> None:  # noqa: ANN001
    from envelock.config import get_settings
    from envelock.security.rotate_credentials import rotate

    old_key = "old-master-key-for-rls-test"
    current = get_settings().credential_master_key.get_secret_value()
    # Two tenants: a tool that saw only "its own" rows would miss one of them.
    async with get_sessionmaker()() as s:
        for n in range(2):
            tenant_id = uuid4()
            s.add(Tenant(id=tenant_id, name=f"rot{n}"))
            await s.flush()
            mailbox = Mailbox(
                tenant_id=tenant_id,
                address=f"pay@rot{n}-{uuid4().hex[:6]}.example",
                mailbox_class=MailboxClass.PROTECTED.value,
            )
            s.add(mailbox)
            await s.flush()
            dek = AESGCM.generate_key(bit_length=256)
            n1, n2 = os.urandom(12), os.urandom(12)
            s.add(
                MailboxCredential(
                    mailbox_id=mailbox.id,
                    tenant_id=tenant_id,
                    kind="imap_password",
                    imap_host="imap.example.com",
                    imap_port=993,
                    ciphertext=n1 + AESGCM(dek).encrypt(n1, b"pw", str(mailbox.id).encode()),
                    wrapped_dek=n2 + AESGCM(_kek_from(old_key)).encrypt(n2, dek, None),
                    key_id=_key_id_from(_kek_from(old_key)),
                )
            )
        await s.commit()

    summary = await rotate(old_key=old_key, new_key=current, dry_run=False)

    assert summary["total"] == 2, (
        "the rotation tool could not see every tenant's credentials — it would "
        "report the store as migrated while it was not"
    )
    assert summary["rotated"] == 2


async def test_the_mail_poller_reaches_mailboxes_with_no_ambient_scope(db) -> None:  # noqa: ANN001
    """The worker's poll loop runs with no tenant bound and no system scope —
    exactly like this test. Under RLS a mailbox loaded before its tenant is bound
    comes back as None, and the cycle would skip every mailbox without a word."""
    from test_imap_live import FakeImapClient, _factory_for, _phishing_raw

    from envelock.core.enums import SourceMechanism
    from envelock.models import Domain
    from envelock.security.crypto import seal
    from envelock.workers.imap_fetch import run_imap_poll_cycle

    async with get_sessionmaker()() as s:
        tenant_id = uuid4()
        domain = f"poll-{uuid4().hex[:6]}.example"
        s.add(Tenant(id=tenant_id, name=domain, plan="complete", payment_method_ok=True))
        await s.flush()
        s.add(Domain(tenant_id=tenant_id, name=domain, registrable_domain=domain))
        mailbox = Mailbox(
            tenant_id=tenant_id,
            address=f"pay@{domain}",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[SourceMechanism.IMAP_IDLE.value],
        )
        s.add(mailbox)
        await s.flush()
        sealed = seal(b"app-password", aad=str(mailbox.id).encode())
        s.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=tenant_id,
                kind="imap_password",
                imap_host="imap.example.com",
                imap_port=993,
                imap_security="ssl",
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
        await s.commit()

    totals = await run_imap_poll_cycle(
        client_factory=_factory_for(FakeImapClient(messages={7: _phishing_raw("7")}))
    )
    assert totals["mailboxes"] == 1, f"the poller did not reach the mailbox: {totals}"
    assert totals["fetched"] == 1


async def _tenant_with_mailbox(**mailbox_fields):  # noqa: ANN003, ANN202
    from envelock.core.enums import SourceMechanism
    from envelock.models import Domain
    from envelock.security.crypto import seal

    tenant_id = uuid4()
    domain = f"bg-{uuid4().hex[:6]}.example"
    async with get_sessionmaker()() as s:
        s.add(Tenant(id=tenant_id, name=domain, plan="complete", payment_method_ok=True))
        await s.flush()
        s.add(Domain(tenant_id=tenant_id, name=domain, registrable_domain=domain,
                     verification_token=f"tok{uuid4().hex[:10]}"))  # noqa: S106
        mailbox = Mailbox(
            tenant_id=tenant_id,
            address=f"pay@{domain}",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[SourceMechanism.IMAP_IDLE.value],
            **mailbox_fields,
        )
        s.add(mailbox)
        await s.flush()
        sealed = seal(b"app-password", aad=str(mailbox.id).encode())
        s.add(
            MailboxCredential(
                mailbox_id=mailbox.id,
                tenant_id=tenant_id,
                kind="imap_password",
                imap_host="imap.example.com",
                imap_port=993,
                imap_security="ssl",
                ciphertext=sealed.ciphertext,
                wrapped_dek=sealed.wrapped_dek,
                key_id=sealed.key_id,
            )
        )
        await s.commit()
        return tenant_id, domain, mailbox.id


async def test_a_queued_history_scan_runs_with_no_ambient_scope(db) -> None:  # noqa: ANN001
    from test_imap_live import FakeImapClient, _factory_for, _phishing_raw

    from envelock.workers.imap_fetch import _run_queued_backfill

    _, _, mailbox_id = await _tenant_with_mailbox()
    await _run_queued_backfill(
        mailbox_id,
        30,
        client_factory=_factory_for(FakeImapClient(messages={3: _phishing_raw("3")})),
    )
    async with get_sessionmaker()() as s:
        state = (await s.get(Mailbox, mailbox_id)).backfill_state
    assert state and state["status"] == "done", f"the queued scan did not run: {state}"


async def test_the_lookalike_watcher_sees_and_records_every_tenant(db, monkeypatch) -> None:  # noqa: ANN001
    from datetime import UTC, datetime

    from envelock.channels.external import brand
    from envelock.models import LookalikeDomain
    from envelock.workers.scheduler import _load_protected_domains, _persist_ct_observation
    from envelock.workers.watchers import DomainObservation

    tenant_id, domain, _ = await _tenant_with_mailbox()
    assert domain in await _load_protected_domains(), (
        "the watcher loaded no protected domains — it would watch nothing"
    )

    class _NoMx:
        has_mx = False

    async def _probe(_domain: str):  # noqa: ANN202
        return _NoMx()

    monkeypatch.setattr(brand, "probe_domain", _probe)
    lookalike = "x" + domain
    await _persist_ct_observation(
        DomainObservation(
            domain=lookalike,
            source="ct",
            observed_at=datetime.now(UTC),
            protected_domain=domain,
            technique="addition",
            similarity=0.9,
        )
    )
    async with get_sessionmaker()() as s:
        rows = (
            await s.execute(
                select(LookalikeDomain).where(LookalikeDomain.tenant_id == tenant_id)
            )
        ).scalars().all()
    assert [r.candidate_domain for r in rows] == [lookalike]


async def test_forwarded_mail_reaches_its_tenant(db) -> None:  # noqa: ANN001
    from test_imap_live import _phishing_raw

    from envelock.channels.mail.forward_runner import (
        resolve_tenant_by_token,
        run_forwarded_message,
    )
    from envelock.models import Domain

    tenant_id, domain, _ = await _tenant_with_mailbox()
    async with get_sessionmaker()() as s:
        token = (
            await s.execute(select(Domain.verification_token).where(Domain.name == domain))
        ).scalar_one()

    assert await resolve_tenant_by_token(token) == tenant_id, (
        "the ingest token resolved to nothing — every forwarded message would be dropped"
    )
    result = await run_forwarded_message(tenant_id, _phishing_raw("f1"))
    dropped = ("no mailbox connected", "tenant not entitled (trial lapsed?)")
    assert result.get("reason") not in dropped, result
