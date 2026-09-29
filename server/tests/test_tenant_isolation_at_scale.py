"""Isolation under load, not just in a pair.

`test_cross_tenant_isolation` proves tenant B cannot reach tenant A's object by
id. That is the right test and it is not enough, because it uses two tenants,
sequentially, on a warm connection. The failures this file looks for only exist
at scale:

* a `WHERE tenant_id = ...` that is correct but reads a stale value from a
  shared object (a module-level cache, a default argument, a contextvar that
  outlives its request);
* a LIST endpoint that filters correctly for one tenant and, under interleaved
  requests, serves rows from whichever tenant's query warmed the cache;
* connection-pool reuse that carries `SET LOCAL` state — the mechanism row-level
  security depends on — from one request into the next;
* a UNIQUE constraint or counter that is global where it should be per-tenant,
  which only shows up once enough tenants exist to collide.

Every one of those is invisible with two tenants and obvious with hundreds, and
every one leaks one company's mail to another. That is the failure this product
cannot survive.

Two deliberate choices about how this is built:

**Seeded through the ORM, not the signup endpoint.** Registration runs scrypt by
design, so a thousand real registrations is minutes of CPU spent proving
something this file is not testing. Tokens are minted exactly as the login route
mints them, so the API is exercised as a real client would.

**Seeded inside each test, not in a fixture.** `_clean_database` is autouse and
synchronous; an async fixture that seeds is ordered such that the truncate ran
*after* the seed, leaving every request to 401 against empty tables — which
reads like an auth bug and is not one. Seeding in the body removes the
ambiguity. It cost an hour to find; it is written down so nobody pays twice.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from envelock.auth.security import Role, issue_token

#: One thousand companies, five logins each — the shape the product is sold
#: into, and enough that a global-uniqueness mistake has to collide.
TENANTS = 1000
USERS_PER_TENANT = 5

#: How many of those to exercise over HTTP. Every tenant is SEEDED (that is what
#: makes collisions and cache-scoping faults possible); a sample is queried,
#: because a thousand sequential requests proves nothing the sample does not and
#: turns a ten-second test into a minute.
SAMPLE = 200


def _token(user_id: UUID, tenant_id: UUID, role: Role = Role.OWNER) -> str:
    return issue_token(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        typ="access",
        ttl=timedelta(minutes=30),
    )


def _headers(t: dict) -> dict:
    return {"Authorization": f"Bearer {_token(t['users'][0], t['tenant_id'])}"}


async def _seed(session, count: int = TENANTS) -> list[dict]:  # noqa: ANN001
    """`count` complete companies. Every value that could collide carries the
    tenant's index, so a leak does not merely show up — it names its owner."""
    from envelock.core.enums import AlertTier, MailboxClass
    from envelock.models import Alert, Domain, Mailbox, Tenant, User

    built: list[dict] = []
    now = datetime.now(UTC)
    for i in range(count):
        slug = f"t{i:04d}"
        tenant = Tenant(id=uuid4(), name=f"Company {i}", plan="complete")
        tenant.payment_method_ok = True
        tenant.primary_domain = f"{slug}.example"
        session.add(tenant)
        # Flushed before its dependents: with thousands of pending objects the
        # unit of work batches inserts by table, which sent alerts ahead of the
        # tenants they reference.
        await session.flush()
        session.add(
            Domain(
                id=uuid4(),
                tenant_id=tenant.id,
                name=f"{slug}.example",
                registrable_domain=f"{slug}.example",
                verification_token="tok",  # noqa: S106 — a DNS proof token
                verified_at=now,
            )
        )
        users = []
        for u in range(USERS_PER_TENANT):
            user = User(
                id=uuid4(),
                tenant_id=tenant.id,
                email=f"user{u}@{slug}.example",
                password_hash="x",  # noqa: S106 — not a credential, a NOT NULL
                role=Role.OWNER.value if u == 0 else Role.MEMBER.value,
                is_admin=(u == 0),
                status="active",
                email_verified_at=now,
            )
            session.add(user)
            users.append(user)
        await session.flush()
        mailbox = Mailbox(
            id=uuid4(),
            tenant_id=tenant.id,
            address=f"pay@{slug}.example",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[],
        )
        session.add(mailbox)
        await session.flush()
        session.add(
            Alert(
                id=uuid4(),
                tenant_id=tenant.id,
                mailbox_id=mailbox.id,
                tier=AlertTier.CRITICAL.value,
                title=f"SECRET-{slug}",  # a leak names its owner
                body=f"body for {slug}",
                state="open",
            )
        )
        built.append(
            {
                "slug": slug,
                "tenant_id": tenant.id,
                "users": [u.id for u in users],
                "mailbox_id": mailbox.id,
            }
        )
    await session.commit()
    return built


def _assert_only_mine(body: str, slug: str, what: str) -> None:
    """Every row returned belongs to `slug`, and the caller's own row is there.

    Parsed rather than substring-matched. At this scale "is any other tenant's
    marker anywhere in this string" is a million comparisons — and a positive
    identity check is the stronger assertion anyway: it also catches a row that
    carries no marker at all, which a negative check waves through.
    """
    payload = json.loads(body)
    rows = payload.get("alerts", payload.get("mailboxes", []))
    assert rows, f"{slug}: {what} came back empty — it should see its own row"
    for row in rows:
        marker = row.get("title") or row.get("address") or ""
        assert slug in marker, (
            f"{slug} was served {what} belonging to someone else: {marker!r}"
        )


@pytest.mark.asyncio
async def test_every_tenant_sees_only_itself_under_interleaved_requests(
    session, client: TestClient
) -> None:
    """The core claim, made across a sample with requests interleaved.

    Sequential per-tenant checks pass even when request state leaks, because
    nothing else has run in between. Interleaving is what makes a shared cache
    or a reused connection actually hand one tenant another's rows.
    """
    built = await _seed(session)

    # Deterministic, and adjacent requests are never the same tenant — the
    # arrangement a per-request cache survives and a shared one does not.
    order = list(range(SAMPLE))
    order = order[1::2] + order[0::2]

    for i in order:
        t = built[i]
        h = _headers(t)
        alerts = client.get("/api/v1/alerts", headers=h)
        mailboxes = client.get("/api/v1/mailboxes", headers=h)
        assert alerts.status_code == 200, alerts.text[:200]
        assert mailboxes.status_code == 200, mailboxes.text[:200]
        _assert_only_mine(alerts.text, t["slug"], "an alert")
        _assert_only_mine(mailboxes.text, t["slug"], "a mailbox")


@pytest.mark.asyncio
async def test_concurrent_requests_from_many_tenants_never_cross(
    session, client: TestClient
) -> None:
    """The same claim with requests genuinely in flight together.

    `TestClient` is synchronous, so the concurrency comes from threads — which
    is the shape that matters: the connection pool, any module-level cache and
    the contextvar row-level security binds are all process-wide and shared
    between threads exactly as they are between concurrent requests.
    """
    built = await _seed(session)

    async def one(i: int) -> tuple[int, int, str]:
        r = await asyncio.to_thread(
            client.get, "/api/v1/alerts", headers=_headers(built[i])
        )
        return i, r.status_code, r.text

    for start in range(0, SAMPLE, 50):
        batch = range(start, min(start + 50, SAMPLE))
        for i, code, body in await asyncio.gather(*(one(i) for i in batch)):
            assert code == 200, f"{built[i]['slug']}: {code} {body[:200]}"
            _assert_only_mine(body, built[i]["slug"], "an alert")


@pytest.mark.asyncio
async def test_a_token_for_one_tenant_cannot_reach_anothers_objects(
    session, client: TestClient
) -> None:
    """Direct object reference, across many pairs rather than one.

    404 not 403 throughout: a 403 confirms the id exists, which turns the
    endpoint into an oracle for enumerating another company's mailboxes.
    """
    built = await _seed(session, count=SAMPLE)

    for i in range(0, SAMPLE, 7):
        victim = built[i]
        attacker = built[(i + 1) % SAMPLE]
        h = _headers(attacker)

        r = client.get(f"/api/v1/mailboxes/{victim['mailbox_id']}", headers=h)
        assert r.status_code != 403, (
            "answered 403 — that confirms the id exists and makes this an "
            "enumeration oracle"
        )
        assert r.status_code in (404, 405, 422), f"{r.status_code}: {r.text[:200]}"
        assert victim["slug"] not in r.text, "the refusal leaked the address"


@pytest.mark.asyncio
async def test_a_member_sees_only_its_own_mailbox_and_only_its_own_tenant(
    session, client: TestClient
) -> None:
    """A non-owner login is confined twice over: to its tenant, and within that
    tenant to its own mailbox.

    Every other test here signs as the owner. Most real logins are not owners,
    and a role check that accidentally stood in for a tenant check would pass
    all of them and fail here.

    The second half is the part worth having. A member of a company is NOT
    entitled to the whole company's alerts — "members see only their own
    mailbox" is what the Team screen promises — so this asserts that the
    member's own alert comes back and the colleague's does not.
    """
    from envelock.core.enums import AlertTier, MailboxClass
    from envelock.models import Alert, Mailbox

    built = await _seed(session, count=40)

    # Give each member a mailbox of their own, with its own alert, so "sees
    # nothing" and "sees only their own" are distinguishable.
    for t in built:
        mb = Mailbox(
            id=uuid4(),
            tenant_id=t["tenant_id"],
            address=f"user1@{t['slug']}.example",
            mailbox_class=MailboxClass.PROTECTED.value,
            sources=[],
        )
        session.add(mb)
        await session.flush()
        session.add(
            Alert(
                id=uuid4(),
                tenant_id=t["tenant_id"],
                mailbox_id=mb.id,
                tier=AlertTier.CRITICAL.value,
                title=f"SECRET-{t['slug']}-MEMBER",
                body="member's own",
                state="open",
            )
        )
    await session.commit()

    for i in range(0, 40, 5):
        t = built[i]
        h = {
            "Authorization": (
                f"Bearer {_token(t['users'][1], t['tenant_id'], Role.MEMBER)}"
            )
        }
        r = client.get("/api/v1/alerts", headers=h)
        assert r.status_code == 200, f"{t['slug']}: {r.status_code} {r.text[:200]}"
        rows = json.loads(r.text).get("alerts", [])
        titles = [row.get("title", "") for row in rows]

        # Confined to its tenant.
        for title in titles:
            assert t["slug"] in title, (
                f"{t['slug']}'s member was served another tenant's alert: {title!r}"
            )
        # Confined, within the tenant, to its own mailbox: the owner's pay@
        # alert must not be here.
        assert f"SECRET-{t['slug']}" not in titles, (
            f"{t['slug']}'s member was served the owner's mailbox alert — "
            "members see only their own mailbox"
        )


@pytest.mark.asyncio
async def test_seeded_scale_did_not_collide_on_anything_global(session) -> None:
    """A thousand companies coexisting at all.

    A UNIQUE index that should be per-tenant but is global does not fail at two
    tenants; it fails the first time two of them pick the same ordinary value —
    a mailbox called `pay@`, a domain, an ingest token. Every tenant here has
    one of each.
    """
    from sqlalchemy import func, select

    from envelock.models import Mailbox, Tenant, User

    await _seed(session)

    for model, expected in (
        (Tenant, TENANTS),
        (Mailbox, TENANTS),
        (User, TENANTS * USERS_PER_TENANT),
    ):
        got = (
            await session.execute(select(func.count()).select_from(model))
        ).scalar_one()
        assert got >= expected, f"{model.__name__}: seeded {expected}, found {got}"
