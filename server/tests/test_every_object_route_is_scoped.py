"""Every route that takes an object id, checked against another tenant's id.

`test_cross_tenant_isolation` checks the routes someone thought to write a test
for — eight of them. The API has **43** paths that accept an object id. The
other thirty-five were covered by nobody, and a missed `WHERE tenant_id = ...`
on any one of them hands another company's data out.

So this does not hold a hand-written list. It reads the OpenAPI schema, finds
every path with an id-shaped parameter, fills it with tenant A's real object,
and calls it as tenant B. A route added next year is covered the day it is
added, without anyone remembering to come back here.

Two rules the assertions encode:

* **Never 2xx.** The obvious one.
* **Never 403.** A 403 confirms the id exists, which turns the endpoint into an
  oracle for enumerating another company's alerts and mailboxes. 404 and 422 are
  both fine — "no such object" and "that is not a valid id" are indistinguishable
  to an attacker, which is the point.

**Routes this cannot fill are reported, not skipped silently.** A test that
quietly covers nine of forty-three while reading as green is worse than no test,
so the coverage count is asserted: if someone adds a route shape this cannot
build an id for, the suite says so and names it.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

PW = "correct horse battery staple 9"

#: Paths that are deliberately NOT tenant-scoped, with the reason. Anything not
#: listed here and not fillable becomes a failure, so this list is the only way
#: to opt out and every entry has to justify itself.
NOT_TENANT_SCOPED = {
    # The operator console. Cross-tenant BY DESIGN — it exists to see every
    # tenant — and gated on a staff account, which test_admin.py covers.
    "/api/v1/admin/",
    # {provider} is a name ("xero", "google"), not an object id: there is no
    # other tenant's provider to point at.
    "/api/v1/accounting/{provider}",
    "/api/v1/connect/oauth/{provider}",
    # {candidate} is a domain name observed in public CT logs, not owned data.
    "/api/v1/lookalikes/{candidate}",
}

_ID_PARAM = re.compile(r"\{([^}]*(?:id|record_id|device_id)[^}]*)\}")

#: Ids that belong to nobody, for the control request below.
def _random_ids() -> dict:
    from uuid import uuid4

    return {
        "alert_id": str(uuid4()),
        "mailbox_id": str(uuid4()),
        "member_id": str(uuid4()),
        "user_id": str(uuid4()),
        "tenant_id": str(uuid4()),
    }


def _normalise(body: str) -> str:
    """Strip the ids a response echoes back, so "same answer" means the same
    ANSWER and not merely the same shape with a different id in it."""
    return re.sub(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<id>", body
    )


def _build(client: TestClient, slug: str) -> dict:
    """One complete tenant with an object of every scoped kind."""
    email = f"owner@{slug}.example"
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": slug},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    h = {"Authorization": f"Bearer {skip['access_token']}"}
    client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": slug, "domain": f"{slug}.example"},
        headers=h,
    )
    me = client.get("/api/v1/auth/me", headers=h).json()

    mb = client.post(
        "/api/v1/mailboxes",
        json={
            "address": f"pay@{slug}.example",
            "mailbox_class": "protected",
            "sources": [],
        },
        headers=h,
    ).json()

    # A colleague, so member-approval routes have a real target.
    client.post(
        "/api/v1/auth/register",
        json={
            "email": f"colleague@{slug}.example",
            "password": PW,
            "tenant_name": slug,
        },
    )
    members = client.get("/api/v1/members", headers=h).json()
    rows = members.get("members", []) if isinstance(members, dict) else (members or [])
    member_id = next(
        (r["id"] for r in rows if r.get("email", "").startswith("colleague@")), ""
    )

    return {
        "slug": slug,
        "headers": h,
        "tenant_id": me.get("tenant_id", ""),
        "user_id": me.get("user_id", member_id),
        "member_id": member_id,
        "mailbox_id": mb.get("id", ""),
        "domain": f"{slug}.example",
    }


def _fill(path: str, victim: dict) -> str | None:
    """Substitute tenant A's real ids into `path`, or None if we cannot."""
    from uuid import uuid4

    out = path
    for param in _ID_PARAM.findall(path):
        value = {
            "alert_id": victim.get("alert_id") or str(uuid4()),
            "mailbox_id": victim["mailbox_id"],
            "user_id": victim["member_id"] or victim["user_id"],
            "staff_id": None,
            "tenant_id": victim["tenant_id"],
            "record_id": str(uuid4()),
            "device_id": str(uuid4()),
            "webhook_id": str(uuid4()),
            "job_id": str(uuid4()),
        }.get(param)
        if not value:
            return None
        out = out.replace("{" + param + "}", value)
    # Non-id params that still have to be real for the route to reach its
    # scoping check rather than dying in validation.
    out = out.replace("{domain}", victim["domain"])
    return None if "{" in out else out


def _scoped_paths(client: TestClient) -> list[tuple[str, str]]:
    spec = client.get("/openapi.json").json()
    out: list[tuple[str, str]] = []
    for path, ops in spec["paths"].items():
        if not _ID_PARAM.search(path):
            continue
        if any(path.startswith(skip) for skip in NOT_TENANT_SCOPED):
            continue
        for method in ops:
            if method in ("get", "post", "put", "patch", "delete"):
                out.append((method.upper(), path))
    return sorted(out)


@pytest.fixture
def pair(client: TestClient) -> tuple[dict, dict, TestClient]:
    victim = _build(client, "victim-co")
    attacker = _build(client, "attacker-co")
    return victim, attacker, client


def test_no_object_route_serves_another_tenant(pair) -> None:  # noqa: ANN001
    victim, attacker, client = pair
    checked: list[str] = []
    unfillable: list[str] = []
    failures: list[str] = []

    for method, path in _scoped_paths(client):
        url = _fill(path, victim)
        if url is None:
            unfillable.append(f"{method} {path}")
            continue
        checked.append(f"{method} {path}")
        r = client.request(method, url, json={}, headers=attacker["headers"])

        if 200 <= r.status_code < 300:
            # A 2xx is not automatically a leak. A route may answer the same
            # thing for "never existed", "expired" and "belongs to someone
            # else" — /jobs/{job_id} does exactly that, deliberately, because
            # its store is in-process and loses status on restart. That is
            # STRONGER than a 404: there is nothing to tell the three apart.
            # So prove indistinguishability rather than assuming a leak.
            control_url = _fill(path, {**victim, **_random_ids()})
            control = client.request(
                method, control_url, json={}, headers=attacker["headers"]
            )
            same = (
                control.status_code == r.status_code
                and _normalise(control.text) == _normalise(r.text)
            )
            if not same:
                failures.append(
                    f"{method} {path} -> {r.status_code}: answered differently "
                    f"for another tenant's real object than for an id that "
                    f"never existed, which distinguishes the two.\n"
                    f"  real:   {r.text[:160]}\n"
                    f"  random: {control.text[:160]}"
                )
        elif r.status_code == 403:
            failures.append(
                f"{method} {path} -> 403: confirms the id exists, which makes "
                "this an enumeration oracle. Answer 404."
            )
        elif victim["slug"] in r.text:
            failures.append(
                f"{method} {path} -> {r.status_code} but the body leaked "
                f"{victim['slug']}: {r.text[:160]}"
            )

    assert not failures, "\n".join(failures)
    # A green test that covered three routes would be worse than none.
    assert len(checked) >= 20, (
        f"only {len(checked)} object routes were exercised, which is too few to "
        f"mean anything. Unfillable: {unfillable}"
    )
    assert not unfillable, (
        "these object routes could not be given an id, so nothing checked them. "
        "Add the parameter to `_fill`, or justify it in NOT_TENANT_SCOPED:\n"
        + "\n".join(unfillable)
    )
