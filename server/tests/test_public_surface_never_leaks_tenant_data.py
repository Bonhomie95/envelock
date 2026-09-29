"""No unauthenticated endpoint may mention a tenant's data.

Fifty routes answer without a token: the landing page's shared-network counts,
the status page, the pricing quote, the provider catalogue, every auth form,
the webhooks. Each is public for a reason. The risk is not that they exist — it
is that one of them grows a field that happens to carry customer data, and
nothing notices, because no test asks.

So this seeds a tenant whose every value is a distinctive marker, calls every
GET that needs no token, and asserts none of those markers comes back. A route
added later is covered the day it is added.

Deliberately GET-only: a POST to a public form with an empty body exercises
validation, not disclosure, and firing writes at every public endpoint is how a
test suite starts sending mail.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

MARKERS = (
    "zzmarkerco",          # the tenant/domain name
    "zzmarker-secret",     # an alert title
    "zzmarkerbox",         # a mailbox local-part
)


@pytest.mark.asyncio
async def test_no_public_endpoint_mentions_a_tenants_data(
    session, client: TestClient
) -> None:
    from uuid import uuid4

    from envelock.core.enums import AlertTier, MailboxClass
    from envelock.models import Alert, Domain, Mailbox, Tenant

    tenant = Tenant(id=uuid4(), name="zzmarkerco", plan="complete")
    tenant.payment_method_ok = True
    tenant.primary_domain = "zzmarkerco.example"
    session.add(tenant)
    await session.flush()
    session.add(
        Domain(
            id=uuid4(),
            tenant_id=tenant.id,
            name="zzmarkerco.example",
            registrable_domain="zzmarkerco.example",
            verification_token="tok",  # noqa: S106 — a DNS proof token
        )
    )
    mailbox = Mailbox(
        id=uuid4(),
        tenant_id=tenant.id,
        address="zzmarkerbox@zzmarkerco.example",
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
            title="zzmarker-secret",
            body="zzmarker-secret body",
            state="open",
        )
    )
    await session.commit()

    spec = client.get("/openapi.json").json()
    checked = 0
    leaks: list[str] = []

    for path, ops in spec["paths"].items():
        if re.search(r"\{", path) or "get" not in ops:
            continue
        r = client.get(path)
        # 401/403 means it is not public at all, which is the other correct
        # answer; 422 means it needs a parameter we are not supplying.
        if r.status_code in (401, 403, 422):
            continue
        checked += 1
        lowered = r.text.lower()
        for marker in MARKERS:
            if marker in lowered:
                leaks.append(f"GET {path} ({r.status_code}) leaked {marker!r}")

    assert not leaks, "\n".join(leaks)
    assert checked >= 8, (
        f"only {checked} public endpoints answered, which is too few for this "
        "to mean anything — did the route table change shape?"
    )
