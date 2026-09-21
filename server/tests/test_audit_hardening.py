"""Regressions for the findings of the 2026-09-01 whole-codebase audit.

Each test here corresponds to a defect that was live in the running product.
They are grouped by the mechanism they protect, not by module, because the
point of the file is "these specific attacks must stay closed".
"""

from __future__ import annotations

import base64
import json
import tomllib
from pathlib import Path

from fastapi.testclient import TestClient

PW = "correct horse battery staple 9"


# ── Packaging ────────────────────────────────────────────────────────────────
def test_every_runtime_import_is_a_runtime_dependency() -> None:
    """Modules imported by `src/` must be declared in `dependencies`, not `dev`.

    `httpx` was declared dev-only while twelve runtime call sites imported it —
    payments, the LLM providers, OAuth token exchange, webhook delivery, the KMS
    providers, Safe Browsing, geo-IP and the CT watcher. The Dockerfile runs
    `pip install .`, so every production image raised ImportError the first time
    any of those ran, and the test suite could never catch it because `.[dev]`
    installs httpx.
    """
    root = Path(__file__).resolve().parents[1]
    meta = tomllib.loads((root / "pyproject.toml").read_text())
    runtime = {
        _dist_name(spec) for spec in meta["project"]["dependencies"]
    }
    dev_only = {
        _dist_name(spec) for spec in meta["project"]["optional-dependencies"]["dev"]
    } - runtime

    imported = set()
    for path in (root / "src").rglob("*.py"):
        for line in path.read_text().splitlines():
            stripped = line.strip()
            for prefix in ("import ", "from "):
                if stripped.startswith(prefix):
                    module = stripped[len(prefix) :].split()[0].split(".")[0]
                    imported.add(module)

    leaked = sorted(dev_only & imported)
    assert not leaked, (
        f"{leaked} are imported by src/ but declared dev-only — a production "
        "image built with `pip install .` will not have them"
    )


def _dist_name(spec: str) -> str:
    """'python-stdnum>=1.20' -> 'python_stdnum' (the import-ish form)."""
    name = spec.split(">")[0].split("<")[0].split("=")[0].split("[")[0].strip()
    return name.replace("-", "_")


# ── Rate limiting ────────────────────────────────────────────────────────────
def _forged_bearer(subject: str) -> str:
    """A token with the right *shape* and a garbage signature."""
    payload = base64.urlsafe_b64encode(
        json.dumps({"sub": subject, "typ": "access"}).encode()
    ).decode().rstrip("=")
    return f"{payload}.{'A' * 43}"


def test_forged_bearer_does_not_mint_a_fresh_rate_limit_bucket() -> None:
    """The limiter must key on a *verified* subject, or fall back to the peer IP.

    `client_identity` used to read `sub` out of the unverified payload, on the
    reasoning that "a forged subject can only throttle itself". But the buckets
    that matter sit on endpoints that take no authentication at all, so an
    attacker could attach a fresh random unsigned bearer per request and land in
    a new empty window every time — unlimited password-reset mail to any address,
    unlimited SMS at our cost, unlimited 25 MB bodies into the parsers.
    """
    from envelock.security.middleware import _subject_of

    assert _subject_of(_forged_bearer("attacker-1")) is None
    assert _subject_of("not-a-token") is None
    assert _subject_of("") is None


def test_forged_bearers_all_share_one_bucket(client: TestClient) -> None:
    """End-to-end: rotating the forged subject must not reset the limit."""
    from envelock.security.limits import RULES

    rule = RULES["auth.password"]
    last = None
    for i in range(rule.limit + 3):
        last = client.post(
            "/api/v1/auth/password/forgot",
            json={"email": f"nobody{i}@acme-forge.example"},
            headers={"Authorization": f"Bearer {_forged_bearer(f'rotating-{i}')}"},
        )
    assert last is not None
    assert last.status_code == 429, (
        "a rotating forged bearer still escaped the limiter — every rate limit "
        "in the product is bypassable"
    )


def test_a_real_token_still_buckets_by_subject() -> None:
    """The legitimate behaviour the unverified read was there to provide: a
    token rotation must NOT hand the holder a fresh bucket."""
    from datetime import timedelta
    from uuid import uuid4

    from envelock.auth.security import Role, issue_token
    from envelock.security.middleware import _subject_of

    user_id, tenant_id = uuid4(), uuid4()

    def mint() -> str:
        return issue_token(
            user_id=user_id,
            tenant_id=tenant_id,
            role=Role.OWNER,
            typ="access",
            ttl=timedelta(minutes=15),
        )

    first, second = mint(), mint()

    assert first != second, "two issued tokens should differ (distinct jti)"
    assert _subject_of(first) == _subject_of(second) == str(user_id)


# ── Domain ownership ─────────────────────────────────────────────────────────
def _register_and_auth(client: TestClient, email: str, name: str) -> dict:
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": PW, "tenant_name": name},
    )
    login = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PW}
    ).json()
    skip = client.post(
        "/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}
    ).json()
    return {"Authorization": f"Bearer {skip['access_token']}"}


def test_cannot_bootstrap_a_domain_belonging_to_someone_else(
    client: TestClient,
) -> None:
    """Workspace hijack: claiming another company's domain used to be a single
    request, after which every future signup from that domain was routed into
    the attacker's tenant as a pending member — with the attacker as owner."""
    victim = _register_and_auth(client, "owner@victimco.example", "VictimCo")
    assert (
        client.post(
            "/api/v1/tenants/bootstrap",
            json={"name": "VictimCo", "domain": "victimco.example"},
            headers=victim,
        ).status_code
        == 201
    )

    attacker = _register_and_auth(client, "attacker@evilco.example", "EvilCo")
    stolen = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Totally VictimCo", "domain": "victimco.example"},
        headers=attacker,
    )
    assert stolen.status_code == 409, (
        "an attacker claimed a domain another tenant already holds — every "
        "future signup from it lands in the attacker's workspace"
    )


def test_cannot_bootstrap_an_unrelated_domain(client: TestClient) -> None:
    """Even an unclaimed domain needs a relationship: your own email domain, or
    a tenant that has already DNS-verified something."""
    attacker = _register_and_auth(client, "attacker@squatco.example", "SquatCo")
    resp = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "Not Mine", "domain": "some-other-company.example"},
        headers=attacker,
    )
    assert resp.status_code == 403


def test_owner_can_still_bootstrap_their_own_domain(client: TestClient) -> None:
    """The legitimate path must be untouched."""
    h = _register_and_auth(client, "owner@legitco.example", "LegitCo")
    resp = client.post(
        "/api/v1/tenants/bootstrap",
        json={"name": "LegitCo", "domain": "legitco.example"},
        headers=h,
    )
    assert resp.status_code == 201
    assert resp.json()["domain"] == "legitco.example"


# ── A1 payment-identifier extraction ─────────────────────────────────────────
IBAN = "GB29NWBK60161331926819"
ZWSP = "​"
NBSP = " "


def _ids(text: str) -> set[tuple[str, str]]:
    from envelock.util.payments import extract_bank_identifiers

    return {(b.scheme, b.identifier) for b in extract_bank_identifiers(text)}


def test_iban_is_found_however_a_human_formatted_it() -> None:
    """Every rendering of one account must produce one identifier.

    The old pattern demanded rigid four-character groups, so the standard
    printed form — the way an IBAN appears on essentially every real invoice —
    did not match as an IBAN at all. The leftover digits then matched the UK
    sort-code pattern, so A1 stored "926819" as the vendor's account. The same
    account typed unspaced stored the full IBAN. Two identifiers for one
    account is precisely the "bank details changed" signal A1 exists to raise:
    it produced false Criticals on reformatted invoices and silent misses on
    genuinely altered ones.
    """
    renderings = [
        f"Please remit to our bank account IBAN {IBAN}",
        "Please remit to our bank account IBAN GB29 NWBK 6016 1331 9268 19",
        f"Remit to IBAN GB29{NBSP}NWBK{NBSP}6016{NBSP}1331{NBSP}9268{NBSP}19",
        "Remit to IBAN GB29\tNWBK\t6016\t1331\t9268\t19",
        "Remit to IBAN GB29 NWBK 6016 1331 9268 19 by Friday please",
    ]
    for text in renderings:
        assert ("iban", IBAN) in _ids(text), f"IBAN not recognised in: {text!r}"


def test_invisible_characters_do_not_hide_a_bank_change() -> None:
    """A zero-width space renders as nothing, so the message reads normally to
    the recipient while every regex sees a different string. It cost an attacker
    one keystroke to switch off the flagship detection entirely."""
    assert ("iban", IBAN) in _ids(
        f"Remit to IBAN GB29NWBK6016133{ZWSP}19268 19"
    )
    # ...and in the context word, which gates sort-code/ACH/account extraction.
    assert _ids(f"Please send to our ba{ZWSP}nk: 60-16-13 / 31926819012")


def test_fullwidth_digits_are_folded() -> None:
    text = "Remit to bank IBAN GB29NWBK60161331926819".replace("2", "２").replace("9", "９")
    assert ("iban", IBAN) in _ids(text)


def test_iban_does_not_also_register_as_a_sort_code() -> None:
    """An IBAN contains long digit runs. Leaving it in the text for the later
    patterns manufactured phantom identifiers for the same account."""
    ids = _ids("Please remit to our bank account IBAN GB29 NWBK 6016 1331 9268 19")
    assert ids == {("iban", IBAN)}, f"phantom identifiers alongside the IBAN: {ids}"


def test_ordinary_numbers_still_do_not_fire() -> None:
    """The precision guard must survive the normalisation change: no payment
    context means no bare-account extraction."""
    assert _ids("Order 12345678901 shipped, tracking 998877665") == set()


# ── Readiness vs liveness ────────────────────────────────────────────────────
def test_health_is_liveness_and_ready_is_readiness(client: TestClient) -> None:
    """`/health` answered 200 without touching a dependency — while deploy.sh
    gated the release on it and the Dockerfile HEALTHCHECK trusted it. A build
    that could not reach Postgres was reported as a successful deploy."""
    live = client.get("/health")
    assert live.status_code == 200
    assert live.json()["status"] == "ok"

    ready = client.get("/ready")
    assert ready.status_code == 200
    body = ready.json()
    assert body["status"] == "ready"
    # The point of the endpoint: it actually reports on dependencies.
    assert body["checks"]["database"] == "ok"


def test_ready_reports_503_when_the_database_is_gone(
    client: TestClient, monkeypatch
) -> None:
    async def _boom() -> str:
        raise ConnectionError("postgres is gone")

    monkeypatch.setattr("envelock.api.health._check_database", _boom)
    resp = client.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["status"] == "not_ready"
    assert resp.json()["checks"]["database"].startswith("failed")


# ── Retention ────────────────────────────────────────────────────────────────
async def test_purge_batches_past_the_bind_parameter_limit(session) -> None:
    """Above ~32767 expired alerts the old `.in_(every_id)` exceeded asyncpg's
    bind-parameter limit, the statement raised, and because the whole purge
    shared one transaction the commit never ran — so nothing at all was purged,
    including the message bodies deleted earlier in the same call. Retention
    silently stopped working entirely, at the point where there was most data.

    2,500 rows is enough to prove the loop batches and terminates (batch = 1000)
    without making the test slow.
    """
    from datetime import UTC, datetime, timedelta
    from uuid import uuid4

    from sqlalchemy import func, select

    from envelock.governance.retention import purge_expired
    from envelock.models import Alert, Tenant

    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="PurgeCo"))
    await session.flush()

    old = datetime.now(UTC) - timedelta(days=800)  # past the 730-day alert policy
    for _ in range(2_500):
        session.add(
            Alert(
                id=uuid4(),
                tenant_id=tenant_id,
                title="expired",
                body="expired alert body",
                tier="low",
                state="open",
                created_at=old,
            )
        )
    await session.commit()

    counts = await purge_expired(session)

    assert counts["alert"] == 2_500
    remaining = (
        await session.execute(
            select(func.count()).select_from(Alert).where(Alert.tenant_id == tenant_id)
        )
    ).scalar_one()
    assert remaining == 0


# ── Baseline poisoning (learn) ───────────────────────────────────────────────
async def test_a_flagged_message_never_becomes_the_vendor_baseline(session) -> None:
    """A HIGH/CRITICAL message must teach the counterparty model nothing.

    `learn()` carried a comment saying bank details are "only learned from
    messages we did not flag" — but no such check existed, and `learn` was
    called unconditionally. That inverted the flagship detection: a fraudster
    impersonating a vendor the tenant had never been emailed by before *was* the
    first message for that counterparty, so their account became the trusted
    baseline. Every genuine invoice from the real vendor afterwards then raised
    "the bank details do not match the account on file" — an alert pointing at
    the victim instead of the attacker.
    """
    from uuid import uuid4

    from sqlalchemy import select

    from envelock.channels.mail.parser import parse_message
    from envelock.core.enums import MailboxClass, SourceMechanism
    from envelock.models import BankRecord, Counterparty, Mailbox, Tenant
    from envelock.platform.pipeline import analyse_event

    owned = frozenset({"acme.com"})
    tenant_id = uuid4()
    session.add(Tenant(id=tenant_id, name="Acme"))
    await session.flush()
    mailbox = Mailbox(
        tenant_id=tenant_id,
        address="pay@acme.com",
        mailbox_class=MailboxClass.PROTECTED.value,
        sources=[SourceMechanism.IMAP_IDLE.value],
    )
    session.add(mailbox)
    await session.flush()

    raw = (
        "From: Accounts <accounts@brand-new-vendor.example>\r\n"
        "To: pay@acme.com\r\n"
        "Subject: URGENT invoice - bank details changed\r\n"
        "Message-ID: <fraud-1@brand-new-vendor.example>\r\n"
        "\r\n"
        "Our bank account has changed. Please remit immediately and "
        "confidentially to IBAN GB33BUKB20201555555555. Do not tell anyone, "
        "this is urgent and must be paid today.\r\n"
    )
    event = parse_message(
        raw.encode(),
        tenant_id=tenant_id,
        mailbox_id=mailbox.id,
        source=SourceMechanism.IMAP_IDLE,
        owned_domains=owned,
        remediable=True,
    )
    result = await analyse_event(session, event, tenant_id=tenant_id, owned_domains=owned)
    await session.commit()

    from envelock.core.enums import AlertTier

    assert result.assessment is not None
    assert result.assessment.tier in (AlertTier.HIGH, AlertTier.CRITICAL), (
        "this message should be flagged; if it is not, the test proves nothing"
    )

    banks = (
        (
            await session.execute(
                select(BankRecord).where(BankRecord.tenant_id == tenant_id)
            )
        )
        .scalars()
        .all()
    )
    assert banks == [], (
        "a flagged message taught us the attacker's account as the vendor's "
        f"baseline: {[b.identifier for b in banks]}"
    )

    # The message is still *observed* — it did arrive, and that is worth knowing.
    cp = (
        await session.execute(
            select(Counterparty).where(
                Counterparty.tenant_id == tenant_id,
                Counterparty.registrable_domain == "brand-new-vendor.example",
            )
        )
    ).scalar_one()
    assert cp.message_count == 1


# ── Novel-vendor BEC path ────────────────────────────────────────────────────
def test_the_novel_vendor_combinations_are_reachable() -> None:
    """A2 must be able to fire on first contact, or the whole family is dead code.

    `risk/engine.py` carries six combinations for "novel-vendor BEC (no prior A1
    baseline to diff against)" — {A2,A7,A14}, {A2,A3}, {A2,A4}, {A2,A5},
    {A2,A6}, {A2,B7} — each forcing CRITICAL with a callback prompt. Every one
    pairs A2 with a signal that only fires on FIRST contact.

    But A7 returns nothing once `message_count > 0`, and A2 used to return
    nothing unless a Counterparty row already existed — and `learn()` creates
    that row only *after* detection. So A2 and A7 were mutually exclusive and
    none of these combinations could ever match. The first-strike BEC that A1
    structurally cannot catch was not caught by this path either: it topped out
    at HIGH with no callback, instead of CRITICAL with "phone them before you
    pay".

    This is a structural assertion rather than a message-level one, because the
    defect was structural: two predicates that can never both be true.
    """
    import inspect

    from envelock.detections import content, impersonation
    from envelock.risk.engine import _COMBINATIONS

    novel = [c for c, _explanation, floor in _COMBINATIONS if "A2" in c and floor is not None]
    assert novel, "the novel-vendor combinations have gone missing"

    a2_source = inspect.getsource(content._A2BankRegistry.evaluate)
    assert "cp is None or not _external" not in a2_source, (
        "A2 bails out when there is no counterparty row again — every "
        "novel-vendor combination is unreachable"
    )

    a7_source = inspect.getsource(impersonation._A7FirstContact.evaluate)
    assert "message_count > 0" in a7_source, (
        "A7 no longer keys on first contact; re-check that it can still "
        "co-occur with A2"
    )
