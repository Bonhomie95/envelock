"""The client sensor, end to end on the server side.

Three things were broken before this, and every one of them meant the Group-C
account-takeover detections the Complete plan sells could never fire:

* sensor sessions never ended, so one heartbeat kept a mailbox "attended"
  forever and silently disabled C11;
* a returning or relocated device never counted as a new sign-in;
* nothing ever noticed a message being read, so C11 had no input at all.

These tests pin the fixes, and the security properties of the new sensor token:
it is scoped to one mailbox and one device, it dies with revocation or with its
owner's suspension, and it cannot read anything.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import platform_sessionmaker as get_sessionmaker
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from envelock.api.auth import _reset_store
from envelock.auth.security import _totp_at
from envelock.main import app
from envelock.models import (
    Alert,
    AttestedRead,
    Finding,
    MailboxCredential,
    SensorDevice,
    SensorPairing,
    SensorSession,
    User,
)
from envelock.platform import sensor as rules

FINGERPRINT = "device-7f3a91c2"
DOMAIN = "sensorco.example"


@pytest.fixture
def client() -> Iterator[TestClient]:
    _reset_store()
    with TestClient(app) as c:
        yield c
    _reset_store()


def _admin(client: TestClient, domain: str = DOMAIN) -> dict[str, str]:
    email = f"it@{domain}"
    pw = "a-long-enough-passphrase"
    client.post(
        "/api/v1/auth/register", json={"email": email, "password": pw, "tenant_name": domain}
    )
    login = client.post("/api/v1/auth/login", json={"email": email, "password": pw}).json()
    setup = client.post("/api/v1/auth/mfa/setup", json={"token": login["mfa_token"]}).json()
    tokens = client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_token": login["mfa_token"],
            "code": _totp_at(setup["secret"], int(time.time()) // 30),
        },
    ).json()
    h = {"Authorization": f"Bearer {tokens['access_token']}"}
    client.post("/api/v1/tenants/bootstrap", json={"name": domain, "domain": domain}, headers=h)
    return h


def _mailbox(client: TestClient, h: dict, address: str) -> str:
    r = client.post(
        "/api/v1/mailboxes",
        json={"address": address, "mailbox_class": "protected"},
        headers=h,
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _pair(client: TestClient, h: dict, mailbox_id: str) -> str:
    r = client.post("/api/v1/sensor/pairings", json={"mailbox_id": mailbox_id}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()["code"]


def _enroll(
    client: TestClient, code: str, *, fingerprint: str = FINGERPRINT, kind: str = "browser"
) -> dict:
    r = client.post(
        "/api/v1/sensor/enroll",
        json={
            "code": code,
            "client": kind,
            "device_fingerprint": fingerprint,
            "label": "Chrome on macOS",
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def _sensor(token: str) -> dict[str, str]:
    return {"Authorization": f"Sensor {token}"}


def _enrolled(client: TestClient) -> tuple[dict, str, dict]:
    """(admin headers, mailbox id, sensor headers) for cfo@DOMAIN."""
    h = _admin(client)
    mailbox_id = _mailbox(client, h, f"cfo@{DOMAIN}")
    token = _enroll(client, _pair(client, h, mailbox_id))["token"]
    return h, mailbox_id, _sensor(token)


def _beat(client: TestClient, headers: dict, **extra) -> dict:
    body = {"device_fingerprint": FINGERPRINT, "browser": "Chrome", "os": "macOS"}
    body.update(extra)
    r = client.post("/api/v1/sensor/heartbeat", json=body, headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def _db(coro_fn):  # noqa: ANN001, ANN202
    async def run():  # noqa: ANN202
        async with get_sessionmaker()() as s:
            out = await coro_fn(s)
            await s.commit()
            return out

    return asyncio.run(run())


# ── Pure rules ───────────────────────────────────────────────────────────────
def test_message_refs_normalise_to_one_spelling() -> None:
    """Thunderbird hands over the Message-ID without brackets, Outlook with
    them. The poller reads the raw header. All three must meet."""
    assert rules.normalize_message_ref("<ABC.123@Mail.Example>") == "abc.123@mail.example"
    assert rules.normalize_message_ref("  abc.123@mail.example ") == "abc.123@mail.example"
    assert rules.normalize_message_ref("*") == "*"


def test_message_refs_match_the_sensor_clients_exactly() -> None:
    """The sensor (JavaScript) and the server (Python) must spell every
    Message-ID the same way, or a read the owner attested looks like an
    intruder's. Both suites check the same vectors file; this one skips only
    when the server repo is checked out without the client beside it."""
    import json
    import pathlib

    fixture = (
        pathlib.Path(__file__).resolve().parents[2]
        / "client/sensor/test/fixtures/message-refs.json"
    )
    if not fixture.exists():
        pytest.skip("client/sensor is not checked out next to server/")
    for raw, expected in json.loads(fixture.read_text())["cases"]:
        assert rules.normalize_message_ref(raw) == expected, raw


def test_pairing_codes_forgive_typing_but_nothing_else() -> None:
    display, hashed = rules.mint_pairing_code()
    assert len(display) == 9 and display[4] == "-"
    assert rules.pairing_code_hash(display) == hashed
    assert rules.pairing_code_hash(display.lower().replace("-", " ")) == hashed
    assert rules.pairing_code_hash("SHORT") is None
    # O and 0 are not in the alphabet — a typo cannot collide with a real code.
    assert rules.pairing_code_hash("O0O0-O0O0") is None


def test_network_change_needs_a_real_move_when_location_is_known() -> None:
    """Phones and home routers change address constantly; alerting on that is
    how a security product gets muted."""
    same_place = {"previous_ip": "1.1.1.1", "previous_country": "US", "previous_asn": 7018}
    assert not rules.network_changed(**same_place, ip="1.1.1.2", country="US", asn=7018)
    assert rules.network_changed(**same_place, ip="5.5.5.5", country="NG", asn=7018)
    assert rules.network_changed(**same_place, ip="5.5.5.5", country="US", asn=16509)
    # Nothing resolves — the address is all there is.
    blind = {"previous_ip": "1.1.1.1", "previous_country": None, "previous_asn": None}
    assert rules.network_changed(**blind, ip="5.5.5.5", country=None, asn=None)


# ── Enrolment ────────────────────────────────────────────────────────────────
def test_a_paired_sensor_reports_with_its_own_token(client: TestClient) -> None:
    _, _, sensor = _enrolled(client)
    body = _beat(client, sensor)
    assert body["acknowledged"] and body["new_session"]
    assert body["reason"] == "new_device"


def test_a_sensor_token_cannot_read_anything(client: TestClient) -> None:
    """Stolen, it can post heartbeats. It cannot read a single alert."""
    _, _, sensor = _enrolled(client)
    for path in ("/api/v1/alerts", "/api/v1/mailboxes", "/api/v1/tenant", "/api/v1/auth/me"):
        assert client.get(path, headers=sensor).status_code == 401, path


def test_a_pairing_code_works_once(client: TestClient) -> None:
    h = _admin(client)
    code = _pair(client, h, _mailbox(client, h, f"cfo@{DOMAIN}"))
    _enroll(client, code)
    again = client.post(
        "/api/v1/sensor/enroll",
        json={"code": code, "client": "browser", "device_fingerprint": "device-other-01"},
    )
    assert again.status_code == 400


def test_an_expired_code_is_refused_with_the_same_answer(client: TestClient) -> None:
    """Every failure reads identically, so the endpoint cannot be used to learn
    whether a code exists."""
    h = _admin(client)
    code = _pair(client, h, _mailbox(client, h, f"cfo@{DOMAIN}"))

    async def expire(s):  # noqa: ANN001, ANN202
        await s.execute(
            update(SensorPairing).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )

    _db(expire)
    expired = client.post(
        "/api/v1/sensor/enroll",
        json={"code": code, "client": "browser", "device_fingerprint": FINGERPRINT},
    )
    never = client.post(
        "/api/v1/sensor/enroll",
        json={"code": "ABCD-EFGH", "client": "browser", "device_fingerprint": FINGERPRINT},
    )
    assert expired.status_code == never.status_code == 400
    assert expired.json() == never.json()


def test_redeeming_codes_is_rate_limited(client: TestClient) -> None:
    """What makes an 8-character code safe is how few guesses you get."""
    statuses = [
        client.post(
            "/api/v1/sensor/enroll",
            json={"code": "ABCD-EFGH", "client": "browser", "device_fingerprint": FINGERPRINT},
        ).status_code
        for _ in range(12)
    ]
    assert 429 in statuses


def test_a_member_cannot_pair_someone_elses_mailbox(client: TestClient) -> None:
    h = _admin(client)
    boss = _mailbox(client, h, f"ceo@{DOMAIN}")
    _mailbox(client, h, f"clerk@{DOMAIN}")
    created = client.post(
        "/api/v1/members", json={"email": f"clerk@{DOMAIN}", "role": "member"}, headers=h
    )
    assert created.status_code == 201, created.text
    login = client.post(
        "/api/v1/auth/login",
        json={"email": f"clerk@{DOMAIN}", "password": created.json()["temporary_password"]},
    ).json()
    skip = client.post("/api/v1/auth/mfa/skip", json={"token": login["mfa_token"]}).json()
    member = {"Authorization": f"Bearer {skip['access_token']}"}
    r = client.post("/api/v1/sensor/pairings", json={"mailbox_id": boss}, headers=member)
    assert r.status_code == 404


# ── Pinning ──────────────────────────────────────────────────────────────────
def test_a_token_speaks_for_one_device_only(client: TestClient) -> None:
    """Otherwise one token could manufacture the concurrency C6 reads, or keep
    a mailbox looking permanently attended so C11 never fires."""
    _, _, sensor = _enrolled(client)
    r = client.post(
        "/api/v1/sensor/heartbeat",
        json={"device_fingerprint": "device-somebody-else"},
        headers=sensor,
    )
    assert r.status_code == 403


def test_a_token_speaks_for_one_mailbox_only(client: TestClient) -> None:
    h, _, sensor = _enrolled(client)
    _mailbox(client, h, f"ceo@{DOMAIN}")
    r = client.post(
        "/api/v1/sensor/heartbeat",
        json={"device_fingerprint": FINGERPRINT, "mailbox_address": f"ceo@{DOMAIN}"},
        headers=sensor,
    )
    assert r.status_code == 403


def test_revoking_a_device_kills_its_token_and_its_session(client: TestClient) -> None:
    h, _, sensor = _enrolled(client)
    _beat(client, sensor)
    device_id = client.get("/api/v1/sensor/devices", headers=h).json()["devices"][0]["id"]

    assert client.delete(f"/api/v1/sensor/devices/{device_id}", headers=h).status_code == 204
    assert (
        client.post(
            "/api/v1/sensor/heartbeat", json={"device_fingerprint": FINGERPRINT}, headers=sensor
        ).status_code
        == 401
    )

    async def open_sessions(s):  # noqa: ANN001, ANN202
        return (
            await s.execute(select(SensorSession).where(SensorSession.ended_at.is_(None)))
        ).scalars().all()

    assert _db(open_sessions) == [], "a revoked device must not keep the mailbox attended"


def test_suspending_the_owner_silences_their_sensors(client: TestClient) -> None:
    _, _, sensor = _enrolled(client)

    async def suspend(s):  # noqa: ANN001, ANN202
        await s.execute(update(User).values(status="suspended"))

    _db(suspend)
    r = client.post(
        "/api/v1/sensor/heartbeat", json={"device_fingerprint": FINGERPRINT}, headers=sensor
    )
    assert r.status_code == 403


# ── Liveness ─────────────────────────────────────────────────────────────────
def test_a_steady_heartbeat_is_one_session(client: TestClient) -> None:
    _, _, sensor = _enrolled(client)
    assert _beat(client, sensor)["new_session"] is True
    second = _beat(client, sensor)
    assert second["new_session"] is False


def test_a_device_that_went_quiet_signs_in_again(client: TestClient) -> None:
    """A laptop reopened the next morning is a sign-in, and C7 has to be asked
    whether it came from somewhere impossible."""
    _, _, sensor = _enrolled(client)
    _beat(client, sensor)

    async def go_quiet(s):  # noqa: ANN001, ANN202
        await s.execute(
            update(SensorSession).values(
                last_seen_at=datetime.now(UTC)
                - timedelta(seconds=rules.SESSION_STALE_SECONDS + 60)
            )
        )

    _db(go_quiet)
    back = _beat(client, sensor)
    assert back["new_session"] is True and back["reason"] == "returned"

    async def sessions(s):  # noqa: ANN001, ANN202
        return (await s.execute(select(SensorSession))).scalars().all()

    rows = _db(sessions)
    assert len(rows) == 2
    assert sum(1 for r in rows if r.ended_at is None) == 1


def test_the_same_device_from_a_new_country_is_a_new_sign_in(
    client: TestClient, monkeypatch
) -> None:
    """The copied browser profile: same device id, same token, different
    network. It must run through the sign-in detections, not just refresh."""
    from envelock.channels.identity import geo

    countries = {"198.51.100.10": "US", "203.0.113.50": "NG"}

    async def fake_lookup(ip, **_):  # noqa: ANN001, ANN202
        return geo.GeoFacts(ip=ip, country=countries.get(ip))

    monkeypatch.setattr(geo, "lookup", fake_lookup)
    _, _, sensor = _enrolled(client)

    home = TestClient(app, client=("198.51.100.10", 50000))
    away = TestClient(app, client=("203.0.113.50", 50000))
    body = {"device_fingerprint": FINGERPRINT}
    assert home.post("/api/v1/sensor/heartbeat", json=body, headers=sensor).json()["new_session"]
    moved = away.post("/api/v1/sensor/heartbeat", json=body, headers=sensor).json()
    assert moved["new_session"] is True
    assert moved["reason"] == "network_changed"


# ── C11 through the endpoint ─────────────────────────────────────────────────
def _flag(client: TestClient, h: dict, ref: str) -> dict:
    r = client.post(
        "/api/v1/sensor/flag-changed",
        json={"mailbox_address": f"cfo@{DOMAIN}", "message_ref": ref, "flag": "seen"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    return r.json()


def _c11(body: dict) -> bool:
    return "C11" in {f["service"] for f in body["findings"]}


def test_installing_the_sensor_no_longer_disables_silent_access(client: TestClient) -> None:
    """The bug: sessions never ended, so after one heartbeat the mailbox was
    "attended" forever and C11 could not fire again."""
    h, _, sensor = _enrolled(client)
    _beat(client, sensor)

    async def go_quiet(s):  # noqa: ANN001, ANN202
        await s.execute(
            update(SensorSession).values(
                last_seen_at=datetime.now(UTC) - timedelta(hours=8)
            )
        )

    _db(go_quiet)
    assert _c11(_flag(client, h, "<overnight@evil.example>"))


def test_a_live_device_covers_a_read(client: TestClient) -> None:
    h, _, sensor = _enrolled(client)
    _beat(client, sensor)
    assert not _c11(_flag(client, h, "<while-here@mail.example>"))


def test_an_attested_message_covers_its_read_in_any_spelling(client: TestClient) -> None:
    h, _, sensor = _enrolled(client)
    r = client.post(
        "/api/v1/sensor/message-opened",
        json={"device_fingerprint": FINGERPRINT, "message_ref": "<Inv-4471@Supplier.Example>"},
        headers=sensor,
    )
    assert r.status_code == 200 and r.json()["message_ref"] == "inv-4471@supplier.example"
    body = _flag(client, h, "inv-4471@supplier.example")
    assert body["attested"] is True and not _c11(body)


def test_an_activity_attestation_covers_any_read_in_its_window(client: TestClient) -> None:
    """Most webmail cannot name the message being read. "The owner is reading
    right now" is still evidence the read was theirs."""
    h, _, sensor = _enrolled(client)
    client.post(
        "/api/v1/sensor/message-opened",
        json={"device_fingerprint": FINGERPRINT, "message_ref": "*"},
        headers=sensor,
    )
    assert _flag(client, h, "<anything@mail.example>")["attested"] is True


# ── C11 from the poller ──────────────────────────────────────────────────────
from tests.test_imap_live import FakeImapClient, _connected_mailbox, _factory_for  # noqa: E402


def _raw(mid: str) -> bytes:
    return (
        b'From: "Jane" <jane@partner.com>\r\n'
        b"To: pay@acme.com\r\n"
        b"Subject: catching up\r\n"
        b"Message-ID: <" + mid.encode() + b">\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Nothing to see here.\r\n"
    )


class ReadAwareImap(FakeImapClient):
    """The fake server, plus the \\Seen state and header PEEK the read-watch uses."""

    def __init__(self, messages: dict[int, bytes]) -> None:
        super().__init__(messages=messages)
        self.seen: set[int] = set()

    def search(self, criteria):  # noqa: ANN001, ANN201
        if criteria == ["UNSEEN"]:
            return sorted(u for u in self.messages if u not in self.seen)
        return super().search(criteria)

    def fetch(self, messages, data):  # noqa: ANN001, ANN201
        if "BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)]" in data:
            out = {}
            for uid in messages:
                raw = self.messages.get(uid)
                if raw is None:
                    continue
                header = next(
                    line for line in raw.split(b"\r\n") if line.lower().startswith(b"message-id")
                )
                out[uid] = {
                    b"FLAGS": (b"\\Seen",) if uid in self.seen else (),
                    b"BODY[HEADER.FIELDS (MESSAGE-ID)]": header + b"\r\n\r\n",
                }
            return out
        return super().fetch(messages, data)


async def _armed(session, *, armed: bool = True, enrolled: bool = True):  # noqa: ANN001, ANN202
    mailbox = await _connected_mailbox(session)
    mailbox.silent_access_armed = armed
    if enrolled:
        session.add(
            SensorDevice(
                tenant_id=mailbox.tenant_id,
                user_id=uuid4(),
                mailbox_id=mailbox.id,
                prefix="abcdefgh",
                hashed="0" * 64,
                client="thunderbird",
                device_fingerprint=FINGERPRINT,
            )
        )
    await session.flush()
    return mailbox


async def _c11_alerts(session, tenant_id) -> int:  # noqa: ANN001
    rows = (
        await session.execute(
            select(Finding.id)
            .join(Alert, Alert.id == Finding.alert_id)
            .where(Alert.tenant_id == tenant_id, Finding.service == "C11")
        )
    ).all()
    return len(rows)


@pytest.mark.asyncio
async def test_the_poller_catches_a_message_read_while_nobody_was_here(session) -> None:
    """The whole point. Before this, nothing ever looked at read flags, so C11
    had no input at all."""
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session)
    imap = ReadAwareImap({201: _raw("m201@partner.com"), 202: _raw("m202@partner.com")})
    first = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert first["ok"] and first["reads_observed"] == 0, "the first poll only sets a baseline"

    imap.seen.add(201)  # someone opens it, with no Envelock device anywhere
    second = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert second["reads_observed"] == 1
    assert second["silent_access_alerts"] == 1
    assert await _c11_alerts(session, mailbox.tenant_id) == 1


@pytest.mark.asyncio
async def test_the_poller_accepts_the_owners_attested_read(session) -> None:
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session)
    imap = ReadAwareImap({201: _raw("m201@partner.com")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))

    session.add(
        AttestedRead(
            tenant_id=mailbox.tenant_id,
            mailbox_id=mailbox.id,
            message_ref="m201@partner.com",
            device_fingerprint=FINGERPRINT,
            read_at=datetime.now(UTC),
        )
    )
    imap.seen.add(201)
    second = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert second["reads_observed"] == 1
    assert second["silent_access_alerts"] == 0


@pytest.mark.asyncio
async def test_a_message_we_moved_is_not_a_read(session) -> None:
    """Our own quarantine and rewrite move messages out of the inbox. A UID
    that vanished is not a UID someone opened."""
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session)
    imap = ReadAwareImap({201: _raw("m201@partner.com")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    del imap.messages[201]
    second = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert second["reads_observed"] == 0


@pytest.mark.asyncio
async def test_an_unarmed_mailbox_is_not_watched(session) -> None:
    """Off until the owner says their mailbox is only read on covered devices —
    otherwise every phone read tonight pages them."""
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session, armed=False)
    imap = ReadAwareImap({201: _raw("m201@partner.com")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    imap.seen.add(201)
    second = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert second["reads_observed"] == 0 and second["silent_access_alerts"] == 0
    cred = (
        await session.execute(
            select(MailboxCredential).where(MailboxCredential.mailbox_id == mailbox.id)
        )
    ).scalar_one()
    assert cred.imap_unseen_uids is None


@pytest.mark.asyncio
async def test_armed_without_a_sensor_is_not_watched(session) -> None:
    """With no sensor enrolled every read is unvouched, so the detection would
    be nothing but false alarms."""
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session, enrolled=False)
    imap = ReadAwareImap({201: _raw("m201@partner.com")})
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    imap.seen.add(201)
    second = await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    assert second["silent_access_alerts"] == 0


@pytest.mark.asyncio
async def test_the_read_watch_never_marks_mail_read(session) -> None:
    """Asking "who read this?" must not answer "we did"."""
    from envelock.workers.imap_fetch import sync_mailbox

    mailbox = await _armed(session)
    imap = ReadAwareImap({201: _raw("m201@partner.com")})
    requested: list = []
    original_fetch = imap.fetch

    def spy(messages, data):  # noqa: ANN001, ANN202
        requested.append(list(data))
        return original_fetch(messages, data)

    imap.fetch = spy
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    imap.seen.add(201)
    await sync_mailbox(session, mailbox, client_factory=_factory_for(imap))
    flat = [item for call in requested for item in call]
    assert flat, "the watch must have fetched something"
    assert all("RFC822" not in item and item != "BODY[]" for item in flat)
