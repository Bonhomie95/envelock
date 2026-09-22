/* The shared core every client runs. */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { API, S, clock, envelockServer, fakeFetch } from "./helpers.mjs";

const vectors = JSON.parse(
  readFileSync(new URL("./fixtures/message-refs.json", import.meta.url), "utf8"),
).cases;

function client(fetchImpl, now = clock()) {
  return new S.SensorClient({
    storage: S.memoryStorage(),
    client: "thunderbird",
    fetch: fetchImpl,
    apiBase: API,
    now,
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Thunderbird/128.0",
  });
}

test("normalises Message-IDs exactly as the server does", () => {
  for (const [input, expected] of vectors) {
    assert.equal(S.normalizeMessageRef(input), expected, JSON.stringify(input));
  }
});

test("a device id is created once and kept", async () => {
  const c = client(envelockServer());
  const first = await c.deviceId();
  assert.match(first, /^dev-[0-9a-f-]{16,}$/);
  assert.equal(await c.deviceId(), first);
});

test("enrolling trades the code for a token and pins the device id", async () => {
  const server = envelockServer();
  const c = client(server);
  const e = await c.enroll("abcd-efgh");
  assert.equal(e.mailbox, "cfo@acme.example");
  assert.equal(e.token, "envs_testtoken1234567890");
  const [call] = server.to("/sensor/enroll");
  assert.equal(call.body.code, "abcd-efgh");
  assert.equal(call.body.client, "thunderbird");
  assert.equal(call.body.device_fingerprint, await c.deviceId());
  assert.equal(call.body.label, "Thunderbird on macOS");
  assert.equal(call.auth, null, "enrolment carries no credential — the code is the credential");
});

test("re-pairing a mailbox replaces its token instead of adding a second", async () => {
  let n = 0;
  const server = fakeFetch({
    "POST /api/v1/sensor/enroll": () => [200, { token: `envs_token_number_${++n}`, mailbox: "cfo@acme.example" }],
  });
  const c = client(server);
  await c.enroll("AAAA-AAAA");
  await c.enroll("BBBB-BBBB");
  const list = await c.enrollments();
  assert.equal(list.length, 1);
  assert.equal(list[0].token, "envs_token_number_2");
});

test("heartbeats authenticate as the sensor, never as a person", async () => {
  const server = envelockServer();
  const c = client(server);
  await c.enroll("abcd-efgh");
  const [result] = await c.heartbeat({ mailClient: "Thunderbird 128" });
  assert.equal(result.ok, true);
  const [call] = server.to("/sensor/heartbeat");
  assert.equal(call.auth, "Sensor envs_testtoken1234567890");
  assert.equal(call.body.device_fingerprint, await c.deviceId());
  assert.equal(call.body.mail_client, "Thunderbird 128");
  assert.equal(call.body.os, "macOS");
  assert.equal("mailbox_address" in call.body, false, "the token already names the mailbox");
});

test("a 401 marks the enrollment removed and it is never retried", async () => {
  const server = envelockServer();
  const c = client(server);
  await c.enroll("abcd-efgh");
  server.calls.length = 0;
  const revoked = fakeFetch({
    "POST /api/v1/sensor/heartbeat": () => [401, { detail: "this sensor has been removed — pair it again" }],
  });
  c.fetchImpl = revoked;
  const [first] = await c.heartbeat();
  assert.equal(first.ok, false);
  assert.equal(first.revoked, true);
  const status = await c.status();
  assert.equal(status[0].revoked, true);
  await c.heartbeat();
  assert.equal(revoked.to("/sensor/heartbeat").length, 1, "no second call with a dead token");
});

test("attests the normalised Message-ID", async () => {
  const server = envelockServer();
  const c = client(server);
  await c.enroll("abcd-efgh");
  const out = await c.attest("CFO@acme.example", "<Inv-4471@Supplier.Example>");
  assert.equal(out.ok, true);
  const [call] = server.to("/sensor/message-opened");
  assert.equal(call.body.message_ref, "inv-4471@supplier.example");
  assert.equal(call.auth, "Sensor envs_testtoken1234567890");
});

test("attesting a mailbox this device is not enrolled for does nothing", async () => {
  const server = envelockServer();
  const c = client(server);
  await c.enroll("abcd-efgh");
  const out = await c.attest("someone-else@acme.example", "<x@y>");
  assert.equal(out.ok, false);
  assert.equal(server.to("/sensor/message-opened").length, 0);
});

test("a failed attestation is retried with the next heartbeat while it is still useful", async () => {
  const now = clock();
  let up = false;
  const server = fakeFetch({
    "POST /api/v1/sensor/enroll": () => [200, { token: "envs_testtoken1234567890", mailbox: "cfo@acme.example" }],
    "POST /api/v1/sensor/heartbeat": () => [200, { acknowledged: true }],
    "POST /api/v1/sensor/message-opened": () => (up ? [200, { recorded: true }] : [503, { detail: "down" }]),
  });
  const c = client(server, now);
  await c.enroll("abcd-efgh");
  await c.attest("cfo@acme.example", "<late@mail.example>");
  up = true;
  now.advance(30 * 1000);
  await c.heartbeat();
  const sends = server.to("/sensor/message-opened");
  assert.equal(sends.length, 2);
  assert.equal(sends[1].body.message_ref, "late@mail.example");
});

test("an attestation too old for the server to accept is dropped, not sent late", async () => {
  const now = clock();
  let up = false;
  const server = fakeFetch({
    "POST /api/v1/sensor/enroll": () => [200, { token: "envs_testtoken1234567890", mailbox: "cfo@acme.example" }],
    "POST /api/v1/sensor/heartbeat": () => [200, { acknowledged: true }],
    "POST /api/v1/sensor/message-opened": () => (up ? [200, { recorded: true }] : [503, { detail: "down" }]),
  });
  const c = client(server, now);
  await c.enroll("abcd-efgh");
  await c.attest("cfo@acme.example", "<stale@mail.example>");
  up = true;
  now.advance(S.ATTEST_MAX_AGE_MS + 1000);
  await c.heartbeat();
  assert.equal(server.to("/sensor/message-opened").length, 1, "only the original failed attempt");
});

test("status reports live only within the server's own session window", async () => {
  const now = clock();
  const c = client(envelockServer(), now);
  await c.enroll("abcd-efgh");
  await c.heartbeat();
  assert.equal((await c.status())[0].live, true);
  now.advance(181 * 1000);
  assert.equal((await c.status())[0].live, false);
});

test("an unreachable server is reported, not thrown", async () => {
  const c = client(async () => {
    throw new TypeError("fetch failed");
  });
  await assert.rejects(c.enroll("abcd-efgh"), /could not reach Envelock/);
});

test("device labels are what a person would recognise", () => {
  assert.equal(
    S.describeDevice("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36 Edg/128.0").label,
    "Edge on Windows",
  );
  assert.equal(S.describeDevice("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0").label, "Firefox on Linux");
  assert.equal(S.describeDevice("anything", "Outlook").label, "Outlook on unknown OS");
});

test("warningLine fits Outlook's 150-character bar and says what to do", () => {
  assert.equal(S.warningLine(null), null);
  assert.equal(
    S.warningLine({ tier: "high", action: "Don't click links until you've checked." }),
    "Envelock HIGH: Don't click links until you've checked.",
  );
  assert.equal(
    S.warningLine({ tier: "critical", confirmed_fraud: true, action: "Do not pay." }),
    "Envelock: confirmed fraud. Do not pay.",
  );
  const long = S.warningLine({ tier: "critical", action: "x".repeat(400) });
  assert.equal(long.length, 150);
  assert.ok(long.endsWith("..."));
});
