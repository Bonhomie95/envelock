#!/usr/bin/env node
/*
 * The shipped sensor core against a real Envelock API — every call over HTTP,
 * nothing faked. Proves the client and server agree on the wire, which the
 * unit tests on each side (each with the other faked) cannot.
 *
 *   ENVELOCK_E2E_API=http://127.0.0.1:8011 node sensor/scripts/e2e-local.mjs
 *
 * Needs a development API (it relies on the dev-only verify_link in the
 * registration response) with domain verification off, so it can add a
 * mailbox on a made-up domain. Never point it at production.
 */
await import("../core/envelock-sensor.js");
const S = globalThis.EnvelockSensor;

const API = (process.env.ENVELOCK_E2E_API || "http://127.0.0.1:8011").replace(/\/+$/, "");
if (/envelock\.org/.test(API)) throw new Error("refusing to run the e2e against production");

const suffix = Math.random().toString(36).slice(2, 8);
const domain = `sensor-e2e-${suffix}.example`;
const admin = `it@${domain}`;
const mailbox = `cfo@${domain}`;
const password = "a-long-enough-passphrase";

let step = 0;
function ok(label, detail = "") {
  step += 1;
  console.log(`  ✔ ${String(step).padStart(2)}  ${label}${detail ? "  — " + detail : ""}`);
}
function fail(label, detail) {
  console.error(`  ✘ ${label}\n      ${detail}`);
  process.exit(1);
}

async function call(method, path, { body, token, sensor } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (sensor) headers.Authorization = `Sensor ${sensor}`;
  const res = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = { raw: text };
  }
  return { status: res.status, json };
}

console.log(`Envelock sensor e2e against ${API}`);

// 1. A workspace and a mailbox, the way a customer makes them.
const reg = await call("POST", "/api/v1/auth/register", {
  body: { email: admin, password, tenant_name: domain },
});
if (reg.status !== 201) fail("register", JSON.stringify(reg.json));
if (reg.json.verify_link) {
  const token = new URL(reg.json.verify_link).searchParams.get("token");
  const v = await call("POST", "/api/v1/auth/verify-email", { body: { token } });
  if (v.status !== 200) fail("verify email", JSON.stringify(v.json));
}
const login = await call("POST", "/api/v1/auth/login", { body: { email: admin, password } });
if (login.status !== 200) fail("login", JSON.stringify(login.json));
const skip = await call("POST", "/api/v1/auth/mfa/skip", { body: { token: login.json.mfa_token } });
const session = skip.json.access_token;
if (!session) fail("session", JSON.stringify(skip.json));
await call("POST", "/api/v1/tenants/bootstrap", { token: session, body: { name: domain, domain } });
const mb = await call("POST", "/api/v1/mailboxes", {
  token: session,
  body: { address: mailbox, mailbox_class: "protected" },
});
if (mb.status !== 201) fail("add mailbox", JSON.stringify(mb.json));
ok("workspace and mailbox created", mailbox);

// 2. The dashboard mints a pairing code.
const pairing = await call("POST", "/api/v1/sensor/pairings", { token: session, body: { mailbox_id: mb.json.id } });
if (pairing.status !== 201) fail("pairing code", JSON.stringify(pairing.json));
ok("pairing code minted", pairing.json.code);

// 3. The real client trades it for its own token.
const client = new S.SensorClient({
  storage: S.memoryStorage(),
  client: "browser",
  apiBase: API,
  userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Chrome/128.0",
});
const enrollment = await client.enroll(pairing.json.code.toLowerCase().replace("-", " "));
if (enrollment.mailbox !== mailbox) fail("enroll", `enrolled for ${enrollment.mailbox}`);
if (!enrollment.token.startsWith("envs_")) fail("enroll", "no sensor token");
ok("enrolled with a typed code", `${enrollment.label}, device ${enrollment.deviceId.slice(0, 14)}…`);

// 4. The code works once.
const reuse = await call("POST", "/api/v1/sensor/enroll", {
  body: { code: pairing.json.code, client: "browser", device_fingerprint: "dev-someone-else-01" },
});
if (reuse.status !== 400) fail("code reuse", `expected 400, got ${reuse.status}`);
ok("a used code is refused", `${reuse.status}`);

// 5. Heartbeat — the first is a sign-in.
const [beat] = await client.heartbeat({ mailClient: "Webmail" });
if (!beat.ok || !beat.body.new_session) fail("first heartbeat", JSON.stringify(beat));
ok("first heartbeat is a new sign-in", `reason=${beat.body.reason}, protection=${beat.body.protection_level}`);
const [again] = await client.heartbeat({ mailClient: "Webmail" });
if (!again.ok || again.body.new_session) fail("second heartbeat", JSON.stringify(again));
ok("second heartbeat continues the session");

// 6. The token cannot read anything.
const peek = await call("GET", "/api/v1/alerts", { sensor: enrollment.token });
if (peek.status !== 401) fail("token scope", `sensor token read /alerts: ${peek.status}`);
ok("the sensor token cannot read alerts", `${peek.status}`);

// 7. Attest a read, then have the server evaluate that read.
const attest = await client.attest(mailbox, "<E2E-Invoice-4471@Supplier.Example>");
if (!attest.ok || attest.body.message_ref !== "e2e-invoice-4471@supplier.example") {
  fail("attest", JSON.stringify(attest));
}
ok("read attested", attest.body.message_ref);
const read = await call("POST", "/api/v1/sensor/flag-changed", {
  token: session,
  body: { mailbox_address: mailbox, message_ref: "e2e-invoice-4471@supplier.example", flag: "seen" },
});
const c11 = (read.json.findings || []).some((f) => f.service === "C11");
if (!read.json.attested || c11) fail("attested read", JSON.stringify(read.json));
ok("the server accepts the owner's read", "attested, no C11");

// 8. The dashboard sees the device, live.
const devices = await call("GET", "/api/v1/sensor/devices", { token: session });
const device = (devices.json.devices || []).find((d) => d.mailbox === mailbox);
if (!device || !device.live || device.client !== "browser") fail("device list", JSON.stringify(devices.json));
ok("dashboard lists the device as live", device.label);

// 9. Removing it in the dashboard kills the token.
const del = await call("DELETE", `/api/v1/sensor/devices/${device.id}`, { token: session });
if (del.status !== 204) fail("revoke", `${del.status}`);
const [dead] = await client.heartbeat();
const status = await client.status();
if (dead.ok || !status[0].revoked) fail("after revoke", JSON.stringify({ dead, status }));
ok("removed in the dashboard → the sensor knows", status[0].lastError);

console.log(`\nAll ${step} steps passed — client and server agree on the wire.`);
