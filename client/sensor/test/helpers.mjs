/* Shared fakes for the sensor tests: a recording fetch, a fake extension
   storage area, and a controllable clock. Loading the sensor files here, once,
   puts EnvelockSensor / EnvelockWebmail / the client factories on globalThis
   exactly as a browser would. */
globalThis.__ENVELOCK_TEST__ = true;

await import("../core/envelock-sensor.js");
await import("../browser/webmail.js");
await import("../browser/background.js");
await import("../thunderbird/background.js");
await import("../outlook/taskpane.js");

export const S = globalThis.EnvelockSensor;
export const W = globalThis.EnvelockWebmail;
export const Background = globalThis.EnvelockBackground;
export const Thunderbird = globalThis.EnvelockThunderbird;
export const Outlook = globalThis.EnvelockOutlook;

export const API = "https://api.envelock.test";

/**
 * A fake server. `routes` maps "METHOD /path" to (body, init) => [status, json].
 * Unrouted calls answer 404. Every call is recorded with its parsed body and
 * Authorization header.
 */
export function fakeFetch(routes = {}) {
  const calls = [];
  async function fetchImpl(url, init = {}) {
    const u = new URL(url);
    const key = `${init.method || "GET"} ${u.pathname}`;
    const body = init.body ? JSON.parse(init.body) : undefined;
    const auth = init.headers ? init.headers.Authorization || null : null;
    calls.push({ key, url, body, auth });
    const route = routes[key];
    const [status, json] = route ? route(body, init) : [404, { detail: "not found" }];
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => json,
    };
  }
  fetchImpl.calls = calls;
  fetchImpl.to = (path) => calls.filter((c) => c.key.endsWith(path));
  return fetchImpl;
}

/** The standard happy-path server for one mailbox. */
export function envelockServer({
  mailbox = "cfo@acme.example",
  token = "envs_testtoken1234567890",
  warnings = {},
} = {}) {
  return fakeFetch({
    "POST /api/v1/sensor/enroll": () => [200, { token, mailbox, device_id: "d1", heartbeat_seconds: 60 }],
    "POST /api/v1/sensor/heartbeat": () => [200, { acknowledged: true }],
    "POST /api/v1/sensor/message-opened": (b) => [
      200,
      { recorded: true, message_ref: b.message_ref, warning: warnings[b.message_ref] ?? null },
    ],
  });
}

/** The server's warning for a flagged message, as /sensor/message-opened sends it. */
export const BANK_CHANGE_WARNING = {
  tier: "critical",
  title: "Bank details changed by a known supplier",
  action: "Don't pay until you've called +1 803 555 0100 (the number on file) to verify.",
  verify_phone: "+1 803 555 0100",
  confirmed_fraud: false,
};

export function clock(start = Date.parse("2026-09-21T09:00:00Z")) {
  let t = start;
  const now = () => t;
  now.advance = (ms) => {
    t += ms;
  };
  return now;
}

/** browser.storage.local / messenger.storage.local, in memory. */
export function fakeStorageArea() {
  const map = new Map();
  return {
    async get(key) {
      return map.has(key) ? { [key]: structuredClone(map.get(key)) } : {};
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) map.set(k, structuredClone(v));
    },
    async remove(key) {
      map.delete(key);
    },
    map,
  };
}
