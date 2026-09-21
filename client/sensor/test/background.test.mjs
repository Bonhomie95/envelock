/* The browser extension's background, driven with a fake `chrome`. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Background, clock, envelockServer, fakeStorageArea } from "./helpers.mjs";

const GMAIL = "https://mail.google.com";
const HINET = "https://webmail.hinet.net";

function fakeChrome({ granted = true } = {}) {
  const registered = [];
  return {
    storage: { local: fakeStorageArea() },
    alarms: { create() {}, onAlarm: { addListener() {} } },
    runtime: {
      id: "test-extension",
      getURL: (p) => "chrome-extension://test-extension/" + p,
      onMessage: { addListener() {} },
    },
    permissions: { contains: async () => granted },
    scripting: {
      getRegisteredContentScripts: async () => registered.slice(),
      unregisterContentScripts: async ({ ids }) => {
        for (const id of ids) registered.splice(registered.findIndex((s) => s.id === id), 1);
      },
      registerContentScripts: async (scripts) => {
        registered.push(...scripts);
      },
    },
    registered,
  };
}

async function setup({ origin = GMAIL, mailbox = "cfo@acme.example", granted } = {}) {
  const api = fakeChrome({ granted });
  const server = envelockServer({ mailbox });
  const now = clock();
  const bg = Background.create(api, { fetch: server, now, userAgent: "Chrome/128 Macintosh" });
  const reply = await bg.onOptionsMessage({
    type: "enroll",
    code: "ABCD-EFGH",
    webmailOrigin: origin,
    webmailKind: "gmail",
    apiBase: "https://api.envelock.test",
  });
  assert.equal(reply.ok, true, reply.error);
  return { api, server, now, bg };
}

const tab = (url) => ({ tab: { id: 1 }, url });

test("the first sign of an open webmail sends a heartbeat immediately", async () => {
  const { server, bg } = await setup();
  await bg.onContentMessage({ type: "present", account: "cfo@acme.example" }, tab(GMAIL + "/mail/u/0/"));
  assert.equal(server.to("/sensor/heartbeat").length, 1);
  // Already present: the next report waits for the minute tick.
  await bg.onContentMessage({ type: "present", account: "cfo@acme.example" }, tab(GMAIL + "/mail/u/0/"));
  assert.equal(server.to("/sensor/heartbeat").length, 1);
});

test("the minute tick beats only while the webmail is still open", async () => {
  const { server, bg, now } = await setup();
  await bg.onContentMessage({ type: "present", account: "cfo@acme.example" }, tab(GMAIL + "/"));
  now.advance(60 * 1000);
  await bg.onAlarm({ name: "envelock-heartbeat" });
  assert.equal(server.to("/sensor/heartbeat").length, 2);
  // The tab closed: no reports for longer than the presence window.
  now.advance(bg.PRESENCE_TTL_MS + 1000);
  await bg.onAlarm({ name: "envelock-heartbeat" });
  assert.equal(server.to("/sensor/heartbeat").length, 2, "absent means silent — that is what C11 relies on");
});

test("opening a message attests it for that mailbox", async () => {
  const { server, bg } = await setup();
  await bg.onContentMessage({ type: "opened", ref: "*", account: "cfo@acme.example" }, tab(GMAIL + "/"));
  const [call] = server.to("/sensor/message-opened");
  assert.equal(call.body.message_ref, "*");
});

test("a named message is attested by its Message-ID", async () => {
  const { server, bg } = await setup({ origin: HINET });
  await bg.onContentMessage({ type: "opened", ref: "<Inv-4471@Supplier.Example>", account: null }, tab(HINET + "/?_task=mail"));
  const [call] = server.to("/sensor/message-opened");
  assert.equal(call.body.message_ref, "inv-4471@supplier.example");
});

test("another Gmail account in the same browser does not speak for this mailbox", async () => {
  const { server, bg } = await setup();
  const out = await bg.onContentMessage({ type: "opened", ref: "*", account: "personal@gmail.com" }, tab(GMAIL + "/"));
  assert.equal(out.matched, 0);
  assert.equal(server.calls.filter((c) => c.key.includes("/sensor/") && !c.key.includes("enroll")).length, 0);
});

test("the person's own webmail gets the content script; Gmail does not need it", async () => {
  const { api } = await setup({ origin: HINET });
  assert.equal(api.registered.length, 1);
  assert.deepEqual(api.registered[0].matches, [HINET + "/*"]);
  assert.equal(api.registered[0].allFrames, true, "Roundcube shows messages in an iframe");

  const gmail = await setup({ origin: GMAIL });
  assert.equal(gmail.api.registered.length, 0, "covered by the manifest already");
});

test("no content script is registered without the person's permission", async () => {
  const { api } = await setup({ origin: HINET, granted: false });
  assert.equal(api.registered.length, 0);
});

test("removing a mailbox unregisters its content script", async () => {
  const { api, bg } = await setup({ origin: HINET });
  await bg.onOptionsMessage({ type: "remove", mailbox: "cfo@acme.example" });
  assert.equal(api.registered.length, 0);
});

test("the settings page is never handed the token", async () => {
  const { bg } = await setup();
  const status = await bg.onOptionsMessage({ type: "status" });
  assert.equal(JSON.stringify(status).includes("envs_"), false);
  assert.equal(status.enrollments[0].webmailOrigin, GMAIL);
});

test("a web page cannot enrol or remove through a content script", async () => {
  const { bg } = await setup();
  let answered = false;
  const handled = bg.onMessage(
    { type: "remove", mailbox: "cfo@acme.example" },
    { tab: { id: 9 }, url: GMAIL + "/" },
    () => {
      answered = true;
    },
  );
  assert.equal(handled, false);
  assert.equal(answered, false);
  const status = await bg.onOptionsMessage({ type: "status" });
  assert.equal(status.enrollments.length, 1, "still enrolled");
});

test("an unknown 'other webmail' address is refused before anything is sent", async () => {
  const api = fakeChrome();
  const server = envelockServer();
  const bg = Background.create(api, { fetch: server });
  const reply = await bg.onOptionsMessage({ type: "enroll", code: "ABCD-EFGH", webmailOrigin: "http://insecure.example" });
  assert.equal(reply.ok, false);
  assert.equal(server.calls.length, 0);
});
