/* The Thunderbird add-on, driven with a fake `messenger`. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { BANK_CHANGE_WARNING, Thunderbird, clock, envelockServer, fakeStorageArea } from "./helpers.mjs";

function fakeMessenger(accounts) {
  const shown = { badge: {}, title: {}, color: {}, notes: [] };
  return {
    shown,
    messageDisplayAction: {
      setBadgeText: ({ tabId, text }) => (shown.badge[tabId] = text),
      setTitle: ({ tabId, title }) => (shown.title[tabId] = title),
      setBadgeBackgroundColor: ({ tabId, color }) => (shown.color[tabId] = color),
    },
    notifications: { create: (id, opts) => shown.notes.push({ id, ...opts }) },
    storage: { local: fakeStorageArea() },
    accounts: {
      list: async () => accounts,
      get: async (id) => accounts.find((a) => a.id === id) || null,
    },
    alarms: { create() {}, onAlarm: { addListener() {} } },
    messageDisplay: { onMessageDisplayed: { addListener() {} } },
    runtime: { id: "tb", onMessage: { addListener() {} }, openOptionsPage() {} },
  };
}

const ACCOUNTS = [
  { id: "account1", identities: [{ email: "CFO@acme.example" }] },
  { id: "account2", identities: [{ email: "home@personal.example" }] },
];

async function setup({ accounts = ACCOUNTS, mailbox = "cfo@acme.example", warnings = {} } = {}) {
  const server = envelockServer({ mailbox, warnings });
  const now = clock();
  const messenger = fakeMessenger(accounts);
  const tb = Thunderbird.create(messenger, { fetch: server, now, version: "128.3.0" });
  tb.shown = messenger.shown;
  const reply = await tb.onOptionsMessage({ type: "enroll", code: "ABCD-EFGH", apiBase: "https://api.envelock.test" });
  assert.equal(reply.ok, true, reply.error);
  return { server, now, tb, reply };
}

test("enrolling a mailbox Thunderbird has reports it straight away", async () => {
  const { server, reply } = await setup();
  assert.equal(reply.inThunderbird, true);
  const [beat] = server.to("/sensor/heartbeat");
  assert.equal(beat.body.mail_client, "Thunderbird 128.3.0");
});

test("a mailbox that is not set up in Thunderbird is never reported present", async () => {
  const { server, reply, tb } = await setup({ mailbox: "someone-else@acme.example" });
  assert.equal(reply.inThunderbird, false);
  await tb.beat();
  assert.equal(server.to("/sensor/heartbeat").length, 0);
});

test("displaying a message attests its real Message-ID", async () => {
  const { server, tb } = await setup();
  await tb.onDisplayed({ headerMessageId: "Inv-4471@Supplier.Example", folder: { accountId: "account1" } });
  const [call] = server.to("/sensor/message-opened");
  assert.equal(call.body.message_ref, "inv-4471@supplier.example");
});

test("a message from another account is not attested for this mailbox", async () => {
  const { server, tb } = await setup();
  await tb.onDisplayed({ headerMessageId: "private@personal.example", folder: { accountId: "account2" } });
  assert.equal(server.to("/sensor/message-opened").length, 0);
});

test("the two display events for one message are counted once", async () => {
  const { server, tb } = await setup();
  const msg = { headerMessageId: "once@mail.example", folder: { accountId: "account1" } };
  await tb.onDisplayed(msg);
  await tb.onDisplayedMany(null, [msg]);
  assert.equal(server.to("/sensor/message-opened").length, 1);
});

test("both shapes of onMessagesDisplayed are understood", async () => {
  const { server, tb, now } = await setup();
  await tb.onDisplayedMany(null, [{ headerMessageId: "a@x", folder: { accountId: "account1" } }]);
  now.advance(10_000);
  await tb.onDisplayedMany(null, { messages: [{ headerMessageId: "b@x", folder: { accountId: "account1" } }] });
  assert.deepEqual(server.to("/sensor/message-opened").map((c) => c.body.message_ref), ["a@x", "b@x"]);
});

test("a message opened from a file (no folder) is ignored", async () => {
  const { server, tb } = await setup();
  await tb.onDisplayed({ headerMessageId: "from-disk@x", external: true });
  assert.equal(server.to("/sensor/message-opened").length, 0);
});

test("a flagged message badges the toolbar button and notifies", async () => {
  const { tb } = await setup({ warnings: { "remit-88@gemini.example": BANK_CHANGE_WARNING } });
  await tb.onDisplayed({ headerMessageId: "remit-88@gemini.example", folder: { accountId: "account1" } }, { id: 7 });
  assert.equal(tb.shown.badge[7], "!");
  assert.equal(tb.shown.color[7], "#b91c1c");
  assert.match(tb.shown.title[7], /^Envelock CRITICAL: Don't pay until you've called \+1 803 555 0100/);
  assert.equal(tb.shown.notes.length, 1);
  assert.match(tb.shown.notes[0].message, /number on file/);

  await tb.onDisplayed({ headerMessageId: "clean@x", folder: { accountId: "account1" } }, { id: 7 });
  assert.equal(tb.shown.badge[7], "", "a clean message clears the badge");
  assert.equal(tb.shown.notes.length, 1);
});
