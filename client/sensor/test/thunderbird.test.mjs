/* The Thunderbird add-on, driven with a fake `messenger`. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Thunderbird, clock, envelockServer, fakeStorageArea } from "./helpers.mjs";

function fakeMessenger(accounts) {
  return {
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

async function setup({ accounts = ACCOUNTS, mailbox = "cfo@acme.example" } = {}) {
  const server = envelockServer({ mailbox });
  const now = clock();
  const tb = Thunderbird.create(fakeMessenger(accounts), { fetch: server, now, version: "128.3.0" });
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
