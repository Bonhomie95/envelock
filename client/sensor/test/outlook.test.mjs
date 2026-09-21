/* The Outlook add-in's controller, driven with a fake Office object. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { Outlook, S, clock, envelockServer } from "./helpers.mjs";

function fakeOffice(email, messageId) {
  const handlers = {};
  const mailbox = {
    userProfile: { emailAddress: email },
    item: messageId ? { internetMessageId: messageId } : null,
    addHandlerAsync(type, fn) {
      handlers[type] = fn;
    },
    removeHandlerAsync(type) {
      delete handlers[type];
    },
  };
  return {
    EventType: { ItemChanged: "olkItemSelectedChanged" },
    context: { mailbox, diagnostics: { platform: "OfficeOnline", version: "16.0" } },
    handlers,
    select(id) {
      mailbox.item = { internetMessageId: id };
      return handlers.olkItemSelectedChanged?.();
    },
  };
}

function controller(office, server) {
  const timers = [];
  return {
    timers,
    c: Outlook.createController(office, {
      storage: S.memoryStorage(),
      fetch: server,
      now: clock(),
      setInterval: (fn, ms) => timers.push({ fn, ms }) && timers.length,
      clearInterval: () => {
        timers.length = 0;
      },
    }),
  };
}

test("pairing starts reporting and attests the open message", async () => {
  const office = fakeOffice("CFO@acme.example", "<Inv-4471@Supplier.Example>");
  const server = envelockServer();
  const { c, timers } = controller(office, server);
  await c.pair("ABCD-EFGH", "https://api.envelock.test");
  assert.equal(server.to("/sensor/heartbeat").length, 1);
  assert.equal(server.to("/sensor/heartbeat")[0].body.mail_client, "Outlook OfficeOnline 16.0");
  assert.equal(server.to("/sensor/message-opened")[0].body.message_ref, "inv-4471@supplier.example");
  assert.equal(timers.length, 1);
  assert.equal(timers[0].ms, 60 * 1000);
});

test("every message shown in the pinned pane is attested", async () => {
  const office = fakeOffice("cfo@acme.example", "<first@x>");
  const server = envelockServer();
  const { c } = controller(office, server);
  await c.pair("ABCD-EFGH", "https://api.envelock.test");
  await office.select("<second@x>");
  await office.select("<third@x>");
  assert.deepEqual(
    server.to("/sensor/message-opened").map((call) => call.body.message_ref),
    ["first@x", "second@x", "third@x"],
  );
});

test("a code for a different mailbox is refused and undone", async () => {
  const office = fakeOffice("cfo@acme.example", "<x@y>");
  const server = envelockServer({ mailbox: "ceo@acme.example" });
  const { c } = controller(office, server);
  await assert.rejects(c.pair("ABCD-EFGH", "https://api.envelock.test"), /signed in as cfo@acme.example/);
  assert.deepEqual(await c.client.enrollments(), [], "a sensor must never vouch for a mailbox it cannot see");
  assert.equal(server.to("/sensor/heartbeat").length, 0);
});

test("an already-paired device starts reporting on open", async () => {
  const office = fakeOffice("cfo@acme.example", null);
  const server = envelockServer();
  const { c } = controller(office, server);
  await c.pair("ABCD-EFGH", "https://api.envelock.test");
  const before = server.to("/sensor/heartbeat").length;
  const again = controller(office, server);
  // Same storage would be the same device; simulate a reopened pane.
  again.c.client.storage = c.client.storage;
  await again.c.start();
  assert.equal(server.to("/sensor/heartbeat").length, before + 1);
});

test("with no message selected, nothing is attested", async () => {
  const office = fakeOffice("cfo@acme.example", null);
  const server = envelockServer();
  const { c } = controller(office, server);
  await c.pair("ABCD-EFGH", "https://api.envelock.test");
  assert.equal(server.to("/sensor/message-opened").length, 0);
});

test("unpairing stops the timer, the listener and the reports", async () => {
  const office = fakeOffice("cfo@acme.example", "<x@y>");
  const server = envelockServer();
  const { c, timers } = controller(office, server);
  await c.pair("ABCD-EFGH", "https://api.envelock.test");
  await c.unpair();
  assert.equal(timers.length, 0);
  assert.equal(office.handlers.olkItemSelectedChanged, undefined);
  assert.deepEqual(await c.client.enrollments(), []);
});
