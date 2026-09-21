/* Recognising webmail, and an opened message, from a URL. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { W } from "./helpers.mjs";

test("knows which product a URL belongs to", () => {
  assert.equal(W.provider("https://mail.google.com/mail/u/0/#inbox"), "gmail");
  assert.equal(W.provider("https://outlook.office.com/mail/inbox"), "outlook");
  assert.equal(W.provider("https://outlook.live.com/mail/0/"), "outlook");
  assert.equal(W.provider("https://webmail.hinet.net/?_task=mail&_mbox=INBOX"), "roundcube");
  assert.equal(W.provider("https://mail.example.com/owa/"), "generic");
  assert.equal(W.provider("not a url"), null);
});

test("Gmail: a thread in the hash is an open message; a list is not", () => {
  const open = "https://mail.google.com/mail/u/0/#inbox/FMfcgzQXKqwkXLpNFjzbBnSHzhDWpKZh";
  assert.equal(W.openMessageKey(open), "gmail:FMfcgzQXKqwkXLpNFjzbBnSHzhDWpKZh");
  assert.equal(
    W.openMessageKey("https://mail.google.com/mail/u/0/#label/Suppliers/FMfcgzQXKqwkXLpNFjzbBnSHzhDWpKZh"),
    "gmail:FMfcgzQXKqwkXLpNFjzbBnSHzhDWpKZh",
  );
  for (const list of ["#inbox", "#inbox/p2", "#search/invoice", "#settings/general", ""]) {
    assert.equal(W.openMessageKey("https://mail.google.com/mail/u/0/" + list), null, list);
  }
});

test("Outlook on the web: /id/<ItemId> is an open message", () => {
  const id = "AAQkADAwATM0MDAAMS1iNTcwLWI0NzItMDACLTAwCgAQAJ";
  assert.equal(W.openMessageKey(`https://outlook.office.com/mail/inbox/id/${id}`), "outlook:" + id);
  assert.equal(W.openMessageKey(`https://outlook.live.com/mail/0/inbox/id/${id}`), "outlook:" + id);
  assert.equal(W.openMessageKey("https://outlook.office.com/mail/inbox"), null);
});

test("Roundcube: show and preview name the message; the list does not", () => {
  assert.equal(
    W.openMessageKey("https://webmail.hinet.net/?_task=mail&_action=show&_uid=4471&_mbox=INBOX"),
    "roundcube:INBOX:4471",
  );
  assert.equal(
    W.openMessageKey("https://webmail.hinet.net/?_task=mail&_uid=12&_mbox=Archive&_framed=1&_action=preview"),
    "roundcube:Archive:12",
  );
  assert.equal(W.openMessageKey("https://webmail.hinet.net/?_task=mail&_mbox=INBOX"), null);
  assert.equal(W.openMessageKey("https://webmail.hinet.net/?_task=mail&_action=show&_uid=abc"), null);
});

test("Roundcube's raw source URL is built from the open message", () => {
  const src = W.roundcubeSourceUrl("https://webmail.hinet.net/?_task=mail&_action=show&_uid=4471&_mbox=INBOX");
  const u = new URL(src);
  assert.equal(u.origin, "https://webmail.hinet.net");
  assert.equal(u.searchParams.get("_action"), "viewsource");
  assert.equal(u.searchParams.get("_uid"), "4471");
  assert.equal(u.searchParams.get("_mbox"), "INBOX");
  assert.equal(W.roundcubeSourceUrl("https://mail.google.com/mail/u/0/#inbox/x"), null);
});

test("reads the Message-ID from the headers and never looks past them", () => {
  const raw =
    "From: a@b.example\r\nMessage-ID:\r\n <folded.1@mail.example>\r\nSubject: x\r\n\r\n" +
    "Message-ID: <in-the-body@evil.example>\r\n";
  assert.equal(W.messageIdFromSource(raw), "<folded.1@mail.example>");
  assert.equal(W.messageIdFromSource("Subject: no id\r\n\r\nbody"), null);
  assert.equal(W.messageIdFromSource("Subject: x\n\nMessage-ID: <body@x>"), null);
});

test("reads the signed-in Gmail account from the title", () => {
  assert.equal(W.accountFromTitle("Inbox (3) - Jane.Doe@Acme.example - Acme Mail"), "jane.doe@acme.example");
  assert.equal(W.accountFromTitle("Mail - Jane Doe - Outlook"), null);
});

test("a tab speaks only for the enrollment on its own origin and account", () => {
  const list = [
    { mailbox: "cfo@acme.example", webmailOrigin: "https://mail.google.com" },
    { mailbox: "ceo@acme.example", webmailOrigin: "https://mail.google.com" },
    { mailbox: "ops@acme.example", webmailOrigin: "https://outlook.office.com" },
    { mailbox: "old@acme.example", webmailOrigin: "https://mail.google.com", revoked: true },
  ];
  const gmailAsCfo = W.matchEnrollments(list, "https://mail.google.com", "cfo@acme.example");
  assert.deepEqual(gmailAsCfo.map((e) => e.mailbox), ["cfo@acme.example"]);
  const owa = W.matchEnrollments(list, "https://outlook.office.com", null);
  assert.deepEqual(owa.map((e) => e.mailbox), ["ops@acme.example"]);
  assert.deepEqual(W.matchEnrollments(list, "https://evil.example", null), []);
});

test("an 'other webmail' address is reduced to an https origin", () => {
  assert.equal(W.normalizeWebmailOrigin("mail.acme.example/roundcube/"), "https://mail.acme.example");
  assert.equal(W.normalizeWebmailOrigin("https://mail.acme.example:8443/x"), "https://mail.acme.example:8443");
  assert.equal(W.normalizeWebmailOrigin("http://mail.acme.example"), null, "never over plain http");
  assert.equal(W.normalizeWebmailOrigin("http://localhost:8080"), "http://localhost:8080");
  assert.equal(W.normalizeWebmailOrigin(""), null);
});
