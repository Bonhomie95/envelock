/*
 * Envelock sensor — webmail recognition.
 *
 * Pure functions over a URL, a page title or a raw message source. Loaded by
 * the content script (in the webmail tab), by the background (to match a tab to
 * an enrolled mailbox) and by the tests. Like the core, it has no import/export
 * so it is both a classic script and an ES module; it exposes
 * `globalThis.EnvelockWebmail`.
 *
 * What it can and cannot see, stated plainly because the server relies on it:
 *
 * - Gmail and Outlook on the web do not expose a message's Message-ID header in
 *   the page. When a message is opened there, the sensor reports "the owner is
 *   reading" (the activity reference) rather than naming the message.
 * - Roundcube — the webmail most ISP and hosting mail runs on — puts the IMAP
 *   UID in the URL and serves the raw source to the signed-in user, so there
 *   the sensor can name the exact message.
 * - Anything else is recognised as "a webmail tab is open", which is presence,
 *   plus "the owner is interacting with it", which is activity.
 */
(function (root) {
  "use strict";

  var KNOWN_WEBMAIL = {
    gmail: ["https://mail.google.com"],
    outlook: [
      "https://outlook.office.com",
      "https://outlook.office365.com",
      "https://outlook.live.com",
    ],
  };

  function parse(url) {
    try {
      return new URL(url);
    } catch (e) {
      return null;
    }
  }

  function originOf(url) {
    var u = parse(url);
    return u ? u.origin : null;
  }

  /* The origin a person typed for "other webmail", reduced to what a host
     permission can name: scheme + host, https only (plus localhost for dev). */
  function normalizeWebmailOrigin(input) {
    var raw = String(input || "").trim();
    if (!raw) return null;
    if (!/^[a-z]+:\/\//i.test(raw)) raw = "https://" + raw;
    var u = parse(raw);
    if (!u || !u.hostname) return null;
    var local = u.hostname === "localhost" || u.hostname === "127.0.0.1";
    if (u.protocol !== "https:" && !(local && u.protocol === "http:")) return null;
    return u.origin;
  }

  function provider(url) {
    var origin = originOf(url);
    if (!origin) return null;
    if (KNOWN_WEBMAIL.gmail.indexOf(origin) !== -1) return "gmail";
    if (KNOWN_WEBMAIL.outlook.indexOf(origin) !== -1) return "outlook";
    var u = parse(url);
    if (u && u.searchParams.get("_task") === "mail") return "roundcube";
    return "generic";
  }

  /* Gmail thread ids in the hash are long base64url-ish tokens:
     #inbox/FMfcgzQXKqwkXLpNFjzbBnSHzhDWpKZh. A list view is "#inbox" or a
     page marker like "#inbox/p2". */
  function gmailKey(u) {
    var hash = (u.hash || "").replace(/^#/, "");
    if (!hash) return null;
    var parts = hash.split("/");
    var last = decodeURIComponent(parts[parts.length - 1] || "");
    if (parts.length < 2 || last.length < 16) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(last) || /^p\d+$/.test(last)) return null;
    return "gmail:" + last;
  }

  /* New Outlook on the web: /mail/inbox/id/<ItemId>, /mail/0/inbox/id/<ItemId>,
     /mail/id/<ItemId>, sometimes URL-encoded. */
  function outlookKey(u) {
    var m = /\/id\/([^/?#]+)/.exec(u.pathname + (u.hash || ""));
    return m && m[1].length >= 16 ? "outlook:" + m[1] : null;
  }

  function roundcubeKey(u) {
    var action = u.searchParams.get("_action");
    var uid = u.searchParams.get("_uid");
    if ((action !== "show" && action !== "preview") || !uid || !/^\d+$/.test(uid)) return null;
    return "roundcube:" + (u.searchParams.get("_mbox") || "INBOX") + ":" + uid;
  }

  /* A stable key for the message currently open in this tab, or null when a
     list (or anything else) is showing. The content script reports a read each
     time the key changes to a new non-null value. */
  function openMessageKey(url) {
    var u = parse(url);
    if (!u) return null;
    switch (provider(url)) {
      case "gmail":
        return gmailKey(u);
      case "outlook":
        return outlookKey(u);
      case "roundcube":
        return roundcubeKey(u);
      default:
        return null;
    }
  }

  /* Roundcube serves the raw message to its signed-in user. Fetching it from
     the page, with the page's own session, is how the sensor learns the exact
     Message-ID of what was just opened. */
  function roundcubeSourceUrl(url) {
    var u = parse(url);
    if (!u || provider(url) !== "roundcube") return null;
    var uid = u.searchParams.get("_uid");
    if (!uid || !/^\d+$/.test(uid)) return null;
    var src = new URL(u.origin + u.pathname);
    src.searchParams.set("_task", "mail");
    src.searchParams.set("_action", "viewsource");
    src.searchParams.set("_uid", uid);
    src.searchParams.set("_mbox", u.searchParams.get("_mbox") || "INBOX");
    return src.toString();
  }

  /* Pull the Message-ID from the headers of a raw message. Only the header
     block is examined; the body is never looked at. */
  function messageIdFromSource(text) {
    var source = String(text || "");
    var end = source.search(/\r?\n\r?\n/);
    var head = (end === -1 ? source : source.slice(0, end))
      /* unfold continuation lines */
      .replace(/\r?\n[ \t]+/g, " ");
    var m = /^message-id:\s*(.+)$/im.exec(head);
    return m ? m[1].trim() : null;
  }

  /* Gmail puts the signed-in address in the title:
     "Inbox (3) - jane@acme.com - Acme Mail". Outlook on the web does not. */
  function accountFromTitle(title) {
    var m = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.exec(String(title || ""));
    return m ? m[0].toLowerCase() : null;
  }

  /* Which enrollments does a report from this tab speak for?
     An enrollment names the webmail origin its owner reads the mailbox on.
     Where the page tells us which account is signed in (Gmail), that has to
     match too — two Gmail accounts in one browser are two different mailboxes.
     Where it does not (Outlook on the web), the origin decides. */
  function matchEnrollments(enrollments, origin, account) {
    var acct = account ? String(account).toLowerCase() : null;
    return (enrollments || []).filter(function (e) {
      if (!e || e.revoked || !e.webmailOrigin || e.webmailOrigin !== origin) return false;
      return !acct || e.mailbox === acct;
    });
  }

  function isKnownOrigin(origin) {
    return (
      KNOWN_WEBMAIL.gmail.indexOf(origin) !== -1 || KNOWN_WEBMAIL.outlook.indexOf(origin) !== -1
    );
  }

  root.EnvelockWebmail = {
    KNOWN_WEBMAIL: KNOWN_WEBMAIL,
    originOf: originOf,
    normalizeWebmailOrigin: normalizeWebmailOrigin,
    provider: provider,
    openMessageKey: openMessageKey,
    roundcubeSourceUrl: roundcubeSourceUrl,
    messageIdFromSource: messageIdFromSource,
    accountFromTitle: accountFromTitle,
    matchEnrollments: matchEnrollments,
    isKnownOrigin: isKnownOrigin,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
