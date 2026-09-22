/*
 * Envelock sensor — Thunderbird add-on background.
 *
 * Thunderbird is the most precise sensor Envelock has. Its MailExtension API
 * hands over the real Message-ID of every message the person displays, so each
 * read is attested exactly — no "the owner is reading something" approximation
 * as on most webmail. And Thunderbird running with the account configured IS
 * the mail client being open, so presence needs no guesswork either.
 *
 *   while Thunderbird runs          → heartbeat every minute, per enrolled
 *                                     mailbox configured in Thunderbird
 *   a message is displayed          → attest its Message-ID for that mailbox
 *
 * A factory over the `messenger` API, like the browser extension's, so the test
 * suite can drive it with a fake.
 */
(function (root) {
  "use strict";

  var ALARM = "envelock-heartbeat";
  /* onMessageDisplayed and onMessagesDisplayed can both fire for one message. */
  var DEDUPE_MS = 5000;

  function create(api, opts) {
    opts = opts || {};
    var S = root.EnvelockSensor;
    var now = opts.now || Date.now;
    var client = new S.SensorClient({
      storage: S.extensionStorage(api.storage.local),
      client: "thunderbird",
      fetch: opts.fetch,
      now: now,
      userAgent: opts.userAgent,
    });
    var appVersion = opts.version || null;
    var recent = {};

    function identities() {
      return Promise.resolve(api.accounts.list()).then(function (accounts) {
        var out = {};
        (accounts || []).forEach(function (account) {
          (account.identities || []).forEach(function (identity) {
            if (identity && identity.email) out[identity.email.toLowerCase()] = account.id;
          });
        });
        return out;
      });
    }

    function mailClient() {
      return appVersion ? "Thunderbird " + appVersion : "Thunderbird";
    }

    /* Only mailboxes this Thunderbird actually has configured are "present":
       an enrollment for an account that was removed from Thunderbird must stop
       saying the owner is here. */
    function presentMailboxes() {
      return Promise.all([client.enrollments(), identities()]).then(function (both) {
        var ids = both[1];
        return both[0]
          .filter(function (e) {
            return !e.revoked && Object.prototype.hasOwnProperty.call(ids, e.mailbox);
          })
          .map(function (e) {
            return e.mailbox;
          });
      });
    }

    function beat() {
      return presentMailboxes().then(function (mailboxes) {
        if (!mailboxes.length) return [];
        return client.heartbeat({ mailboxes: mailboxes, mailClient: mailClient(), appName: "Thunderbird" });
      });
    }

    function accountEmails(accountId) {
      if (!accountId) return Promise.resolve([]);
      return Promise.resolve(api.accounts.get(accountId)).then(function (account) {
        return ((account && account.identities) || [])
          .map(function (i) {
            return (i.email || "").toLowerCase();
          })
          .filter(Boolean);
      });
    }

    /* Thunderbird has no bar inside the message we may write to without
       "messagesModify", which the sensor deliberately never holds (it never
       changes mail). So the warning goes on the message toolbar button — a red
       badge and its tooltip, per message tab — and, for a flagged message, a
       desktop notification the person can't miss. */
    function showWarning(tab, ref, result) {
      var line = S.warningLine(S.warningOf(result));
      var action = api.messageDisplayAction;
      if (action && tab && tab.id != null) {
        action.setBadgeText({ tabId: tab.id, text: line ? "!" : "" });
        if (line) action.setBadgeBackgroundColor({ tabId: tab.id, color: "#b91c1c" });
        action.setTitle({ tabId: tab.id, title: line || "Envelock" });
      }
      if (line && api.notifications) {
        api.notifications.create("envelock-" + ref, {
          type: "basic",
          title: "Envelock warning",
          message: line,
          iconUrl: "icons/icon-48.png",
        });
      }
      return result;
    }

    function onDisplayed(message, tab) {
      if (!message || !message.headerMessageId) return Promise.resolve(null);
      var ref = S.normalizeMessageRef(message.headerMessageId);
      var t = now();
      if (recent[ref] && t - recent[ref] < DEDUPE_MS) return Promise.resolve(null);
      recent[ref] = t;
      var accountId = message.folder && message.folder.accountId;
      return Promise.all([accountEmails(accountId), client.enrollments()]).then(function (both) {
        var emails = both[0];
        var match = both[1].find(function (e) {
          return !e.revoked && emails.indexOf(e.mailbox) !== -1;
        });
        if (!match) return null;
        return client.attest(match.mailbox, ref).then(function (result) {
          return showWarning(tab, ref, result);
        });
      });
    }

    function onDisplayedMany(tab, displayed) {
      var list = Array.isArray(displayed) ? displayed : (displayed && displayed.messages) || [];
      return Promise.all(
        list.map(function (m) {
          return onDisplayed(m, tab);
        }),
      );
    }

    function onOptionsMessage(msg) {
      if (msg.type === "status") {
        return Promise.all([client.status(), identities()]).then(function (both) {
          var ids = both[1];
          return {
            ok: true,
            accounts: Object.keys(ids),
            enrollments: both[0].map(function (s) {
              return Object.assign({}, s, {
                inThunderbird: Object.prototype.hasOwnProperty.call(ids, s.mailbox),
              });
            }),
          };
        });
      }
      if (msg.type === "remove") {
        return client.remove(msg.mailbox).then(function () {
          return { ok: true };
        });
      }
      if (msg.type === "enroll") {
        return client
          .enroll(msg.code, { apiBase: msg.apiBase || undefined, appName: "Thunderbird" })
          .then(function (enrollment) {
            return identities().then(function (ids) {
              var here = Object.prototype.hasOwnProperty.call(ids, enrollment.mailbox);
              /* Report straight away so the dashboard shows the device live. */
              return (here ? beat() : Promise.resolve()).then(function () {
                return { ok: true, mailbox: enrollment.mailbox, inThunderbird: here };
              });
            });
          })
          .catch(function (err) {
            return { ok: false, error: err.message || String(err) };
          });
      }
      return Promise.resolve({ ok: false, error: "unknown request" });
    }

    function start() {
      api.alarms.create(ALARM, { periodInMinutes: 1 });
      api.alarms.onAlarm.addListener(function (alarm) {
        if (alarm && alarm.name === ALARM) beat();
      });
      if (api.messageDisplay.onMessageDisplayed) {
        api.messageDisplay.onMessageDisplayed.addListener(function (tab, message) {
          onDisplayed(message, tab);
        });
      }
      if (api.messageDisplay.onMessagesDisplayed) {
        api.messageDisplay.onMessagesDisplayed.addListener(onDisplayedMany);
      }
      /* Thunderbird's runtime.onMessage accepts a returned promise. */
      api.runtime.onMessage.addListener(function (msg, sender) {
        if (!msg || !msg.type || (sender && sender.tab)) return undefined;
        return onOptionsMessage(msg);
      });
      if (api.browserAction && api.browserAction.onClicked) {
        api.browserAction.onClicked.addListener(function () {
          api.runtime.openOptionsPage();
        });
      }
      return beat();
    }

    return {
      client: client,
      beat: beat,
      onDisplayed: onDisplayed,
      onDisplayedMany: onDisplayedMany,
      onOptionsMessage: onOptionsMessage,
      presentMailboxes: presentMailboxes,
      start: start,
    };
  }

  root.EnvelockThunderbird = { create: create };

  var api = root.messenger || root.browser;
  if (api && api.runtime && api.runtime.id && !root.__ENVELOCK_TEST__) {
    Promise.resolve(api.runtime.getBrowserInfo ? api.runtime.getBrowserInfo() : null).then(
      function (info) {
        create(api, { version: info && info.version }).start();
      },
      function () {
        create(api, {}).start();
      },
    );
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
