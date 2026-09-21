/*
 * Envelock sensor — browser extension background.
 *
 * Holds the sensor tokens (the webmail pages never see them), turns what the
 * content scripts report into heartbeats and read attestations, and keeps the
 * content script registered on whatever webmail the person told us they use.
 *
 * Presence is the heart of it. A heartbeat means "the mail client for this
 * mailbox is open on this device right now", so it is only sent while a
 * webmail tab for that mailbox has reported in recently. That is what lets
 * Envelock say, later, "a message was read while none of your devices were
 * here" — and mean it.
 *
 * Written as a factory over the extension API so the test suite can drive it
 * with a fake `chrome` object; the bottom of the file starts it for real.
 */
(function (root) {
  "use strict";

  /* Chrome runs this as a service worker and loads the shared files itself;
     Firefox lists them in the manifest before this one. */
  if (typeof importScripts === "function" && !root.EnvelockSensor) {
    importScripts("envelock-sensor.js", "webmail.js");
  }

  var ALARM = "envelock-heartbeat";
  /* A webmail tab reports in every 30s; three missed reports and it has gone. */
  var PRESENCE_TTL_MS = 90 * 1000;
  var KEY_PRESENCE = "envelock.presence";
  var SCRIPT_PREFIX = "envelock-webmail-";

  var CONTENT_TYPES = { present: true, opened: true, activity: true };
  var OPTIONS_TYPES = { enroll: true, remove: true, status: true };

  function create(api, opts) {
    opts = opts || {};
    var S = root.EnvelockSensor;
    var W = root.EnvelockWebmail;
    var now = opts.now || Date.now;
    var storage = S.extensionStorage(api.storage.local);
    var client = new S.SensorClient({
      storage: storage,
      client: "browser",
      fetch: opts.fetch,
      now: now,
      userAgent: opts.userAgent,
    });

    function presence() {
      return storage.get(KEY_PRESENCE).then(function (map) {
        return map || {};
      });
    }

    /* Record that these mailboxes are open now; resolve to the ones that were
       not open a moment ago — those get an immediate heartbeat, so a sign-in
       is seen within seconds instead of at the next minute tick. */
    function markPresent(mailboxes) {
      return presence().then(function (map) {
        var t = now();
        var arrived = mailboxes.filter(function (m) {
          return !map[m] || t - map[m] > PRESENCE_TTL_MS;
        });
        mailboxes.forEach(function (m) {
          map[m] = t;
        });
        return storage.set(KEY_PRESENCE, map).then(function () {
          return arrived;
        });
      });
    }

    function presentMailboxes() {
      return presence().then(function (map) {
        var t = now();
        return Object.keys(map).filter(function (m) {
          return t - map[m] <= PRESENCE_TTL_MS;
        });
      });
    }

    function beat(mailboxes) {
      if (!mailboxes.length) return Promise.resolve([]);
      return client.heartbeat({ mailboxes: mailboxes, mailClient: "Webmail" });
    }

    function senderOrigin(sender, msg) {
      return (
        (sender && sender.origin) ||
        (sender && sender.url && W.originOf(sender.url)) ||
        (msg && msg.origin) ||
        null
      );
    }

    function onContentMessage(msg, sender) {
      var origin = senderOrigin(sender, msg);
      return client.enrollments().then(function (list) {
        var matched = W.matchEnrollments(list, origin, msg.account);
        if (!matched.length) return { matched: 0 };
        var mailboxes = matched.map(function (e) {
          return e.mailbox;
        });
        return markPresent(mailboxes).then(function (arrived) {
          var work = [beat(arrived)];
          if (msg.type === "opened" || msg.type === "activity") {
            var ref = msg.type === "opened" ? msg.ref || S.ACTIVITY_REF : S.ACTIVITY_REF;
            mailboxes.forEach(function (m) {
              work.push(client.attest(m, ref));
            });
          }
          return Promise.all(work).then(function () {
            return { matched: mailboxes.length };
          });
        });
      });
    }

    function onAlarm(alarm) {
      if (!alarm || alarm.name !== ALARM) return Promise.resolve([]);
      return presentMailboxes().then(beat);
    }

    /* The person's own webmail (anything but Gmail and Outlook on the web,
       which the manifest covers) gets the content script registered at runtime,
       and only for origins they granted. Re-done on every start: Firefox does
       not persist runtime registrations. */
    function syncContentScripts() {
      if (!api.scripting || !api.scripting.registerContentScripts) return Promise.resolve([]);
      return client.enrollments().then(function (list) {
        var origins = [];
        list.forEach(function (e) {
          if (
            !e.revoked &&
            e.webmailOrigin &&
            !W.isKnownOrigin(e.webmailOrigin) &&
            origins.indexOf(e.webmailOrigin) === -1
          ) {
            origins.push(e.webmailOrigin);
          }
        });
        return Promise.resolve(api.scripting.getRegisteredContentScripts())
          .then(function (existing) {
            var ours = (existing || [])
              .map(function (s) {
                return s.id;
              })
              .filter(function (id) {
                return id.indexOf(SCRIPT_PREFIX) === 0;
              });
            return ours.length
              ? api.scripting.unregisterContentScripts({ ids: ours })
              : undefined;
          })
          .then(function () {
            return Promise.all(
              origins.map(function (origin) {
                return Promise.resolve(
                  api.permissions.contains({ origins: [origin + "/*"] }),
                ).then(function (granted) {
                  return granted ? origin : null;
                });
              }),
            );
          })
          .then(function (granted) {
            var scripts = granted
              .filter(Boolean)
              .map(function (origin) {
                return {
                  id: SCRIPT_PREFIX + origin.replace(/[^a-z0-9]/gi, "_"),
                  matches: [origin + "/*"],
                  js: ["webmail.js", "content.js"],
                  runAt: "document_idle",
                  /* Roundcube shows a message in a preview iframe. */
                  allFrames: true,
                };
              });
            return scripts.length
              ? Promise.resolve(api.scripting.registerContentScripts(scripts)).then(function () {
                  return scripts;
                })
              : scripts;
          });
      });
    }

    function onOptionsMessage(msg) {
      if (msg.type === "status") {
        return Promise.all([client.status(), client.enrollments()]).then(function (both) {
          var byMailbox = {};
          both[1].forEach(function (e) {
            byMailbox[e.mailbox] = e;
          });
          return {
            ok: true,
            enrollments: both[0].map(function (s) {
              var e = byMailbox[s.mailbox] || {};
              /* Never hand the token to a page, even our own. */
              return Object.assign({}, s, {
                webmailOrigin: e.webmailOrigin || null,
                apiBase: e.apiBase || null,
              });
            }),
          };
        });
      }
      if (msg.type === "remove") {
        return client
          .remove(msg.mailbox)
          .then(syncContentScripts)
          .then(function () {
            return { ok: true };
          });
      }
      if (msg.type === "enroll") {
        var origin = W.normalizeWebmailOrigin(msg.webmailOrigin);
        if (!origin) return Promise.resolve({ ok: false, error: "Enter the address of your webmail." });
        return client
          .enroll(msg.code, {
            apiBase: msg.apiBase || undefined,
            extra: { webmailOrigin: origin, webmailKind: msg.webmailKind || "other" },
          })
          .then(function (enrollment) {
            return syncContentScripts().then(function () {
              return { ok: true, mailbox: enrollment.mailbox, label: enrollment.label };
            });
          })
          .catch(function (err) {
            return { ok: false, error: err.message || String(err) };
          });
      }
      return Promise.resolve({ ok: false, error: "unknown request" });
    }

    function isExtensionPage(sender) {
      if (!sender || sender.tab) return false;
      var base = api.runtime.getURL ? api.runtime.getURL("") : null;
      return !base || !sender.url || sender.url.indexOf(base) === 0;
    }

    function onMessage(msg, sender, sendResponse) {
      if (!msg || typeof msg.type !== "string") return false;
      var work = null;
      if (CONTENT_TYPES[msg.type] && sender && sender.tab) {
        work = onContentMessage(msg, sender);
      } else if (OPTIONS_TYPES[msg.type] && isExtensionPage(sender)) {
        /* Only our own settings page may enrol or remove — never a web page. */
        work = onOptionsMessage(msg);
      }
      if (!work) return false;
      work.then(sendResponse, function (err) {
        sendResponse({ ok: false, error: (err && err.message) || String(err) });
      });
      return true; /* keeps sendResponse alive for the async answer (Chrome) */
    }

    function start() {
      api.alarms.create(ALARM, { periodInMinutes: 1 });
      api.alarms.onAlarm.addListener(onAlarm);
      api.runtime.onMessage.addListener(onMessage);
      if (api.runtime.onStartup) api.runtime.onStartup.addListener(syncContentScripts);
      if (api.runtime.onInstalled) api.runtime.onInstalled.addListener(syncContentScripts);
      return syncContentScripts();
    }

    return {
      client: client,
      onContentMessage: onContentMessage,
      onOptionsMessage: onOptionsMessage,
      onMessage: onMessage,
      onAlarm: onAlarm,
      syncContentScripts: syncContentScripts,
      presentMailboxes: presentMailboxes,
      start: start,
      ALARM: ALARM,
      PRESENCE_TTL_MS: PRESENCE_TTL_MS,
    };
  }

  root.EnvelockBackground = { create: create };

  var ext = root.browser || root.chrome;
  if (ext && ext.runtime && ext.runtime.id && !root.__ENVELOCK_TEST__) {
    create(ext).start();
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
