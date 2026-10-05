/*
 * Envelock sensor — Outlook add-in task pane.
 *
 * Outlook gives add-ins no background process: code runs only while the task
 * pane is open. So this sensor is honest about that — it reports while the pane
 * is pinned open, and the pane tells the person to pin it. Pinned, it follows
 * them from message to message:
 *
 *   while the pane is open    → heartbeat every minute
 *   each message shown        → attest its internetMessageId (the real
 *                               Message-ID header — precise, like Thunderbird)
 *
 * The token lives in this device's localStorage, never in Office roaming
 * settings: those are stored inside the mailbox, where anyone who broke into
 * it could read the token and forge the very attestations meant to catch them.
 *
 * `createController` holds all the logic and takes the Office object as a
 * parameter so the test suite can drive it; `mountView` is only DOM glue.
 */
(function (root) {
  "use strict";

  function createController(office, opts) {
    opts = opts || {};
    var S = root.EnvelockSensor;
    var mb = office.context.mailbox;
    var mailbox = S.normalizeMailbox(mb.userProfile && mb.userProfile.emailAddress);
    var client = new S.SensorClient({
      storage: opts.storage,
      client: "outlook",
      fetch: opts.fetch,
      now: opts.now,
      userAgent: opts.userAgent,
    });
    var timer = null;
    var listeners = [];
    var vouched = 0;  // reads this pane has confirmed as the owner's, this session

    function notify() {
      listeners.forEach(function (fn) {
        fn();
      });
    }

    function hostName() {
      var d = office.context.diagnostics;
      if (!d) return "Outlook";
      return ("Outlook " + (d.platform || "") + " " + (d.version || "")).replace(/\s+/g, " ").trim();
    }

    function currentMessageId() {
      var item = mb.item;
      return item && item.internetMessageId ? item.internetMessageId : null;
    }

    var WARNING_KEY = "envelock-warning";
    var lastWarning = null;

    /* Outlook's own info bar at the top of the reading pane — the one place in
       Outlook a person reads before they act. Replaced (not stacked) per
       message, and removed when the message has nothing flagged. */
    function showWarning(result) {
      var item = mb.item;
      var line = S.warningLine(S.warningOf(result));
      lastWarning = line;
      var bar = item && item.notificationMessages;
      if (!bar) return;
      if (line && office.MailboxEnums) {
        bar.replaceAsync(WARNING_KEY, {
          type: office.MailboxEnums.ItemNotificationMessageType.ErrorMessage,
          message: line,
        });
      } else if (bar.removeAsync) {
        bar.removeAsync(WARNING_KEY);
      }
    }

    function attestCurrent() {
      var id = currentMessageId();
      if (!id) return Promise.resolve(null);
      return client.attest(mailbox, id).then(function (result) {
        vouched += 1;
        showWarning(result);
        return result;
      });
    }

    function beat() {
      return client
        .heartbeat({ mailboxes: [mailbox], mailClient: hostName(), appName: "Outlook" })
        .then(function (results) {
          notify();
          return results;
        });
    }

    function enrollment() {
      return client.enrollments().then(function (list) {
        return list.find(function (e) {
          return e.mailbox === mailbox;
        });
      });
    }

    function onItemChanged() {
      return attestCurrent().then(notify);
    }

    function startWatching() {
      if (timer) return Promise.resolve();
      timer = (opts.setInterval || setInterval)(beat, S.HEARTBEAT_SECONDS * 1000);
      if (mb.addHandlerAsync && office.EventType) {
        mb.addHandlerAsync(office.EventType.ItemChanged, onItemChanged);
      }
      return beat().then(attestCurrent);
    }

    function stopWatching() {
      if (timer) (opts.clearInterval || clearInterval)(timer);
      timer = null;
      if (mb.removeHandlerAsync && office.EventType) {
        try {
          mb.removeHandlerAsync(office.EventType.ItemChanged);
        } catch (e) {
          /* already gone */
        }
      }
    }

    /* A pairing code names one mailbox. If it is not the one this Outlook is
       signed in to, the pairing is undone rather than kept: a sensor reporting
       reads for a mailbox it is not looking at would vouch for reads it never
       saw — the one thing a sensor must never do. */
    function pair(code, apiBase) {
      return client.enroll(code, { apiBase: apiBase || undefined, appName: "Outlook" }).then(function (e) {
        if (e.mailbox !== mailbox) {
          return client.remove(e.mailbox).then(function () {
            throw new Error(
              "That code is for " + e.mailbox + ", but Outlook is signed in as " + mailbox + ". Create a code for " + mailbox + " instead.",
            );
          });
        }
        return startWatching().then(function () {
          notify();
          return e;
        });
      });
    }

    function unpair() {
      stopWatching();
      return client.remove(mailbox).then(notify);
    }

    function start() {
      return enrollment().then(function (e) {
        if (e && !e.revoked) return startWatching();
        notify();
        return null;
      });
    }

    function snapshot() {
      return Promise.all([client.status(), client.deviceId()]).then(function (both) {
        var mine = both[0].find(function (s) {
          return s.mailbox === mailbox;
        });
        return {
          mailbox: mailbox,
          enrollment: mine || null,
          deviceId: both[1],
          watching: Boolean(timer),
          warning: lastWarning,
          vouched: vouched,
        };
      });
    }

    return {
      mailbox: mailbox,
      client: client,
      start: start,
      pair: pair,
      unpair: unpair,
      beat: beat,
      onItemChanged: onItemChanged,
      snapshot: snapshot,
      onChange: function (fn) {
        listeners.push(fn);
      },
    };
  }

  function ago(iso) {
    if (!iso) return null;
    var secs = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
    if (secs < 45) return "just now";
    if (secs < 90) return "a minute ago";
    if (secs < 3600) return Math.round(secs / 60) + " min ago";
    return Math.round(secs / 3600) + "h ago";
  }

  function mountView(controller, doc) {
    var $ = function (id) {
      return doc.getElementById(id);
    };

    function show(text, ok) {
      var el = $("result");
      el.textContent = text;
      el.className = "msg " + (ok ? "ok" : "err");
    }

    function render() {
      return controller.snapshot().then(function (s) {
        $("loading").classList.add("hidden");
        var e = s.enrollment;
        var paired = e && !e.revoked;
        $("watching").classList.toggle("hidden", !paired);
        $("pair").classList.toggle("hidden", Boolean(paired));
        $("pair-mailbox").textContent = s.mailbox;
        if (!paired) {
          if (e && e.revoked) show("This device was removed in the Envelock dashboard. Pair it again to keep reporting.", false);
          return;
        }
        $("warning").textContent = s.warning || "";
        $("warning").classList.toggle("hidden", !s.warning);
        $("mailbox").textContent = s.mailbox;
        $("dot").className = "dot" + (e.live ? " live" : "");
        $("state").textContent = e.live
          ? "Watching — Envelock knows these reads are yours"
          : e.lastError
            ? "Not reporting: " + e.lastError
            : "Connecting…";
        // A visible sign of life, so "Watching" isn't the only feedback: when it
        // last checked in, and how many reads it has confirmed as yours.
        var checkin = ago(e.lastBeatAt) || "just now";
        var n = s.vouched || 0;
        $("live").textContent =
          "Last check-in " + checkin + " · " + n + " read" + (n === 1 ? "" : "s") +
          " confirmed yours this session";
        $("live").classList.toggle("hidden", !e.live);
        $("device").textContent = (e.label || "This device") + " · " + s.deviceId;
      }).catch(function (err) {
        // Without this the pane sits on "Starting…" for ever and the person
        // reasonably concludes the sensor is broken. Say what happened instead.
        $("loading").textContent =
          "The sensor couldn't start: " + (err && err.message ? err.message : String(err));
        $("loading").className = "msg err";
        $("loading").classList.remove("hidden");
      });
    }

    controller.onChange(render);

    $("pair").addEventListener("submit", function (event) {
      event.preventDefault();
      $("submit").disabled = true;
      controller
        .pair($("code").value, $("server").value.trim())
        .then(function () {
          $("code").value = "";
          show("Paired. Pin this pane to keep it reporting.", true);
        })
        .catch(function (err) {
          show(err.message || String(err), false);
        })
        .then(function () {
          $("submit").disabled = false;
          render();
        });
    });

    $("unpair").addEventListener("click", function () {
      controller.unpair().then(render);
    });

    render();
  }

  root.EnvelockOutlook = { createController: createController, mountView: mountView };

  /* Office.onReady only ever fires inside an Office host. Everywhere else —
     the page's own URL, the Apps list, the admin centre's "Open" — it simply
     never calls back, and the pane used to sit on "Starting…" with nothing to
     explain it. Say where the add-in actually lives instead. */
  function showHelp(doc) {
    var loading = doc.getElementById("loading");
    var help = doc.getElementById("help");
    if (loading) loading.classList.add("hidden");
    if (help) help.classList.remove("hidden");
  }

  function hideHelp(doc) {
    var help = doc.getElementById("help");
    if (help) help.classList.add("hidden");
  }

  /* How long to wait for Office before concluding we are NOT inside Outlook.
     Office.onReady only fires inside a host, so a timeout is the only signal
     that we are somewhere else (the Apps list, the page's own URL). It must be
     GENEROUS: office.js loads from Microsoft's CDN and the host handshake can
     easily take several seconds on first open or a slow network. The old 4s
     fired the "not in Outlook" help WHILE Outlook was still starting, then the
     real pane mounted underneath it — a scary error sitting above a working
     form, which reads as "broken". A late onReady now also hides the help, so
     even if the timer wins the race, Outlook becoming ready always corrects it. */
  var NOT_IN_OUTLOOK_MS = 15000;

  if (root.document && !root.__ENVELOCK_TEST__) {
    var doc = root.document;
    if (!root.Office || !root.Office.onReady) {
      showHelp(doc);
    } else {
      var ready = false;
      var giveUp = setTimeout(function () {
        if (!ready) showHelp(doc);
      }, NOT_IN_OUTLOOK_MS);
      root.Office.onReady(function (info) {
        if (!info || info.host !== root.Office.HostType.Outlook) {
          showHelp(doc);
          return;
        }
        ready = true;
        clearTimeout(giveUp);
        hideHelp(doc); // in case the timer already showed it on a slow load
        var controller = createController(root.Office, {
          storage: root.EnvelockSensor.webStorage(root.localStorage),
        });
        mountView(controller, doc);
        controller.start().catch(function (err) {
          var el = doc.getElementById("result");
          if (!el) return;
          el.textContent =
            "Couldn't reach Envelock: " + (err && err.message ? err.message : String(err));
          el.className = "msg err";
        });
      });
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
