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
      controller.snapshot().then(function (s) {
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
        $("device").textContent = (e.label || "This device") + " · " + s.deviceId;
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

  if (root.Office && root.document && !root.__ENVELOCK_TEST__) {
    root.Office.onReady(function (info) {
      if (!info || info.host !== root.Office.HostType.Outlook) return;
      var controller = createController(root.Office, {
        storage: root.EnvelockSensor.webStorage(root.localStorage),
      });
      mountView(controller, root.document);
      controller.start();
    });
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
