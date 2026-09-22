/*
 * Envelock sensor — runs inside a webmail tab.
 *
 * It reports three things to the extension's background, and nothing else:
 *
 *   present  — this webmail is open (every 30s while the tab exists)
 *   opened   — a message was just opened (with its Message-ID when the page
 *              lets us learn it, otherwise the activity marker)
 *   activity — the person is clicking or typing in their mail (at most once a
 *              minute)
 *
 * It never reads message content, never touches the page's own data, and sends
 * nothing to Envelock itself — the background does that, with the sensor's own
 * token, so no page script can see or reach it.
 */
(function () {
  "use strict";

  var W = globalThis.EnvelockWebmail;
  var api = globalThis.browser || globalThis.chrome;
  if (!W || !api || !api.runtime) return;
  /* Only the top frame speaks for presence; a Roundcube preview iframe speaks
     only for the message it shows. */
  var isTop = window.top === window;

  var PRESENCE_MS = 30 * 1000;
  var ACTIVITY_MS = 60 * 1000;
  var lastKey = null;
  var lastActivity = 0;

  function send(message, onReply) {
    try {
      message.origin = location.origin;
      message.account = W.accountFromTitle(document.title);
      var reply = api.runtime.sendMessage(message);
      if (onReply && reply && typeof reply.then === "function") {
        reply.then(onReply, function () {});
      }
    } catch (e) {
      /* The extension was updated or removed under this tab. Nothing to do. */
    }
  }

  /* Envelock's verdict on the message just opened, above it on the page. In a
     shadow root so the webmail's CSS can't hide or restyle it, and replaced on
     every message so a warning never lingers on the next one. */
  var BANNER_ID = "envelock-warning-banner";
  function showWarning(reply) {
    var old = document.getElementById(BANNER_ID);
    if (old) old.remove();
    var line = reply && reply.warning;
    if (!line || !document.body) return;
    var host = document.createElement("div");
    host.id = BANNER_ID;
    var root = host.attachShadow ? host.attachShadow({ mode: "closed" }) : host;
    var box = document.createElement("div");
    box.setAttribute("role", "alert");
    box.textContent = "\u26A0 " + line;
    box.style.cssText =
      "margin:8px;padding:10px 14px;border:2px solid #b91c1c;background:#fef2f2;" +
      "color:#7f1d1d;font:600 13px/1.45 -apple-system,Segoe UI,Arial,sans-serif;border-radius:6px;";
    root.appendChild(box);
    document.body.insertBefore(host, document.body.firstChild);
  }

  function opened(key) {
    var sourceUrl = W.roundcubeSourceUrl(location.href);
    if (!sourceUrl) {
      send({ type: "opened", ref: "*", key: key });
      return;
    }
    /* Same-origin, with the page's own session. Only the header block is
       parsed — see messageIdFromSource. */
    fetch(sourceUrl, { credentials: "include" })
      .then(function (res) {
        return res.ok ? res.text() : "";
      })
      .then(function (text) {
        send({ type: "opened", ref: W.messageIdFromSource(text) || "*", key: key }, showWarning);
      })
      .catch(function () {
        send({ type: "opened", ref: "*", key: key });
      });
  }

  function check() {
    var key = W.openMessageKey(location.href);
    if (key && key !== lastKey) opened(key);
    lastKey = key;
  }

  function activity() {
    var now = Date.now();
    if (now - lastActivity < ACTIVITY_MS) return;
    lastActivity = now;
    send({ type: "activity" });
  }

  /* Webmail is a single-page app: the URL changes without a page load, and not
     always with an event. A cheap once-a-second comparison catches all of it. */
  setInterval(check, 1000);
  window.addEventListener("hashchange", check);
  window.addEventListener("popstate", check);
  check();

  if (isTop) {
    send({ type: "present" });
    setInterval(function () {
      send({ type: "present" });
    }, PRESENCE_MS);
    document.addEventListener("click", activity, true);
    document.addEventListener("keydown", activity, true);
  }
})();
