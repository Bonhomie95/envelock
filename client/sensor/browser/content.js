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

  function send(message) {
    try {
      message.origin = location.origin;
      message.account = W.accountFromTitle(document.title);
      api.runtime.sendMessage(message);
    } catch (e) {
      /* The extension was updated or removed under this tab. Nothing to do. */
    }
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
        send({ type: "opened", ref: W.messageIdFromSource(text) || "*", key: key });
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
