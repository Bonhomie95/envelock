/* Envelock sensor — Thunderbird settings page. Thunderbird's messaging API
   returns promises, so no callback juggling is needed here. */
(function () {
  "use strict";

  var api = globalThis.messenger || globalThis.browser;
  var $ = function (id) {
    return document.getElementById(id);
  };

  function ask(message) {
    return Promise.resolve(api.runtime.sendMessage(message)).then(
      function (reply) {
        return reply || { ok: false, error: "no answer from the add-on" };
      },
      function (err) {
        return { ok: false, error: String(err) };
      },
    );
  }

  function show(text, ok) {
    var el = $("result");
    el.textContent = text;
    el.className = "msg " + (ok ? "ok" : "err");
  }

  function when(iso) {
    if (!iso) return "never";
    var secs = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (secs < 60) return "just now";
    if (secs < 3600) return Math.round(secs / 60) + " min ago";
    return new Date(iso).toLocaleString();
  }

  function render(reply) {
    var accounts = reply.accounts || [];
    $("accounts").textContent = accounts.length
      ? "Accounts here: " + accounts.join(", ")
      : "No accounts set up in Thunderbird yet.";
    var box = $("list");
    box.textContent = "";
    var list = reply.enrollments || [];
    if (!list.length) {
      var none = document.createElement("p");
      none.className = "muted";
      none.textContent = "None yet.";
      box.appendChild(none);
      return;
    }
    list.forEach(function (e) {
      var row = document.createElement("div");
      row.className = "item";
      var dot = document.createElement("span");
      dot.className = "dot" + (e.revoked || !e.inThunderbird ? " bad" : e.live ? " live" : "");
      var grow = document.createElement("div");
      grow.className = "grow";
      var mb = document.createElement("div");
      mb.className = "mb";
      mb.textContent = e.mailbox;
      var meta = document.createElement("div");
      meta.className = "muted";
      meta.textContent = e.revoked
        ? "Removed from the Envelock dashboard — add it again with a new code."
        : !e.inThunderbird
          ? "This account is not set up in Thunderbird, so nothing is reported for it."
          : (e.live ? "Reporting" : "Starting") + " · last seen " + when(e.lastBeatAt);
      grow.appendChild(mb);
      grow.appendChild(meta);
      var remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", function () {
        ask({ type: "remove", mailbox: e.mailbox }).then(refresh);
      });
      row.appendChild(dot);
      row.appendChild(grow);
      row.appendChild(remove);
      box.appendChild(row);
    });
  }

  function refresh() {
    return ask({ type: "status" }).then(render);
  }

  $("enroll").addEventListener("submit", function (event) {
    event.preventDefault();
    var server = $("server").value.trim() || "https://api.envelock.org";
    var origin;
    try {
      origin = new URL(server).origin;
    } catch (e) {
      show("That server address is not valid.", false);
      return;
    }
    $("submit").disabled = true;
    /* The default server is granted by the manifest; a custom one needs asking,
       and only from inside this click. */
    var granted =
      origin === "https://api.envelock.org"
        ? Promise.resolve(true)
        : Promise.resolve(api.permissions.request({ origins: [origin + "/*"] }));
    granted
      .then(function (ok) {
        if (!ok) throw new Error("Thunderbird did not allow contacting " + origin + ".");
        return ask({ type: "enroll", code: $("code").value, apiBase: server });
      })
      .then(function (reply) {
        $("submit").disabled = false;
        if (reply.ok) {
          $("code").value = "";
          show(
            reply.inThunderbird
              ? "Added " + reply.mailbox + ". Envelock now knows when you read it here."
              : "Added " + reply.mailbox + ", but that account is not set up in this Thunderbird — add it to Thunderbird for the sensor to report.",
            reply.inThunderbird,
          );
        } else {
          show(reply.error || "That did not work.", false);
        }
        refresh();
      })
      .catch(function (err) {
        $("submit").disabled = false;
        show(err.message || String(err), false);
      });
  });

  refresh();
  setInterval(refresh, 15000);
})();
