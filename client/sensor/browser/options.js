/* Envelock sensor — settings page. Talks only to the extension's background,
   which holds the tokens; this page never sees one. */
(function () {
  "use strict";

  /* `chrome.*` first: it takes callbacks in Chrome AND Firefox, whereas
     Firefox's `browser.*` is promise-only and rejects a callback argument. */
  var api = globalThis.chrome || globalThis.browser;
  var $ = function (id) {
    return document.getElementById(id);
  };

  function ask(message) {
    return new Promise(function (resolve) {
      api.runtime.sendMessage(message, function (reply) {
        resolve(reply || { ok: false, error: "no answer from the extension" });
      });
    });
  }

  function chosenWebmail() {
    var picked = document.querySelector('input[name="webmail"]:checked');
    var value = picked ? picked.value : "";
    if (value === "other") return { kind: "other", origin: $("other").value.trim() };
    var kind = value.indexOf("google") !== -1 ? "gmail" : "outlook";
    return { kind: kind, origin: value };
  }

  function originPattern(url) {
    try {
      var u = new URL(/^[a-z]+:\/\//i.test(url) ? url : "https://" + url);
      return u.origin + "/*";
    } catch (e) {
      return null;
    }
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

  function render(list) {
    var box = $("list");
    box.textContent = "";
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
      dot.className = "dot" + (e.revoked ? " bad" : e.live ? " live" : "");
      var grow = document.createElement("div");
      grow.className = "grow";
      var mb = document.createElement("div");
      mb.className = "mb";
      mb.textContent = e.mailbox;
      var meta = document.createElement("div");
      meta.className = "muted";
      meta.textContent = e.revoked
        ? "Removed from the Envelock dashboard — add it again with a new code."
        : (e.live ? "Reporting" : "Waiting for your webmail to be open") +
          " · last seen " +
          when(e.lastBeatAt) +
          (e.webmailOrigin ? " · " + e.webmailOrigin.replace(/^https?:\/\//, "") : "") +
          (e.lastError && !e.live ? " · " + e.lastError : "");
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
    return ask({ type: "status" }).then(function (reply) {
      render((reply && reply.enrollments) || []);
    });
  }

  document.querySelectorAll('input[name="webmail"]').forEach(function (radio) {
    radio.addEventListener("change", function () {
      $("other-wrap").classList.toggle("hidden", chosenWebmail().kind !== "other");
    });
  });

  $("enroll").addEventListener("submit", function (event) {
    event.preventDefault();
    var webmail = chosenWebmail();
    var server = $("server").value.trim() || "https://api.envelock.org";
    var origins = [originPattern(webmail.origin), originPattern(server)].filter(Boolean);
    if (origins.length < 2) {
      show("Enter the address of your webmail.", false);
      return;
    }
    $("submit").disabled = true;
    /* Must be the first thing this handler does: browsers only show the
       permission prompt from inside the click that caused it. */
    api.permissions.request({ origins: origins }, function (granted) {
      if (!granted) {
        $("submit").disabled = false;
        show("Envelock needs to see that webmail to know when it is open. Nothing was changed.", false);
        return;
      }
      ask({
        type: "enroll",
        code: $("code").value,
        webmailOrigin: webmail.origin,
        webmailKind: webmail.kind,
        apiBase: server,
      }).then(function (reply) {
        $("submit").disabled = false;
        if (reply.ok) {
          $("code").value = "";
          show(
            "Added " + reply.mailbox + ". Keep your webmail open in this browser and Envelock will know it is you.",
            true,
          );
        } else {
          show(reply.error || "That did not work.", false);
        }
        refresh();
      });
    });
  });

  refresh();
  setInterval(refresh, 15000);
})();
