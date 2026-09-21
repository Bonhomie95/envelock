/* Envelock sensor — toolbar popup: is each mailbox being reported, right now? */
(function () {
  "use strict";

  /* `chrome.*` first: it takes callbacks in Chrome AND Firefox, whereas
     Firefox's `browser.*` is promise-only and rejects a callback argument. */
  var api = globalThis.chrome || globalThis.browser;

  document.getElementById("settings").addEventListener("click", function () {
    api.runtime.openOptionsPage();
    window.close();
  });

  api.runtime.sendMessage({ type: "status" }, function (reply) {
    var list = (reply && reply.enrollments) || [];
    var box = document.getElementById("list");
    document.getElementById("empty").classList.toggle("hidden", list.length > 0);
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
        ? "Removed — pair it again"
        : e.live
          ? "Watching — you are here"
          : "Open your webmail to report";
      grow.appendChild(mb);
      grow.appendChild(meta);
      row.appendChild(dot);
      row.appendChild(grow);
      box.appendChild(row);
    });
  });
})();
