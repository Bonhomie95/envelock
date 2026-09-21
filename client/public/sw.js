/* Envelock service worker — L1 Web Push (PRD §8.1).
 *
 * Its only job is to turn a pushed alert into a browser notification even when the
 * app tab is closed, and to focus/open the dashboard when the user clicks it. The
 * payload shape is set by the server's PushSender.payload():
 *   { title, body, tag, requireInteraction, data: { url, alert_id } }
 */

self.addEventListener("install", () => {
  // Take over as soon as installed so the first enable works without a reload.
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch {
    data = { body: event.data ? event.data.text() : "" };
  }
  const title = data.title || "Envelock alert";
  const options = {
    body: data.body || "You have a new security alert.",
    tag: data.tag || undefined,
    requireInteraction: data.requireInteraction === true,
    data: { url: (data.data && data.data.url) || "/dashboard" },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/dashboard";
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((wins) => {
        for (const w of wins) {
          // Focus an already-open app tab and route it to the alert.
          if ("focus" in w) {
            if ("navigate" in w && target) {
              try {
                w.navigate(target);
              } catch {
                /* cross-origin navigate can throw; focus is enough */
              }
            }
            return w.focus();
          }
        }
        if (self.clients.openWindow) return self.clients.openWindow(target);
        return undefined;
      }),
  );
});
