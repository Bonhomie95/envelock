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
  event.waitUntil(
    Promise.all([
      self.registration.showNotification(title, options),
      // An open dashboard refreshes now, not on its next timed poll.
      self.clients
        .matchAll({ type: "window" })
        .then((wins) => wins.forEach((w) => w.postMessage({ type: "envelock:alert" }))),
    ]),
  );
});

// What the page stored for us (src/lib/push.ts, keep in step): the current
// subscription's endpoint and auth secret, the VAPID key and the API origin.
const PUSH_STORE = "envelock-push";
const PUSH_RECORD = "/__envelock/push-subscription";

async function savedSubscription() {
  try {
    const hit = await (await caches.open(PUSH_STORE)).match(PUSH_RECORD);
    return hit ? await hit.json() : null;
  } catch {
    return null;
  }
}

function keyBytes(b64url) {
  const b64 = (b64url + "=".repeat((4 - (b64url.length % 4)) % 4))
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

// The browser replaced or expired the subscription (Firefox does; the old
// endpoint then answers 410 Gone and the server forgets it). Subscribe again
// under the same key and tell the server, proving it with the old
// subscription's auth secret — this worker has no session to sign in with.
// It used to resubscribe without telling anyone, so alerts stopped until the
// next visit; and with no `oldSubscription` (allowed) it did nothing at all.
async function rotateSubscription(event) {
  const saved = await savedSubscription();
  const old = event.oldSubscription || null;
  const oldKeys = (old && old.toJSON().keys) || {};
  const oldEndpoint = (old && old.endpoint) || (saved && saved.endpoint);
  const oldAuth = oldKeys.auth || (saved && saved.auth);
  let sub = event.newSubscription || null;
  if (!sub) {
    const key =
      (old && old.options && old.options.applicationServerKey) ||
      (saved && saved.key && keyBytes(saved.key));
    if (!key) return;
    sub = await self.registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: key,
    });
  }
  // Nothing to prove the change with: the next visit registers it instead.
  if (!oldEndpoint || !oldAuth) return;
  const keys = sub.toJSON().keys || {};
  const res = await fetch(`${(saved && saved.api) || ""}/api/v1/push/rotate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      old_endpoint: oldEndpoint,
      old_auth: oldAuth,
      endpoint: sub.endpoint,
      p256dh: keys.p256dh,
      auth: keys.auth,
    }),
  });
  if (res.ok && saved) {
    const cache = await caches.open(PUSH_STORE);
    await cache.put(
      PUSH_RECORD,
      new Response(JSON.stringify({ ...saved, endpoint: sub.endpoint, auth: keys.auth })),
    );
  }
}

self.addEventListener("pushsubscriptionchange", (event) => {
  event.waitUntil(rotateSubscription(event));
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
