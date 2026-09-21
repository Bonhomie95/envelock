/* L1 Web Push enrolment (PRD §8.1) — the browser side of the alert rung the
 * server already ships. Registers the service worker, subscribes the browser with
 * the deployment's VAPID key, and hands the subscription to the API so Critical
 * alerts can reach the user with the tab closed. Everything degrades gracefully:
 * an unsupported browser or an unconfigured server just yields a state the UI can
 * show, never a thrown crash on load.
 */
import { api } from "./api";

export type PushState =
  | "unsupported" // browser lacks service worker / push / notifications
  | "unavailable" // server has no VAPID key configured
  | "denied" // user blocked notifications in the browser
  | "off" // supported + available, not yet subscribed
  | "on"; // subscribed and permitted

export function pushSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    "serviceWorker" in navigator &&
    typeof window !== "undefined" &&
    "PushManager" in window &&
    "Notification" in window
  );
}

// VAPID keys travel as base64url; PushManager wants an ArrayBuffer-backed view.
// (Explicit ArrayBuffer so the type is a plain Uint8Array<ArrayBuffer>, which is
// what applicationServerKey accepts — not the ArrayBufferLike default.)
function urlBase64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const buffer = new ArrayBuffer(raw.length);
  const out = new Uint8Array(buffer);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function registration(): Promise<ServiceWorkerRegistration> {
  // ready resolves once an active worker controls the page; register is idempotent.
  await navigator.serviceWorker.register("/sw.js");
  return navigator.serviceWorker.ready;
}

/** Current push state for this browser + deployment, without prompting. */
export async function getPushState(): Promise<PushState> {
  if (!pushSupported()) return "unsupported";
  try {
    const cfg = await api.sensorConfig();
    if (!cfg.push_available) return "unavailable";
  } catch {
    return "unavailable";
  }
  if (Notification.permission === "denied") return "denied";
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = reg ? await reg.pushManager.getSubscription() : null;
    return sub ? "on" : "off";
  } catch {
    return "off";
  }
}

function keysOf(sub: PushSubscription): { endpoint: string; p256dh: string; auth: string } {
  const json = sub.toJSON();
  const k = json.keys ?? {};
  return { endpoint: sub.endpoint, p256dh: k.p256dh ?? "", auth: k.auth ?? "" };
}

/** Prompt for permission, subscribe, and register with the server. Returns the
 *  resulting state. Throws only on an unexpected failure the UI should surface. */
export async function enablePush(): Promise<PushState> {
  if (!pushSupported()) return "unsupported";
  const cfg = await api.sensorConfig();
  if (!cfg.push_available || !cfg.vapid_public_key) return "unavailable";

  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    return permission === "denied" ? "denied" : "off";
  }

  const reg = await registration();
  let sub = await reg.pushManager.getSubscription();
  if (!sub) {
    sub = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: urlBase64ToUint8Array(cfg.vapid_public_key),
    });
  }
  const body = keysOf(sub);
  if (!body.p256dh || !body.auth) return "off"; // browser gave no encryption keys
  try {
    await api.pushSubscribe(body);
  } catch (e) {
    // The browser subscription already exists at this point — without this
    // rollback, a server refusal (e.g. the endpoint belongs to another
    // account, 409) left getPushState() reading "on" forever while the server
    // had no record and would never push. Clean up, then surface the error.
    try {
      await sub.unsubscribe();
    } catch {
      /* best effort */
    }
    throw e;
  }
  return "on";
}

/** Unsubscribe this browser and tell the server to stop sending to it. */
export async function disablePush(): Promise<PushState> {
  if (!pushSupported()) return "unsupported";
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = reg ? await reg.pushManager.getSubscription() : null;
    if (sub) {
      const body = keysOf(sub);
      try {
        await api.pushUnsubscribe(body);
      } catch {
        /* server may already have dropped it; unsubscribe locally regardless */
      }
      await sub.unsubscribe();
    }
  } catch {
    /* best-effort */
  }
  return "off";
}
