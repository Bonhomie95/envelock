/* L1 Web Push enrolment (PRD §8.1) — the browser side of the alert rung the
 * server already ships. Registers the service worker, subscribes the browser with
 * the deployment's VAPID key, and hands the subscription to the API so Critical
 * alerts can reach the user with the tab closed. Everything degrades gracefully:
 * an unsupported browser or an unconfigured server just yields a state the UI can
 * show, never a thrown crash on load.
 */
import { api, API_BASE } from "./api";

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

/** An iPhone or iPad browser tab. Web push exists there only for web apps added
 *  to the Home Screen (iOS 16.4+): in a Safari tab there is no PushManager at
 *  all, so the toggle was simply hidden and nobody was told how to get alerts. */
export function needsHomeScreenForPush(): boolean {
  if (typeof navigator === "undefined" || typeof window === "undefined") return false;
  const ua = navigator.userAgent || "";
  // iPadOS reports itself as a Mac; touch is what gives it away.
  const iOS =
    /iPhone|iPad|iPod/.test(ua) ||
    (/Macintosh/.test(ua) && (navigator.maxTouchPoints ?? 0) > 1);
  const standalone =
    window.matchMedia?.("(display-mode: standalone)").matches === true ||
    (navigator as Navigator & { standalone?: boolean }).standalone === true;
  return iOS && !standalone && !pushSupported();
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

// "Turn off" is remembered per browser so re-registration below never overrides
// it. Signing out also drops the subscription, but that is not a choice to stop
// alerts — the next sign-in here resumes them.
const OPT_OUT_KEY = "envelock:push-off";

function optedOut(): boolean {
  try {
    return localStorage.getItem(OPT_OUT_KEY) === "1";
  } catch {
    return false;
  }
}

function setOptedOut(off: boolean): void {
  try {
    if (off) localStorage.setItem(OPT_OUT_KEY, "1");
    else localStorage.removeItem(OPT_OUT_KEY);
  } catch {
    /* storage blocked — the choice just isn't remembered */
  }
}

/* What the service worker needs when the push service replaces this browser's
 * subscription (`pushsubscriptionchange`): it holds no session — the bearer
 * token lives in this page's storage — so it proves the change to the server
 * with the old subscription's auth secret, and resubscribes under the stored
 * key when the browser does not hand it the old subscription. Cache Storage,
 * because both the page and the worker can read it. Keep in step with sw.js. */
const SW_STORE = "envelock-push";
const SW_RECORD = "/__envelock/push-subscription";

async function shareWithWorker(sub: PushSubscription, vapidKey: string): Promise<void> {
  try {
    if (typeof caches === "undefined") return;
    const { endpoint, auth } = keysOf(sub);
    const cache = await caches.open(SW_STORE);
    await cache.put(
      SW_RECORD,
      new Response(JSON.stringify({ endpoint, auth, key: vapidKey, api: API_BASE })),
    );
  } catch {
    /* best effort: without it a rotated subscription waits for the next visit */
  }
}

async function forgetForWorker(): Promise<void> {
  try {
    if (typeof caches !== "undefined") await caches.delete(SW_STORE);
  } catch {
    /* nothing stored, or storage blocked */
  }
}

/** This browser's subscription under the deployment's current VAPID key. One
 *  made under any other key is undeliverable — the push service rejects every
 *  send for it — so it is replaced rather than reused. */
async function currentSubscription(
  reg: ServiceWorkerRegistration,
  vapidKey: string,
): Promise<PushSubscription> {
  const key = urlBase64ToUint8Array(vapidKey);
  const existing = await reg.pushManager.getSubscription();
  const held = existing?.options.applicationServerKey;
  const sameKey =
    !held ||
    (held.byteLength === key.length &&
      new Uint8Array(held).every((b, i) => b === key[i]));
  if (existing && sameKey) return existing;
  if (existing) await existing.unsubscribe();
  return reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
}

/** Current push state for this browser + deployment, without prompting.
 *
 *  With permission already granted it also (re-)registers the subscription with
 *  the server. That is what keeps push working: the server's copy disappears on
 *  sign-out, when another account in this browser claims the endpoint, after a
 *  server move, or when the browser rotates the subscription — and every time
 *  the toggle went on reading "on" while nothing was ever delivered. */
export async function getPushState(): Promise<PushState> {
  if (!pushSupported()) return "unsupported";
  let vapidKey: string;
  try {
    const cfg = await api.sensorConfig();
    if (!cfg.push_available || !cfg.vapid_public_key) return "unavailable";
    vapidKey = cfg.vapid_public_key;
  } catch {
    return "unavailable";
  }
  if (Notification.permission === "denied") return "denied";
  if (Notification.permission !== "granted" || optedOut()) return "off";
  try {
    const sub = await currentSubscription(await registration(), vapidKey);
    const body = keysOf(sub);
    if (!body.p256dh || !body.auth) return "off";
    await api.pushSubscribe(body);
    await shareWithWorker(sub, vapidKey);
    return "on";
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
  setOptedOut(false);

  const sub = await currentSubscription(await registration(), cfg.vapid_public_key);
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
  await shareWithWorker(sub, cfg.vapid_public_key);
  return "on";
}

/** Unsubscribe this browser and tell the server to stop sending to it.
 *  `optOut` is the user's own "Turn off": remembered, so it is not undone on
 *  the next visit. Sign-out passes nothing — alerts resume at the next sign-in. */
export async function disablePush(optOut = false): Promise<PushState> {
  if (optOut) setOptedOut(true);
  // A subscription deliberately dropped must not be revived by the worker.
  await forgetForWorker();
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
