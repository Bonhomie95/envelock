/* The service worker when the browser replaces its push subscription.
 *
 * `pushsubscriptionchange` used to resubscribe without telling the server, so
 * the old endpoint answered 410, the server forgot it, and alerts stopped until
 * the next visit. With no `oldSubscription` (the spec allows it) it did nothing
 * at all. The worker holds no session; it proves the change with the old
 * subscription's auth secret, which the page stored for it.
 */

import { describe, expect, it, vi } from "vitest";
import swSource from "../../public/sw.js?raw";

type Listener = (event: unknown) => void;
type Sub = { endpoint: string; toJSON: () => { keys: Record<string, string> } };

const RECORD = "/__envelock/push-subscription";
const KEY = "BHtNJC1InWkPCbHF8JuKGrdv9MRC1kkpi5SIfDP5AbrVk27d80j4OGqPIyRiUlx3z6N3q66rrxv2u1A-JaaWN4E";

function fakeCaches(record?: object) {
  const store = new Map<string, string>();
  if (record) store.set(RECORD, JSON.stringify(record));
  return {
    store,
    open: async () => ({
      match: async (key: string) => (store.has(key) ? new Response(store.get(key)) : undefined),
      put: async (key: string, res: Response) => {
        store.set(key, await res.text());
      },
    }),
  };
}

type Win = { focused?: boolean; visibilityState?: string };

function loadWorker(caches: ReturnType<typeof fakeCaches>, windows: Win[] = [{}]) {
  const listeners: Record<string, Listener> = {};
  const fresh: Sub = {
    endpoint: "https://push.example/rotated",
    toJSON: () => ({ keys: { p256dh: "new-p256dh", auth: "new-auth" } }),
  };
  const subscribe = vi.fn(async () => fresh);
  const fetch = vi.fn(async () => ({ ok: true }));
  const posted: unknown[] = [];
  const shown: string[] = [];
  const options: Record<string, unknown>[] = [];
  const matchAll = vi.fn(async () =>
    windows.map((w) => ({ ...w, postMessage: (m: unknown) => posted.push(m) })),
  );
  const self = {
    addEventListener: (type: string, fn: Listener) => {
      listeners[type] = fn;
    },
    registration: {
      pushManager: { subscribe },
      showNotification: async (title: string, opts: Record<string, unknown>) => {
        shown.push(title);
        options.push(opts);
      },
    },
    clients: { claim: async () => undefined, matchAll },
    skipWaiting: () => undefined,
  };
  new Function("self", "caches", "fetch", "Response", "atob", swSource)(
    self,
    caches,
    fetch,
    Response,
    atob,
  );
  return { listeners, subscribe, fetch, matchAll, posted, shown, options };
}

async function change(listener: Listener, event: Record<string, unknown>) {
  let pending: Promise<unknown> = Promise.resolve();
  listener({ ...event, waitUntil: (p: Promise<unknown>) => (pending = p) });
  await pending;
}

describe("pushsubscriptionchange", () => {
  it("resubscribes under the stored key and reports the change to the server", async () => {
    const caches = fakeCaches({
      endpoint: "https://push.example/old",
      auth: "old-auth",
      key: KEY,
      api: "https://api.example",
    });
    const { listeners, subscribe, fetch } = loadWorker(caches);

    await change(listeners.pushsubscriptionchange, { oldSubscription: null, newSubscription: null });

    expect(subscribe).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, { body: string }];
    expect(url).toBe("https://api.example/api/v1/push/rotate");
    expect(JSON.parse(init.body)).toEqual({
      old_endpoint: "https://push.example/old",
      old_auth: "old-auth",
      endpoint: "https://push.example/rotated",
      p256dh: "new-p256dh",
      auth: "new-auth",
    });
    // The next rotation proves itself with the new secret.
    expect(JSON.parse(caches.store.get(RECORD)!)).toMatchObject({
      endpoint: "https://push.example/rotated",
      auth: "new-auth",
    });
  });

  it("uses the subscription the browser hands it when there is one", async () => {
    const { listeners, subscribe, fetch } = loadWorker(fakeCaches());
    const old = {
      endpoint: "https://push.example/firefox-old",
      options: { applicationServerKey: new Uint8Array([4, 1, 2]).buffer },
      toJSON: () => ({ keys: { p256dh: "p", auth: "firefox-old-auth" } }),
    };

    await change(listeners.pushsubscriptionchange, { oldSubscription: old, newSubscription: null });

    expect(subscribe).toHaveBeenCalledTimes(1);
    const body = JSON.parse((fetch.mock.calls[0] as unknown as [string, { body: string }])[1].body);
    expect(body.old_endpoint).toBe("https://push.example/firefox-old");
    expect(body.old_auth).toBe("firefox-old-auth");
  });
});

describe("push", () => {
  it("shows the alert and tells every open window which one arrived", async () => {
    const { listeners, matchAll, posted, shown } = loadWorker(fakeCaches());
    const payload = { title: "LOW: Envelock", body: "Test", data: { url: "/", alert_id: "t-1" } };

    await change(listeners.push, { data: { json: () => payload } });

    expect(shown).toEqual(["LOW: Envelock"]);
    // The page's "Send test" waits for this id: it is how it knows the push
    // reached this browser and not another one. Uncontrolled windows too, or a
    // dashboard opened before the worker took over never hears it.
    expect(matchAll).toHaveBeenCalledWith({ type: "window", includeUncontrolled: true });
    expect(posted).toEqual([{ type: "envelock:alert", alert_id: "t-1", ring: true }]);
  });

  it("asks for the system sound and has exactly one tab chime, the one in use", async () => {
    const { listeners, posted, options } = loadWorker(fakeCaches(), [
      { visibilityState: "hidden" },
      { focused: true, visibilityState: "visible" },
      { visibilityState: "visible" },
    ]);
    const payload = { title: "HIGH: Envelock", tag: "a-1", data: { alert_id: "a-1" } };

    await change(listeners.push, { data: { json: () => payload } });

    expect(options[0]).toMatchObject({ silent: false, renotify: true, tag: "a-1" });
    expect(posted.map((m) => (m as { ring: boolean }).ring)).toEqual([false, true, false]);
  });

  it("never sets renotify without a tag, which Chrome refuses", async () => {
    const { listeners, options } = loadWorker(fakeCaches());

    await change(listeners.push, { data: { json: () => ({ title: "x" }) } });

    expect(options[0]).toMatchObject({ renotify: false, silent: false });
  });
});
