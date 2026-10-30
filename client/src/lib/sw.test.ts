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

function loadWorker(caches: ReturnType<typeof fakeCaches>) {
  const listeners: Record<string, Listener> = {};
  const fresh: Sub = {
    endpoint: "https://push.example/rotated",
    toJSON: () => ({ keys: { p256dh: "new-p256dh", auth: "new-auth" } }),
  };
  const subscribe = vi.fn(async () => fresh);
  const fetch = vi.fn(async () => ({ ok: true }));
  const self = {
    addEventListener: (type: string, fn: Listener) => {
      listeners[type] = fn;
    },
    registration: { pushManager: { subscribe } },
    clients: { claim: async () => undefined, matchAll: async () => [] },
    skipWaiting: () => undefined,
  };
  new Function("self", "caches", "fetch", "Response", "atob", swSource)(
    self,
    caches,
    fetch,
    Response,
    atob,
  );
  return { listeners, subscribe, fetch };
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
