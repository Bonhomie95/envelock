/* What the page leaves for the service worker.
 *
 * The worker can only re-register a rotated subscription if it knows the old
 * one's endpoint and auth secret, the VAPID key and where the API is — the page
 * stores them after every successful registration, and forgets them when the
 * user turns alerts off (a dropped subscription must not be revived).
 */

import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("./api", () => ({
  API_BASE: "https://api.example",
  api: {
    sensorConfig: vi.fn(),
    pushSubscribe: vi.fn(),
    pushUnsubscribe: vi.fn(),
  },
}));

import { api } from "./api";
import { disablePush, getPushState } from "./push";

const KEY = "BHtNJC1InWkPCbHF8JuKGrdv9MRC1kkpi5SIfDP5AbrVk27d80j4OGqPIyRiUlx3z6N3q66rrxv2u1A-JaaWN4E";
const RECORD = "/__envelock/push-subscription";

const store = new Map<string, string>();
const caches = {
  open: async () => ({
    put: async (key: string, res: Response) => {
      store.set(key, await res.text());
    },
  }),
  delete: async () => {
    store.clear();
    return true;
  },
};

beforeEach(() => {
  store.clear();
  localStorage.clear();
  vi.mocked(api.sensorConfig).mockResolvedValue({
    heartbeat_seconds: 60,
    vapid_public_key: KEY,
    push_available: true,
    endpoints: {},
  });
  vi.mocked(api.pushSubscribe).mockResolvedValue({ subscribed: true });
  const raw = atob(KEY.replace(/-/g, "+").replace(/_/g, "/") + "=");
  const sub = {
    endpoint: "https://push.example/device",
    options: { applicationServerKey: Uint8Array.from(raw, (c) => c.charCodeAt(0)).buffer },
    toJSON: () => ({ keys: { p256dh: "p256dh-key", auth: "auth-secret" } }),
    unsubscribe: vi.fn(async () => true),
  };
  const reg = { pushManager: { getSubscription: async () => sub, subscribe: vi.fn() } };
  vi.stubGlobal("PushManager", function PushManager() {});
  vi.stubGlobal("Notification", { permission: "granted" });
  vi.stubGlobal("caches", caches);
  Object.defineProperty(navigator, "serviceWorker", {
    configurable: true,
    value: {
      register: vi.fn(async () => reg),
      ready: Promise.resolve(reg),
      getRegistration: async () => reg,
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

it("leaves the worker what it needs to re-register a rotated subscription", async () => {
  expect(await getPushState()).toBe("on");
  expect(JSON.parse(store.get(RECORD) ?? "null")).toEqual({
    endpoint: "https://push.example/device",
    auth: "auth-secret",
    key: KEY,
    api: "https://api.example",
  });
});

it("forgets it when the user turns alerts off", async () => {
  await getPushState();
  await disablePush(true);
  expect(store.size).toBe(0);
});
