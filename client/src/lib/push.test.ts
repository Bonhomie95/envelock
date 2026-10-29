/* Browser-alert enrolment: the half of "notifications never arrive" that lives
 * in the browser.
 *
 * The toggle used to read "on" whenever this browser held a subscription, even
 * when the server had no copy of it — after a sign-out, a server move, another
 * account claiming the endpoint, or a VAPID key change. Push then went nowhere
 * and nothing on screen said so.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("./api", () => ({
  api: {
    sensorConfig: vi.fn(),
    pushSubscribe: vi.fn(),
    pushUnsubscribe: vi.fn(),
  },
}));

import { api } from "./api";
import { disablePush, getPushState } from "./push";

const KEY = "BHtNJC1InWkPCbHF8JuKGrdv9MRC1kkpi5SIfDP5AbrVk27d80j4OGqPIyRiUlx3z6N3q66rrxv2u1A-JaaWN4E";
const OTHER_KEY = "BAAAAC1InWkPCbHF8JuKGrdv9MRC1kkpi5SIfDP5AbrVk27d80j4OGqPIyRiUlx3z6N3q66rrxv2u1A-JaaWN4E";

function keyBytes(b64: string): ArrayBuffer {
  const raw = atob(b64.replace(/-/g, "+").replace(/_/g, "/") + "=");
  return Uint8Array.from(raw, (c) => c.charCodeAt(0)).buffer;
}

function fakeSub(endpoint: string, key: string) {
  return {
    endpoint,
    options: { applicationServerKey: keyBytes(key) },
    toJSON: () => ({ endpoint, keys: { p256dh: "p256dh-key", auth: "auth-secret" } }),
    unsubscribe: vi.fn(async () => true),
  };
}

let held: ReturnType<typeof fakeSub> | null;
const subscribe = vi.fn(async () => {
  held = fakeSub("https://push.example/new", KEY);
  return held;
});

beforeEach(() => {
  held = null;
  localStorage.clear();
  vi.mocked(api.sensorConfig).mockResolvedValue({
    heartbeat_seconds: 60,
    vapid_public_key: KEY,
    push_available: true,
    endpoints: {},
  });
  vi.mocked(api.pushSubscribe).mockResolvedValue({ subscribed: true });
  const reg = { pushManager: { getSubscription: async () => held, subscribe } };
  vi.stubGlobal("PushManager", function PushManager() {});
  vi.stubGlobal("Notification", { permission: "granted" });
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

describe("getPushState", () => {
  it("re-registers an existing subscription with the server on every visit", async () => {
    held = fakeSub("https://push.example/kept", KEY);
    expect(await getPushState()).toBe("on");
    expect(api.pushSubscribe).toHaveBeenCalledWith({
      endpoint: "https://push.example/kept",
      p256dh: "p256dh-key",
      auth: "auth-secret",
    });
    expect(subscribe).not.toHaveBeenCalled();
  });

  it("resumes after sign-out dropped the subscription, without a prompt", async () => {
    await disablePush(); // what sign-out does
    expect(await getPushState()).toBe("on");
    expect(subscribe).toHaveBeenCalledOnce();
    expect(api.pushSubscribe).toHaveBeenCalledWith(
      expect.objectContaining({ endpoint: "https://push.example/new" }),
    );
  });

  it("never overrides the user's own Turn off", async () => {
    await disablePush(true);
    expect(await getPushState()).toBe("off");
    expect(subscribe).not.toHaveBeenCalled();
    expect(api.pushSubscribe).not.toHaveBeenCalled();
  });

  it("replaces a subscription made under an old VAPID key", async () => {
    const stale = fakeSub("https://push.example/stale", OTHER_KEY);
    held = stale;
    expect(await getPushState()).toBe("on");
    expect(stale.unsubscribe).toHaveBeenCalled();
    expect(api.pushSubscribe).toHaveBeenCalledWith(
      expect.objectContaining({ endpoint: "https://push.example/new" }),
    );
  });

  it("reads off when the server refuses the registration", async () => {
    held = fakeSub("https://push.example/kept", KEY);
    vi.mocked(api.pushSubscribe).mockRejectedValue(new Error("409"));
    expect(await getPushState()).toBe("off");
  });

  it("does nothing until permission was granted", async () => {
    vi.stubGlobal("Notification", { permission: "default" });
    expect(await getPushState()).toBe("off");
    expect(subscribe).not.toHaveBeenCalled();
  });
});
