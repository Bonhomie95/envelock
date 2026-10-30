/* iPhone and iPad: web push exists only for a web app on the Home Screen.
 *
 * In a Safari tab there is no PushManager, so the alerts panel was simply hidden
 * and nobody was told how to get alerts; and with no web-app manifest the app
 * could not be installed in a way that gets push at all.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import indexHtml from "../../index.html?raw";
import manifestSource from "../../public/manifest.json?raw";
import { needsHomeScreenForPush } from "./push";

const IPHONE =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";

function userAgent(ua: string) {
  Object.defineProperty(navigator, "userAgent", { configurable: true, value: ua });
}

afterEach(() => {
  delete (navigator as { userAgent?: string }).userAgent;
  vi.unstubAllGlobals();
});

describe("needsHomeScreenForPush", () => {
  it("is true for an iPhone Safari tab", () => {
    userAgent(IPHONE);
    expect(needsHomeScreenForPush()).toBe(true);
  });

  it("is false once opened from the Home Screen", () => {
    userAgent(IPHONE);
    vi.stubGlobal("matchMedia", (q: string) => ({ matches: q === "(display-mode: standalone)" }));
    expect(needsHomeScreenForPush()).toBe(false);
  });

  it("is false on a desktop browser", () => {
    userAgent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36");
    expect(needsHomeScreenForPush()).toBe(false);
  });
});

describe("the app can be put on the Home Screen", () => {
  it("links a standalone web-app manifest", () => {
    expect(indexHtml).toMatch(/<link rel="manifest" href="\/manifest.json"/);
    const manifest = JSON.parse(manifestSource);
    expect(manifest.display).toBe("standalone");
    expect(manifest.start_url).toBe("/dashboard");
  });
});

describe("the alerts panel on an iPhone", () => {
  it("says how to get alerts instead of disappearing", async () => {
    vi.doMock("../lib/push", async (actual) => ({
      ...(await actual<typeof import("./push")>()),
      getPushState: vi.fn(async () => "unsupported"),
      needsHomeScreenForPush: () => true,
    }));
    const { PushAlerts } = await import("../pages/Dashboard");
    render(<PushAlerts />);
    expect(await screen.findByText(/Add to Home Screen/)).toBeVisible();
    vi.doUnmock("../lib/push");
  });
});
