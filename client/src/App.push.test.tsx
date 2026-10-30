/* Browser alerts resume wherever a signed-in session lands.
 *
 * Re-registering the push subscription happened only inside the Setup tab's
 * toggle, and the console opens on Alerts — so after a sign-out (which drops the
 * server's copy) nobody got a browser alert again until they opened Setup.
 */

import { afterEach, expect, it, vi } from "vitest";
import { render, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

vi.mock("./lib/push", () => ({
  getPushState: vi.fn(async () => "on"),
  disablePush: vi.fn(async () => "off"),
}));

import App from "./App";
import { auth } from "./lib/api";
import { getPushState } from "./lib/push";

function signIn() {
  const payload = btoa(
    JSON.stringify({ sub: "u", tenant: "t", role: "owner", typ: "access", exp: 9e9, jti: "j" }),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  auth.set(`${payload}.sig`);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

it("re-registers push on a console page that is not the Setup tab", async () => {
  signIn();
  // Every API call stays in flight: the page renders its loading state.
  vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
  render(
    <MemoryRouter initialEntries={["/billing"]}>
      <App />
    </MemoryRouter>,
  );
  await waitFor(() => expect(getPushState).toHaveBeenCalled());
});

it("does nothing for someone signed out", async () => {
  vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
  render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  );
  await new Promise((r) => setTimeout(r, 50));
  expect(getPushState).not.toHaveBeenCalled();
});
