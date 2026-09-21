/* The API client's session handling.
 *
 * This module decides three things that a user experiences directly and that no
 * server test can cover: whether a 15-minute-old tab silently recovers or throws
 * the customer out, whether a burst of expired calls stampedes the refresh
 * endpoint, and whether an error reaches the UI as something a person can read.
 *
 * All three were previously verified only by using the app.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, auth } from "./api";

/** A signed token shape the client can parse — the payload is base64url of JSON,
 *  which is all `auth.role` reads. The signature is never checked client-side. */
function fakeToken(role = "owner"): string {
  const payload = btoa(
    JSON.stringify({ sub: "u", tenant: "t", role, typ: "access", exp: 9e9, jti: "j" }),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `${payload}.signature`;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("token storage", () => {
  it("reports signed-out when there is no token", () => {
    expect(auth.signedIn).toBe(false);
    expect(auth.role).toBeNull();
  });

  it("reads the role out of the token so admin nav needs no round-trip", () => {
    auth.set(fakeToken("admin"));
    expect(auth.signedIn).toBe(true);
    expect(auth.role).toBe("admin");
  });

  it("returns null rather than throwing on a corrupt token", () => {
    // A truncated or hand-edited token must not crash the shell on first paint.
    localStorage.setItem("envelock.access_token", "not-a-token");
    expect(auth.role).toBeNull();
  });

  it("clears both tokens on sign-out", () => {
    auth.set(fakeToken(), "refresh-token");
    auth.clear();
    expect(localStorage.getItem("envelock.access_token")).toBeNull();
    expect(localStorage.getItem("envelock.refresh_token")).toBeNull();
  });
});

describe("expired access tokens", () => {
  it("refreshes once and replays the request", async () => {
    // The lived experience this protects: leave a tab open through lunch, click
    // something, and it works instead of bouncing you to sign-in.
    auth.set(fakeToken(), "refresh-token");
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401))
      .mockResolvedValueOnce(
        jsonResponse({ access_token: fakeToken(), refresh_token: "rotated" }),
      )
      .mockResolvedValueOnce(jsonResponse({ counterparties: [] }));

    await expect(api.counterparties()).resolves.toEqual({ counterparties: [] });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(localStorage.getItem("envelock.refresh_token")).toBe("rotated");
  });

  it("does not retry a second time if the replay also 401s", async () => {
    // Otherwise a revoked session becomes an infinite refresh loop against the
    // endpoint whose whole job is detecting replay.
    auth.set(fakeToken(), "refresh-token");
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401))
      .mockResolvedValueOnce(
        jsonResponse({ access_token: fakeToken(), refresh_token: "rotated" }),
      )
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401));

    await expect(api.counterparties()).rejects.toBeInstanceOf(ApiError);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("clears the session when the refresh itself is rejected", async () => {
    auth.set(fakeToken(), "stale-refresh");
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ detail: "expired" }, 401))
      .mockResolvedValueOnce(jsonResponse({ detail: "reuse detected" }, 401));

    await expect(api.counterparties()).rejects.toBeInstanceOf(ApiError);
    expect(auth.signedIn).toBe(false);
  });
});

describe("errors the customer reads", () => {
  it("surfaces the server's message rather than the status text", async () => {
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "that domain is already verified" }, 409),
    );
    await expect(api.counterparties()).rejects.toMatchObject({
      status: 409,
      message: "that domain is already verified",
    });
  });

  it("flattens FastAPI validation lists into one readable sentence", async () => {
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        { detail: [{ msg: "value is not a valid phone number" }] },
        422,
      ),
    );
    await expect(api.counterparties()).rejects.toMatchObject({
      message: "value is not a valid phone number",
    });
  });

  it("turns a rate limit into a wait time instead of a status code", async () => {
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "rate limit exceeded", retry_after: 300 }, 429),
    );
    await expect(api.counterparties()).rejects.toMatchObject({
      message: "Too many attempts. Try again in about 5 minutes.",
    });
  });

  it("keeps a structured detail so the UI can act on it", async () => {
    // The IMAP connect flow has to show the customer the certificate a server
    // presented; flattening the detail to a string would throw that away.
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          detail: {
            message: "certificate not trusted",
            certificate: { subject: "mail.example.com" },
          },
        },
        400,
      ),
    );
    const error = await api.counterparties().catch((e: unknown) => e as ApiError);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).certificate).toEqual({ subject: "mail.example.com" });
  });
});

describe("registry calls", () => {
  it("encodes the domain into the path", async () => {
    // A domain is user input on a path segment. Interpolating it raw is how a
    // stray slash silently becomes a different endpoint.
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(jsonResponse({ domain: "acme.com", records: [] }));
    await api.supplierRecords("acme.com/../admin");
    expect(fetchMock.mock.calls[0][0]).toContain(
      encodeURIComponent("acme.com/../admin"),
    );
  });

  it("sends the callback number as a JSON body", async () => {
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ domain: "acme.com", verified_phone: "+1 555 0100" }),
    );
    await api.setCallbackNumber("acme.com", "+1 555 0100");
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ phone: "+1 555 0100" });
  });

  it("marks a dry-run import so the preview writes nothing", async () => {
    auth.set(fakeToken());
    fetchMock.mockResolvedValueOnce(jsonResponse({ dry_run: true, rows_parsed: 0 }));
    await api.importVendors("Vendor,Email\n", true);
    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body)).dry_run).toBe(true);
  });
});
