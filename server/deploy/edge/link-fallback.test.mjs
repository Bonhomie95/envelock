// node --test server/deploy/edge/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import worker, { verifiedDestination, signature } from "./link-fallback.js";

const vectors = JSON.parse(readFileSync(new URL("./test-vectors.json", import.meta.url)));
const env = { ORIGIN: "https://origin.invalid", LINK_EDGE_SECRET: vectors.secret };

test("signs exactly like the server (shared vectors)", async () => {
  for (const c of vectors.cases) {
    const sig = c.path.split(".").pop();
    assert.equal(await signature(vectors.secret, c.token, c.url), sig);
    assert.equal(await verifiedDestination(c.path, vectors.secret), c.url);
  }
});

test("a tampered destination or signature is refused", async () => {
  const c = vectors.cases[1];
  const [, , token, rest] = c.path.split("/");
  const [payload, sig] = rest.split(".");
  const evil = Buffer.from("https://evil.example/").toString("base64url");
  assert.equal(await verifiedDestination(`/r/${token}/${evil}.${sig}`, vectors.secret), null);
  const flipped = sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A");
  assert.equal(await verifiedDestination(`/r/${token}/${payload}.${flipped}`, vectors.secret), null);
  assert.equal(await verifiedDestination(c.path, "a-different-secret"), null);
  assert.equal(await verifiedDestination(`/r/${token}`, vectors.secret), null);
});

test("a signed javascript: URL still gets no continue button", async () => {
  const url = "javascript:alert(1)";
  const sig = await signature(vectors.secret, "tok", url);
  const path = `/r/tok/${Buffer.from(url).toString("base64url")}.${sig}`;
  assert.equal(await verifiedDestination(path, vectors.secret), null);
});

function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return fn().finally(() => {
    globalThis.fetch = original;
  });
}

test("a healthy origin's answer is passed through untouched", async () => {
  await withFetch(
    async () => new Response(null, { status: 302, headers: { location: "https://dest.example/" } }),
    async () => {
      const res = await worker.fetch(new Request(`https://go.example${vectors.cases[1].path}`), env);
      assert.equal(res.status, 302);
      assert.equal(res.headers.get("location"), "https://dest.example/");
    },
  );
});

test("origin down: the signed destination gets a warning page with a continue", async () => {
  await withFetch(
    async () => {
      throw new TypeError("connect ECONNREFUSED");
    },
    async () => {
      const res = await worker.fetch(new Request(`https://go.example${vectors.cases[1].path}`), env);
      assert.equal(res.status, 200);
      const html = await res.text();
      assert.match(html, /couldn't check this link/);
      assert.match(html, /shipping-weekly\.example/);
      assert.match(html, /href="http:\/\/shipping-weekly\.example\/issue\/42"/);
    },
  );
});

test("origin 5xx on an unsigned link: a plain try-again page, never a redirect", async () => {
  await withFetch(
    async () => new Response("bad gateway", { status: 502 }),
    async () => {
      const res = await worker.fetch(new Request("https://go.example/r/sometoken"), env);
      assert.equal(res.status, 503);
      assert.match(await res.text(), /temporarily unavailable/);
    },
  );
});

test("only /r/ is served", async () => {
  const res = await worker.fetch(new Request("https://go.example/admin"), env);
  assert.equal(res.status, 404);
});
