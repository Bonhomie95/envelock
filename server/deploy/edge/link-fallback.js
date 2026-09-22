// Envelock link fallback — a Cloudflare Worker in front of the click-time
// redirector (/r/...).
//
// Every protected link in every customer's inbox points at one origin. If that
// origin is down (a reboot, a deploy gone wrong, a hosting outage) every one of
// those links would fail at once. This worker sits in front of it:
//
//   1. Normally it just passes the click to the origin, which checks the
//      destination live and redirects, warns or blocks. Nothing changes.
//   2. If the origin can't be reached (network error, timeout, 5xx), it reads
//      the destination the server embedded in the link — signed with a secret
//      only the server and this worker share — and shows a page that says the
//      live check couldn't run, names the real site, and lets the person
//      continue. A forged or tampered link gets no such page.
//
// Configuration (Cloudflare → Workers → this worker → Settings → Variables):
//   ORIGIN            e.g. https://api.envelock.org   (plain text)
//   LINK_EDGE_SECRET  same value as ENVELOCK_LINK_EDGE_SECRET on the server (secret)

const ORIGIN_TIMEOUT_MS = 5000;

function b64urlToBytes(s) {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function bytesToB64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Mirrors envelock.platform.links.edge_signature. */
export async function signature(secret, token, url) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${token}\n${url}`));
  return bytesToB64url(new Uint8Array(mac)).slice(0, 22);
}

/** The verified http(s) destination of /r/{token}/{payload}.{sig}, else null. */
export async function verifiedDestination(pathname, secret) {
  if (!secret) return null;
  const m = /^\/r\/([A-Za-z0-9_-]+)\/([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]{22})$/.exec(pathname);
  if (!m) return null;
  const [, token, payload, sig] = m;
  let url;
  try {
    url = new TextDecoder("utf-8", { fatal: true }).decode(b64urlToBytes(payload));
  } catch {
    return null;
  }
  if (!timingSafeEqual(await signature(secret, token, url), sig)) return null;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  return url;
}

function esc(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function page(title, color, heading, body, actions = "") {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${title}</title></head>
<body style="margin:0;background:#f6f7f9;font-family:-apple-system,Segoe UI,Arial,sans-serif;">
<div style="max-width:560px;margin:8vh auto;padding:0 16px;">
<div style="background:#fff;border:1px solid #e5e7eb;border-top:6px solid ${color};border-radius:8px;padding:28px;">
<div style="font-size:20px;font-weight:700;color:#111827;">${heading}</div>
<div style="font-size:14px;color:#374151;margin-top:12px;line-height:1.6;">${body}</div>
${actions}
<div style="font-size:11px;color:#9ca3af;margin-top:24px;">Protected by Envelock.</div>
</div></div></body></html>`;
}

export function fallbackPage(url) {
  const host = new URL(url).hostname;
  return page(
    "Link check unavailable",
    "#b45309",
    "We couldn't check this link just now",
    `Envelock re-checks every link when you click it, and that check isn't reachable
     at the moment. This link goes to <b>${esc(host)}</b>. Continue only if you
     were expecting a link to that site.`,
    `<div style="margin-top:20px;"><a href="${esc(url)}" rel="noreferrer"
      style="display:inline-block;background:#b45309;color:#fff;text-decoration:none;
      padding:10px 18px;border-radius:6px;font-size:14px;">Continue to ${esc(host)}</a></div>`,
  );
}

export function unavailablePage() {
  return page(
    "Temporarily unavailable",
    "#6b7280",
    "This link is temporarily unavailable",
    "Envelock's link check can't be reached right now. Please try again in a minute.",
  );
}

async function fromOrigin(request, env) {
  const incoming = new URL(request.url);
  const target = new URL(incoming.pathname + incoming.search, env.ORIGIN);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
  try {
    const headers = new Headers(request.headers);
    const ip = request.headers.get("cf-connecting-ip");
    if (ip) headers.set("x-forwarded-for", ip);
    return await fetch(target, {
      method: "GET",
      headers,
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (!pathname.startsWith("/r/") || request.method !== "GET") {
      return new Response("Not found", { status: 404 });
    }
    try {
      const res = await fromOrigin(request, env);
      if (res.status < 500) return res;
    } catch {
      // unreachable or timed out — fall through to the fallback
    }
    const url = await verifiedDestination(pathname, env.LINK_EDGE_SECRET);
    const html = url ? fallbackPage(url) : unavailablePage();
    return new Response(html, {
      status: url ? 200 : 503,
      headers: {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "x-robots-tag": "noindex",
        "referrer-policy": "no-referrer",
      },
    });
  },
};
