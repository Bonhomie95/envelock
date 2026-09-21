/**
 * Client-side mirror of the server's passphrase policy (auth/security.py) and
 * disposable-email block (auth/email_policy.py). This is UX only — the server is
 * the authority — but it lets someone see whether their passphrase and email will
 * be accepted *before* submitting, instead of guessing after a 422.
 */

const WEAK_TOKENS = ["password", "qwerty", "letmein", "admin", "123456", "iloveyou"];
const WEAK_EXACT = new Set([
  "passphrase",
  "welcome",
  "changeme",
  "administrator",
  "qwertyuiop",
]);

export interface PassphraseCheck {
  /** Passes the server policy — safe to submit. */
  ok: boolean;
  /** 0–4, for the strength bar. */
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  /** Actionable guidance (the failing reason, or encouragement). */
  hint: string;
}

export function checkPassphrase(pw: string): PassphraseCheck {
  if (!pw) return { ok: false, score: 0, label: "", hint: "" };

  const lower = pw.trim().toLowerCase();
  const distinct = new Set(pw).size;
  const hasDigit = /\d/.test(pw);
  const hasUpper = /[A-Z]/.test(pw);
  const allLower = pw === lower;
  const hasWeak = WEAK_EXACT.has(lower) || WEAK_TOKENS.some((t) => lower.includes(t));

  // Hard-fail reasons, in the same order the server checks them.
  if (pw.length < 12)
    return {
      ok: false,
      score: 0,
      label: "Too short",
      hint: "Use at least 12 characters — a passphrase of a few unrelated words is ideal.",
    };
  if (hasWeak)
    return {
      ok: false,
      score: 1,
      label: "Weak",
      hint: "Contains a very common word or pattern — pick something unpredictable.",
    };
  if (distinct < 5)
    return {
      ok: false,
      score: 1,
      label: "Weak",
      hint: "Too repetitive — mix in more distinct characters.",
    };
  if (pw.length < 16 && !hasDigit && allLower)
    return {
      ok: false,
      score: 2,
      label: "Fair",
      hint: "Add a number, a capital, or make it a longer passphrase (16+ characters).",
    };

  // Passes the policy — grade for encouragement.
  let s = 2;
  if (pw.length >= 16) s += 1;
  if (pw.length >= 24 || (hasDigit && hasUpper && distinct >= 10)) s += 1;
  const score = Math.min(4, s) as 0 | 1 | 2 | 3 | 4;
  return {
    ok: true,
    score,
    label: score >= 4 ? "Strong" : score === 3 ? "Good" : "Acceptable",
    hint: score >= 4 ? "Strong passphrase." : "Accepted — longer is even better.",
  };
}

// A small, common subset of the server's disposable list — enough for instant
// feedback. The server enforces the full, extensible list.
const DISPOSABLE = new Set([
  "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
  "tempmail.com", "throwawaymail.com", "getnada.com", "yopmail.com",
  "trashmail.com", "maildrop.cc", "sharklasers.com", "fakeinbox.com",
  "dispostable.com", "moakt.com", "mohmal.com", "emailondeck.com",
]);

export function isLikelyDisposableEmail(email: string): boolean {
  const at = email.lastIndexOf("@");
  if (at < 0) return false;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return DISPOSABLE.has(domain);
}

// Consumer free-mail domains — mirrors the server's _FREE_MAIL (util/domains.py).
// A company on Google Workspace / Microsoft 365 is NOT here: it uses its own
// domain, so it stays allowed. Only the consumer domains themselves are blocked.
const CONSUMER_MAIL = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.uk", "outlook.com",
  "hotmail.com", "live.com", "msn.com", "aol.com", "icloud.com", "me.com",
  "proton.me", "protonmail.com", "gmx.com", "mail.com", "zoho.com",
  "qq.com", "163.com", "126.com", "sina.com", "foxmail.com",
  "naver.com", "yandex.com", "rediffmail.com",
]);

export function isConsumerEmail(email: string): boolean {
  const at = email.lastIndexOf("@");
  if (at < 0) return false;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return CONSUMER_MAIL.has(domain);
}

/* Structural domain check that mirrors the server's `valid_domain`
   (security/limits.py). Catches the common signup mistake of typing a company
   name ("Acme Corp") into the domain field — which reduces to a truthy-but-bogus
   value that would silently break every domain-based lookup for the tenant. */
function labelChars(label: string): boolean {
  // Each character must be a-z, 0-9, a hyphen, or a non-ASCII (IDN) codepoint —
  // the same rule the server applies per label.
  for (const ch of label) {
    const code = ch.codePointAt(0)!;
    const isAlnum =
      (code >= 48 && code <= 57) || (code >= 97 && code <= 122); // 0-9, a-z
    if (!(isAlnum || ch === "-" || code > 127)) return false;
  }
  return true;
}

export function looksLikeDomain(value: string): boolean {
  const candidate = value.trim().replace(/\.$/, "").toLowerCase();
  if (!candidate || candidate.length > 253) return false;
  if (candidate.includes("..") || /[\s/@:]/.test(candidate)) return false;
  const labels = candidate.split(".");
  if (labels.length < 2) return false;
  if (labels.every((l) => /^\d+$/.test(l))) return false; // bare IPv4
  return labels.every(
    (l) =>
      l.length > 0 &&
      l.length <= 63 &&
      !l.startsWith("-") &&
      !l.endsWith("-") &&
      labelChars(l),
  );
}
