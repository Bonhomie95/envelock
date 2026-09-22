export type Tier = "low" | "medium" | "high" | "critical";

export interface Finding {
  // Null for anonymous callers — the internal detection code is withheld
  // server-side (PRD §16); `category` is the public, plain-English grouping.
  service: string | null;
  category?: string;
  tier: Tier;
  score?: number;
  summary: string;
  evidence?: Record<string, unknown>;
}

export interface Assessment {
  tier: Tier;
  score: number;
  title: string;
  body: string;
  services: string[] | null;
  requires_callback: boolean;
  callback_phone: string | null;
  rationale: string[];
  alertable: boolean;
}

export interface AnalyseResult {
  message: {
    from: string;
    display_name: string | null;
    reply_to: string | null;
    subject: string | null;
    attachments: string[];
    urls: string[];
    remediable: boolean;
  };
  findings: Finding[];
  assessment: Assessment | null;
}

export interface ScanHit {
  candidate: string;
  technique: string;
  similarity: number;
  tier: Tier;
  armed: boolean;
  /** ISO registration date from RDAP, or null if unregistered / unknown. */
  registered_at: string | null;
}

export interface ScanResult {
  protected_domain: string;
  candidates_checked: number;
  hits: ScanHit[];
  note: string;
}

export interface Quote {
  plan: string;
  term: string;
  platform_cents: number;
  protected_cents: number;
  monitored_cents: number;
  subtotal_cents: number;
  discount_cents: number;
  total_cents: number;
  total_usd: number;
  breakdown: Record<string, unknown>;
}

export interface Coverage {
  sources: string[];
  capabilities: string[];
  protection_level: "full" | "standard" | "limited";
  active_detections: string[];
  inactive_detections: string[];
}

export interface ConnectMethod {
  id: string;
  name: string;
  tier: number;
  effort: string;
  who: string;
  steps: string[];
  remediation: boolean;
  identity_from: string;
  protection_level: "full" | "standard" | "limited";
}

export interface ConnectionPlan {
  domain: string;
  detected: boolean;
  mx_hosts: string[];
  provider: {
    id: string;
    name: string;
    aliases: string[];
    notes: string | null;
  };
  imap: { host: string | null; port: number };
  dns: { dmarc_policy: string | null; spf_present: boolean };
  recommended: ConnectMethod;
  alternatives: ConnectMethod[];
}

export interface AlertRecord {
  id: string;
  tier: Tier;
  title: string;
  body: string;
  state: string;
  mailbox_id: string | null;
  counterparty_domain: string | null;
  requires_callback: boolean;
  callback_phone: string | null;
  // AI autoflag — the fraud judge independently confirmed this alert.
  ai_flagged?: boolean;
  ai_verdict?: string | null;
  /** The sum that was about to move, on payment-fraud alerts. Null means the
   *  message named no figure — never zero. */
  amount_at_risk?: number | null;
  amount_currency?: string | null;
  created_at: string;
  acknowledged_at: string | null;
}

export interface ProtectionGap {
  capability: string;
  unlocks: string;
  how: string;
  provided_by: string[];
}

export interface ProtectionAdvice {
  level: "full" | "standard" | "limited";
  is_max: boolean;
  next_level: "full" | "standard" | null;
  missing: ProtectionGap[];
}

/** One (host, port, security) the connector will try, and where it came from —
 *  "dns-srv" and "autoconfig" are the domain's own published settings, the rest
 *  are conventions we fall back to. */
export interface ImapSettings {
  host: string;
  port: number;
  security: "ssl" | "starttls" | "none";
  source: string;
}

/** Why a connection failed, in a form the UI can act on. `code` is stable;
 *  `hint` is the fix to show under the field. */
export interface ImapError {
  code: string;
  message: string;
  hint: string;
  detail: string;
}

/** What a mail server presented, when we refused its certificate.
 *
 *  Shown so the customer can make the decision a desktop mail client offers in
 *  its exception dialog — but with the details in front of them rather than
 *  behind a shrug. Most often this is shared hosting whose certificate names
 *  the provider rather than the customer's own domain. */
export interface ImapCertificate {
  /** Lowercase hex. What gets approved, and what we then pin to. */
  sha256: string;
  subject: string;
  issuer: string;
  /** Every host name the certificate is actually valid for. */
  names: string[];
  not_before: string;
  not_after: string;
  /** The host we connected to — the other half of the comparison. */
  host: string;
  expired: boolean;
  self_signed: boolean;
  matches_host: boolean;
  /** One sentence naming what is wrong with it, in plain language. */
  summary: string;
}

export interface ImapProbeResult {
  ok: boolean;
  settings: ImapSettings | null;
  username: string | null;
  error: ImapError | null;
  attempts: (ImapSettings & { username: string; ok: boolean; error?: ImapError })[];
  reason: string;
  /** Present only when the failure was the certificate. */
  certificate?: ImapCertificate | null;
}

export interface ImapConnectBody {
  password: string;
  /** Optional: leave the server blank and we detect it. */
  imap_host?: string;
  imap_port?: number;
  security?: "ssl" | "starttls" | "none";
  username?: string;
  /** False pins the attempt to exactly the settings given (no fallback). */
  autodiscover?: boolean;
  /** SHA-256 of a certificate the customer has looked at and approved. Sent
   *  only after a certificate failure showed them what the server presented,
   *  so it is a decision about one specific certificate rather than a blanket
   *  "trust anything" switch. */
  accept_certificate_sha256?: string;
}

/** One entry in the tenant's own audit trail (E5). This is what makes "IT can
 *  see who acted and who ignored it" answerable — including the actions
 *  Envelock's own operators take on the account. */
export interface AuditEvent {
  id: string;
  action: string;
  actor_id: string | null;
  target_type: string | null;
  target_id: string | null;
  detail: Record<string, unknown> | null;
  at: string;
}

/** A domain registered to look like one of the tenant's own. `armed` is the
 *  field that matters: a lookalike with MX records can actually send mail. */
export interface LookalikeDomain {
  candidate: string;
  protected: string;
  technique: string;
  similarity: number;
  armed: boolean;
  status: string;
  first_seen_source: string | null;
}

/** A supplier as the registry sees it.
 *
 *  This type previously described fields the endpoint does not return
 *  (`registrable_domain`, `known_bank_ids`, `is_trusted`) and omitted the ones
 *  it does, so anything reading it got `undefined` at runtime while the compiler
 *  was satisfied. It now matches `GET /api/v1/counterparties`. */
export interface Counterparty {
  domain: string;
  display_name: string | null;
  message_count: number;
  verified_phone: string | null;
  /** Active, verified payment identifiers we hold for this supplier. */
  bank_records: number;
  risk_score: number;
  tier: Tier;
  advice: string;
  /** What finance still has to record before this supplier is fully covered. */
  needs: ("bank_details" | "callback_number")[];
}

export interface BankRecord {
  id: string;
  scheme: "iban" | "swift" | "ach" | "sortcode" | "account" | "crypto";
  identifier: string;
  bank_name: string | null;
  country: string | null;
  active: boolean;
  first_seen_at: string | null;
  verified_at: string | null;
}

export interface SupplierDetail {
  domain: string;
  display_name: string | null;
  verified_phone: string | null;
  records: BankRecord[];
}

export interface VendorImportResult {
  dry_run: boolean;
  rows_parsed: number;
  suppliers_created: number;
  suppliers_matched: number;
  bank_records_created: number;
  bank_records_already_present: number;
  problems: string[];
  suppliers: { domain: string; name: string | null }[];
}

export interface MailboxRecord {
  id: string;
  address: string;
  mailbox_class: string;
  sources: string[];
  protection_level: "full" | "standard" | "limited";
  protection?: ProtectionAdvice;
  inactive_detections: string[];
  is_shared: boolean;
  last_sync_at?: string | null;
  needs_reconnect?: boolean;
  connection_error?: string | null;
  /** C11 silent-access detection, opted into by the owner. */
  silent_access_armed?: boolean;
  /** Split key custody: work the API handed to the worker and is waiting on. */
  sync_pending?: boolean;
  backfill_pending?: boolean;
  backfill_state?: {
    status: "queued" | "running" | "done" | "failed";
    days?: number;
    analysed?: number;
    reason?: string | null;
    queued_at?: string;
    started_at?: string;
    finished_at?: string;
  } | null;
}

export interface SyncResult {
  ok: boolean;
  fetched: number;
  alerted?: number;
  quarantined?: number;
  alerts?: { uid: number; alert_id: string; tier: string | null; title: string | null }[];
  /** Set when this process could not decrypt the credential and handed the
   *  sync to the worker instead — see the server's split key custody. */
  queued?: boolean;
  message?: string;
}

/** One enrolled sensor: an install of the browser extension, Thunderbird
 *  add-on or Outlook add-in, on one device, for one mailbox. */
export interface SensorDevice {
  id: string;
  mailbox_id: string;
  mailbox: string | null;
  client: "browser" | "thunderbird" | "outlook";
  label: string | null;
  enrolled_at: string | null;
  last_seen_at: string | null;
  live: boolean;
  revoked: boolean;
}

export interface SensorPairing {
  code: string;
  expires_at: string;
  mailbox: string;
  ttl_seconds: number;
}

export interface PreventedLoss {
  /** Per currency, never summed — see the server's `prevented_loss`. */
  by_currency: { currency: string; amount: number }[];
  incidents: number;
  /** Confirmed frauds that named no amount. Shown, never folded into the total. */
  unpriced_incidents: number;
}

export interface PublicStatus {
  state: "operational" | "degraded" | "down";
  summary: string;
  components: { id: string; name: string; state: string; detail: string }[];
  checked_at: string;
}

export interface NetworkStats {
  domains_judged: number;
  domains_confirmed_fraudulent: number;
  actionable: number;
  confirmations: number;
}

export interface Oversight {
  prevented_loss: PreventedLoss;
  /** Rolling 30 days — the dashboard's "stopped this month". */
  month?: {
    payment_requests: number;
    payments_checked_by_currency: { currency: string; amount: number }[];
    quarantined: number;
    confirmed_fraud: number;
  };
  total: number;
  open: number;
  critical_open: number;
  acknowledged: number;
  unacknowledged_over_15m: number;
  mailboxes: number;
  domains: number;
  by_tier: Record<string, number>;
  coverage: Record<string, number>;
}

export interface SimulationResult {
  runs: { id: string; expected: string; detected: string[]; passed: boolean }[];
  passed: number;
  total: number;
}

export interface TenantInfo {
  tenant_id: string;
  name: string | null;
  plan: string;
  subscribed_plan?: string;
  trial_ended?: boolean;
  billing?: {
    /** A live Stripe subscription — plan and seat changes update it in place. */
    subscription: boolean;
    /** Monthly price of one mailbox beyond the plan's included five. */
    extra_mailbox_cents: number;
  };
  trial: {
    started_at: string | null;
    ends_at: string | null;
    days_left: number | null;
    active: boolean;
    payment_method_ok: boolean;
  };
  mailboxes?: {
    used: number;
    capacity: number;
    included: number;
    extra_seats: number;
    can_add: boolean;
  };
  domains: {
    name: string;
    registrable_domain: string;
    verified: boolean;
    is_defensive: boolean;
  }[];
  primary_domain: string | null;
  //: Colleagues who self-registered and are awaiting an admin's approval.
  pending_members: number;
}

export interface AccountingConnectionInfo {
  provider: "xero" | "quickbooks";
  label: string;
  org_name: string | null;
  flag_bills: boolean;
  connected_at: string;
  last_sync_at: string | null;
  syncing: boolean;
  last_error: string | null;
  summary: {
    suppliers_seen: number;
    suppliers_imported: number;
    skipped_no_domain: number;
    suppliers_created: number;
    bank_records_created: number;
  } | null;
}

export interface VerificationAttempt {
  id: string;
  channel: "call" | "sms";
  status: "pending" | "confirmed" | "denied" | "no_answer" | "expired";
  phone: string | null;
  account: string | null;
  note: string | null;
  created_at: string;
  responded_at: string | null;
  expires_at: string | null;
}

export interface PaymentVerificationInfo {
  supplier: string | null;
  supplier_name: string | null;
  /** The number on the supplier record — never one taken from the email. */
  phone_on_file: string | null;
  /** Masked, e.g. "IBAN ••••5555". */
  account: string | null;
  amount: number | null;
  currency: string | null;
  sms_available: boolean;
  attempts: VerificationAttempt[];
  alert_state: string;
}

export interface QualityMetric {
  id: string;
  name: string;
  observed: number | null;
  target: number | null;
  unit: string | null;
  sample_size: number;
  meets: boolean | null;
}

const TOKEN_KEY = "envelock.access_token";
const REFRESH_KEY = "envelock.refresh_token";

export const auth = {
  get token(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },
  get refreshToken(): string | null {
    return localStorage.getItem(REFRESH_KEY);
  },
  /** Store the access token, and the refresh token when the endpoint returns one
   *  (login / MFA verify / skip / refresh). The refresh token is what keeps a
   *  session alive past the short 15-minute access-token TTL. */
  set(token: string, refresh?: string | null) {
    localStorage.setItem(TOKEN_KEY, token);
    if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  get signedIn(): boolean {
    return Boolean(localStorage.getItem(TOKEN_KEY));
  },
  /** Role from the token payload ("owner" | "admin" | "member"), for showing
   *  admin-only nav without a round-trip. The server still enforces every check. */
  get role(): string | null {
    const t = localStorage.getItem(TOKEN_KEY);
    if (!t) return null;
    try {
      const raw = t.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
      const json = atob(raw + "=".repeat((4 - (raw.length % 4)) % 4));
      return (JSON.parse(json).role as string) ?? null;
    } catch {
      return null;
    }
  },
};

// Where the backend actually lives.
//
// Set VITE_API_BASE_URL at BUILD time when the client is served from a different
// origin than the API (e.g. a static host in front of a separate API host); the
// value is baked into the bundle. Leave it unset and every call is same-origin,
// which is what you want when one web server serves the app and proxies /api to
// the backend — and what the Vite dev proxy does locally.
//
// Deliberately no hardcoded fallback host: a wrong-but-plausible default meant a
// build with a missing env file silently pointed a customer's dashboard at
// somebody else's backend. Same-origin fails loudly and locally instead.
export const API_BASE = (
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? ""
).replace(/\/+$/, "");

/** Prefix an "/api/..." path with the backend origin. */
export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

export class ApiError extends Error {
  status: number;

  /** The parsed `detail` when the server sent a structured one, rather than a
   *  string. Some failures carry data the UI has to act on — a rejected TLS
   *  certificate the customer must be shown before they can decide about it —
   *  and flattening that to a message would throw the data away. */
  detail?: unknown;

  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.status = status;
    this.detail = detail;
  }

  /** The certificate a mail server presented, when that is why we failed. */
  get certificate(): ImapCertificate | null {
    const d = this.detail as { certificate?: ImapCertificate } | undefined;
    return d?.certificate ?? null;
  }

  get unauthorized() {
    return this.status === 401 || this.status === 403;
  }
}

// A single in-flight refresh, shared by any requests that 401 at once, so a burst
// of expired calls triggers exactly one /auth/refresh rather than a stampede.
let refreshInFlight: Promise<boolean> | null = null;

async function tryRefresh(): Promise<boolean> {
  const rt = auth.refreshToken;
  if (!rt) return false;
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch(apiUrl("/api/v1/auth/refresh"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: rt }),
        });
        if (!res.ok) {
          auth.clear(); // refresh reuse/expiry → the session is truly over
          return false;
        }
        const body = (await res.json()) as {
          access_token: string;
          refresh_token?: string;
        };
        auth.set(body.access_token, body.refresh_token);
        return true;
      } catch {
        return false;
      } finally {
        refreshInFlight = null;
      }
    })();
  }
  return refreshInFlight;
}

/** An authenticated file download (the API needs the bearer token, so a plain
 *  link can't carry it). Refreshes an expired session once, like `request`. */
async function download(path: string, fallbackName: string, _retried = false): Promise<void> {
  const res = await fetch(apiUrl(path), {
    headers: auth.token ? { Authorization: `Bearer ${auth.token}` } : {},
  });
  if (res.status === 401 && !_retried && auth.refreshToken && (await tryRefresh())) {
    return download(path, fallbackName, true);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json())?.detail ?? detail;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, String(detail));
  }
  const name =
    /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") ?? "")?.[1] ?? fallbackName;
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function request<T>(path: string, init?: RequestInit, _retried = false): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;

  const res = await fetch(apiUrl(path), { ...init, headers });

  // Access token expired mid-session → refresh once and replay the request, so a
  // 15-minute-old tab doesn't fail with "expired". Don't loop the refresh call.
  if (
    res.status === 401 &&
    !_retried &&
    auth.refreshToken &&
    !path.includes("/auth/refresh") &&
    !path.includes("/auth/login")
  ) {
    if (await tryRefresh()) return request<T>(path, init, true);
  }

  // A 401 that survived the refresh attempt (or had no refresh token) means the
  // session is truly over — expired, or revoked by refresh-reuse detection (e.g.
  // two tabs racing the rotating refresh token). Clear it and send the user to
  // sign in, rather than surfacing a cryptic 401 on whatever they just clicked
  // (which reads like "wrong password" on, say, the IMAP test).
  if (
    res.status === 401 &&
    !path.includes("/auth/login") &&
    !path.includes("/auth/refresh")
  ) {
    auth.clear();
    if (
      typeof window !== "undefined" &&
      !window.location.pathname.startsWith("/signin")
    ) {
      window.location.assign("/signin");
    }
  }

  if (!res.ok) {
    let detail = res.statusText;
    let structured: unknown;
    try {
      const body = await res.json();
      const d = body?.detail;
      if (typeof d === "string") {
        detail = d;
      } else if (Array.isArray(d)) {
        // FastAPI validation errors are a list of {loc, msg, type}.
        detail = d.map((e) => e?.msg ?? String(e)).join("; ") || detail;
      } else if (d && typeof d === "object") {
        // A structured detail. Show its message and keep the rest for the
        // caller — `JSON.stringify` here used to put raw JSON in front of the
        // customer and discard the parts the UI needed.
        structured = d;
        detail = (d as { message?: string }).message ?? detail;
      }
      // Make throttling human: "try again in ~N minutes" beats a bare message.
      if (res.status === 429) {
        const secs = Number(body?.retry_after ?? res.headers.get("Retry-After"));
        if (Number.isFinite(secs) && secs > 0) {
          const mins = Math.ceil(secs / 60);
          detail = `Too many attempts. Try again in about ${
            mins <= 1 ? "a minute" : `${mins} minutes`
          }.`;
        } else {
          detail = "Too many attempts. Please wait a little and try again.";
        }
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail, structured);
  }
  return res.json() as Promise<T>;
}

export const api = {
  analyse: (body: {
    raw_message: string;
    owned_domains?: string[];
    known_counterparties?: string[];
    counterparty_known_bank_ids?: string[];
    counterparty_message_count?: number;
    counterparty_phone?: string | null;
    source?: string;
  }) =>
    request<AnalyseResult>("/api/v1/analyse", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  scanDomain: (domain: string) =>
    request<ScanResult>("/api/v1/domains/scan", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),

  quote: (body: {
    plan: string;
    term: string;
    mail_domains: number;
    protected: number;
    monitored: number;
  }) =>
    request<Quote>("/api/v1/pricing/quote", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  coverage: (sources: string[]) =>
    request<Coverage>(
      `/api/v1/coverage?sources=${encodeURIComponent(sources.join(","))}`,
    ),

  connect: (domain: string) =>
    request<ConnectionPlan>(
      `/api/v1/domains/${encodeURIComponent(domain)}/connect`,
    ),

  // ── Auth ──────────────────────────────────────────────────────────────────
  register: (body: { email: string; password: string; tenant_name: string }) =>
    request<{
      user_id: string;
      tenant_id: string;
      next: string;
      verification_required?: boolean;
      verify_link?: string;
    }>("/api/v1/auth/register", { method: "POST", body: JSON.stringify(body) }),

  verifyEmail: (token: string) =>
    request<{ verified: boolean }>("/api/v1/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ token }),
    }),

  recoverySignIn: (body: { mfa_token: string; recovery_code: string }) =>
    request<{
      access_token: string;
      refresh_token: string;
      recovery_codes_remaining: number;
      warning?: string;
    }>("/api/v1/auth/recovery", { method: "POST", body: JSON.stringify(body) }),

  resendVerification: (email: string) =>
    request<{ status: string }>("/api/v1/auth/verify-email/resend", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  login: (body: { email: string; password: string }) =>
    request<{ mfa_token: string; mfa_setup_required?: boolean }>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify(body) },
    ),

  // Begin a password reset. An MFA account gets back method:"mfa" + a reset token
  // (used with the authenticator code); a non-MFA account gets method:"email".
  /** Begin a reset. The answer is deliberately identical for a real address and
   *  an unknown one — it never reveals whether an account exists. What it DOES
   *  report is whether this deployment can send email at all, which is a
   *  property of the deployment rather than the account, and therefore safe to
   *  state: without it the UI said "check your email" on a deployment that had
   *  no relay and sent nothing, forever. */
  forgotPassword: (email: string) =>
    request<{
      message: string;
      email_delivery: "available" | "unavailable";
      code_reset_available: boolean;
      reset_link?: string; // development only
    }>("/api/v1/auth/password/forgot", {
      method: "POST",
      body: JSON.stringify({ email }),
    }),

  /** Complete a reset from an emailed link. `code` is additionally required when
   *  the account has an authenticator. */
  resetPassword: (body: { token: string; new_password: string; code?: string }) =>
    request<{ ok: boolean; message: string }>("/api/v1/auth/password/reset", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  /** Reset with the authenticator alone — no email, no link. This is what keeps
   *  recovery working on a deployment whose relay is not provisioned yet. */
  resetPasswordWithCode: (body: {
    email: string;
    code: string;
    new_password: string;
  }) =>
    request<{ ok: boolean; message: string }>(
      "/api/v1/auth/password/reset-with-code",
      { method: "POST", body: JSON.stringify(body) },
    ),

  mfaSetup: (mfaToken: string) =>
    request<{ secret: string; otpauth_uri: string }>("/api/v1/auth/mfa/setup", {
      method: "POST",
      body: JSON.stringify({ token: mfaToken }),
    }),

  mfaVerify: (body: { mfa_token: string; code: string }) =>
    request<{
      access_token: string;
      refresh_token?: string;
      role: string;
      recovery_codes?: string[];
    }>("/api/v1/auth/mfa/verify", { method: "POST", body: JSON.stringify(body) }),

  // Defer MFA and start a session now. The dashboard nags until it's enabled.
  mfaSkip: (mfaToken: string) =>
    request<{
      access_token: string;
      refresh_token?: string;
      role: string;
      mfa_deferred: boolean;
    }>("/api/v1/auth/mfa/skip", {
      method: "POST",
      body: JSON.stringify({ token: mfaToken }),
    }),

  // Turn MFA on from inside an authenticated session (for users who skipped it).
  mfaEnroll: () =>
    request<{ secret: string; otpauth_uri: string }>("/api/v1/auth/mfa/enroll", {
      method: "POST",
    }),

  mfaActivate: (code: string) =>
    request<{ mfa_enabled: boolean; recovery_codes: string[] }>(
      "/api/v1/auth/mfa/activate",
      { method: "POST", body: JSON.stringify({ code }) },
    ),

  // Change the account password behind a step-up re-auth. All other sessions are
  // revoked on success, so the caller should sign in again.
  changePassword: (body: {
    current_password: string;
    new_password: string;
    mfa_code?: string;
  }) =>
    request<{ status: string; sessions_revoked: boolean }>("/api/v1/auth/password", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // Turn MFA off — requires the current password AND a fresh code.
  mfaDisable: (body: { password: string; mfa_code: string }) =>
    request<{ mfa_enabled: boolean }>("/api/v1/auth/mfa/disable", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  me: () =>
    request<{
      email: string;
      role: string;
      tenant_id: string;
      is_admin: boolean;
      must_change_password: boolean;
      mfa_enabled: boolean;
      phone: string | null;
      phone_verified: boolean;
      recovery_codes_remaining: number;
    }>("/api/v1/auth/me"),

  // First-login password set for an owner-provisioned account (no MFA needed).
  setInitialPassword: (new_password: string) =>
    request<{ status: string }>("/api/v1/auth/password/initial", {
      method: "POST",
      body: JSON.stringify({ new_password }),
    }),

  logout: () =>
    request<{ status: string }>("/api/v1/auth/logout", { method: "POST" }),

  // Verified phone — a second, out-of-band channel for Critical alerts and
  // recovery. The code is sent by SMS (surfaced in dev for local testing).
  // Changing an already-verified phone requires current_password (+ mfa_code when
  // MFA is on); the first add needs neither.
  phoneStart: (body: { phone: string; current_password?: string; mfa_code?: string }) =>
    request<{ status: string; delivered: boolean; dev_code?: string }>(
      "/api/v1/auth/phone/start",
      { method: "POST", body: JSON.stringify(body) },
    ),

  phoneVerify: (code: string) =>
    request<{ phone_verified: boolean; phone: string }>(
      "/api/v1/auth/phone/verify",
      { method: "POST", body: JSON.stringify({ code }) },
    ),

  // ── Team management (owner-provisioned) ─────────────────────────────────────
  members: () =>
    request<{
      members: {
        id: string;
        email: string;
        role: string;
        status: string;
        pending_password: boolean;
        is_self: boolean;
      }[];
      seats: { used: number; cap: number; entitled: boolean; protected_mailboxes: number };
    }>("/api/v1/members"),

  createMember: (body: { email: string; role: "member" | "admin" }) =>
    request<{
      id: string;
      email: string;
      role: string;
      temporary_password: string;
      note: string;
    }>("/api/v1/members", { method: "POST", body: JSON.stringify(body) }),

  approveMember: (userId: string) =>
    request<{ approved: boolean; email: string }>(
      `/api/v1/members/${userId}/approve`,
      { method: "POST" },
    ),

  removeMember: (userId: string) =>
    request<{ removed: boolean; email: string }>(
      `/api/v1/members/${userId}/reject`,
      { method: "POST" },
    ),

  // ── Tenant data ───────────────────────────────────────────────────────────
  bootstrap: (body: { name: string; domain: string }) =>
    request<{ tenant_id: string; domain: string; ingest_address: string }>(
      "/api/v1/tenants/bootstrap",
      { method: "POST", body: JSON.stringify(body) },
    ),

  tenant: () => request<TenantInfo>("/api/v1/tenant"),

  // Domain-control verification (PRD signup funnel). Show the DNS record, then
  // verify once the customer has added it. Until a domain is verified, a mailbox
  // on it cannot be connected for live mail.
  domainVerification: (domain: string) =>
    request<{
      domain: string;
      verified: boolean;
      txt: { host: string; type: string; value: string };
      cname: { host: string; type: string; value: string };
    }>(`/api/v1/domains/${encodeURIComponent(domain)}/verification`),

  verifyDomain: (domain: string) =>
    request<{ domain: string; verified: boolean }>(
      `/api/v1/domains/${encodeURIComponent(domain)}/verify`,
      { method: "POST" },
    ),

  // Push/sensor config — carries the VAPID public key the browser needs to
  // subscribe, and whether push is even configured on this deployment.
  sensorConfig: () =>
    request<{
      heartbeat_seconds: number;
      vapid_public_key: string | null;
      push_available: boolean;
      endpoints: Record<string, string>;
    }>("/api/v1/sensor/config"),

  // L1 Web Push registration (PRD §8.1). Register the browser so Critical alerts
  // reach the user even when the app tab is closed.
  pushSubscribe: (body: { endpoint: string; p256dh: string; auth: string }) =>
    request<{ subscribed: boolean }>("/api/v1/push/subscribe", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  pushUnsubscribe: (body: { endpoint: string; p256dh: string; auth: string }) =>
    request<{ subscribed: boolean }>("/api/v1/push/unsubscribe", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // E10 — per-counterparty risk profiles.
  counterparties: () =>
    request<{ counterparties: Counterparty[] }>("/api/v1/counterparties"),

  /** ── The supplier registry ──────────────────────────────────────────────
   *  The whole product thesis: hold the account a supplier is really paid into
   *  and the number to ring, so a changed IBAN is checked against a record
   *  rather than a guess. The server has had these endpoints all along; nothing
   *  in the app called them, so the one capability competitors cannot copy was
   *  unreachable. */
  addSupplier: (body: {
    domain: string;
    display_name?: string;
    verified_phone?: string;
  }) =>
    request<{ domain: string; created: boolean }>("/api/v1/counterparties", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  supplierRecords: (domain: string) =>
    request<SupplierDetail>(
      `/api/v1/counterparties/${encodeURIComponent(domain)}/bank-records`,
    ),

  addBankRecord: (
    domain: string,
    body: {
      scheme: BankRecord["scheme"];
      identifier: string;
      bank_name?: string;
      country?: string;
    },
  ) =>
    request<{ domain: string; identifier: string }>(
      `/api/v1/counterparties/${encodeURIComponent(domain)}/bank-records`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  retireBankRecord: (domain: string, id: string) =>
    request<{ id: string; active: boolean }>(
      `/api/v1/counterparties/${encodeURIComponent(domain)}/bank-records/${id}`,
      { method: "DELETE" },
    ),

  setCallbackNumber: (domain: string, phone: string) =>
    request<{ domain: string; verified_phone: string }>(
      `/api/v1/counterparties/${encodeURIComponent(domain)}/phone`,
      { method: "POST", body: JSON.stringify({ phone }) },
    ),

  /** Import the AP vendor master. `dry_run` previews without writing. */
  importVendors: (csv: string, dryRun = false) =>
    request<VendorImportResult>("/api/v1/counterparties/import", {
      method: "POST",
      body: JSON.stringify({ csv, dry_run: dryRun }),
    }),

  /** Progress of a background job (currently: onboarding backfill). */
  jobStatus: (id: string) =>
    request<{
      id: string;
      status: "queued" | "running" | "done" | "failed" | "unknown";
      progress?: Record<string, unknown>;
      result?: Record<string, unknown> | null;
      error?: string | null;
      detail?: string;
    }>(`/api/v1/jobs/${encodeURIComponent(id)}`),

  /** Group D — domains registered to impersonate this tenant. On the free Guard
   *  tier this is the ONLY thing the product produces, so it must be visible. */
  lookalikes: () =>
    request<{ lookalikes: LookalikeDomain[]; armed_count: number }>(
      "/api/v1/lookalikes",
    ),

  reportLookalike: (candidate: string, fraudulent = true) =>
    request<unknown>(
      `/api/v1/lookalikes/${encodeURIComponent(candidate)}/report?fraudulent=${fraudulent}`,
      { method: "POST" },
    ),

  // Change the subscribed plan (owner only). Moving to a paid tier needs an
  // active trial or a card on file; the server returns 402 otherwise.
  changePlan: (plan: string) =>
    request<{
      subscribed_plan: string;
      plan: string;
      payment_method_ok: boolean;
      trial_active: boolean;
    }>("/api/v1/tenant/plan", { method: "POST", body: JSON.stringify({ plan }) }),

  // Full account deletion. The domain trial ledger is retained (anti-abuse), so a
  // returning owner gets no fresh trial. Requires the password (+ code if MFA on).
  deleteTenant: (body: { password: string; mfa_code?: string }) =>
    request<{ deleted: boolean; domain_ledger_retained: boolean }>("/api/v1/tenant", {
      method: "DELETE",
      body: JSON.stringify(body),
    }),

  alerts: (state?: string) =>
    request<{ alerts: AlertRecord[]; count: number }>(
      `/api/v1/alerts${state ? `?state=${state}` : ""}`,
    ),

  acknowledgeAlert: (id: string) =>
    request<AlertRecord>(`/api/v1/alerts/${id}/acknowledge`, { method: "POST" }),

  /* The AI analyst's full working for one alert. Admin-only server-side (the
     taxonomy rule keeps the detail off member views), so callers must handle a
     403 as "not for you" rather than as an error worth showing. */
  alertAi: (id: string) =>
    request<{
      alert_id: string;
      ai_flagged: boolean;
      verdicts: {
        verdict: string;
        confidence: number | null;
        rationale: string | null;
        escalated: boolean;
        rule_tier: string | null;
        final_tier: string | null;
        provider: string | null;
        model: string | null;
        input_tokens: number | null;
        output_tokens: number | null;
        cost_micros: number | null;
        human_disposition: string | null;
        created_at: string;
      }[];
    }>(`/api/v1/alerts/${id}/ai`),

  // ── Supplier verification of a bank-detail change ─────────────────────────
  verification: (alertId: string) =>
    request<PaymentVerificationInfo>(`/api/v1/alerts/${alertId}/verification`),

  recordCallOutcome: (
    alertId: string,
    outcome: "confirmed" | "denied" | "no_answer",
    note?: string,
  ) =>
    request<{ attempt: VerificationAttempt; alert_state: string }>(
      `/api/v1/alerts/${alertId}/verification/call`,
      { method: "POST", body: JSON.stringify({ outcome, note }) },
    ),

  sendVerificationText: (alertId: string) =>
    request<{ attempt: VerificationAttempt }>(
      `/api/v1/alerts/${alertId}/verification/sms`,
      { method: "POST" },
    ),

  // Public (no session): the page a supplier opens from our text.
  supplierVerification: (token: string) =>
    request<{ company: string; account: string | null; status: string }>(
      `/api/v1/verify/${encodeURIComponent(token)}`,
    ),

  answerSupplierVerification: (token: string, answer: "yes" | "no") =>
    request<{ status: string }>(`/api/v1/verify/${encodeURIComponent(token)}`, {
      method: "POST",
      body: JSON.stringify({ answer }),
    }),

  // ── Accounting systems (Xero / QuickBooks Online) ──────────────────────────
  accounting: () =>
    request<{
      available: { provider: "xero" | "quickbooks"; label: string }[];
      connections: AccountingConnectionInfo[];
    }>("/api/v1/accounting"),
  connectAccounting: (provider: string) =>
    request<{ url: string }>(`/api/v1/accounting/${provider}/connect`, { method: "POST" }),
  syncAccounting: (provider: string) =>
    request<AccountingConnectionInfo>(`/api/v1/accounting/${provider}/sync`, { method: "POST" }),
  setAccountingFlagBills: (provider: string, flag_bills: boolean) =>
    request<AccountingConnectionInfo>(`/api/v1/accounting/${provider}`, {
      method: "PATCH",
      body: JSON.stringify({ flag_bills }),
    }),
  disconnectAccounting: (provider: string) =>
    request<{ disconnected: boolean }>(`/api/v1/accounting/${provider}`, { method: "DELETE" }),

  // The alert's evidence record (PDF) — for an insurer, a bank or the police.
  downloadEvidence: (alertId: string) =>
    download(`/api/v1/alerts/${alertId}/evidence.pdf`, "envelock-evidence.pdf"),

  quarantineAlert: (id: string) =>
    request<{
      succeeded: boolean;
      reason: string;
      alert_only?: boolean;
      queued?: boolean;
      already_quarantined?: boolean;
    }>(`/api/v1/alerts/${id}/quarantine`, { method: "POST" }),

  backfillMailbox: (id: string, opts?: { full?: boolean; days?: number }) =>
    request<{
      mailbox: string;
      days: number;
      job: { id: string } | null;
      reason: string;
      /** Handed to the worker (split key custody); progress is on the mailbox. */
      queued?: boolean;
    }>(
      `/api/v1/mailboxes/${id}/backfill` +
        (opts?.full ? "?full=true" : opts?.days ? `?days=${opts.days}` : ""),
      { method: "POST" },
    ),

  mailboxes: () => request<{ mailboxes: MailboxRecord[] }>("/api/v1/mailboxes"),

  addMailbox: (body: {
    address: string;
    mailbox_class: string;
    sources: string[];
  }) =>
    request<MailboxRecord>("/api/v1/mailboxes", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  addMailboxesBulk: (body: { addresses: string[]; mailbox_class: string }) =>
    request<{
      created: MailboxRecord[];
      skipped: { address: string; reason: string }[];
      created_count: number;
      skipped_count: number;
      //: How many were refused purely for lack of a seat (vs invalid/duplicate/
      //: unverified-domain), so the UI can prompt to buy more rather than lump
      //: them in with genuine errors.
      over_limit_count: number;
      capacity: number;
    }>("/api/v1/mailboxes/bulk", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  connectImap: (mailboxId: string, body: ImapConnectBody) =>
    request<MailboxRecord & { imap?: ImapSettings & { username: string } }>(
      `/api/v1/mailboxes/${mailboxId}/connect/imap`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  // What server this mailbox most likely needs — no password involved. Backs the
  // "Find my settings" button, which is what turns a failed connection into a
  // one-click one for anyone who doesn't know their IMAP host by heart.
  imapSettings: (mailboxId: string) =>
    request<{
      address: string;
      detected: boolean;
      settings: ImapSettings | null;
      candidates: ImapSettings[];
      note: string;
    }>(`/api/v1/mailboxes/${mailboxId}/connect/imap/settings`),

  // Poll a connected IMAP mailbox immediately — the "Sync now" button. Fetches
  // any new mail through the full detection pipeline and reports what it found.
  syncMailbox: (mailboxId: string) =>
    request<SyncResult>(`/api/v1/mailboxes/${mailboxId}/sync`, {
      method: "POST",
    }),

  // Verify IMAP settings without storing anything (the form's "Test" button).
  testImap: (mailboxId: string, body: ImapConnectBody) =>
    request<ImapProbeResult>(
      `/api/v1/mailboxes/${mailboxId}/connect/imap/test`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  // Mark a mailbox as connected by forwarding (alert-only — Limited coverage).
  connectForward: (mailboxId: string) =>
    request<MailboxRecord>(`/api/v1/mailboxes/${mailboxId}/connect/forward`, {
      method: "POST",
    }),

  mailboxActivity: (mailboxId: string) =>
    request<{
      address: string;
      connected: boolean;
      protection_level: "full" | "standard" | "limited";
      sources: string[];
      inactive_detections: string[];
      last_sync_at: string | null;
      messages_scanned: number;
      alerts_raised: number;
      events: { action: string; at: string; detail: unknown }[];
    }>(`/api/v1/mailboxes/${mailboxId}/activity`),

  patchMailbox: (
    mailboxId: string,
    body: { silent_access_armed?: boolean; display_name?: string; is_shared?: boolean },
  ) =>
    request<MailboxRecord>(`/api/v1/mailboxes/${mailboxId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),

  /* ── Client sensor ──────────────────────────────────────────────────────
     Pairing codes are minted here and typed into the extension / add-on /
     add-in, which trades them for a token of its own. The dashboard never
     sees that token. */
  createSensorPairing: (mailboxId: string) =>
    request<SensorPairing>("/api/v1/sensor/pairings", {
      method: "POST",
      body: JSON.stringify({ mailbox_id: mailboxId }),
    }),

  sensorDevices: () =>
    request<{ devices: SensorDevice[]; heartbeat_seconds: number }>("/api/v1/sensor/devices"),

  revokeSensorDevice: (deviceId: string) =>
    request<void>(`/api/v1/sensor/devices/${deviceId}`, { method: "DELETE" }),

  removeMailbox: (mailboxId: string) =>
    request<{ removed: boolean; address: string }>(
      `/api/v1/mailboxes/${mailboxId}`,
      { method: "DELETE" },
    ),

  ingestAddress: () =>
    request<{
      ingest_address: string;
      steps: string[];
      warning: string;
      limitation: string;
    }>("/api/v1/ingest-address"),

  oversight: () => request<Oversight>("/api/v1/oversight"),

  /* The public status page's source of truth, and the shared-network counts.
     Both are unauthenticated: the status page in particular has to keep
     answering when the product itself is what is broken. */
  status: () => request<PublicStatus>("/api/v1/status/public"),

  network: () => request<NetworkStats>("/api/v1/network"),

  audit: (limit = 50) =>
    request<{ events: AuditEvent[] }>(`/api/v1/audit?limit=${limit}`),

  simulate: (protected_domain: string) =>
    request<SimulationResult>("/api/v1/simulate", {
      method: "POST",
      body: JSON.stringify({ protected_domain }),
    }),

  brandPosture: (domain: string) =>
    request<{
      domain: string;
      spf_present: boolean;
      dmarc_present: boolean;
      dmarc_policy: string | null;
      protected: boolean;
      tier: Tier;
      summary: string;
      recommendations: string[];
    }>(`/api/v1/brand/${encodeURIComponent(domain)}/posture`),

  channelStatus: () =>
    request<{
      mail_providers: { source: string; configured: boolean; reason: string | null }[];
      imap_broker: Record<string, number | string>;
      notification_rungs: { rung: string; configured: boolean; metered: boolean }[];
    }>("/api/v1/status/channels"),

  resolveAlert: (id: string, dismiss = false) =>
    request<AlertRecord>(
      `/api/v1/alerts/${id}/resolve${dismiss ? "?dismiss=true" : ""}`,
      { method: "POST" },
    ),

  // ── Tier 1 OAuth connection ─────────────────────────────────────────────────
  oauthProviders: () =>
    request<{ configured: string[]; supported: string[] }>(
      "/api/v1/connect/oauth/providers",
    ),

  oauthAuthorize: (provider: string, mailbox_address: string) =>
    request<{ provider: string; authorize_url: string; state: string }>(
      `/api/v1/connect/oauth/${provider}/authorize`,
      { method: "POST", body: JSON.stringify({ mailbox_address }) },
    ),

  // ── Billing / payment gate ──────────────────────────────────────────────────
  paymentProviders: () =>
    request<{ configured: string[] }>("/api/v1/billing/providers"),

  // Start a hosted Stripe Checkout for a paid plan; returns the URL to redirect
  // the browser to. Activation happens server-side via the Stripe webhook.
  startCheckout: (plan: string, extra_mailboxes = 0) =>
    request<{ url: string; id: string }>("/api/v1/billing/checkout", {
      method: "POST",
      body: JSON.stringify({ plan, extra_mailboxes }),
    }),

  // Set the number of paid mailboxes beyond the plan's five, on the live Stripe
  // subscription. Increases are charged (prorated) before they're granted.
  setSeats: (extra_mailboxes: number) =>
    request<{ extra_mailbox_seats: number; capacity: number }>("/api/v1/billing/seats", {
      method: "PUT",
      body: JSON.stringify({ extra_mailboxes }),
    }),

  // Buy additional mailbox seats (verify-instrument model; sandbox works in dev).
  buySeats: (count: number, provider: string, reference: string) =>
    request<{ extra_mailbox_seats: number; purchased: number }>(
      "/api/v1/billing/seats",
      { method: "POST", body: JSON.stringify({ count, provider, reference }) },
    ),

  // Open the Stripe-hosted billing portal (update card, invoices, cancel).
  billingPortal: (return_path = "/billing") =>
    request<{ url: string }>("/api/v1/billing/portal", {
      method: "POST",
      body: JSON.stringify({ return_path }),
    }),

  confirmPayment: (body: {
    provider: string;
    reference: string;
    identifier: string;
  }) =>
    request<{
      gate_passed: boolean;
      trial_allowed: boolean;
      trial_started: boolean;
      trial_ends_at: string | null;
      eligibility: string;
      reason: string;
      instrument: { provider: string; brand: string | null; last4: string | null };
    }>("/api/v1/billing/confirm", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  // ── Live governing metrics (PRD §15.4) ──────────────────────────────────────
  qualityMetrics: () =>
    request<{ tenant_id: string; metrics: QualityMetric[] }>(
      "/api/v1/metrics/quality",
    ),

  runEscalations: () =>
    request<{ escalated: unknown[]; count: number }>(
      "/api/v1/escalations/run",
      { method: "POST" },
    ),

  health: () =>
    request<{ status: string; version: string; env: string }>("/health"),
};
