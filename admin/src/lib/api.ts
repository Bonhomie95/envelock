const TOKEN_KEY = "envelock.admin_token";
const REFRESH_KEY = "envelock.admin_refresh";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
  get unauthorized() {
    return this.status === 401;
  }
  get notAdmin() {
    // The console gate returns 404 to a valid session that isn't a super-admin.
    return this.status === 404;
  }
}

export const auth = {
  get token() {
    return localStorage.getItem(TOKEN_KEY);
  },
  get refreshToken() {
    return localStorage.getItem(REFRESH_KEY);
  },
  set(token: string, refresh?: string | null) {
    localStorage.setItem(TOKEN_KEY, token);
    if (refresh) localStorage.setItem(REFRESH_KEY, refresh);
  },
  clear() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(REFRESH_KEY);
  },
  get signedIn() {
    return Boolean(localStorage.getItem(TOKEN_KEY));
  },
};

// Keep a long-lived operator session alive past the 15-minute access-token TTL by
// exchanging the refresh token on a 401, then replaying the request once.
let refreshInFlight: Promise<boolean> | null = null;
async function tryRefresh(): Promise<boolean> {
  const rt = auth.refreshToken;
  if (!rt) return false;
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const res = await fetch("/api/v1/admin/auth/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token: rt }),
        });
        if (!res.ok) {
          auth.clear();
          return false;
        }
        const b = (await res.json()) as { access_token: string; refresh_token?: string };
        auth.set(b.access_token, b.refresh_token);
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

async function request<T>(
  path: string,
  init: RequestInit = {},
  retried = false,
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  const token = auth.token;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(path, { ...init, headers });
  if (
    res.status === 401 &&
    !retried &&
    auth.refreshToken &&
    !path.includes("/auth/login") &&
    !path.includes("/auth/refresh") &&
    !path.includes("/auth/mfa") &&
    !path.includes("/auth/password")
  ) {
    if (await tryRefresh()) return request<T>(path, init, true);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = (body.detail as string) ?? detail;
    } catch {
      /* keep statusText */
    }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

// ── Types ────────────────────────────────────────────────────────────────────
/** Who the console is talking to and exactly what they may do. The client hides
 *  what it must not offer; the server still enforces every check. */
export interface Me {
  id: string;
  email: string;
  name: string | null;
  department: string;
  permissions: string[];
  break_glass: boolean;
}

export interface DepartmentInfo {
  id: string;
  name: string;
  description: string;
  permissions: string[];
}

export interface StaffRow {
  id: string;
  email: string;
  name: string | null;
  department: string;
  status: string;
  permissions: string[];
  granted_permissions: string[];
  revoked_permissions: string[];
  mfa_enabled: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  created_by: string | null;
  created_at: string | null;
}

export interface AuditRow {
  id: string;
  at: string | null;
  actor: string;
  action: string;
  target_type: string | null;
  target_id: string | null;
  tenant_id: string | null;
  ip: string | null;
  detail: Record<string, unknown>;
}

export interface SecurityCheck {
  id: string;
  title: string;
  state: "pass" | "warn" | "fail";
  detail: string;
  remedy: string;
  severity: "critical" | "high" | "medium" | "low";
}

export interface SecurityPosture {
  generated_at: string;
  summary: {
    total: number;
    passing: number;
    warning: number;
    failing: number;
    state: "healthy" | "attention" | "action_required";
  };
  checks: SecurityCheck[];
}

export interface SystemCheck {
  component: string;
  state: "up" | "degraded" | "down";
  critical: boolean;
  detail: string;
}

export interface SystemStatus {
  overall: "operational" | "degraded" | "down";
  checked_at: string;
  env: string;
  version: string;
  checks: SystemCheck[];
}

export interface Overview {
  tenants: number;
  users: number;
  pending_users: number;
  mailboxes: number;
  open_alerts: number;
  critical_open: number;
  paying_tenants: number;
  active_trials: number;
  plan_distribution: Record<string, number>;
  generated_at: string;
}

export interface TenantRow {
  id: string;
  name: string;
  primary_domain: string | null;
  is_active: boolean;
  users: number;
  mailboxes: number;
  open_alerts: number;
  created_at: string | null;
  subscribed_plan: string;
  effective_plan: string;
  trial_active: boolean;
  trial_days_left: number;
  trial_ends_at: string | null;
  payment_method_ok: boolean;
  has_billing_account: boolean;
}

export interface UserRow {
  id: string;
  email: string;
  role: string;
  status: string;
  mfa_enabled: boolean;
  tenant_id: string;
  tenant_name: string;
  created_at: string | null;
}

export interface TenantDetailFull {
  id: string;
  name: string;
  is_active: boolean;
  created_at: string | null;
  subscribed_plan: string;
  effective_plan: string;
  trial_active: boolean;
  trial_days_left: number;
  trial_ends_at: string | null;
  payment_method_ok: boolean;
  has_billing_account: boolean;
  users: {
    id: string;
    email: string;
    role: string;
    status: string;
    mfa_enabled: boolean;
    created_at: string | null;
  }[];
  mailboxes: {
    id: string;
    address: string;
    mailbox_class: string;
    protection_level: string;
    sources: string[];
  }[];
  domains: {
    registrable_domain: string;
    verified: boolean;
    dmarc_policy: string | null;
    is_defensive: boolean;
  }[];
  recent_alerts: {
    id: string;
    tier: string;
    title: string;
    state: string;
    created_at: string | null;
  }[];
}

// ── API ──────────────────────────────────────────────────────────────────────
export const api = {
  // Operator sign-in, against `staff_accounts` — NOT the customer login. A
  // customer token opens nothing here, and vice versa.
  login: (email: string, password: string) =>
    request<{
      mfa_token: string;
      mfa_setup_required: boolean;
      must_change_password: boolean;
    }>("/api/v1/admin/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  // Enrolment is required, not offered: there is no skip for an operator.
  mfaSetup: (mfaToken: string) =>
    request<{ secret: string; otpauth_uri: string }>("/api/v1/admin/auth/mfa/setup", {
      method: "POST",
      body: JSON.stringify({ token: mfaToken }),
    }),
  mfaVerify: (mfaToken: string, code: string) =>
    request<{
      access_token: string;
      refresh_token?: string;
      must_change_password: boolean;
      recovery_codes?: string[];
    }>("/api/v1/admin/auth/mfa/verify", {
      method: "POST",
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    }),
  setOwnPassword: (currentPassword: string, newPassword: string) =>
    request<{ status: string }>("/api/v1/admin/auth/password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword,
      }),
    }),
  logout: () => request<unknown>("/api/v1/admin/auth/logout", { method: "POST" }),

  whoami: () => request<Me>("/api/v1/admin/whoami"),
  overview: () => request<Overview>("/api/v1/admin/overview"),

  // ── Staff ────────────────────────────────────────────────────────────────
  staffRoles: () =>
    request<{
      departments: DepartmentInfo[];
      permissions: { id: string; label: string }[];
      your_permissions: string[];
    }>("/api/v1/admin/staff/roles"),
  staff: () =>
    request<{ staff: StaffRow[]; break_glass_emails: string[]; you: Me }>(
      "/api/v1/admin/staff",
    ),
  createStaff: (body: {
    email: string;
    name?: string;
    department: string;
    granted_permissions?: string[];
    revoked_permissions?: string[];
  }) =>
    request<StaffRow & { temporary_password: string; next: string }>(
      "/api/v1/admin/staff",
      { method: "POST", body: JSON.stringify(body) },
    ),
  updateStaff: (
    id: string,
    body: {
      name?: string;
      department?: string;
      granted_permissions?: string[];
      revoked_permissions?: string[];
    },
  ) =>
    request<StaffRow>(`/api/v1/admin/staff/${id}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  suspendStaff: (id: string) =>
    request<StaffRow>(`/api/v1/admin/staff/${id}/suspend`, { method: "POST" }),
  reinstateStaff: (id: string) =>
    request<StaffRow>(`/api/v1/admin/staff/${id}/reinstate`, { method: "POST" }),
  resetStaffPassword: (id: string) =>
    request<StaffRow & { temporary_password: string; next: string }>(
      `/api/v1/admin/staff/${id}/reset-password`,
      { method: "POST" },
    ),
  staffAudit: (actor = "") =>
    request<{ events: AuditRow[] }>(
      `/api/v1/admin/staff/audit?actor=${encodeURIComponent(actor)}`,
    ),

  // ── Security posture ─────────────────────────────────────────────────────
  security: () => request<SecurityPosture>("/api/v1/admin/security"),

  // ── System status (live health of every worker/dependency) ───────────────
  systemStatus: () => request<SystemStatus>("/api/v1/admin/status/system"),

  tenants: (query = "", offset = 0) =>
    request<{ total: number; limit: number; offset: number; tenants: TenantRow[] }>(
      `/api/v1/admin/tenants?query=${encodeURIComponent(query)}&offset=${offset}`,
    ),
  tenant: (id: string) => request<TenantDetailFull>(`/api/v1/admin/tenants/${id}`),

  users: (query = "", offset = 0) =>
    request<{ total: number; limit: number; offset: number; users: UserRow[] }>(
      `/api/v1/admin/users?query=${encodeURIComponent(query)}&offset=${offset}`,
    ),

  setPlan: (tenantId: string, plan: string) =>
    request<unknown>(`/api/v1/admin/tenants/${tenantId}/plan`, {
      method: "POST",
      body: JSON.stringify({ plan }),
    }),
  extendTrial: (tenantId: string, days: number) =>
    request<unknown>(`/api/v1/admin/tenants/${tenantId}/extend-trial`, {
      method: "POST",
      body: JSON.stringify({ days }),
    }),
  suspendTenant: (tenantId: string) =>
    request<unknown>(`/api/v1/admin/tenants/${tenantId}/suspend`, { method: "POST" }),
  activateTenant: (tenantId: string) =>
    request<unknown>(`/api/v1/admin/tenants/${tenantId}/activate`, { method: "POST" }),

  approveUser: (userId: string) =>
    request<unknown>(`/api/v1/admin/users/${userId}/approve`, { method: "POST" }),
  suspendUser: (userId: string) =>
    request<unknown>(`/api/v1/admin/users/${userId}/suspend`, { method: "POST" }),
  activateUser: (userId: string) =>
    request<unknown>(`/api/v1/admin/users/${userId}/activate`, { method: "POST" }),
  setRole: (userId: string, role: string) =>
    request<unknown>(`/api/v1/admin/users/${userId}/role`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
};
