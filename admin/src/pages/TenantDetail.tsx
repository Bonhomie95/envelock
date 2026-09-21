import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, Check, Loader2, Power, UserCheck, UserX } from "lucide-react";
import { api, type TenantDetailFull } from "../lib/api";
import { useCan } from "../lib/permissions";
import { Badge, Button, cn } from "../components/ui";

// Must match the server's accepted set (api/admin._PLANS). "solo" was missing,
// so a tenant on it rendered with no plan highlighted and no way back to it.
const PLANS = ["guard", "solo", "essential", "complete"];
const ROLES = ["member", "admin", "owner"];

export default function TenantDetail() {
  const { id = "" } = useParams();
  const [t, setT] = useState<TenantDetailFull | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  // Controls the operator cannot use are not rendered. The server refuses them
  // regardless; showing a button that always 403s is just a worse error message.
  const canBill = useCan("tenant:billing");
  const canSuspendTenant = useCan("tenant:suspend");
  const canManageUsers = useCan("user:manage");
  const canSetRole = useCan("user:role");

  const load = useCallback(async () => {
    try {
      setT(await api.tenant(id));
    } catch {
      setError("Could not load this tenant.");
    }
  }, [id]);

  useEffect(() => {
    // Fetch-on-mount: the loading flag flips before the first await. That is
    // the pattern the rule explicitly allows ("subscribe to an external
    // system"), not the derived-state cascade it targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  async function act(key: string, fn: () => Promise<unknown>) {
    setBusy(key);
    setError(null);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed.");
    } finally {
      setBusy(null);
    }
  }

  if (error && !t) return <p className="shell py-10 text-sm text-[var(--danger)]">{error}</p>;
  if (!t) return <p className="shell fg-3 py-10 text-sm">Loading…</p>;

  return (
    <div className="shell py-8">
      <Link to="/tenants" className="fg-3 mono inline-flex items-center gap-1.5 text-xs hover:text-[var(--fg)]">
        <ArrowLeft size={12} aria-hidden /> ALL TENANTS
      </Link>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-bold tracking-tight">{t.name}</h1>
        <Badge label={t.effective_plan} tone={t.effective_plan} />
        {t.trial_active && <Badge label={`TRIAL · ${t.trial_days_left}d`} tone="pending" />}
        {!t.is_active && <Badge label="SUSPENDED" tone="suspended" />}
      </div>
      <p className="fg-3 mono mt-1 text-xs">
        {t.domains.map((d) => d.registrable_domain).join(", ") || "no domain"}
        {t.has_billing_account && " · Stripe customer"}
      </p>

      {error && <p className="mt-3 text-sm text-[var(--danger)]">{error}</p>}

      {/* Billing & lifecycle actions */}
      {(canBill || canSuspendTenant) && (
      <div className="panel mt-6 p-5">
        <h2 className="sect-label">Plan &amp; billing</h2>
        {canBill && (
        <>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {PLANS.map((p) => (
            <button
              key={p}
              onClick={() => act(`plan-${p}`, () => api.setPlan(t.id, p))}
              disabled={busy !== null}
              className={cn(
               "mono cursor-pointer border px-3 py-1.5 text-[11px] tracking-wide uppercase transition-colors",
                t.subscribed_plan === p
                  ? "accent border-[var(--accent)]"
                  : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
              )}
            >
              {busy === `plan-${p}` ? "…" : p}
            </button>
          ))}
          <span className="fg-3 mono ml-2 text-[11px]">subscribed: {t.subscribed_plan}</span>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-2 border-t pt-4">
          <span className="fg-2 text-xs">Extend trial:</span>
          {[7, 14, 30].map((d) => (
            <Button
              key={d}
              size="sm"
              variant="line"
              disabled={busy !== null}
              onClick={() => act(`ext-${d}`, () => api.extendTrial(t.id, d))}
            >
              {busy === `ext-${d}` ? <Loader2 size={12} className="animate-spin" aria-hidden /> : null}
              +{d}d
            </Button>
          ))}
          <span className="fg-3 mono ml-auto text-[11px]">
            {t.trial_active
              ? `${t.trial_days_left} days left`
              : t.payment_method_ok
                ? "paid"
                : "trial ended"}
          </span>
        </div>
        </>
        )}

        {canSuspendTenant && (
        <div className="mt-4 border-t pt-4">
          {t.is_active ? (
            <Button
              size="sm"
              variant="danger"
              disabled={busy !== null}
              onClick={() => act("suspend-t", () => api.suspendTenant(t.id))}
            >
              <Power size={12} aria-hidden /> SUSPEND TENANT
            </Button>
          ) : (
            <Button
              size="sm"
              variant="accent"
              disabled={busy !== null}
              onClick={() => act("activate-t", () => api.activateTenant(t.id))}
            >
              <Power size={12} aria-hidden /> REACTIVATE TENANT
            </Button>
          )}
        </div>
        )}
      </div>
      )}

      {/* Users */}
      <div className="panel mt-6">
        <h2 className="sect-label border-b px-5 py-3.5">Users ({t.users.length})</h2>
        <ul className="divide-y" role="list">
          {t.users.map((u) => (
            <li key={u.id} className="flex flex-wrap items-center gap-3 px-5 py-3.5">
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{u.email}</p>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <Badge label={u.role} tone={u.role} />
                  <Badge label={u.status} tone={u.status} />
                  {!u.mfa_enabled && <span className="fg-3 mono text-[10px]">no 2FA</span>}
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-1.5">
                {canManageUsers && u.status === "pending" && (
                  <Button
                    size="sm"
                    variant="accent"
                    disabled={busy !== null}
                    onClick={() => act(`ap-${u.id}`, () => api.approveUser(u.id))}
                  >
                    <UserCheck size={12} aria-hidden /> APPROVE
                  </Button>
                )}
                {canManageUsers && u.status === "active" && u.role !== "owner" && (
                  <Button
                    size="sm"
                    variant="line"
                    disabled={busy !== null}
                    onClick={() => act(`su-${u.id}`, () => api.suspendUser(u.id))}
                  >
                    <UserX size={12} aria-hidden /> SUSPEND
                  </Button>
                )}
                {canManageUsers && u.status === "suspended" && (
                  <Button
                    size="sm"
                    variant="line"
                    disabled={busy !== null}
                    onClick={() => act(`re-${u.id}`, () => api.activateUser(u.id))}
                  >
                    <Check size={12} aria-hidden /> REACTIVATE
                  </Button>
                )}
                {canSetRole && (
                  <select
                    value={u.role}
                    disabled={busy !== null}
                    onChange={(e) => act(`role-${u.id}`, () => api.setRole(u.id, e.target.value))}
                    aria-label={`Role for ${u.email}`}
                    className="mono cursor-pointer border bg-[var(--bg)] px-2 py-1.5 text-[11px] uppercase"
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </li>
          ))}
        </ul>
      </div>

      {/* Mailboxes + domains */}
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <div className="panel">
          <h2 className="sect-label border-b px-5 py-3.5">Mailboxes ({t.mailboxes.length})</h2>
          {t.mailboxes.length === 0 ? (
            <p className="fg-3 p-5 text-xs">None connected.</p>
          ) : (
            <ul className="divide-y" role="list">
              {t.mailboxes.map((m) => (
                <li key={m.id} className="flex items-center gap-3 px-5 py-3">
                  <span className="min-w-0 flex-1 truncate text-sm">{m.address}</span>
                  <Badge label={m.protection_level} />
                  <span className="fg-3 mono text-[10px] uppercase">{m.mailbox_class}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="panel">
          <h2 className="sect-label border-b px-5 py-3.5">Domains ({t.domains.length})</h2>
          {t.domains.length === 0 ? (
            <p className="fg-3 p-5 text-xs">None.</p>
          ) : (
            <ul className="divide-y" role="list">
              {t.domains.map((d) => (
                <li key={d.registrable_domain} className="flex items-center gap-3 px-5 py-3">
                  <span className="mono min-w-0 flex-1 truncate text-sm">{d.registrable_domain}</span>
                  {d.verified && <Badge label="verified" tone="active" />}
                  {d.dmarc_policy && (
                    <span className="fg-3 mono text-[10px] uppercase">p={d.dmarc_policy}</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Recent alerts */}
      <div className="panel mt-6">
        <h2 className="sect-label border-b px-5 py-3.5">Recent alerts</h2>
        {t.recent_alerts.length === 0 ? (
          <p className="fg-3 p-5 text-xs">No alerts — quiet is the correct state.</p>
        ) : (
          <ul className="divide-y" role="list">
            {t.recent_alerts.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-5 py-3">
                <Badge label={a.tier} tone={a.tier} />
                <span className="min-w-0 flex-1 truncate text-sm">{a.title}</span>
                <span className="fg-3 mono text-[10px] uppercase">{a.state}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
