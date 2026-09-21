import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  RefreshCw,
  XCircle,
} from "lucide-react";
import { ApiError, api, type SystemCheck, type SystemStatus } from "../lib/api";
import { Button, cn } from "../components/ui";

/* Live health of every moving part — the page you watch during launch.
 *
 * Every row is read from the running system; each check is bounded server-side
 * so a down dependency can't hang this page. State is icon + word + colour,
 * never colour alone. */
const STATE_META = {
  down: { icon: XCircle, tone: "text-[var(--danger)]", border: "border-[var(--danger)]", label: "DOWN" },
  degraded: { icon: AlertTriangle, tone: "text-[var(--warn)]", border: "border-[var(--warn)]", label: "DEGRADED" },
  up: { icon: CheckCircle2, tone: "text-[var(--ok)]", border: "border-[var(--rule-strong)]", label: "UP" },
} as const;

const OVERALL_META = {
  down: { tone: "text-[var(--danger)]", label: "SYSTEM DOWN" },
  degraded: { tone: "text-[var(--warn)]", label: "DEGRADED" },
  operational: { tone: "text-[var(--ok)]", label: "ALL SYSTEMS OPERATIONAL" },
} as const;

const LABELS: Record<string, string> = {
  database: "Database (Postgres)",
  redis: "Cache / rate limiter (Redis)",
  imap_poll_worker: "IMAP poll worker",
  scheduler: "Background scheduler",
  outbound_email: "Outbound email",
  ai_cascade: "AI fraud cascade",
  credential_custody: "Credential key custody",
  oauth_providers: "OAuth providers",
};

function Row({ check }: { check: SystemCheck }) {
  const meta = STATE_META[check.state];
  const Icon = meta.icon;
  return (
    <tr>
      <td className="whitespace-nowrap py-2 pr-4">
        <span
          className={cn(
            "mono inline-flex items-center gap-1.5 border px-2 py-1 text-[10px] font-semibold tracking-wide uppercase",
            meta.tone,
            meta.border,
          )}
        >
          <Icon size={12} aria-hidden />
          {meta.label}
        </span>
      </td>
      <td className="py-2 pr-4 text-sm font-medium">
        {LABELS[check.component] ?? check.component}
        {check.critical && <span className="fg-3 ml-2 text-[10px] uppercase">critical</span>}
      </td>
      <td className="fg-2 py-2 text-sm">{check.detail}</td>
    </tr>
  );
}

export default function Status() {
  const [data, setData] = useState<SystemStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // State is only set in the promise callbacks, never synchronously, so the
  // effect below can call this on mount without a cascading render.
  const load = useCallback(
    () =>
      api
        .systemStatus()
        .then((status) => {
          setData(status);
          setError(null);
        })
        .catch((e) => {
          setError(e instanceof ApiError ? e.message : "Couldn't load system status.");
        })
        .finally(() => setLoading(false)),
    [],
  );

  useEffect(() => {
    void load();
    // Auto-refresh: this is a page you leave open during launch.
    const t = setInterval(() => void load(), 15_000);
    return () => clearInterval(t);
  }, [load]);

  const overall = data ? OVERALL_META[data.overall] : null;

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-bold tracking-tight">System status</h1>
        <Button variant="quiet" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          Refresh
        </Button>
      </div>

      {error && (
        <p role="alert" className="mt-4 rounded border border-red-500/30 bg-red-500/5 px-4 py-2 text-sm">
          {error}
        </p>
      )}

      {loading && !data ? (
        <p className="fg-3 mt-8 text-sm">Loading…</p>
      ) : data ? (
        <>
          <div className="panel mt-4 flex flex-wrap items-baseline justify-between gap-3 p-5">
            <span className={cn("text-lg font-bold tracking-tight", overall?.tone)}>
              {overall?.label}
            </span>
            <span className="fg-3 mono text-xs">
              {data.env} · {data.version} · checked{" "}
              {new Date(data.checked_at).toLocaleTimeString()}
            </span>
          </div>

          <div className="panel mt-4 overflow-x-auto p-2">
            <table className="w-full border-collapse">
              <tbody className="divide-y divide-[var(--rule)]">
                {data.checks.map((c) => (
                  <Row key={c.component} check={c} />
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
    </div>
  );
}
