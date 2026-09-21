import { useCallback, useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, RefreshCw, ShieldAlert, XCircle } from "lucide-react";
import { ApiError, api, type SecurityCheck, type SecurityPosture } from "../lib/api";
import { Button, cn } from "../components/ui";

/* Is this deployment actually secure?
 *
 * Every row is read from the running system, not from a document, and every
 * failing row carries the specific thing to do about it. Failures sort first
 * because this page gets read top-down during an incident. */

/* State is carried by an icon AND a word AND a colour — never colour alone, or
   the eight per cent of men with a red/green deficiency read a healthy row and
   a failing one identically. */
const STATE_META = {
  fail: {
    icon: XCircle,
    tone: "text-[var(--danger)]",
    border: "border-[var(--danger)]",
    label: "FAIL",
  },
  warn: {
    icon: AlertTriangle,
    tone: "text-[var(--warn)]",
    border: "border-[var(--warn)]",
    label: "WARN",
  },
  pass: {
    icon: CheckCircle2,
    tone: "text-[var(--ok)]",
    border: "border-[var(--rule-strong)]",
    label: "PASS",
  },
} as const;

/* One check, as a table row.
 *
 * A table rather than a stack of cards because the operator reads this page
 * top-down looking for the rows that are wrong, and aligned columns let the eye
 * run down STATE without reading anything else. The remedy hangs off its own
 * left rule so "what do I do" is scannable in the same way. */
function CheckRow({ check }: { check: SecurityCheck }) {
  const meta = STATE_META[check.state];
  const Icon = meta.icon;
  return (
    <tr>
      <td className="whitespace-nowrap">
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
      <td className="fg-3 mono text-[10px] whitespace-nowrap uppercase">
        {check.severity}
      </td>
      <td>
        <h3 className="text-[13px] font-semibold">{check.title}</h3>
        <p className="fg-2 mt-1 text-xs leading-relaxed">{check.detail}</p>
      </td>
      <td className="w-[34%]">
        {check.remedy ? (
          <p className="remedy is-actionable">{check.remedy}</p>
        ) : (
          <p className="remedy">No action required.</p>
        )}
      </td>
    </tr>
  );
}

export default function Security() {
  const [posture, setPosture] = useState<SecurityPosture | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setPosture(await api.security());
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the posture.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: the loading flag flips before the first await. That is
    // the pattern the rule explicitly allows ("subscribe to an external
    // system"), not the derived-state cascade it targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const summary = posture?.summary;
  const headline =
    summary?.state === "action_required"
      ? "Action required"
      : summary?.state === "attention"
        ? "Needs attention"
        : "Healthy";

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold">Security posture</h1>
          <p className="fg-2 mt-1.5 max-w-2xl text-sm leading-relaxed">
            Read live from this deployment — configuration, key custody and the
            data itself. A security product has to be able to answer this about
            itself, and not from a document.
          </p>
        </div>
        <Button size="sm" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={13} className={cn(loading && "animate-spin")} aria-hidden />
          RECHECK
        </Button>
      </div>

      {error && (
        <p role="alert" className="mt-4 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}

      {summary && (
        <div className="statstrip mt-6 grid-cols-2 lg:grid-cols-4">
          <div className="stat-cell flex items-center gap-3">
            <ShieldAlert
              size={22}
              className={cn(
                "shrink-0",
                summary.state === "healthy"
                  ? "text-[var(--ok)]"
                  : summary.state === "attention"
                    ? "text-[var(--warn)]"
                    : "text-[var(--danger)]",
              )}
              aria-hidden
            />
            <div className="min-w-0">
              <div className="text-base font-bold">{headline}</div>
              <div className="fg-3 mono truncate text-[10px]">
                CHECKED {new Date(posture!.generated_at).toLocaleString()}
              </div>
            </div>
          </div>
          <div className="stat-cell">
            <div className="sect-label">Failing</div>
            <div
              className={cn(
                "stat-figure mt-2",
                summary.failing > 0 ? "is-hot" : "is-quiet",
              )}
            >
              {summary.failing}
            </div>
          </div>
          <div className="stat-cell">
            <div className="sect-label">Warning</div>
            <div
              className={cn(
                "stat-figure mt-2",
                summary.warning > 0 ? "is-warn" : "is-quiet",
              )}
            >
              {summary.warning}
            </div>
          </div>
          <div className="stat-cell">
            <div className="sect-label">Passing</div>
            <div className="stat-figure is-good mt-2">{summary.passing}</div>
          </div>
        </div>
      )}

      {loading && !posture ? (
        <p className="fg-3 mono mt-8 text-sm">Checking…</p>
      ) : (
        <div className="panel mt-4 overflow-x-auto">
          <table className="dtable min-w-[56rem]">
            <thead>
              <tr>
                <th>State</th>
                <th>Severity</th>
                <th>Check</th>
                <th>Remedy</th>
              </tr>
            </thead>
            <tbody>
              {posture?.checks.map((c) => (
                <CheckRow key={c.id} check={c} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
