import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { ApiError, api, type AuditRow } from "../lib/api";
import { Button, cn } from "../components/ui";

/* What operators have done. Separate from the customer-facing audit log so a
   customer never sees it and an operator cannot prune it from a tenant view. */
export default function Audit() {
  const [rows, setRows] = useState<AuditRow[]>([]);
  const [actor, setActor] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (who: string) => {
    setLoading(true);
    try {
      setRows((await api.staffAudit(who)).events);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the audit log.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: the loading flag flips before the first await. That is
    // the pattern the rule explicitly allows ("subscribe to an external
    // system"), not the derived-state cascade it targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load("");
  }, [load]);

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold">Operator audit trail</h1>
          <p className="fg-2 mt-1.5 max-w-2xl text-sm leading-relaxed">
            Every platform action, with who took it. Customer-impacting actions are
            also written to that customer's own audit log, so nothing we do to an
            account is invisible to them.
          </p>
        </div>
        <div className="flex gap-2">
          <input
            value={actor}
            onChange={(e) => setActor(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void load(actor)}
            placeholder="Filter by operator…"
            aria-label="Filter by operator"
            className="field h-9 w-56 text-sm"
          />
          <Button size="sm" onClick={() => void load(actor)} disabled={loading}>
            <RefreshCw size={13} className={cn(loading && "animate-spin")} aria-hidden />
            SEARCH
          </Button>
        </div>
      </div>

      {error && (
        <p role="alert" className="mt-4 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}

      <div className="panel mt-6 overflow-x-auto">
        <table className="dtable min-w-[48rem]">
          <thead>
            <tr>
              {["When", "Operator", "Action", "Target", "From"].map((h) => (
                <th key={h}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.id} className="border-b last:border-0 align-top">
                <td className="fg-2 mono px-4 py-3 text-xs whitespace-nowrap">
                  {row.at ? new Date(row.at).toLocaleString() : "—"}
                </td>
                <td className="px-4 py-3 text-xs">{row.actor}</td>
                <td className="mono px-4 py-3 text-xs">{row.action}</td>
                <td className="fg-2 px-4 py-3 text-xs break-all">
                  {row.target_type ? `${row.target_type} ${row.target_id ?? ""}` : "—"}
                  {Object.keys(row.detail).length > 0 && (
                    <div className="fg-3 mono mt-1 text-[10px] break-all">
                      {JSON.stringify(row.detail)}
                    </div>
                  )}
                </td>
                <td className="fg-3 mono px-4 py-3 text-xs">{row.ip ?? "—"}</td>
              </tr>
            ))}
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={5} className="fg-3 px-4 py-8 text-center text-sm">
                  Nothing recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
