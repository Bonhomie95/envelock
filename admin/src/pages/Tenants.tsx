import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronRight, Search } from "lucide-react";
import { ApiError, api, type TenantRow } from "../lib/api";
import { Badge, Button } from "../components/ui";

const LIMIT = 100; // must match the server default (api/admin.tenants)

export default function Tenants() {
  const [rows, setRows] = useState<TenantRow[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    let live = true;
    // Fetch-on-mount: the loading flag flips before the first await. That is
    // the pattern the rule explicitly allows ("subscribe to an external
    // system"), not the derived-state cascade it targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setLoading(true);
    const t = setTimeout(() => {
      api
        .tenants(query, offset)
        .then((r) => {
          if (!live) return;
          setRows(r.tenants);
          setTotal(r.total);
          setError(null);
        })
        .catch((e) => {
          // Rendering "No tenants match" on a 403/500 showed an error as an
          // empty platform — the single most misleading thing this page could say.
          if (!live) return;
          setError(e instanceof ApiError ? e.message : "Couldn't load tenants.");
        })
        .finally(() => live && setLoading(false));
    }, 200);
    return () => {
      live = false;
      clearTimeout(t);
    };
  }, [query, offset]);

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-2xl font-bold tracking-tight">Tenants</h1>
        <span className="fg-3 mono text-xs">
          {total > rows.length
            ? `${offset + 1}–${offset + rows.length} of ${total}`
            : `${total} total`}
        </span>
      </div>

      {error && (
        <p role="alert" className="mt-4 rounded border border-red-500/30 bg-red-500/5 px-4 py-2 text-sm">
          {error}
        </p>
      )}

      <div className="relative mt-4">
        <Search size={15} className="fg-3 absolute top-1/2 left-3 -translate-y-1/2" aria-hidden />
        <input
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            // A new search starts from the first page.
            setOffset(0);
          }}
          placeholder="Search by name or domain…"
          className="field pl-10"
        />
      </div>

      <div className="panel mt-4 divide-y">
        {loading && rows.length === 0 ? (
          <p className="fg-3 p-8 text-center text-sm">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="fg-3 p-8 text-center text-sm">
            {error ? "" : "No tenants match."}
          </p>
        ) : (
          rows.map((t) => (
            <Link
              key={t.id}
              to={`/tenants/${t.id}`}
              className="flex items-center gap-3 px-4 py-3.5 transition-colors hover:bg-[var(--bg-hover)]"
            >
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="truncate text-sm font-semibold">
                    {t.primary_domain ?? t.name}
                  </span>
                  <Badge label={t.effective_plan} tone={t.effective_plan} />
                  {t.trial_active && (
                    <Badge label={`TRIAL ${t.trial_days_left}d`} tone="pending" />
                  )}
                  {!t.is_active && <Badge label="SUSPENDED" tone="suspended" />}
                </div>
                <div className="fg-3 mono mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-[11px]">
                  <span className="tnum">{t.users} users</span>
                  <span className="tnum">{t.mailboxes} mailboxes</span>
                  <span className={t.open_alerts > 0 ? "text-[var(--warn)] tnum" : "tnum"}>
                    {t.open_alerts} open alerts
                  </span>
                  {t.payment_method_ok && <span className="text-[var(--ok)]">card on file</span>}
                </div>
              </div>
              <ChevronRight size={16} className="fg-3 shrink-0" aria-hidden />
            </Link>
          ))
        )}
      </div>

      {total > rows.length + offset || offset > 0 ? (
        <div className="mt-4 flex items-center justify-between gap-3">
          <Button
            variant="quiet"
            disabled={offset === 0 || loading}
            onClick={() => setOffset(Math.max(0, offset - LIMIT))}
          >
            Previous
          </Button>
          <span className="fg-3 mono text-xs">
            page {Math.floor(offset / LIMIT) + 1} of {Math.max(1, Math.ceil(total / LIMIT))}
          </span>
          <Button
            variant="quiet"
            disabled={offset + rows.length >= total || loading}
            onClick={() => setOffset(offset + LIMIT)}
          >
            Next
          </Button>
        </div>
      ) : null}
    </div>
  );
}
