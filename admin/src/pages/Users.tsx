import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Check, Search, UserCheck, UserX } from "lucide-react";
import { api, type UserRow, ApiError } from "../lib/api";
import { Badge, Button } from "../components/ui";
import { useCan } from "../lib/permissions";

const LIMIT = 100; // must match the server default (api/admin.users)

export default function UsersPage() {
  const [rows, setRows] = useState<UserRow[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  // Support holds user:manage; billing and compliance do not, and must not be
  // offered a button the server will refuse.
  const canManageUsers = useCan("user:manage");

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.users(query, offset);
      setRows(r.users);
      setTotal(r.total);
      setError(null);
    } catch (e) {
      // A 403/500 used to render "No users match" — an error dressed as an
      // empty platform.
      setError(e instanceof ApiError ? e.message : "Couldn't load users.");
    } finally {
      setLoading(false);
    }
  }, [query, offset]);

  useEffect(() => {
    const t = setTimeout(() => void fetchUsers(), 200);
    return () => clearTimeout(t);
  }, [fetchUsers]);

  async function act(key: string, fn: () => Promise<unknown>) {
    setBusy(key);
    setError(null);
    try {
      await fn();
      await fetchUsers();
    } catch (e) {
      // No catch here at all before — a 409 (e.g. "suspend the owner via the
      // tenant") just left the row unchanged with no explanation.
      setError(e instanceof ApiError ? e.message : "That action failed.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h1 className="text-2xl font-bold tracking-tight">Users</h1>
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
          placeholder="Search by email…"
          className="field pl-10"
        />
      </div>

      <div className="panel mt-4 divide-y">
        {loading && rows.length === 0 ? (
          <p className="fg-3 p-8 text-center text-sm">Loading…</p>
        ) : rows.length === 0 ? (
          <p className="fg-3 p-8 text-center text-sm">
            {error ? "" : "No users match."}
          </p>
        ) : (
          rows.map((u) => (
            <div key={u.id} className="flex flex-wrap items-center gap-3 px-4 py-3.5">
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{u.email}</p>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <Badge label={u.role} tone={u.role} />
                  <Badge label={u.status} tone={u.status} />
                  <Link
                    to={`/tenants/${u.tenant_id}`}
                    className="fg-3 mono text-[11px] hover:text-[var(--accent)]"
                  >
                    {u.tenant_name}
                  </Link>
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
              </div>
            </div>
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
