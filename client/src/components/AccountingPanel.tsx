import { useCallback, useEffect, useRef, useState } from "react";
import { Link2, Loader2, RefreshCw } from "lucide-react";
import { ApiError, api, type AccountingConnectionInfo } from "../lib/api";
import { toast } from "../lib/toast";
import { Button } from "./primitives";
import ConfirmDialog from "./ConfirmDialog";

/* Xero / QuickBooks: the vendor master, live. Suppliers, the account they're
   paid into and the number to ring come straight from the books — and when a
   bank-change alert names a supplier, their unpaid bills get a warning note
   where the person paying will see it. */

function ago(iso: string | null) {
  if (!iso) return "not yet";
  const mins = Math.round((Date.now() - Date.parse(iso)) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  return hours < 48 ? `${hours} h ago` : new Date(iso).toLocaleDateString();
}

export default function AccountingPanel({ onSynced }: { onSynced: () => Promise<void> }) {
  const [state, setState] = useState<Awaited<ReturnType<typeof api.accounting>> | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [removing, setRemoving] = useState<AccountingConnectionInfo | null>(null);
  const wasSyncing = useRef(false);

  const load = useCallback(async () => {
    try {
      setState(await api.accounting());
    } catch {
      setState({ available: [], connections: [] });
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount; the setter runs after the await.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  // Back from the provider's consent screen (?accounting=connected|declined|failed).
  useEffect(() => {
    const url = new URL(window.location.href);
    const result = url.searchParams.get("accounting");
    if (!result) return;
    if (result === "connected") toast.success("Connected. Reading your suppliers now…");
    else if (result === "declined") toast.info("Connection cancelled — nothing was changed.");
    else toast.error("That connection didn't complete. Try again, or import a file instead.");
    url.searchParams.delete("accounting");
    window.history.replaceState(window.history.state, "", url.pathname + url.search + url.hash);
  }, []);

  // While the worker is reading the books, check back every few seconds.
  const syncing = state?.connections.some((c) => c.syncing) ?? false;
  useEffect(() => {
    if (!syncing) {
      if (wasSyncing.current) void onSynced();
      wasSyncing.current = false;
      return;
    }
    wasSyncing.current = true;
    const t = setTimeout(() => void load(), 3000);
    return () => clearTimeout(t);
  }, [syncing, state, load, onSynced]);

  if (!state || (state.available.length === 0 && state.connections.length === 0)) return null;

  async function act(key: string, fn: () => Promise<unknown>) {
    setBusy(key);
    try {
      await fn();
      await load();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "That didn't work. Try again.");
    } finally {
      setBusy(null);
    }
  }

  const connected = new Set(state.connections.map((c) => c.provider));
  const offer = state.available.filter((p) => !connected.has(p.provider));

  return (
    <section className="panel mt-8 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <Link2 size={16} className="accent" aria-hidden />
        <h2 className="text-sm font-semibold">Accounting system</h2>
      </div>

      {state.connections.map((c) => (
        <div key={c.provider} className="mt-4 border-t border-[var(--rule)] pt-4">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
            <span className="min-w-0 flex-1 text-sm">
              <span className="font-semibold">{c.label}</span>
              {c.org_name && <span className="fg-2"> · {c.org_name}</span>}
            </span>
            <Button
              size="sm"
              variant="line"
              disabled={busy !== null || c.syncing}
              onClick={() => act("sync-" + c.provider, () => api.syncAccounting(c.provider))}
            >
              {c.syncing ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : (
                <RefreshCw size={12} aria-hidden />
              )}
              {c.syncing ? "SYNCING" : "SYNC NOW"}
            </Button>
            <Button size="sm" variant="quiet" disabled={busy !== null} onClick={() => setRemoving(c)}>
              DISCONNECT
            </Button>
          </div>
          <p className="fg-3 mono-xs mt-2">
            LAST SYNCED {ago(c.last_sync_at).toUpperCase()}
            {c.summary &&
              ` · ${c.summary.suppliers_imported} SUPPLIERS · ${c.summary.bank_records_created} NEW ACCOUNTS`}
          </p>
          {c.summary && c.summary.skipped_no_domain > 0 && (
            <p className="fg-2 mt-1 text-xs leading-relaxed">
              {c.summary.skipped_no_domain} supplier
              {c.summary.skipped_no_domain === 1 ? " has" : "s have"} no business email or
              website in {c.label}, so Envelock can't match their mail — add one there and sync.
            </p>
          )}
          {c.last_error && (
            <p className="mt-2 text-xs text-[var(--danger)]" role="alert">
              Last sync failed: {c.last_error}. Reconnect if it keeps happening.
            </p>
          )}
          <label className="mt-3 flex cursor-pointer items-start gap-2 text-xs">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={c.flag_bills}
              disabled={busy !== null}
              onChange={(e) =>
                act("flag-" + c.provider, () =>
                  api.setAccountingFlagBills(c.provider, e.target.checked),
                )
              }
            />
            <span className="fg-2 leading-relaxed">
              When an email changes a supplier's bank details, add a warning note to
              their unpaid bills in {c.label}. Envelock never changes amounts, statuses
              or bank details.
            </span>
          </label>
        </div>
      ))}

      {offer.length > 0 && (
        <div className={state.connections.length ? "mt-4 border-t border-[var(--rule)] pt-4" : "mt-3"}>
          <p className="fg-2 text-xs leading-relaxed">
            Connect your books and Envelock reads your suppliers, the accounts they're paid
            into and their phone numbers, and keeps them in step. It never edits a supplier;
            it can add a warning note to a bill when bank details change (you choose).
          </p>
          <div className="mt-3 flex flex-wrap gap-2">
            {offer.map((p) => (
              <Button
                key={p.provider}
                size="sm"
                variant="accent"
                disabled={busy !== null}
                onClick={() =>
                  act("connect-" + p.provider, async () => {
                    const { url } = await api.connectAccounting(p.provider);
                    window.location.assign(url);
                  })
                }
              >
                {busy === "connect-" + p.provider && (
                  <Loader2 size={12} className="animate-spin" aria-hidden />
                )}
                CONNECT {p.label.toUpperCase()}
              </Button>
            ))}
          </div>
        </div>
      )}

      <ConfirmDialog
        open={removing !== null}
        title={`Disconnect ${removing?.label}?`}
        body="Envelock stops reading it and forgets its access. Suppliers already imported stay on this page."
        confirmLabel="DISCONNECT"
        onCancel={() => setRemoving(null)}
        onConfirm={async () => {
          const c = removing;
          setRemoving(null);
          if (c) await act("remove-" + c.provider, () => api.disconnectAccounting(c.provider));
        }}
      />
    </section>
  );
}
