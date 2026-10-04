import { useState } from "react";
import { FlaskConical, Check, X, Lock, Loader2 } from "lucide-react";
import { api, ApiError, type SimulationResult } from "../lib/api";
import { Button } from "./primitives";

/** Run the product's own benign attack simulations against this workspace, on
 * the plan it actually has, and show what was caught.
 *
 * Every simulated message carries `X-Envelock-Simulation: true` and is analysed
 * in-process — nothing is sent to the mailbox and nothing is stored as an alert.
 * `plan_locked` means a bigger plan would have caught it; we say so rather than
 * showing a bare miss, which would read as a broken product.
 */
export default function SimulationPanel({ domain }: { domain: string }) {
  const [result, setResult] = useState<SimulationResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    if (busy || !domain) return;
    setBusy(true);
    setError(null);
    try {
      setResult(await api.simulate(domain));
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Couldn't run the simulation just now.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel p-5">
      <div className="flex items-start gap-3">
        <FlaskConical size={18} className="accent mt-0.5 shrink-0" aria-hidden />
        <div className="min-w-0 grow">
          <h2 className="text-base font-semibold">Test your protection</h2>
          <p className="fg-2 mt-1 text-sm leading-relaxed">
            Run a set of benign look-alike attacks — a supplier bank-detail
            switch, a look-alike domain, a phishing link, an identical-looking
            sender — against your own plan. Nothing is sent to your mailbox, and
            nothing is saved as an alert.
          </p>
        </div>
      </div>

      <div className="mt-4">
        <Button onClick={() => void run()} disabled={busy || !domain}>
          {busy ? (
            <Loader2 size={14} className="animate-spin" aria-hidden />
          ) : (
            <FlaskConical size={14} aria-hidden />
          )}
          {busy ? "RUNNING…" : "RUN SIMULATION"}
        </Button>
      </div>

      {error && (
        <p className="msg err mt-3 text-xs" role="alert">
          {error}
        </p>
      )}

      {result && (
        <div className="mt-4" role="status">
          <p className="text-sm font-semibold">
            {result.passed} of {result.total} attacks caught on your {result.plan ?? "current"}{" "}
            plan
            {result.plan_locked > 0 && (
              <span className="fg-3 font-normal">
                {" "}
                · {result.plan_locked} need a higher plan
              </span>
            )}
          </p>
          <ul className="mt-3 space-y-2" role="list">
            {result.runs.map((r) => (
              <li key={r.id} className="flex items-start gap-2 text-sm">
                {r.passed ? (
                  <Check size={16} className="mt-0.5 shrink-0 text-[var(--success)]" aria-hidden />
                ) : r.plan_locked ? (
                  <Lock size={16} className="fg-3 mt-0.5 shrink-0" aria-hidden />
                ) : (
                  <X size={16} className="mt-0.5 shrink-0 text-[var(--danger)]" aria-hidden />
                )}
                <span className="min-w-0">
                  <span className="font-medium">{r.name}</span>
                  <span className="fg-3 block text-xs">
                    {r.passed
                      ? "Caught"
                      : r.plan_locked
                        ? "Your plan doesn't include this detection — upgrade to catch it"
                        : "Not caught"}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
