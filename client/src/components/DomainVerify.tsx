import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../lib/api";
import { Button } from "./primitives";

/**
 * Domain-control verification (PRD signup funnel). Shows the DNS record the
 * customer must add and a "Verify" button. Until the domain is verified, no
 * mailbox on it can be connected for live mail — this is what stops someone
 * signing up with a company address they don't control.
 *
 * It also polls in the background every 10s, so the moment the customer saves
 * the record at their registrar we catch it and advance — no need to sit and
 * click Verify. `onBack` (when provided) renders an escape hatch, used by the
 * onboarding gate to let a user step back out to sign-in.
 */
function CopyValue({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      aria-label={`Copy ${label}`}
      className="cursor-pointer rounded border border-current/20 px-1.5 py-0.5 text-[10px] tracking-wide uppercase opacity-80 hover:opacity-100"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

export function DomainVerify({
  domain,
  onVerified,
  onBack,
}: {
  domain: string;
  onVerified?: () => void;
  onBack?: () => void;
}) {
  const [record, setRecord] = useState<{
    txt: { host: string; type: string; value: string };
    cname: { host: string; type: string; value: string };
    verified: boolean;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [method, setMethod] = useState<"txt" | "cname">("txt");
  // Guards the background poll from racing a manual verify or firing after we've
  // already succeeded.
  const verifiedRef = useRef(false);

  const [loadFailed, setLoadFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.domainVerification(domain);
      setRecord(r);
      setLoadFailed(false);
      if (r.verified) verifiedRef.current = true;
    } catch {
      // Swallowing this used to render NOTHING below the "verify your domain"
      // heading — an API blip became a dead end with no controls at all.
      setLoadFailed(true);
    }
  }, [domain]);

  useEffect(() => {
    // Fetch-on-mount: load() sets state after its first await, the intended
    // pattern here, not the cascading-render case the rule targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  // `silent` is the background poll: it never shows a spinner or an error, it
  // just advances if the record has propagated. The manual Verify press is loud.
  const verify = useCallback(
    async (silent: boolean) => {
      if (verifiedRef.current) return;
      if (!silent) {
        setBusy(true);
        setError(null);
      }
      try {
        const r = await api.verifyDomain(domain);
        if (r.verified) {
          verifiedRef.current = true;
          setRecord((prev) => (prev ? { ...prev, verified: true } : prev));
          onVerified?.();
        } else if (!silent) {
          setError(
            "DNS record not found yet — it can take a few minutes to propagate. " +
              "We'll keep checking automatically.",
          );
        }
      } catch (e) {
        if (!silent)
          setError(
            e instanceof Error
              ? e.message
              : "DNS record not found yet — it can take a few minutes to propagate.",
          );
      } finally {
        if (!silent) setBusy(false);
      }
    },
    [domain, onVerified],
  );

  /* A bare "re-checks every 10s" gives no sign the page is alive — people press
     Verify repeatedly because nothing appears to be happening. A visible
     countdown that turns into "Checking DNS…" and restarts on a miss shows the
     work, so waiting feels like progress rather than a hang. */
  const POLL_SECONDS = 10;
  const [countdown, setCountdown] = useState(POLL_SECONDS);
  const [autoChecking, setAutoChecking] = useState(false);

  useEffect(() => {
    if (!record || record.verified) return;
    const id = setInterval(() => {
      setCountdown((n) => {
        if (n > 1) return n - 1;
        // Hit zero: run the silent check, then start the countdown again.
        setAutoChecking(true);
        void verify(true).finally(() => setAutoChecking(false));
        return POLL_SECONDS;
      });
    }, 1000);
    return () => clearInterval(id);
  }, [record, verify]);

  if (!record) {
    if (!loadFailed) return null; // first load still in flight
    return (
      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
        <p className="font-semibold">Couldn't load the verification record.</p>
        <p className="fg-2 mt-1 text-xs">
          This is usually temporary. Your domain and data are unaffected.
        </p>
        <Button size="sm" className="mt-3" onClick={() => void load()}>
          Try again
        </Button>
      </div>
    );
  }
  if (record.verified) {
    return (
      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3 text-sm">
        <span className="font-semibold text-emerald-500">✓ {domain} verified</span> — you
        control this domain, so mailboxes on it can be connected.
      </div>
    );
  }

  const chosen = method === "txt" ? record.txt : record.cname;

  return (
    <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
      <p className="font-semibold text-amber-600 dark:text-amber-400">
        Verify control of {domain}
      </p>
      {/* "Add this DNS record" next to a TXT/CNAME switch read as "add both" —
          people were creating two records and waiting for the second to matter. */}
      <p className="mt-1 opacity-80">
        Add <strong>one</strong> of these records at your registrar — TXT{" "}
        <em>or</em> CNAME, whichever your registrar makes easier. You do not need
        both. We check automatically.
      </p>

      <div className="mt-3 flex items-center gap-2 text-xs">
        <span className="opacity-60">Choose one:</span>
        <button
          type="button"
          aria-pressed={method === "txt"}
          onClick={() => setMethod("txt")}
          className={`rounded px-2 py-1 ${method === "txt" ? "bg-amber-500/20 font-semibold" : "opacity-60"}`}
        >
          TXT
        </button>
        <button
          type="button"
          aria-pressed={method === "cname"}
          onClick={() => setMethod("cname")}
          className={`rounded px-2 py-1 ${method === "cname" ? "bg-amber-500/20 font-semibold" : "opacity-60"}`}
        >
          CNAME
        </button>
      </div>

      {/* Copy buttons: a 30-character token retyped into a registrar's form is
          the most likely reason verification "doesn't work". */}
      <dl className="mt-2 grid grid-cols-[auto_1fr_auto] items-center gap-x-3 gap-y-1.5 font-mono text-xs">
        <dt className="opacity-60">Type</dt>
        <dd className="col-span-2">{chosen.type}</dd>
        <dt className="opacity-60">Host</dt>
        <dd className="break-all">{chosen.host}</dd>
        <dd>
          <CopyValue value={chosen.host} label="host" />
        </dd>
        <dt className="opacity-60">Value</dt>
        <dd className="break-all">{chosen.value}</dd>
        <dd>
          <CopyValue value={chosen.value} label="value" />
        </dd>
      </dl>

      {error && <p className="mt-2 text-red-500">{error}</p>}

      <div className="mt-3 flex items-center gap-2">
        <Button onClick={() => void verify(false)} disabled={busy}>
          {busy ? "Checking DNS…" : "Verify"}
        </Button>
        {onBack && (
          <Button variant="quiet" onClick={onBack} disabled={busy}>
            Back
          </Button>
        )}
        <span className="ml-auto text-xs opacity-70" aria-live="polite">
          {busy || autoChecking ? (
            <span className="inline-flex items-center gap-1.5">
              <span
                className="inline-block size-2 animate-pulse rounded-full bg-amber-500"
                aria-hidden
              />
              Checking DNS…
            </span>
          ) : (
            `Checking again in ${countdown}s`
          )}
        </span>
      </div>
    </div>
  );
}
