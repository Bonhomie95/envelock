import { useState, type FormEvent } from "react";
import { Check, Copy, Loader2, Search, Server, ShieldOff } from "lucide-react";
import { api, type ConnectionPlan } from "../lib/api";
import { Button, LevelChip } from "./primitives";

export default function ConnectionAdvisor({
  defaultDomain = "",
}: {
  defaultDomain?: string;
}) {
  const [domain, setDomain] = useState(defaultDomain);
  const [plan, setPlan] = useState<ConnectionPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function run(e?: FormEvent) {
    e?.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setError(null);
    setPlan(null);
    try {
      setPlan(await api.connect(domain.trim()));
    } catch {
      setError("Lookup failed. Check the domain and try again.");
    } finally {
      setLoading(false);
    }
  }

  function copyImap() {
    if (!plan?.imap.host) return;
    void navigator.clipboard.writeText(`${plan.imap.host}:${plan.imap.port}`);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section className="panel">
      <div className="border-b px-5 py-3.5">
        <h2 className="sect-label">Connection advisor</h2>
        <p className="fg-3 mt-1 text-xs">
          Detects your mail server and IMAP settings
        </p>
      </div>

      <form onSubmit={run} className="flex flex-col gap-px border-b p-5 sm:flex-row">
        <div className="relative flex-1">
          <Server
            size={15}
            className="fg-3 pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2"
            aria-hidden
          />
          <label htmlFor="advisor-domain" className="sr-only">
            Domain to look up
          </label>
          <input
            id="advisor-domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="yourcompany.com"
            autoComplete="url"
            className="field pl-10"
          />
        </div>
        <Button
          type="submit"
          variant="accent"
          size="lg"
          disabled={loading || !domain.trim()}
        >
          {loading ? (
            <>
              <Loader2 size={14} className="animate-spin" aria-hidden />
              CHECKING
            </>
          ) : (
            <>
              <Search size={14} aria-hidden />
              CHECK
            </>
          )}
        </Button>
      </form>

      {error && (
        <p role="alert" className="p-5 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}

      {!plan && !error && !loading && (
        <p className="fg-3 p-5 text-xs leading-relaxed">
          Enter your domain to see its provider, IMAP host/port and DMARC status.
        </p>
      )}

      {plan && (
        <div className="rise">
          {/* Detected provider */}
          <div className="border-b p-5">
            <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="sect-label">Detected</span>
              <span className="text-base font-semibold">
                {plan.provider.name}
              </span>
              {!plan.detected && (
                <span className="mono-xs fg-3">NOT RECOGNISED</span>
              )}
            </div>

            {plan.provider.aliases.length > 0 && (
              <p className="fg-3 mt-1 text-xs">
                Also known as {plan.provider.aliases.join(", ")}
              </p>
            )}

            {plan.mx_hosts.length > 0 && (
              <div className="mt-4">
                <span className="sect-label">MX records</span>
                <ul className="mt-2 space-y-1" role="list">
                  {plan.mx_hosts.slice(0, 3).map((h) => (
                    <li key={h} className="fg-2 truncate font-mono text-xs">
                      {h}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {plan.imap.host && (
              <div className="mt-4 flex items-center gap-3">
                <div className="min-w-0">
                  <span className="sect-label">IMAP</span>
                  <p className="fg-2 truncate font-mono text-xs">
                    {plan.imap.host}:{plan.imap.port}
                  </p>
                </div>
                <Button
                  size="sm"
                  variant="line"
                  onClick={copyImap}
                  className="ml-auto"
                >
                  {copied ? (
                    <>
                      <Check size={12} aria-hidden /> COPIED
                    </>
                  ) : (
                    <>
                      <Copy size={12} aria-hidden /> COPY
                    </>
                  )}
                </Button>
              </div>
            )}

            {/* DNS posture — free, and worth showing whether or not they connect */}
            <div className="mt-4 flex flex-wrap gap-x-6 gap-y-1 border-t pt-4">
              <span className="mono-xs">
                <span className="fg-3">SPF </span>
                <span className={plan.dns.spf_present ? "text-[var(--ok)]" : "text-[var(--warn)]"}>
                  {plan.dns.spf_present ? "PRESENT" : "MISSING"}
                </span>
              </span>
              <span className="mono-xs">
                <span className="fg-3">DMARC </span>
                <span
                  className={
                    plan.dns.dmarc_policy === "reject" ||
                    plan.dns.dmarc_policy === "quarantine"
                      ? "text-[var(--ok)]"
                      : "text-[var(--warn)]"
                  }
                >
                  {plan.dns.dmarc_policy
                    ? `p=${plan.dns.dmarc_policy}`.toUpperCase()
                    : "MISSING"}
                </span>
              </span>
            </div>

            {/* Plain-English posture — "p=none" means nothing to most IT staff. */}
            {plan.dns.dmarc_policy === "reject" ||
            plan.dns.dmarc_policy === "quarantine" ? (
              <p className="fg-3 mt-2 text-xs leading-relaxed">
                DMARC is enforcing — spoofed mail claiming to be {domain.trim()} is
                rejected or quarantined by receivers. Good.
              </p>
            ) : (
              <p className="mt-2 text-xs leading-relaxed text-[var(--warn,#d97706)]">
                {plan.dns.dmarc_policy === "none"
                  ? "DMARC is set to p=none — it only monitors, so anyone can still spoof this domain. Move it to p=quarantine, then p=reject."
                  : "No DMARC record — anyone can send mail as this domain. Publish a DMARC record (start at p=none to observe, then enforce)."}{" "}
               
              </p>
            )}

          </div>

          {/* Recommendation — one line, not a walkthrough. */}
          <div className="flex flex-wrap items-center gap-2 p-5">
            <span className="mono-xs accent">RECOMMENDED</span>
            <span className="text-sm font-semibold">{plan.recommended.name}</span>
            <LevelChip level={plan.recommended.protection_level} />
            {plan.recommended.remediation ? (
              <span className="mono-xs text-[var(--ok)]">· CAN QUARANTINE</span>
            ) : (
              <span className="mono-xs fg-3 flex items-center gap-1">
                <ShieldOff size={10} aria-hidden /> ALERT ONLY
              </span>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
