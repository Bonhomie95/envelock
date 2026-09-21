import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2, RefreshCw, XCircle } from "lucide-react";
import { api, type PublicStatus } from "../lib/api";
import { Button, cn } from "../components/primitives";

/* The public status page.
 *
 * We ask businesses to hand us access to their mail. The minimum we owe them in
 * return is somewhere to look that is not the marketing site when something
 * feels wrong.
 *
 * Two things this page does that most status pages get wrong:
 *
 * 1. **It says what an outage does NOT affect.** The single most useful fact
 *    during an Envelock incident is that the customer's mail is still flowing,
 *    because we are never in the delivery path. That belongs at the top, not
 *    buried in an incident note.
 * 2. **It fails honestly.** If this page cannot reach the API, that IS the
 *    status — so it says so plainly rather than spinning forever or, worse,
 *    rendering a cheerful default.
 */

const POLL_MS = 60_000;

const TONE: Record<string, { dot: string; text: string; label: string }> = {
  operational: { dot: "bg-[var(--accent)]", text: "accent", label: "OPERATIONAL" },
  degraded: {
    dot: "bg-[var(--warn,#d97706)]",
    text: "text-[var(--warn,#d97706)]",
    label: "DEGRADED",
  },
  down: { dot: "bg-[var(--danger)]", text: "text-[var(--danger)]", label: "DOWN" },
};

function tone(state: string) {
  return TONE[state] ?? TONE.degraded;
}

export default function Status() {
  const [status, setStatus] = useState<PublicStatus | null>(null);
  const [unreachable, setUnreachable] = useState(false);
  const [loading, setLoading] = useState(true);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);

  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    try {
      setStatus(await api.status());
      setUnreachable(false);
    } catch {
      // Not an error state to hide — being unable to reach us is the status.
      setUnreachable(true);
    } finally {
      setCheckedAt(new Date());
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Subscribing to an external system (our own API) and polling it — the case
    // the rule's own documentation exempts. The synchronous setState it objects
    // to is the loading flag on the first fetch, and delaying that to a
    // microtask only to satisfy the linter would make the page render "All
    // systems operational" for a frame before it has asked anything, which on
    // this page of all pages is the wrong default.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    const id = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  const overall = unreachable ? "down" : (status?.state ?? "operational");
  const t = tone(overall);

  return (
    <main className="shell py-16 md:py-24">
      <div className="grid12 items-start">
        <div className="col-span-12 lg:col-span-7">
          <p className="sect-label">System status</p>

          <div className="mt-5 flex items-center gap-3">
            <span
              className={cn(
                "size-3 shrink-0 rounded-full",
                t.dot,
                overall !== "operational" && "animate-pulse",
              )}
              aria-hidden
            />
            <h1 className="headline text-balance">
              {unreachable
                ? "We cannot be reached from here."
                : (status?.summary ?? "Checking…")}
            </h1>
          </div>

          <p className="fg-2 mt-5 text-[15px] leading-relaxed">
            {unreachable ? (
              <>
                This page could not reach the Envelock API. That may be an outage
                on our side, or the connection between you and us. Either way,
                your mail is unaffected — Envelock is never in your mail&rsquo;s
                delivery path, so nothing here can delay or lose a message.
              </>
            ) : (
              <>
                Live, checked against the running system each time this page
                loads. Nothing on it is set by hand.
              </>
            )}
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-4">
            <Button variant="line" size="sm" onClick={() => void refresh()} disabled={loading}>
              {loading ? (
                <Loader2 size={13} className="animate-spin" aria-hidden />
              ) : (
                <RefreshCw size={13} aria-hidden />
              )}
              CHECK AGAIN
            </Button>
            {checkedAt && (
              <span className="fg-3 mono-xs tnum">
                CHECKED {checkedAt.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        <div className="col-span-12 mt-12 lg:col-span-4 lg:col-start-9 lg:mt-0">
          <div className="panel p-6">
            <p className="flex items-center gap-2 text-sm font-semibold">
              {overall === "operational" ? (
                <CheckCircle2 size={15} className="accent" aria-hidden />
              ) : (
                <XCircle size={15} className="text-[var(--danger)]" aria-hidden />
              )}
              Your email keeps flowing
            </p>
            <p className="fg-2 mt-3 text-sm leading-relaxed">
              Envelock sits alongside your mail system, never in the delivery
              path. There is no failure of ours that can hold up a message —
              during an outage you lose the checking, not the mail.
            </p>
          </div>
        </div>
      </div>

      {status && !unreachable && (
        <section className="mt-16">
          <h2 className="sect-label">Components</h2>
          <ul className="mt-6 divide-y" role="list">
            {status.components.map((c) => {
              const ct = tone(c.state);
              return (
                <li key={c.id} className="flex flex-col gap-2 py-5 sm:flex-row sm:gap-6">
                  <div className="flex items-center gap-3 sm:w-64 sm:shrink-0">
                    <span className={cn("size-2 shrink-0 rounded-full", ct.dot)} aria-hidden />
                    <span className="text-sm font-medium">{c.name}</span>
                  </div>
                  <p className="fg-2 flex-1 text-sm leading-relaxed">{c.detail}</p>
                  <span className={cn("mono-xs shrink-0 sm:w-28 sm:text-right", ct.text)}>
                    {ct.label}
                  </span>
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <section className="mt-16 border-t pt-10">
        <h2 className="sect-label">If something is wrong and this page says it is fine</h2>
        <p className="fg-2 mt-4 max-w-2xl text-[15px] leading-relaxed">
          Tell us. A status page that disagrees with a customer is a status page
          that is wrong, not a customer who is mistaken. Write to{" "}
          <a
            href="mailto:security@envelock.org"
            className="accent underline underline-offset-4"
          >
            security@envelock.org
          </a>{" "}
          — and if you believe you are looking at a live fraud attempt right now,
          say so in the subject line and we will treat it as an incident.
        </p>
        <p className="fg-3 mt-6 text-sm">
          Looking for how the product works instead?{" "}
          <Link to="/docs" className="accent underline underline-offset-4">
            The documentation
          </Link>{" "}
          covers every detection and integration.
        </p>
      </section>
    </main>
  );
}
