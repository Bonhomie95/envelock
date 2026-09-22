import { AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react";
import type { ReactNode } from "react";
import type { AlertRecord, Oversight } from "../lib/api";
import { cn } from "./primitives";

/* The dashboard's first screen, answering the three questions the person who
   uses it (usually finance or an office manager, not IT) actually has:
   does anything need me, what did this do for us, and is it still working?
   Everything else is one click away in the tabs underneath. */

export interface HealthIssue {
  id: string;
  text: string;
  action?: { label: string; onClick: () => void };
}

function money(rows: { currency: string; amount: number }[]): string | null {
  if (!rows.length) return null;
  const sym: Record<string, string> = { USD: "$", EUR: "€", GBP: "£", NGN: "₦" };
  return rows
    .slice(0, 2)
    .map((r) => {
      const body = r.amount.toLocaleString(undefined, { maximumFractionDigits: 0 });
      return sym[r.currency] ? `${sym[r.currency]}${body}` : `${r.currency} ${body}`;
    })
    .join(" + ");
}

function Card({
  label,
  tone,
  children,
}: {
  label: string;
  tone: "hot" | "ok" | "quiet";
  children: ReactNode;
}) {
  return (
    <div
      className={cn(
        "panel flex flex-col p-5",
        tone === "hot" && "border-[var(--danger)]",
      )}
    >
      <h2 className="sect-label">{label}</h2>
      <div className="mt-3 flex-1">{children}</div>
    </div>
  );
}

export default function TodayPanel({
  open,
  stats,
  issues,
  onShowAlerts,
}: {
  open: AlertRecord[];
  stats: Oversight | null;
  issues: HealthIssue[];
  onShowAlerts: () => void;
}) {
  const urgent = open.filter((a) => a.tier === "critical" || a.tier === "high");
  const month = stats?.month;
  const stopped = money(stats?.prevented_loss.by_currency ?? []);
  const checked = money(month?.payments_checked_by_currency ?? []);

  return (
    <div className="grid gap-4 md:grid-cols-3">
      <Card label="Needs you now" tone={urgent.length ? "hot" : "quiet"}>
        {urgent.length ? (
          <>
            <p className="stat-figure is-hot">{urgent.length}</p>
            <p className="fg-2 mt-2 text-sm leading-relaxed">
              {urgent.length === 1 ? "alert" : "alerts"} to act on
              {urgent[0] && (
                <>
                  {" "}
                  — starting with <span className="font-semibold">{urgent[0].title}</span>
                </>
              )}
            </p>
            <button
              type="button"
              onClick={onShowAlerts}
              className="accent mono-xs mt-3 cursor-pointer hover:underline"
            >
              OPEN THE QUEUE ↓
            </button>
          </>
        ) : (
          <p className="flex items-start gap-2 text-sm">
            <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-[var(--ok)]" aria-hidden />
            Nothing needs you right now.
            {open.length > 0 && ` ${open.length} lower-priority alert${open.length === 1 ? "" : "s"} below.`}
          </p>
        )}
      </Card>

      <Card label="Stopped · last 30 days" tone="quiet">
        {stats ? (
          <>
            {stopped ? (
              <p className="stat-figure accent">{stopped}</p>
            ) : (
              <p className="stat-figure is-quiet">{month?.confirmed_fraud ?? 0}</p>
            )}
            <p className="fg-2 mt-2 text-sm leading-relaxed">
              {stopped
                ? "kept from going to the wrong account"
                : `confirmed fraud${month?.confirmed_fraud === 1 ? "" : "s"}`}
              {month && month.quarantined > 0 && ` · ${month.quarantined} dangerous emails removed`}
            </p>
            {month && month.payment_requests > 0 && (
              <p className="fg-3 mt-2 text-xs">
                {checked ? `${checked} in` : month.payment_requests}{" "}
                payment request{month.payment_requests === 1 ? "" : "s"} checked
              </p>
            )}
          </>
        ) : (
          <p className="fg-3 text-sm">Your team's results show here.</p>
        )}
      </Card>

      <Card label="Protection health" tone={issues.length ? "hot" : "ok"}>
        {issues.length === 0 ? (
          <p className="flex items-start gap-2 text-sm">
            <ShieldCheck size={16} className="mt-0.5 shrink-0 text-[var(--ok)]" aria-hidden />
            Everything is connected and working.
          </p>
        ) : (
          <ul className="space-y-3" role="list">
            {issues.map((i) => (
              <li key={i.id} className="text-sm leading-snug">
                <span className="flex items-start gap-2">
                  <AlertTriangle size={14} className="mt-0.5 shrink-0 text-[var(--warn,#b45309)]" aria-hidden />
                  <span>
                    {i.text}
                    {i.action && (
                      <>
                        {" "}
                        <button
                          type="button"
                          onClick={i.action.onClick}
                          className="accent cursor-pointer font-semibold whitespace-nowrap hover:underline"
                        >
                          {i.action.label} →
                        </button>
                      </>
                    )}
                  </span>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
