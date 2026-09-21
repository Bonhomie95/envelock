import { createElement, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  Banknote,
  Bell,
  Check,
  CheckCircle2,
  Copy,
  CreditCard,
  Fingerprint,
  Forward,
  Globe,
  Inbox,
  KeyRound,
  Link2,
  Loader2,
  PhoneCall,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
  type LucideIcon,
} from "lucide-react";
import {
  ApiError,
  api,
  auth,
  type AlertRecord,
  type AuditEvent,
  type LookalikeDomain,
  type ConnectionPlan,
  type ImapConnectBody,
  type ImapCertificate,
  type ImapProbeResult,
  type MailboxRecord,
  type Oversight,
  type PreventedLoss,
  type QualityMetric,
  type TenantInfo,
  type Tier,
} from "../lib/api";

// Sources that mean a mailbox's MAIL is actually being ingested (vs identity-only
// signals like the sensor). Used to tell "connected" from "unconnected".
const MAIL_SOURCES = new Set([
  "graph_api",
  "gmail_api",
  "admin_api",
  "imap_idle",
  "imap_poll",
  "forward_ingest",
  "journal",
]);
import { Button, LevelChip, TierChip, cn } from "../components/primitives";
import ConfirmDialog from "../components/ConfirmDialog";
import ConnectionAdvisor from "../components/ConnectionAdvisor";
import { DomainVerify } from "../components/DomainVerify";
import MfaEnroll from "../components/MfaEnroll";
import SensorPanel from "../components/SensorPanel";
import { PLAN_RANK, PLAN_TIERS } from "../lib/plans";
import { toast } from "../lib/toast";
import {
  disablePush,
  enablePush,
  getPushState,
  type PushState,
} from "../lib/push";

interface Me {
  email: string;
  mfa_enabled: boolean;
}

/* Icons are chosen from the detection id so the queue stays readable at a
   glance without the server having to send presentation details. */
const SERVICE_ICON: Record<string, LucideIcon> = {
  A1: Banknote,
  A2: Banknote,
  A13: Banknote,
  C1: Link2,
  C2: Link2,
  C3: Link2,
  C4: Link2,
  C11: Fingerprint,
  C7: Fingerprint,
  C6: Fingerprint,
  D4: Globe,
  A3: Globe,
  A4: Globe,
};

function iconFor(alert: AlertRecord): LucideIcon {
  const match = alert.body.match(/\b([ABCD]\d{1,2})\b/);
  return (match && SERVICE_ICON[match[1]]) || Inbox;
}

function timeOf(iso: string): string {
  const then = new Date(iso);
  const mins = Math.floor((Date.now() - then.getTime()) / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min`;
  if (mins < 1440) return `${Math.floor(mins / 60)} hr`;
  return then.toLocaleDateString();
}

/* The AI analyst's working for one alert.
 *
 * The chip on the card said "AI CONFIRMED" and that was the entire story the
 * product told: no rationale, no confidence, no record of what it cost or
 * whether it changed the outcome — while the server recorded all of it on every
 * call and exposed it at /alerts/{id}/ai, which nothing had ever called. We
 * sell the plain-English judgement as the feature; this is where a customer
 * actually reads it.
 *
 * Admin-only server-side. A 403 means "not for this role" and renders nothing
 * rather than an error the member can do nothing about.
 */
function AiVerdictPanel({ alertId }: { alertId: string }) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<
    | { kind: "idle" }
    | { kind: "loading" }
    | { kind: "hidden" }
    | { kind: "error"; message: string }
    | { kind: "ready"; verdicts: AiVerdict[] }
  >({ kind: "idle" });

  async function toggle() {
    const next = !open;
    setOpen(next);
    if (!next || state.kind !== "idle") return;
    setState({ kind: "loading" });
    try {
      const r = await api.alertAi(alertId);
      setState({ kind: "ready", verdicts: r.verdicts });
    } catch (e) {
      if (e instanceof ApiError && e.status === 403) setState({ kind: "hidden" });
      else
        setState({
          kind: "error",
          message: e instanceof ApiError ? e.message : "Could not load the AI verdict",
        });
    }
  }

  if (state.kind === "hidden") return null;

  return (
    <div className="mt-4 border-t pt-3">
      <button
        type="button"
        onClick={() => void toggle()}
        aria-expanded={open}
        className="fg-2 mono-xs flex cursor-pointer items-center gap-1.5 hover:text-[var(--fg)]"
      >
        <Sparkles size={11} aria-hidden />
        {open ? "HIDE" : "WHY THE AI AGREED"}
      </button>

      {open && (
        <div className="mt-3">
          {state.kind === "loading" && (
            <p className="fg-3 mono-xs flex items-center gap-1.5">
              <Loader2 size={11} className="animate-spin" aria-hidden /> READING…
            </p>
          )}
          {state.kind === "error" && (
            <p className="fg-3 mono-xs" role="status">
              {state.message}
            </p>
          )}
          {state.kind === "ready" && state.verdicts.length === 0 && (
            <p className="fg-3 text-xs leading-relaxed">
              The deterministic checks settled this one on their own — the AI
              analyst was never called. That is the normal case, and it is why
              the feature is affordable.
            </p>
          )}
          {state.kind === "ready" &&
            state.verdicts.map((v, i) => (
              <div key={i} className={cn("text-xs", i > 0 && "mt-4 border-t pt-3")}>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                  <span className="mono-xs accent">{v.verdict.toUpperCase()}</span>
                  {v.confidence !== null && (
                    <span className="fg-3 mono-xs tnum">
                      CONFIDENCE {Math.round(v.confidence * 100)}%
                    </span>
                  )}
                  <span className="fg-3 mono-xs">
                    {v.escalated
                      ? `RAISED ${String(v.rule_tier ?? "").toUpperCase()} → ${String(
                          v.final_tier ?? "",
                        ).toUpperCase()}`
                      : "NO CHANGE TO SEVERITY"}
                  </span>
                </div>
                {v.rationale && (
                  <p className="fg-2 mt-2.5 leading-relaxed">{v.rationale}</p>
                )}
                <p className="fg-3 mono-xs mt-2.5">
                  {[v.provider, v.model].filter(Boolean).join(" · ") || "model not recorded"}
                  {v.cost_micros !== null &&
                    ` · ${(v.cost_micros / 10_000).toFixed(2)}¢`}
                </p>
              </div>
            ))}
          <p className="fg-3 mono-xs mt-3">
            THE ANALYST CAN RAISE A SEVERITY, NEVER LOWER ONE
          </p>
        </div>
      )}
    </div>
  );
}

type AiVerdict = Awaited<ReturnType<typeof api.alertAi>>["verdicts"][number];

/* "Envelock stopped £X leaving this company."
 *
 * The one number that turns a renewal from a cost conversation into a return
 * one, and until now the product knew it and never said it. Three rules, all of
 * which exist because this is the figure a customer is most likely to check
 * against their own ledger:
 *
 * - confirmed frauds only (the server decides; an open alert may be dismissed
 *   tomorrow and a dismissed one was a false positive);
 * - per currency, never summed — £ plus ₦ is a number that is true in neither;
 * - incidents we could not price are stated, not folded in or hidden, so the
 *   headline reads "at least this much" honestly.
 *
 * Renders nothing at all when there is nothing to claim. A zero here is an
 * advert for not having been attacked yet.
 */
function PreventedPanel({ prevented }: { prevented: PreventedLoss | undefined }) {
  if (!prevented || prevented.by_currency.length === 0) return null;

  const amounts = prevented.by_currency.map((row) => {
    const symbol = ({ USD: "$", EUR: "€", GBP: "£", NGN: "₦" } as Record<string, string>)[
      row.currency
    ];
    const body = row.amount.toLocaleString(undefined, {
      minimumFractionDigits: 0,
      maximumFractionDigits: 2,
    });
    return symbol ? `${symbol}${body}` : `${row.currency} ${body}`;
  });

  return (
    <div className="panel mt-4 p-6">
      <p className="sect-label">Money stopped</p>
      <p className="mt-3 flex flex-wrap items-baseline gap-x-3 gap-y-1">
        {amounts.map((amount, i) => (
          <span key={i} className="font-mono tnum accent text-3xl font-semibold tracking-tight">
            {amount}
          </span>
        ))}
      </p>
      <p className="fg-2 mt-3 text-sm leading-relaxed">
        stopped from going to the wrong bank account, across{" "}
        {prevented.incidents} confirmed{" "}
        {prevented.incidents === 1 ? "incident" : "incidents"}.
        {prevented.unpriced_incidents > 0 && (
          <>
            {" "}
            A further {prevented.unpriced_incidents} confirmed{" "}
            {prevented.unpriced_incidents === 1 ? "incident" : "incidents"} named
            no amount, so the real figure is higher.
          </>
        )}
      </p>
      <p className="fg-3 mono-xs mt-4">
        CONFIRMED BY YOUR TEAM · AMOUNTS READ FROM THE MESSAGES THEMSELVES
      </p>
    </div>
  );
}

function AlertRow({
  alert,
  onAcknowledge,
  onQuarantine,
  onResolve,
}: {
  alert: AlertRecord;
  onAcknowledge: (id: string) => Promise<void>;
  onQuarantine: (id: string) => Promise<void>;
  onResolve: (id: string, dismiss: boolean) => Promise<void>;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  // CONFIRM FRAUD is the one control here that reaches outside this tenant: it
  // reports the counterparty to the cross-tenant graph (E8), so it changes what
  // every other Envelock customer sees. It sat 8px from DISMISS, same size, same
  // quiet variant, and fired on one click with no confirmation and no undo.
  const [confirmFraud, setConfirmFraud] = useState(false);
  // Lowercase + createElement: the icon is a *value* looked up from a stable
  // module-level map, not a component defined during render.
  const icon = iconFor(alert);
  const acked = alert.state !== "open";
  // Only resolved/dismissed alerts are finished. "acked" means a human has SEEN
  // it — one click on ACKNOWLEDGE used to permanently remove quarantine and
  // confirm-fraud from the UI, on the exact alerts where those actions matter.
  const closed = alert.state === "resolved" || alert.state === "dismissed";

  async function run(action: "ack" | "quarantine" | "fraud" | "dismiss") {
    setBusy(action);
    setNote(null);
    try {
      if (action === "ack") await onAcknowledge(alert.id);
      else if (action === "quarantine") await onQuarantine(alert.id);
      else await onResolve(alert.id, action === "dismiss");
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Action failed");
    } finally {
      setBusy(null);
    }
  }

  // A short, stable handle for the alert. Support conversations happen over the
  // phone while someone is looking at this screen, and "the second one down" is
  // not something either side can act on.
  const reference = `ENV-${alert.id.replace(/-/g, "").slice(0, 6).toUpperCase()}`;

  return (
    <article
      className={cn(
        "alertcard p-5 sm:p-6",
        `tier-${alert.tier}`,
        acked && "opacity-55",
      )}
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <TierChip tier={alert.tier} blink={!acked} />
        {alert.ai_flagged && (
          <span
            className="mono-xs fg-2 flex items-center gap-1"
            title="Envelock's AI fraud check independently confirmed this alert"
          >
            <Sparkles size={11} aria-hidden />
            AI CONFIRMED
          </span>
        )}
        <span className="mono-xs fg-3 tnum">{reference}</span>
        {alert.amount_at_risk != null && alert.amount_currency && (
          <span
            className="mono-xs accent tnum"
            title="The largest sum named in the message that produced this alert"
          >
            {alert.amount_currency} {alert.amount_at_risk.toLocaleString()}
          </span>
        )}
        <span className="mono-xs fg-3 ml-auto tnum">
          {timeOf(alert.created_at)}
        </span>
      </div>

      <div className="mt-4 flex gap-4">
        {createElement(icon, {
          size: 17,
          className: "fg-3 mt-0.5 shrink-0",
          "aria-hidden": true,
        })}
        <div className="min-w-0 flex-1">
          <h3 className="text-sm leading-snug font-semibold text-pretty">
            {alert.title}
          </h3>
          <p className="fg-2 mt-3 text-sm leading-relaxed whitespace-pre-line">
            {alert.body}
          </p>

          {alert.requires_callback && !acked && (
            <div className="callout mt-4 flex flex-wrap items-center gap-2.5 px-4 py-3">
              <PhoneCall size={14} className="shrink-0" aria-hidden />
              <span className="text-xs font-semibold">
                {alert.callback_phone
                  ? `Call ${alert.callback_phone} to verify — the number on file with us, not the one in the email`
                  : "Verify by phone before paying. No number on file — add one so it appears here."}
              </span>
            </div>
          )}

          {note && (
            <p className="fg-3 mono-xs mt-3" role="status">
              {note}
            </p>
          )}

          {alert.ai_flagged && <AiVerdictPanel alertId={alert.id} />}

          <div className="mt-4 flex flex-wrap items-center gap-2">
            {closed ? (
              <span className="fg-3 mono-xs flex items-center gap-1.5">
                <CheckCircle2 size={12} aria-hidden />
                {alert.state.toUpperCase()}
              </span>
            ) : (
              <>
                {acked ? (
                  <span className="fg-3 mono-xs flex items-center gap-1.5">
                    <CheckCircle2 size={12} aria-hidden />
                    ACKED
                  </span>
                ) : (
                  <Button
                    size="sm"
                    variant="line"
                    disabled={busy !== null}
                    onClick={() => run("ack")}
                  >
                    {busy === "ack" ? (
                      <Loader2 size={12} className="animate-spin" aria-hidden />
                    ) : null}
                    ACKNOWLEDGE
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="quiet"
                  disabled={busy !== null}
                  onClick={() => run("quarantine")}
                >
                  QUARANTINE
                </Button>
                {/* Confirming real fraud reports the counterparty to the
                    cross-tenant graph, protecting every other customer (E8) —
                    so it is gated behind a confirmation, unlike the actions
                    whose blast radius stops at this tenant. */}
                <Button
                  size="sm"
                  variant="quiet"
                  disabled={busy !== null}
                  onClick={() => setConfirmFraud(true)}
                  title="Confirm this was real fraud — warns every other tenant"
                >
                  CONFIRM FRAUD
                </Button>
                <Button
                  size="sm"
                  variant="quiet"
                  disabled={busy !== null}
                  onClick={() => run("dismiss")}
                >
                  DISMISS
                </Button>
              </>
            )}
          </div>
        </div>
      </div>

      <ConfirmDialog
        open={confirmFraud}
        title={`Report ${reference} as confirmed fraud?`}
        body={
          (alert.tier === "high" || alert.tier === "critical") &&
          alert.counterparty_domain
            ? "This tells every other Envelock customer that " +
              alert.counterparty_domain +
              " is fraudulent, and it cannot be undone from here. Only confirm " +
              "if you have verified the fraud — for example by calling the " +
              "supplier on a number you already had. If you just don't want " +
              "this alert, use DISMISS."
            : "This marks the alert as confirmed fraud in your records. Only " +
              "confirm if you verified it — if you just don't want this " +
              "alert, use DISMISS."
        }
        confirmLabel="REPORT AS FRAUD"
        busy={busy === "fraud"}
        onCancel={() => setConfirmFraud(false)}
        onConfirm={() => {
          setConfirmFraud(false);
          void run("fraud");
        }}
      />
    </article>
  );
}

/* Where the common providers issue the app-specific password an IMAP login needs
   once two-factor is on. Surfaced prominently on the dashboard, not in the form. */
interface ImapHelp {
  label: string;
  url: string;
}
const IMAP_HELP: Record<string, ImapHelp> = {
  google: {
    label: "Google app password",
    url: "https://myaccount.google.com/apppasswords",
  },
  microsoft365: {
    label: "Microsoft app password",
    url: "https://account.microsoft.com/security",
  },
  icloud: {
    label: "Apple app-specific password",
    url: "https://appleid.apple.com/account/manage",
  },
  fastmail: {
    label: "Fastmail app password",
    url: "https://app.fastmail.com/settings/security/apppassword",
  },
  zoho: {
    label: "Zoho app password",
    url: "https://accounts.zoho.com/home#security/app_password",
  },
};

/* A prominent, one-time explainer surfaced on the dashboard (not buried in the
   connect form): the single biggest IMAP snag is that providers reject the normal
   password once two-factor is on. Links to where each issues an app password. */
function AppPasswordNotice() {
  const [open, setOpen] = useState(false);
  return (
    <div className="callout p-4">
      <div className="flex items-start gap-3">
        <KeyRound size={16} className="mt-0.5 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold">Connecting a mailbox over IMAP?</p>
          <p className="fg-2 mt-1 text-xs leading-relaxed">
            Most providers reject your normal password over IMAP once two-factor is
            on. Create an <span className="font-semibold">app-specific password</span>{" "}
            first, then paste it when connecting.
          </p>
          <button
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            className="accent mono-xs mt-2 cursor-pointer hover:underline"
          >
            {open ? "HIDE PROVIDER LINKS" : "WHERE TO GET ONE →"}
          </button>
          {open && (
            <ul className="mt-2 grid gap-1.5 sm:grid-cols-2" role="list">
              {Object.entries(IMAP_HELP).map(([id, h]) => (
                <li key={id}>
                  <a
                    href={h.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="fg-2 mono-xs inline-flex items-center gap-1.5 hover:text-[var(--accent)]"
                  >
                    <KeyRound size={11} aria-hidden /> {h.label} →
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

/* The one number that answers "is my email actually being protected?".
 *
 * Deliberately counts CONNECTED mailboxes, not added ones: an address that has
 * been typed in but never connected protects nothing, and a figure that counted
 * it would be the flattering-but-false state this product exists to avoid. The
 * label says exactly what is being divided by what, so the percentage cannot be
 * mistaken for a security score. */
function CoverageSummary({ mailboxes }: { mailboxes: MailboxRecord[] }) {
  const connected = mailboxes.filter((m) =>
    m.sources.some((s) => MAIL_SOURCES.has(s)),
  );
  const full = connected.filter((m) => m.protection_level === "full").length;
  const ratio = mailboxes.length
    ? Math.round((connected.length / mailboxes.length) * 100)
    : 0;
  const needsAttention = mailboxes.filter((m) => m.needs_reconnect).length;

  return (
    <div className="panel p-5">
      <div className="flex items-start justify-between gap-3">
        <h2 className="sect-label">Coverage</h2>
        <a href="#coverage" className="fg-3 mono-xs hover:text-[var(--fg)]">
          DETAIL →
        </a>
      </div>

      <div className="mt-3 flex items-baseline gap-1.5">
        <span className="stat-figure is-accent">{ratio}</span>
        <span className="fg-3 font-mono text-lg">%</span>
      </div>
      <p className="fg-3 mono-xs mt-1.5">
        {connected.length} OF {mailboxes.length} MAILBOXES CONNECTED
      </p>
      <div className="meter mt-3" role="img" aria-label={`${ratio} per cent of mailboxes connected`}>
        <span style={{ width: `${ratio}%` }} />
      </div>

      <dl className="mt-4 space-y-2 border-t pt-4 text-xs">
        <div className="flex items-center justify-between gap-3">
          <dt className="fg-2">Full protection</dt>
          <dd className="font-mono tnum">{full}</dd>
        </div>
        <div className="flex items-center justify-between gap-3">
          <dt className="fg-2">Alert-only</dt>
          <dd className="font-mono tnum">{connected.length - full}</dd>
        </div>
        {needsAttention > 0 && (
          <div className="flex items-center justify-between gap-3">
            <dt className="text-[var(--danger)]">Needs reconnecting</dt>
            <dd className="font-mono tnum text-[var(--danger)]">
              {needsAttention}
            </dd>
          </div>
        )}
      </dl>
    </div>
  );
}

/* The tenant's own audit trail (E5).
 *
 * The endpoint and its client binding both existed; nothing ever called them,
 * so "IT can see who acted and who ignored it" — a thing the product is sold on
 * — was answerable only by querying the database. It also surfaces the actions
 * Envelock's own operators take on the account, which is the half a customer
 * has the most right to see. */
const AUDIT_LABELS: Record<string, string> = {
  "alert.raised": "Alert raised",
  "alert.viewed": "Alert viewed",
  "alert.acknowledged": "Alert acknowledged",
  "alert.resolved": "Alert resolved",
  "alert.dismissed": "Alert dismissed",
  "alert.escalated": "Escalated",
  "message.quarantined": "Message quarantined",
  "mailbox.connected": "Mailbox connected",
  "settings.changed": "Settings changed",
  "webhook.registered": "SIEM webhook registered",
  "webhook.removed": "SIEM webhook removed",
  "admin.plan_changed": "Plan changed by Envelock",
  "admin.trial_extended": "Trial extended by Envelock",
  "admin.tenant_suspended": "Account suspended by Envelock",
  "admin.tenant_activated": "Account reactivated by Envelock",
  "admin.user_approved": "User approved by Envelock",
  "admin.user_suspended": "User suspended by Envelock",
  "admin.role_changed": "Role changed by Envelock",
};

function AuditTrail() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || events !== null) return;
    let live = true;
    api
      .audit(50)
      .then((r) => live && setEvents(r.events))
      .catch((e) =>
        live && setError(e instanceof ApiError ? e.message : "Could not load the trail."),
      );
    return () => {
      live = false;
    };
  }, [open, events]);

  return (
    <div className="panel">
      <button
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center justify-between gap-3 px-5 py-3.5 text-left"
      >
        <span className="sect-label">Audit trail</span>
        <span className="fg-3 mono-xs">{open ? "HIDE" : "SHOW"}</span>
      </button>

      {open && (
        <div className="border-t px-5 py-4">
          {error && (
            <p role="alert" className="text-xs text-[var(--danger)]">
              {error}
            </p>
          )}
          {events === null && !error && (
            <p className="fg-3 mono-xs">LOADING…</p>
          )}
          {events !== null && events.length === 0 && (
            <p className="fg-3 text-xs leading-relaxed">
              Nothing recorded yet. Every action on this account — yours and
              anything Envelock support does — appears here.
            </p>
          )}
          {events !== null && events.length > 0 && (
            <ol className="space-y-2.5" role="list">
              {events.map((e) => (
                <li key={e.id} className="flex items-baseline gap-3 text-xs">
                  <time
                    dateTime={e.at}
                    className="fg-3 mono-xs tnum shrink-0"
                    title={new Date(e.at).toLocaleString()}
                  >
                    {timeOf(e.at)}
                  </time>
                  <span className="min-w-0 flex-1">
                    <span className="font-medium">
                      {AUDIT_LABELS[e.action] ?? e.action}
                    </span>
                    {typeof e.detail?.address === "string" && (
                      <span className="fg-2"> — {e.detail.address}</span>
                    )}
                    {typeof e.detail?.by === "string" && (
                      <span className="fg-3"> by {e.detail.by}</span>
                    )}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}

/* Group D — domains registered to impersonate this company.
 *
 * This had a working endpoint, a client binding and no UI at all, which matters
 * most for the free Guard tier: brand monitoring is the ONLY thing Envelock
 * produces for a Guard customer, so without this panel their dashboard showed
 * them nothing the product had actually done. It is also the strongest argument
 * for upgrading, and it was invisible.
 *
 * `armed` is the field that decides how alarmed to be: a lookalike domain with
 * MX records can send mail today; one without is a squat that has not been
 * weaponised yet. Sorting and labelling on that, rather than on similarity,
 * is what keeps this from being a wall of noise. */
function LookalikeWatch() {
  const [rows, setRows] = useState<LookalikeDomain[] | null>(null);
  const [armed, setArmed] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .lookalikes()
      .then((r) => {
        if (!live) return;
        setRows(r.lookalikes);
        setArmed(r.armed_count);
      })
      .catch((e) =>
        live &&
        setError(e instanceof ApiError ? e.message : "Could not load domain watch."),
      );
    return () => {
      live = false;
    };
  }, []);

  // Nothing found is the healthy state and says so, but an empty panel while
  // still loading would flash "all clear" before we know that.
  if (rows === null && !error) return null;

  return (
    <div className="panel">
      <div className="flex items-baseline justify-between gap-3 border-b px-5 py-3.5">
        <h2 className="sect-label">Domain watch</h2>
        {rows !== null && rows.length > 0 && (
          <span className="mono-xs fg-3 tnum">
            {armed} OF {rows.length} CAN SEND MAIL
          </span>
        )}
      </div>

      <div className="px-5 py-4">
        {error && (
          <p role="alert" className="text-xs text-[var(--danger)]">
            {error}
          </p>
        )}

        {rows !== null && rows.length === 0 && (
          <p className="fg-3 text-xs leading-relaxed">
            No lookalike domains found for you yet. We watch certificate
            transparency logs continuously and this fills in the moment somebody
            registers a domain built to be mistaken for yours — on every plan,
            including the free one.
          </p>
        )}

        {rows !== null && rows.length > 0 && (
          <ul className="space-y-3" role="list">
            {rows.slice(0, 8).map((row) => (
              <li key={row.candidate} className="flex items-start gap-3">
                <Globe
                  size={14}
                  className={cn(
                    "mt-0.5 shrink-0",
                    row.armed ? "text-[var(--danger)]" : "fg-3",
                  )}
                  aria-hidden
                />
                <div className="min-w-0 flex-1">
                  <p className="font-mono truncate text-xs font-medium">
                    {row.candidate}
                  </p>
                  <p className="fg-3 mono-xs mt-0.5">
                    {row.technique.replace(/_/g, " ").toUpperCase()} ·{" "}
                    {Math.round(row.similarity * 100)}% SIMILAR
                  </p>
                  {/* Icon + colour + words: never colour alone. */}
                  <p
                    className={cn(
                      "mt-1 text-xs leading-relaxed",
                      row.armed ? "text-[var(--danger)]" : "fg-2",
                    )}
                  >
                    {row.armed
                      ? "Has mail servers configured — this domain can send email pretending to be you today."
                      : "Registered but not set up to send mail yet. We keep watching it."}
                  </p>
                </div>
              </li>
            ))}
          </ul>
        )}

        {rows !== null && rows.length > 8 && (
          <p className="fg-3 mono-xs mt-3">
            + {rows.length - 8} MORE BEING WATCHED
          </p>
        )}
      </div>
    </div>
  );
}

/* One mailbox in the list. Owns the per-row interactive state — "Sync now",
   the reconnect prompt when a stored credential has gone bad, and the plain
   explainer of why the protection level is what it is and how to raise it. */
const IMAP_SOURCES = new Set(["imap_idle", "imap_poll"]);

/* A history scan the worker ran on the API's behalf (split key custody). The
   in-process job registry cannot carry progress across processes, so the
   worker writes it to the mailbox and it is read from there. */
function BackfillLine({ state }: { state: NonNullable<MailboxRecord["backfill_state"]> }) {
  const text =
    state.status === "queued"
      ? "History scan queued"
      : state.status === "running"
        ? "History scan running…"
        : state.status === "done"
          ? `History scan complete — ${state.analysed ?? 0} message${state.analysed === 1 ? "" : "s"} learned from`
          : `History scan failed${state.reason ? ` — ${state.reason}` : ""}`;
  return (
    <p
      className={cn(
        "mono-xs mt-1",
        state.status === "failed" ? "text-[var(--danger)]" : "fg-3",
      )}
    >
      {text.toUpperCase()}
    </p>
  );
}

function MailboxRow({
  mailbox: m,
  onChanged,
  onRemove,
}: {
  mailbox: MailboxRecord;
  onChanged: () => Promise<void>;
  onRemove: (id: string) => void | Promise<void>;
}) {
  const connected = m.sources.some((s) => MAIL_SOURCES.has(s));
  const isImap = m.sources.some((s) => IMAP_SOURCES.has(s));
  const [syncing, setSyncing] = useState(false);
  const [scanning, setScanning] = useState(false);

  // E11 onboarding backfill: the endpoint (and its polling helper) existed with
  // zero callers — "we learn what normal looks like in minutes" had no button.
  async function scanHistory() {
    setScanning(true);
    setNote(null);
    try {
      const r = await api.backfillMailbox(m.id);
      if (r.queued) {
        // Split key custody: the API cannot open the credential, so the worker
        // runs the scan. Its progress lands on the mailbox, which this row
        // shows — so say so rather than implying it already ran.
        setNote(
          `History scan of the last ${r.days} days queued — it starts within a minute and its progress shows here.`,
        );
        await onChanged();
        return;
      }
      if (!r.job) {
        setNote(`History scan planned for the last ${r.days} days — ${r.reason}.`);
        return;
      }
      setNote(`Scanning the last ${r.days} days of mail…`);
      for (let i = 0; i < 150; i++) {
        await new Promise((res) => setTimeout(res, 2000));
        const j = await api.jobStatus(r.job.id);
        if (j.status === "done") {
          setNote("History scan complete — baselines learned.");
          toast.success(`${m.address}: history scan complete.`);
          await onChanged();
          return;
        }
        if (j.status === "failed") {
          setNote(j.error ?? "History scan failed — try again.");
          return;
        }
      }
      setNote("Scan is still running in the background — safe to leave this page.");
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Couldn't start the history scan.");
    } finally {
      setScanning(false);
    }
  }
  const [note, setNote] = useState<string | null>(null);

  async function sync() {
    setSyncing(true);
    setNote(null);
    try {
      const r = await api.syncMailbox(m.id);
      if (r.queued) {
        const queued = r.message ?? "Sync queued — new mail will be checked within a minute.";
        setNote(queued);
        toast.success(`${m.address}: ${queued}`);
        await onChanged();
        return;
      }
      const summary =
        r.fetched === 0
          ? "Synced — no new mail."
          : `Synced ${r.fetched} message${r.fetched === 1 ? "" : "s"}` +
            (r.alerted ? `, ${r.alerted} flagged` : "") +
            (r.quarantined ? `, ${r.quarantined} quarantined` : "") +
            ".";
      setNote(summary);
      if (r.alerted) toast.error(`${m.address}: ${summary}`);
      else toast.success(`${m.address}: ${summary}`);
      await onChanged();
    } catch (e) {
      const message =
        e instanceof ApiError ? e.message : "Could not sync this mailbox.";
      setNote(message);
      toast.error(message);
    } finally {
      setSyncing(false);
    }
  }

  return (
    <li className="px-5 py-3.5">
      <div className="flex items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{m.address}</p>
          <p className="fg-3 mono-xs mt-0.5">
            {connected
              ? m.sources.filter((s) => MAIL_SOURCES.has(s))[0].toUpperCase()
              : "UNCONNECTED"}{" "}
            · {m.mailbox_class.toUpperCase()}
            {m.last_sync_at && ` · SYNCED ${timeOf(m.last_sync_at)}`}
            {m.sync_pending && " · SYNC QUEUED"}
          </p>
          {m.backfill_state && <BackfillLine state={m.backfill_state} />}
        </div>
        {isImap && !m.needs_reconnect && (
          <button
            onClick={() => void sync()}
            disabled={syncing}
            title="Fetch new mail now"
            className="fg-2 inline-flex cursor-pointer items-center gap-1 rounded border border-[var(--line)] px-2 py-1 text-xs font-semibold transition-colors hover:text-[var(--fg)] disabled:opacity-50"
          >
            {syncing ? (
              <Loader2 size={12} className="animate-spin" aria-hidden />
            ) : (
              <RefreshCw size={12} aria-hidden />
            )}
            Sync
          </button>
        )}
        {connected && (
          <button
            onClick={() => void scanHistory()}
            disabled={scanning}
            title="Analyse recent history to learn suppliers, bank details and writing style"
            className="fg-2 inline-flex cursor-pointer items-center gap-1 rounded border border-[var(--line)] px-2 py-1 text-xs font-semibold transition-colors hover:text-[var(--fg)] disabled:opacity-50"
          >
            {scanning ? (
              <Loader2 size={12} className="animate-spin" aria-hidden />
            ) : (
              <Inbox size={12} aria-hidden />
            )}
            Scan history
          </button>
        )}
        <LevelChip level={m.protection_level} />
        <button
          onClick={() => void onRemove(m.id)}
          aria-label={`Remove ${m.address}`}
          title="Remove mailbox"
          className="fg-3 cursor-pointer p-1 transition-colors hover:text-[var(--danger)]"
        >
          <Trash2 size={14} aria-hidden />
        </button>
      </div>

      {m.needs_reconnect && (
        <div className="mt-2 flex items-start gap-2 rounded border border-[var(--danger)] bg-[var(--danger)]/10 px-3 py-2">
          <ShieldAlert size={14} className="mt-0.5 text-[var(--danger)]" aria-hidden />
          <p className="text-xs">
            <span className="font-semibold">Reconnect needed.</span>{" "}
            {m.connection_error ??
              "This mailbox can no longer be read — its stored password is invalid."}{" "}
            It looks connected but is not being protected until you reconnect it below.
          </p>
        </div>
      )}

      {/* A poll that failed for a transient reason (server unreachable, TLS
          hiccup) is not a reconnect prompt, but it must not be silent either:
          "connected" with no mail arriving is the worst state to hide. */}
      {!m.needs_reconnect && m.connection_error && (
        <div className="callout mt-2 flex items-start gap-2 px-3 py-2">
          <ShieldAlert size={14} className="mt-0.5 shrink-0" aria-hidden />
          <p className="text-xs leading-relaxed">
            <span className="font-semibold">Last sync didn&rsquo;t complete.</span>{" "}
            {m.connection_error} We keep retrying — press Sync to try now.
          </p>
        </div>
      )}

      {note && <p className="fg-2 mono-xs mt-2">{note}</p>}

      {/* Why this level, and exactly how to raise it — so "Standard" is never a
          bare word. Distinct from the billing plan (shown in the header). */}
      {connected && m.protection && !m.protection.is_max && m.protection.missing.length > 0 && (
        <details className="mt-2 rounded border border-[var(--line)] px-3 py-2">
          <summary className="fg-2 cursor-pointer text-xs font-semibold">
            {m.protection_level.toUpperCase()} protection — reach{" "}
            {m.protection.next_level?.toUpperCase()} →
          </summary>
          <ul className="mt-2 space-y-1.5" role="list">
            {m.protection.missing.map((g) => (
              <li key={g.capability} className="fg-3 text-xs">
                <span className="fg-2">{g.unlocks}</span> — {g.how}.
              </li>
            ))}
          </ul>
        </details>
      )}

      {m.inactive_detections.length > 0 && (
        <p className="fg-3 mono-xs mt-2">
          INACTIVE: {m.inactive_detections.slice(0, 6).join(" ")}
          {m.inactive_detections.length > 6 && " …"}
        </p>
      )}

      {(!connected || m.needs_reconnect) && (
        <MailboxConnect mailbox={m} onConnected={onChanged} />
      )}
      {connected && !m.needs_reconnect && <MailboxActivity mailboxId={m.id} />}
    </li>
  );
}

/* What the connection attempt actually did, and what to do about it.

   The old form said "could not reach the IMAP server" for a typo, a blocked
   port, a TLS mismatch and a provider that has switched password auth off —
   four different fixes behind one sentence. The server now returns a code, so
   this shows the specific remedy and, where the remedy is OAuth, the button
   that performs it. */
const IMAP_ERROR_ACTION: Record<string, string> = {
  dns_not_found: "Open server settings and press “Find my settings”.",
  timeout: "Open server settings and try STARTTLS on port 143.",
  connection_refused: "Open server settings and try the other port.",
  tls_error: "Open server settings and switch SSL/TLS ↔ STARTTLS.",
  certificate_error: "Use the exact server name your provider documents.",
  blocked_host: "Use your provider's public mail server name.",
};

function ImapProbeReport({
  result,
  onUseOauth,
  oauthAvailable,
}: {
  result: ImapProbeResult;
  onUseOauth: () => void;
  oauthAvailable: boolean;
}) {
  const [detail, setDetail] = useState(false);

  if (result.ok) {
    return (
      <div className="border border-[var(--ok)] p-3" role="status">
        <p className="flex items-start gap-1.5 text-xs leading-relaxed text-[var(--ok)]">
          <Check size={13} className="mt-0.5 shrink-0" aria-hidden />
          <span>
            Signed in. Using{" "}
            <span className="font-mono">
              {result.settings?.host}:{result.settings?.port}
            </span>{" "}
            ({result.settings?.security === "ssl" ? "SSL/TLS" : result.settings?.security}
            ) as <span className="font-mono">{result.username}</span>.
          </span>
        </p>
      </div>
    );
  }

  const error = result.error;
  const suggestsOauth =
    error?.code === "oauth_required" || error?.code === "app_password_required";

  return (
    <div className="border border-[var(--danger)] p-3" role="alert">
      <p className="flex items-start gap-1.5 text-xs leading-relaxed text-[var(--danger)]">
        <X size={13} className="mt-0.5 shrink-0" aria-hidden />
        <span className="font-semibold">{error?.message ?? "Could not connect."}</span>
      </p>
      {error?.hint && (
        <p className="fg-2 mt-1.5 pl-[18px] text-xs leading-relaxed">{error.hint}</p>
      )}
      {error && IMAP_ERROR_ACTION[error.code] && (
        <p className="fg-3 mono-xs mt-1.5 pl-[18px]">
          {IMAP_ERROR_ACTION[error.code]}
        </p>
      )}
      {suggestsOauth && oauthAvailable && (
        <div className="mt-2.5 pl-[18px]">
          <Button size="sm" variant="accent" onClick={onUseOauth}>
            <Link2 size={12} aria-hidden /> CONNECT WITH OAUTH INSTEAD
          </Button>
        </div>
      )}
      {result.attempts.length > 0 && (
        <div className="mt-2.5 pl-[18px]">
          <button
            type="button"
            onClick={() => setDetail((d) => !d)}
            aria-expanded={detail}
            className="fg-3 mono-xs cursor-pointer hover:text-[var(--fg)]"
          >
            {detail ? "HIDE" : "SHOW"} WHAT WE TRIED ({result.attempts.length})
          </button>
          {detail && (
            <ul className="fg-3 mono-xs mt-1.5 space-y-1" role="list">
              {result.attempts.map((a, i) => (
                <li key={`${a.host}:${a.port}:${i}`} className="break-all">
                  {a.ok ? "✓" : "✗"} {a.host}:{a.port} ·{" "}
                  {a.security === "ssl" ? "SSL" : a.security.toUpperCase()} ·{" "}
                  {a.username}
                  {a.error ? ` — ${a.error.code}` : ""}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

/* Connect a mailbox using the RIGHT method for its actual mail provider — detected
   from the domain's MX records, not from whichever OAuth apps this deployment
   happens to have configured. A Google/Microsoft domain gets one-click OAuth; any
   other provider (ISP, custom domain) connects over IMAP with an app password, or
   by forwarding a copy. This is the fix for "Connect Google" showing on a domain
   that isn't on Google. */
function MailboxConnect({
  mailbox,
  onConnected,
}: {
  mailbox: MailboxRecord;
  onConnected: () => Promise<void>;
}) {
  const address = mailbox.address;
  const emailDomain = address.split("@")[1] ?? "";
  const [plan, setPlan] = useState<ConnectionPlan | null>(null);
  const [configured, setConfigured] = useState<string[]>([]);
  const [mode, setMode] = useState<"imap" | "forward" | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  // IMAP form
  const [host, setHost] = useState("");
  const [port, setPort] = useState(993);
  const [security, setSecurity] = useState<"ssl" | "starttls" | "none">("ssl");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [ingest, setIngest] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [advanced, setAdvanced] = useState(false);
  const [detected, setDetected] = useState<string | null>(null);
  const [probe, setProbe] = useState<ImapProbeResult | null>(null);
  // A certificate the server presented that we refused. Held here, not acted
  // on: the customer decides, after seeing what it actually says.
  const [certificate, setCertificate] = useState<ImapCertificate | null>(null);
  const [trustCertificate, setTrustCertificate] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .connect(emailDomain)
      .then((p) => {
        if (!live) return;
        setPlan(p);
        if (p.imap.host) setHost(p.imap.host);
        setPort(p.imap.port || 993);
      })
      .catch(() => {});
    api
      .oauthProviders()
      .then((r) => live && setConfigured(r.configured))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [emailDomain]);

  async function oauth(provider: string) {
    setBusy(provider);
    try {
      const { authorize_url } = await api.oauthAuthorize(provider, address);
      window.location.assign(authorize_url);
    } catch (e) {
      setBusy(null);
      setNote(
        e instanceof ApiError ? e.message : "Could not start connection.",
      );
    }
  }

  // The server is optional: blank means "detect it". When the user has typed
  // one we send it, and the backend still falls back to the alternatives if it
  // does not answer — unless they have pinned it under Advanced.
  const imapBody = (): ImapConnectBody => ({
    password,
    // Whatever server is in the form is tried FIRST either way. The difference
    // is the fallback: with the panel closed we also try the alternatives we
    // discover, with it open we use exactly what was typed.
    ...(host ? { imap_host: host, imap_port: port, security } : {}),
    username: username.trim() || undefined,
    ...(trustCertificate && certificate
      ? { accept_certificate_sha256: certificate.sha256 }
      : {}),
    // Pin to exactly these settings only when a server was actually typed.
    // `!advanced` alone meant that merely opening the panel — which now happens
    // automatically after a failure — sent no host with autodiscover off, and
    // the backend correctly refused that with a 422.
    autodiscover: !(advanced && host.trim()),
  });

  // Detect the server from the address — no password needed. This is the step
  // that removes the guesswork most failed connections come from.
  async function findSettings() {
    setBusy("detect");
    setNote(null);
    try {
      const r = await api.imapSettings(mailbox.id);
      if (r.settings) {
        setHost(r.settings.host);
        setPort(r.settings.port);
        setSecurity(r.settings.security);
        setDetected(r.detected ? r.note : r.note);
      } else {
        setNote(
          "We could not detect your mail server. Enter it from your provider's help page.",
        );
      }
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not detect settings.");
    } finally {
      setBusy(null);
    }
  }

  // A failed connection is exactly the moment someone needs the server fields,
  // and until now it was the one moment the form did not show them: the error
  // was printed and the panel stayed shut, leaving no visible way to type the
  // settings from their provider's help page. Open it, and prefill our best
  // guess so they are correcting a value rather than starting from a blank box.
  async function revealManualSettings() {
    setAdvanced(true);
    if (host.trim()) return;
    try {
      const r = await api.imapSettings(mailbox.id);
      if (r.settings) {
        setHost(r.settings.host);
        setPort(r.settings.port);
        setSecurity(r.settings.security);
        setDetected(r.note);
      }
    } catch {
      // Prefilling is a convenience; the empty fields are still usable.
    }
  }

  // Verify the settings without saving — lets the user get the config right
  // before committing the mailbox.
  async function testImap() {
    if (!password) {
      setNote("Enter the mailbox password first.");
      return;
    }
    setBusy("test");
    setNote(null);
    setProbe(null);
    try {
      const r = await api.testImap(mailbox.id, imapBody());
      setProbe(r);
      // A successful probe may have landed on different settings than were
      // typed; show what actually worked so the form matches reality.
      if (r.ok && r.settings) {
        setHost(r.settings.host);
        setPort(r.settings.port);
        setSecurity(r.settings.security);
      } else if (!r.ok) {
        if (r.certificate) {
          setCertificate(r.certificate);
          setTrustCertificate(false);
          setAdvanced(true);
        } else {
          // The ladder was tried and nothing answered. Hand over the controls.
          await revealManualSettings();
        }
      }
    } catch (e) {
      setProbe({
        ok: false,
        settings: null,
        username: null,
        error: {
          code: "unknown",
          message: e instanceof ApiError ? e.message : "Test failed.",
          hint: "",
          detail: "",
        },
        attempts: [],
        reason: "",
      });
      await revealManualSettings();
    } finally {
      setBusy(null);
    }
  }

  async function submitImap() {
    if (!password) {
      setNote("Enter the mailbox password or app password.");
      return;
    }
    setBusy("imap");
    setNote(null);
    try {
      const r = await api.connectImap(mailbox.id, imapBody());
      setPassword("");
      setMode(null);
      setProbe(null);
      toast.success(
        r.imap
          ? `Connected ${mailbox.address} on ${r.imap.host}:${r.imap.port}.`
          : `Connected ${mailbox.address}.`,
      );
      await onConnected();
    } catch (e) {
      const cert = e instanceof ApiError ? e.certificate : null;
      if (cert) {
        // A certificate problem has its own remedy, and telling them to go and
        // check the host and port would send them looking in the wrong place.
        setCertificate(cert);
        setTrustCertificate(false);
        setNote(e instanceof ApiError ? e.message : "Could not connect.");
        setAdvanced(true);
      } else {
        setNote(
          (e instanceof ApiError ? e.message : "Could not connect.") +
            " Enter your server details below — your mail provider's help pages " +
            "list them under IMAP settings.",
        );
        await revealManualSettings();
      }
    } finally {
      setBusy(null);
    }
  }

  async function openForward() {
    setMode("forward");
    if (ingest === null) {
      try {
        setIngest((await api.ingestAddress()).ingest_address);
      } catch {
        setIngest("");
      }
    }
  }

  function copyIngest() {
    if (!ingest) return;
    void navigator.clipboard.writeText(ingest);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // The user confirms they've set the forwarding rule — record it so the mailbox
  // reads as covered (alert-only) instead of leaving the address sitting there.
  async function markForwarding() {
    setBusy("forward");
    setNote(null);
    try {
      await api.connectForward(mailbox.id);
      setMode(null);
      await onConnected();
    } catch (e) {
      setNote(
        e instanceof ApiError ? e.message : "Could not confirm forwarding.",
      );
    } finally {
      setBusy(null);
    }
  }

  const rec = plan?.recommended.id ?? "";
  const providerName = plan?.provider.name ?? null;
  const isMs = rec === "oauth_microsoft" && configured.includes("microsoft");
  const isGoogle = rec === "oauth_google" && configured.includes("google");

  return (
    <div className="mt-2.5">
      {providerName && plan?.detected && (
        <p className="fg-3 mono-xs mb-2">DETECTED: {providerName}</p>
      )}
      <div className="flex flex-wrap gap-2">
        {/* One-click OAuth only when the domain really is on that provider. */}
        {isMs && (
          <Button
            size="sm"
            variant="line"
            disabled={busy !== null}
            onClick={() => oauth("microsoft")}
          >
            <Link2 size={12} aria-hidden /> Connect Microsoft&nbsp;365
          </Button>
        )}
        {isGoogle && (
          <Button
            size="sm"
            variant="line"
            disabled={busy !== null}
            onClick={() => oauth("google")}
          >
            <Link2 size={12} aria-hidden /> Connect Google
          </Button>
        )}
        {/* IMAP works on any provider — the universal path for ISP / custom mail. */}
        <Button
          size="sm"
          variant={isMs || isGoogle ? "quiet" : "line"}
          disabled={busy !== null}
          onClick={() => setMode(mode === "imap" ? null : "imap")}
        >
          <KeyRound size={12} aria-hidden /> Connect via IMAP
        </Button>
        <Button
          size="sm"
          variant="line"
          disabled={busy !== null}
          aria-pressed={mode === "forward"}
          onClick={() =>
            mode === "forward" ? setMode(null) : void openForward()
          }
        >
          <Forward size={12} aria-hidden /> Forwarding
        </Button>
      </div>

      {mode === "imap" && (
        <div className="mt-3 space-y-3 border-l-2 border-[var(--accent)] pl-3">
          {/* The password is what the customer HAS; the server is what we can
              work out. So it comes first, and the server settings are tucked
              behind "Advanced" unless detection needs correcting. */}
          <div>
            <label htmlFor={`imap-pw-${mailbox.id}`} className="fg-3 mono-xs block">
              MAILBOX PASSWORD
            </label>
            <div className="relative mt-1">
              <input
                id={`imap-pw-${mailbox.id}`}
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="app password or mailbox password"
                className="field w-full pr-16 text-sm"
                autoComplete="off"
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="fg-3 mono-xs absolute inset-y-0 right-2 my-auto h-5 cursor-pointer hover:text-[var(--fg)]"
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? "HIDE" : "SHOW"}
              </button>
            </div>
            <p className="fg-3 mt-1.5 text-xs leading-relaxed">
              We work out your mail server automatically. If the first one
              doesn&rsquo;t answer, we try the alternatives before giving up.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="accent"
              disabled={busy !== null}
              onClick={submitImap}
            >
              {busy === "imap" ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : null}{" "}
              CONNECT MAILBOX
            </Button>
            <Button size="sm" variant="line" disabled={busy !== null} onClick={testImap}>
              {busy === "test" ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : null}{" "}
              TEST FIRST
            </Button>
            <button
              type="button"
              onClick={() => setAdvanced((v) => !v)}
              aria-expanded={advanced}
              className="fg-3 mono-xs cursor-pointer hover:text-[var(--fg)]"
            >
              {advanced ? "HIDE SERVER SETTINGS" : "SERVER SETTINGS"}
            </button>
          </div>

          {certificate && (
            <div className="space-y-2 border-t pt-3">
              <div className="mono-xs" style={{ color: "var(--danger, #d33)" }}>
                THIS SERVER&rsquo;S CERTIFICATE WAS NOT ACCEPTED
              </div>
              <p className="text-xs leading-relaxed">{certificate.summary}</p>

              <dl className="mono-xs grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
                <dt className="fg-3">YOU CONNECTED TO</dt>
                <dd className="break-all">{certificate.host}</dd>
                <dt className="fg-3">VALID FOR</dt>
                <dd className="break-all">
                  {certificate.names.length
                    ? certificate.names.join(", ")
                    : "no host names"}
                </dd>
                <dt className="fg-3">ISSUED BY</dt>
                <dd className="break-all">
                  {certificate.self_signed ? "itself (self-signed)" : certificate.issuer}
                </dd>
                <dt className="fg-3">EXPIRES</dt>
                <dd>{certificate.not_after}</dd>
                <dt className="fg-3">FINGERPRINT</dt>
                <dd className="break-all">{certificate.sha256}</dd>
              </dl>

              {/* The genuine fix comes first. Connecting by a name the
                  certificate already covers needs no exception at all, and on
                  shared hosting it is what the provider documents. */}
              {certificate.names.length > 0 && !certificate.expired && (
                <p className="fg-3 text-xs leading-relaxed">
                  Best fix: put{" "}
                  <button
                    type="button"
                    className="accent cursor-pointer underline"
                    onClick={() => {
                      setHost(certificate.names[0].replace(/^\*\./, "mail."));
                      setCertificate(null);
                      setTrustCertificate(false);
                    }}
                  >
                    {certificate.names[0]}
                  </button>{" "}
                  in the server box above instead. Then nothing needs trusting.
                </p>
              )}

              <label className="flex cursor-pointer items-start gap-2 text-xs leading-relaxed">
                <input
                  type="checkbox"
                  checked={trustCertificate}
                  onChange={(e) => setTrustCertificate(e.target.checked)}
                  className="mt-0.5"
                />
                <span>
                  Trust <strong>this exact certificate</strong> for this mailbox.
                  {certificate.expired ? (
                    <span className="block">
                      This one has expired — ask whoever runs the server to renew
                      it rather than trusting it.
                    </span>
                  ) : (
                    <span className="fg-3 block">
                      We will check every future connection is the same
                      certificate, byte for byte. If it ever changes, we stop and
                      tell you — so this is narrower than it sounds, not a
                      blanket exception.
                    </span>
                  )}
                </span>
              </label>
            </div>
          )}

          {advanced && (
            <div className="space-y-2 border-t pt-3">
              <div className="flex items-center justify-between gap-2">
                <label htmlFor={`imap-host-${mailbox.id}`} className="fg-3 mono-xs">
                  IMAP SERVER &amp; PORT
                </label>
                <button
                  type="button"
                  onClick={findSettings}
                  disabled={busy !== null}
                  className="accent mono-xs cursor-pointer hover:underline disabled:opacity-50"
                >
                  {busy === "detect" ? "DETECTING…" : "FIND MY SETTINGS"}
                </button>
              </div>
              <div className="flex gap-2">
                <input
                  id={`imap-host-${mailbox.id}`}
                  value={host}
                  onChange={(e) => {
                    setHost(e.target.value);
                    // A different server means a different certificate; an
                    // approval must never survive the thing it applied to.
                    setCertificate(null);
                    setTrustCertificate(false);
                  }}
                  placeholder="detected automatically"
                  className="field min-w-0 flex-1 text-sm"
                  autoComplete="off"
                  aria-label="IMAP host"
                />
                <input
                  value={port}
                  onChange={(e) => setPort(Number(e.target.value) || 0)}
                  inputMode="numeric"
                  className="field w-20 shrink-0 text-sm"
                  aria-label="IMAP port"
                />
              </div>
              {detected && <p className="fg-3 text-xs leading-relaxed">{detected}</p>}

              <label className="fg-3 mono-xs block">SECURITY</label>
              <div className="flex gap-px" role="group" aria-label="Transport security">
                {(
                  [
                    ["ssl", "SSL/TLS", 993],
                    ["starttls", "STARTTLS", 143],
                    ["none", "NONE", 143],
                  ] as const
                ).map(([val, label, defPort]) => (
                  <button
                    key={val}
                    type="button"
                    onClick={() => {
                      setSecurity(val);
                      setPort(defPort); // sensible default; still editable
                    }}
                    aria-pressed={security === val}
                    className={cn(
                      "font-mono flex-1 cursor-pointer border px-2 py-1.5 text-[11px] tracking-wide transition-colors",
                      security === val
                        ? "accent border-[var(--accent)]"
                        : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
                    )}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <label htmlFor={`imap-user-${mailbox.id}`} className="fg-3 mono-xs block">
                USERNAME
              </label>
              <input
                id={`imap-user-${mailbox.id}`}
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder={address}
                className="field text-sm"
                autoComplete="off"
                aria-label="IMAP username"
              />
              <p className="fg-3 text-xs leading-relaxed">
                With server settings open we use exactly these — no fallback.
                Close this panel to let us find a working server for you.
              </p>
            </div>
          )}

          {probe && <ImapProbeReport result={probe} onUseOauth={() => oauth(
            plan?.provider.id === "google" ? "google" : "microsoft",
          )} oauthAvailable={isMs || isGoogle} />}
        </div>
      )}

      {mode === "forward" && (
        <div className="mt-3 space-y-2.5 border-l-2 border-[var(--accent)] pl-3">
          <p className="fg-3 text-xs leading-relaxed">
            In your mail provider, forward a copy of inbound mail to this
            address. Works on every provider — alert-only, no quarantine.
          </p>
          <div className="flex items-center gap-2">
            <code className="font-mono flex-1 text-xs break-all">
              {ingest || "…"}
            </code>
            <Button
              size="sm"
              variant="line"
              onClick={copyIngest}
              disabled={!ingest}
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
          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <Button
              size="sm"
              variant="accent"
              disabled={busy !== null || !ingest}
              onClick={markForwarding}
            >
              {busy === "forward" ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : (
                <Check size={12} aria-hidden />
              )}
              I'VE SET UP FORWARDING
            </Button>
            <Button
              size="sm"
              variant="quiet"
              onClick={() => setMode(null)}
              disabled={busy !== null}
            >
              CANCEL
            </Button>
          </div>
          <p className="fg-3 text-[11px] leading-relaxed">
            Marking this done sets the mailbox to{" "}
            <span className="font-semibold">Limited</span> (alert-only) coverage
            — forwarding arrives after delivery, so it can warn but not
            quarantine. Connect via IMAP or OAuth for full protection.
          </p>
        </div>
      )}

      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}

      {/* The way out when IMAP simply will not work.
          Some mailboxes cannot be reached over IMAP at all — the provider has
          switched it off, a firewall blocks it, or it only speaks an
          authentication mechanism we do not. Forwarding needs none of that:
          the customer adds a rule in whatever mail system they already have,
          so no mailbox is ever out of reach. It is offered only after a
          failure, because it protects less than a real connection and should
          not tempt anyone away from the better option first. */}
      {note && mode === "imap" && (
        <p className="fg-3 mt-2 text-xs leading-relaxed">
          Still no luck? You can{" "}
          <button
            type="button"
            className="accent cursor-pointer underline"
            onClick={() => {
              setNote(null);
              setCertificate(null);
              void openForward();
            }}
          >
            forward this mailbox to Envelock instead
          </button>
          . It works with any mail system and needs no password — though it can
          only alert you, not quarantine a message or rewrite its links.
        </p>
      )}
    </div>
  );
}

/* Plan / trial state at a glance. Guard is free forever (no countdown); a paid
   trial shows days remaining and turns amber, then red, as it runs out. */
function PlanBadge({ tenant }: { tenant: TenantInfo }) {
  const { plan, trial } = tenant;
  let text: string;
  let tone = "border-[var(--rule)] fg-2";

  let title: string | undefined;

  if (trial.active && trial.days_left !== null) {
    text = `TRIAL · ${trial.days_left} DAY${trial.days_left === 1 ? "" : "S"} LEFT`;
    tone =
      trial.days_left <= 3
        ? "border-[var(--danger)] text-[var(--danger)]"
        : "border-[var(--warn,#d97706)] text-[var(--warn,#d97706)]";
    const top = (tenant.subscribed_plan ?? "complete").toUpperCase();
    title = `${top} plan free until ${new Date(trial.ends_at!).toLocaleDateString()}. Add billing to keep it.`;
  } else if (tenant.trial_ended) {
    text = "TRIAL ENDED · ON GUARD";
    tone = "border-[var(--warn,#d97706)] text-[var(--warn,#d97706)]";
    title =
      "Your trial ended — now on Guard (free). Add billing to restore full protection.";
  } else if (plan === "guard") {
    text = "GUARD · FREE";
    tone = "border-[var(--accent)] accent";
    title = "Guard is free forever — Channel-3 domain & brand monitoring.";
  } else {
    text = `${plan.toUpperCase()}${trial.payment_method_ok ? "" : " · SET UP BILLING"}`;
  }

  return (
    <span
      className={cn(
        "font-mono rounded border px-2 py-0.5 text-[10px] font-semibold tracking-wide",
        tone,
      )}
      title={title}
    >
      {text}
    </span>
  );
}

/* Split a pasted blob of addresses on commas, spaces or new lines — however IT
   copied them out of a spreadsheet or admin console. */
function parseAddresses(blob: string): string[] {
  return Array.from(
    new Set(
      blob
        .split(/[\s,;]+/)
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean),
    ),
  );
}

function ClassPicker({
  klass,
  onChange,
}: {
  klass: "protected" | "monitored";
  onChange: (c: "protected" | "monitored") => void;
}) {
  return (
    <>
      <div className="flex gap-px" role="group" aria-label="Mailbox class">
        {(["protected", "monitored"] as const).map((c) => (
          <button
            key={c}
            type="button"
            onClick={() => onChange(c)}
            aria-pressed={klass === c}
            className={cn(
              "font-mono flex-1 cursor-pointer border px-2 py-1.5 text-[11px] tracking-wide uppercase transition-colors",
              klass === c
                ? "accent border-[var(--accent)]"
                : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
            )}
          >
            {c}
          </button>
        ))}
      </div>
      <p className="fg-3 mt-1.5 text-xs">
        {klass === "protected"
          ? "Full content + fraud detection — finance, execs, anyone who touches money."
          : "Account-takeover detection only — cheaper, for everyone else."}
      </p>
    </>
  );
}

/* Connect many IMAP mailboxes in one pass. The IMAP *server* settings (host, port,
   security) are the same for every mailbox on a domain, so they're entered once at
   the top and auto-detected from the provider; only the per-mailbox app-password —
   which genuinely differs per account — is typed per row. This is the "don't retype
   the server config for all 50 boxes" path; one-off connects still use MailboxRow. */
function BulkImapConnect({
  mailboxes,
  domain,
  onDone,
}: {
  mailboxes: MailboxRecord[];
  domain: string | null;
  onDone: () => Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(993);
  const [security, setSecurity] = useState<"ssl" | "starttls" | "none">("ssl");
  const [showPw, setShowPw] = useState(false);
  const [pw, setPw] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<Record<string, { ok: boolean; msg: string }>>(
    {},
  );
  const [note, setNote] = useState<string | null>(null);

  // Auto-detect the domain's IMAP server so the shared settings are prefilled.
  useEffect(() => {
    if (!domain || !open) return;
    let live = true;
    api
      .connect(domain)
      .then((p) => {
        if (!live) return;
        if (p.imap.host) setHost(p.imap.host);
        if (p.imap.port) setPort(p.imap.port);
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [domain, open]);

  const withPw = mailboxes.filter((m) => (pw[m.id] ?? "").trim().length > 0);

  async function connectAll() {
    if (withPw.length === 0) {
      setNote("Enter the app-password for at least one mailbox.");
      return;
    }
    setBusy(true);
    setNote(null);
    const next: Record<string, { ok: boolean; msg: string }> = {};
    for (const m of withPw) {
      try {
        // The shared server is a starting point, not a constraint: each mailbox
        // falls back to its own discovered settings if this one doesn't answer,
        // so one wrong shared guess no longer fails the whole batch.
        const r = await api.connectImap(m.id, {
          ...(host ? { imap_host: host, imap_port: port, security } : {}),
          username: m.address,
          password: pw[m.id].trim(),
        });
        next[m.id] = {
          ok: true,
          msg: r.imap ? `connected · ${r.imap.host}:${r.imap.port}` : "connected",
        };
      } catch (e) {
        next[m.id] = {
          ok: false,
          msg: e instanceof ApiError ? e.message : "connection failed",
        };
      }
    }
    setResults(next);
    setBusy(false);
    const ok = Object.values(next).filter((r) => r.ok).length;
    const failed = Object.values(next).length - ok;
    if (failed === 0) toast.success(`Connected ${ok} mailbox${ok === 1 ? "" : "es"}.`);
    else if (ok === 0) toast.error(`None connected — ${failed} failed. See the reasons below.`);
    else toast.info(`Connected ${ok}; ${failed} failed. See the reasons below.`);
    await onDone();
  }

  if (mailboxes.length < 2) return null; // one-off connects use the per-row form

  if (!open) {
    return (
      <div className="border-t p-4">
        <Button
          size="sm"
          variant="line"
          className="w-full"
          onClick={() => setOpen(true)}
        >
          <KeyRound size={13} aria-hidden /> CONNECT {mailboxes.length} OVER IMAP AT
          ONCE
        </Button>
        <p className="fg-3 mt-2 text-xs leading-relaxed">
          Set the IMAP server once for the whole domain; enter each mailbox's own
          app-password. No re-typing host and port per mailbox.
        </p>
      </div>
    );
  }

  return (
    <div className="border-t p-4">
      <div className="space-y-2 border-l-2 border-[var(--accent)] pl-3">
        <label className="fg-3 mono-xs block">IMAP SERVER &amp; PORT (all mailboxes)</label>
        <div className="flex gap-2">
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="detected automatically"
            className="field flex-1 text-sm"
            autoComplete="off"
            aria-label="IMAP host"
          />
          <input
            value={port}
            onChange={(e) => setPort(Number(e.target.value) || 0)}
            inputMode="numeric"
            className="field w-20 text-sm"
            aria-label="IMAP port"
          />
        </div>
        <div className="flex gap-px" role="group" aria-label="Transport security">
          {(
            [
              ["ssl", "SSL/TLS", 993],
              ["starttls", "STARTTLS", 143],
              ["none", "NONE", 143],
            ] as const
          ).map(([val, label, defPort]) => (
            <button
              key={val}
              type="button"
              onClick={() => {
                setSecurity(val);
                setPort(defPort);
              }}
              aria-pressed={security === val}
              className={cn(
                "font-mono flex-1 cursor-pointer border px-2 py-1.5 text-[11px] tracking-wide transition-colors",
                security === val
                  ? "accent border-[var(--accent)]"
                  : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
              )}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="mt-3 flex items-center justify-between">
        <label className="fg-3 mono-xs block">APP-PASSWORD PER MAILBOX</label>
        <button
          type="button"
          onClick={() => setShowPw((s) => !s)}
          className="fg-3 mono-xs cursor-pointer hover:text-[var(--fg)]"
        >
          {showPw ? "HIDE" : "SHOW"}
        </button>
      </div>
      <p className="fg-3 mt-1 text-xs leading-relaxed">
        Most providers need an app-specific password (not the normal one) once
        two-factor is on. Leave a box blank to skip it for now.
      </p>
      <ul className="mt-2 space-y-1.5" role="list">
        {mailboxes.map((m) => {
          const r = results[m.id];
          return (
            <li key={m.id} className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate text-sm" title={m.address}>
                {m.address}
              </span>
              <input
                type={showPw ? "text" : "password"}
                value={pw[m.id] ?? ""}
                onChange={(e) =>
                  setPw((prev) => ({ ...prev, [m.id]: e.target.value }))
                }
                placeholder="app-password"
                className="field h-8 w-40 text-sm"
                autoComplete="off"
                aria-label={`App-password for ${m.address}`}
                disabled={r?.ok}
              />
              {r &&
                (r.ok ? (
                  <Check size={14} className="shrink-0 text-emerald-500" aria-label="connected" />
                ) : (
                  <span
                    className="shrink-0 text-[11px] text-red-600"
                    title={r.msg}
                  >
                    failed
                  </span>
                ))}
            </li>
          );
        })}
      </ul>

      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}

      <div className="mt-3 flex gap-2">
        <Button size="sm" variant="accent" onClick={connectAll} disabled={busy}>
          {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : null}
          {busy ? "CONNECTING…" : `CONNECT ${withPw.length || ""}`.trim()}
        </Button>
        <Button size="sm" variant="quiet" onClick={() => setOpen(false)} disabled={busy}>
          DONE
        </Button>
      </div>
    </div>
  );
}

/* Add mailboxes to the tenant — how IT brings whole departments under protection.
   A 50-seat domain is not added one box at a time, so this defaults to a bulk
   paste; a single-address mode stays for the one-off. */
function AddMailbox({
  onAdded,
  mailboxes,
}: {
  onAdded: () => Promise<void>;
  mailboxes?: TenantInfo["mailboxes"];
}) {
  const full = mailboxes ? !mailboxes.can_add : false;
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"many" | "one">("many");
  const [address, setAddress] = useState("");
  const [blob, setBlob] = useState("");
  const [klass, setKlass] = useState<"protected" | "monitored">("protected");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [result, setResult] = useState<{
    added: number;
    skipped: number;
    overLimit: number;
  } | null>(null);

  const parsed = mode === "many" ? parseAddresses(blob) : [];
  // Seats still free on the plan. Used to warn BEFORE submitting that a big paste
  // won't all fit, rather than letting the server silently skip the overflow.
  const seatsLeft = mailboxes
    ? Math.max(0, mailboxes.capacity - mailboxes.used)
    : null;
  const overBy =
    mode === "many" && seatsLeft !== null ? Math.max(0, parsed.length - seatsLeft) : 0;

  async function submitOne() {
    if (!address.includes("@")) {
      setNote("Enter a full email address.");
      return;
    }
    setBusy(true);
    setNote(null);
    try {
      await api.addMailbox({
        address: address.trim(),
        mailbox_class: klass,
        sources: [],
      });
      setAddress("");
      setOpen(false);
      await onAdded();
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not add mailbox.");
    } finally {
      setBusy(false);
    }
  }

  async function submitMany() {
    if (parsed.length === 0) {
      setNote("Paste one or more email addresses.");
      return;
    }
    setBusy(true);
    setNote(null);
    setResult(null);
    try {
      const r = await api.addMailboxesBulk({
        addresses: parsed,
        mailbox_class: klass,
      });
      setResult({
        added: r.created_count,
        skipped: r.skipped_count,
        overLimit: r.over_limit_count,
      });
      setBlob("");
      await onAdded();
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not add mailboxes.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <div className="border-t p-4">
        {mailboxes && (
          <div className="mb-3 flex items-center justify-between gap-2">
            <span className="fg-3 mono-xs tnum">
              {mailboxes.used} / {mailboxes.capacity} SEATS USED
            </span>
            {mailboxes.extra_seats > 0 && (
              <span className="fg-3 mono-xs">+{mailboxes.extra_seats} bought</span>
            )}
          </div>
        )}
        {full ? (
          <div className="callout p-3">
            <p className="text-xs font-semibold">
              {mailboxes && mailboxes.capacity === 0
                ? "Your plan can't protect mailboxes"
                : `All ${mailboxes?.capacity ?? ""} mailbox seats are in use`}
            </p>
            <p className="fg-2 mt-1 text-[11px] leading-relaxed">
              {mailboxes && mailboxes.capacity === 0
                ? "Upgrade to Essential or Complete to protect mailboxes."
                : "Buy more seats (or upgrade your plan) to add another mailbox."}
            </p>
            <Link to="/billing" className="mt-2 inline-block">
              <Button size="sm" variant="accent">
                {mailboxes && mailboxes.capacity === 0 ? "UPGRADE" : "BUY SEATS"}
              </Button>
            </Link>
          </div>
        ) : (
          <>
            <Button
              size="sm"
              variant="line"
              className="w-full"
              onClick={() => setOpen(true)}
            >
              <Plus size={13} aria-hidden /> ADD MAILBOXES
            </Button>
            <p className="fg-3 mt-2 text-xs leading-relaxed">
              Paste your whole finance team or the full domain at once.
              Microsoft&nbsp;365 and Google can import the entire organisation with
              one admin consent; other providers connect per mailbox after adding.
            </p>
          </>
        )}
      </div>
    );
  }

  return (
    <div className="border-t p-4">
      <div className="mb-3 flex gap-px" role="group" aria-label="Add mode">
        {(["many", "one"] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => {
              setMode(m);
              setNote(null);
              setResult(null);
            }}
            aria-pressed={mode === m}
            className={cn(
              "font-mono flex-1 cursor-pointer border px-2 py-1.5 text-[11px] tracking-wide uppercase transition-colors",
              mode === m
                ? "accent border-[var(--accent)]"
                : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
            )}
          >
            {m === "many" ? "Paste many" : "One address"}
          </button>
        ))}
      </div>

      {mode === "many" ? (
        <>
          <label
            className="block text-xs font-semibold"
            htmlFor="bulk-mailboxes"
          >
            Email addresses
          </label>
          <textarea
            id="bulk-mailboxes"
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
            rows={5}
            placeholder={
              "finance@yourcompany.com\nexecs@yourcompany.com\naccounts@yourcompany.com"
            }
            spellCheck={false}
            className="field mt-1.5 h-auto resize-y py-2 text-sm leading-relaxed"
          />
          <p className="fg-3 mt-1 text-xs">
            {parsed.length > 0
              ? `${parsed.length} address${parsed.length === 1 ? "" : "es"}${
                  seatsLeft !== null ? ` · ${seatsLeft} seat${seatsLeft === 1 ? "" : "s"} left` : ""
                } — separated by commas, spaces or new lines.`
              : "Paste from a spreadsheet — commas, spaces or new lines all work."}
          </p>
          {overBy > 0 && (
            <p className="mt-1 text-xs font-medium text-amber-600 dark:text-amber-400">
              That's {overBy} more than your {seatsLeft} remaining seat
              {seatsLeft === 1 ? "" : "s"}. The first {seatsLeft} will be added; the
              rest are skipped until you buy more seats.
            </p>
          )}
        </>
      ) : (
        <>
          <label className="block text-xs font-semibold" htmlFor="new-mailbox">
            Mailbox address
          </label>
          <input
            id="new-mailbox"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="accounts@yourcompany.com"
            autoComplete="off"
            className="field mt-1.5 text-sm"
          />
        </>
      )}

      <div className="mt-3">
        <ClassPicker klass={klass} onChange={setKlass} />
      </div>

      {result && (
        <p className="accent mt-2 text-xs font-semibold">
          Added {result.added}
          {result.skipped > 0 && (
            <span className="fg-3 font-normal">
              {" "}
              · skipped {result.skipped}
              {result.overLimit > 0
                ? ` (${result.overLimit} need more seats, the rest already added, invalid or unverified)`
                : " (already added, invalid or on an unverified domain)"}
            </span>
          )}
        </p>
      )}
      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}

      <div className="mt-3 flex gap-2">
        <Button
          size="sm"
          variant="accent"
          onClick={mode === "many" ? submitMany : submitOne}
          disabled={busy || (mode === "many" && parsed.length === 0)}
        >
          {busy ? (
            <Loader2 size={12} className="animate-spin" aria-hidden />
          ) : null}
          {mode === "many" ? `ADD ${parsed.length || ""}`.trim() : "ADD"}
        </Button>
        <Button
          size="sm"
          variant="quiet"
          onClick={() => setOpen(false)}
          disabled={busy}
        >
          {result ? "DONE" : "CANCEL"}
        </Button>
      </div>
    </div>
  );
}

/* The two numbers that decide whether the product survives (PRD §15.4): if
   Critical false positives climb, the interrupt gets muted; if detonation
   fall-through climbs, so does COGS. Shown from live data, honestly blank until
   there is any. */
function GoverningMetrics() {
  const [metrics, setMetrics] = useState<QualityMetric[] | null>(null);

  useEffect(() => {
    api
      .qualityMetrics()
      .then((r) => setMetrics(r.metrics))
      .catch(() => setMetrics(null));
  }, []);

  if (!metrics) return null;

  const fmt = (m: QualityMetric): string => {
    if (m.observed === null) return "—";
    return m.unit === "ratio"
      ? `${(m.observed * 100).toFixed(1)}%`
      : String(m.observed);
  };

  return (
    <div className="panel p-5">
      <h2 className="sect-label">Detection quality</h2>
      <p className="fg-3 mt-1 text-xs leading-relaxed">
        The two numbers that govern the product, measured live
      </p>
      <ul className="mt-4 space-y-2.5" role="list">
        {metrics.map((m) => (
          <li
            key={m.id}
            className="flex items-baseline justify-between gap-3 text-sm"
          >
            <span className="fg-2">{m.name}</span>
            <span className="flex items-baseline gap-2">
              <span
                className={cn(
                  "tnum font-mono font-semibold",
                  m.meets === false && "text-red-500",
                  m.meets === true && "accent",
                )}
              >
                {fmt(m)}
              </span>
              <span className="fg-3 text-xs">
                {/* `meets` is null when there's no sample to judge against yet —
                    that's "no data", not a failure. Keying the label off
                    `observed` alone printed "off target" for a healthy 0. */}
                {m.meets === null
                  ? "no data"
                  : m.meets
                    ? "on target"
                    : "off target"}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* Friendly labels for the audit actions that show up on a mailbox. */
const ACTION_LABEL: Record<string, string> = {
  "mailbox.connected": "Connection updated",
  "mailbox.removed": "Removed",
  "message.quarantined": "Message quarantined",
  "alert.raised": "Alert raised",
  "alert.acknowledged": "Alert acknowledged",
  "alert.resolved": "Alert resolved",
};

/* What has actually happened on this mailbox — so IT can see it is protected,
   not only when an alert fires. Fetched lazily when expanded. */
function MailboxActivity({ mailboxId }: { mailboxId: string }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<Awaited<
    ReturnType<typeof api.mailboxActivity>
  > | null>(null);
  const [loading, setLoading] = useState(false);

  const [loadError, setLoadError] = useState(false);

  async function toggle() {
    setLoadError(false);
    const next = !open;
    setOpen(next);
    if (next && !data) {
      setLoading(true);
      try {
        setData(await api.mailboxActivity(mailboxId));
      } catch {
        // Nothing "surfaced this on next load" — the panel just said
        // Loading… forever. Close and let the user retry.
        setOpen(false);
        setLoadError(true);
      } finally {
        setLoading(false);
      }
    }
  }

  return (
    <div className="mt-2.5">
      <button
        onClick={toggle}
        aria-expanded={open}
        className="fg-3 mono-xs flex cursor-pointer items-center gap-1.5 transition-colors hover:text-[var(--fg)]"
      >
        <Activity size={11} aria-hidden />
        {open ? "HIDE ACTIVITY" : "ACTIVITY"}
      </button>
      {loadError && (
        <p className="fg-3 mono-xs mt-1" role="alert">
          Couldn't load activity — tap ACTIVITY to retry.
        </p>
      )}

      {open && (
        <div className="rise mt-2 border-l border-[var(--rule)] pl-3">
          {loading || !data ? (
            <p className="fg-3 text-xs">Loading…</p>
          ) : (
            <>
              <div className="flex flex-wrap gap-x-5 gap-y-1">
                <span className="mono-xs">
                  <span className="fg-3">SCANNED </span>
                  <span className="tnum">{data.messages_scanned}</span>
                </span>
                <span className="mono-xs">
                  <span className="fg-3">ALERTS </span>
                  <span className="tnum">{data.alerts_raised}</span>
                </span>
                {data.last_sync_at && (
                  <span className="mono-xs">
                    <span className="fg-3">LAST SYNC </span>
                    {timeOf(data.last_sync_at)}
                  </span>
                )}
              </div>
              <ul className="mt-2 space-y-1.5" role="list">
                {data.events.length === 0 ? (
                  <li className="fg-3 text-xs">
                    Connected and monitoring. Nothing to report — quiet is the
                    correct state.
                  </li>
                ) : (
                  data.events.map((e, i) => (
                    <li
                      key={`${e.at}-${i}`}
                      className="flex items-baseline gap-2 text-xs"
                    >
                      <span className="fg-2">
                        {ACTION_LABEL[e.action] ?? e.action}
                      </span>
                      <span className="fg-3 mono-xs ml-auto shrink-0">
                        {timeOf(e.at)}
                      </span>
                    </li>
                  ))
                )}
              </ul>
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* Getting-started checklist — the first thing a new owner needs, driven entirely
   by real tenant state. It disappears once every step is done, so it never nags a
   set-up account. Each open step carries the one action that completes it. */
function OnboardingChecklist({
  connectedCount,
  mfaEnabled,
  paymentOk,
  onSetupMfa,
}: {
  connectedCount: number;
  mfaEnabled: boolean;
  paymentOk: boolean;
  onSetupMfa: () => void;
}) {
  const steps = [
    {
      key: "connect",
      done: connectedCount > 0,
      label: "Secure your most important mailboxes first",
      hint: "Finance, executives, accounts payable — the ones fraud targets. Connect in one click with Microsoft or Google, or IMAP / forwarding for anything else.",
      action: (
        <a href="#coverage" className="accent mono-xs hover:underline">
          ADD MAILBOX →
        </a>
      ),
    },
    {
      key: "mfa",
      done: mfaEnabled,
      label: "Turn on two-factor authentication",
      hint: "Stops a stolen password from becoming a stolen account.",
      action: (
        <button
          onClick={onSetupMfa}
          className="accent mono-xs cursor-pointer hover:underline"
        >
          SET UP →
        </button>
      ),
    },
    {
      key: "billing",
      done: paymentOk,
      label: "Add billing to keep full protection",
      hint: "Your trial drops to Guard (free) if no card is on file when it ends.",
      action: (
        <Link to="/billing" className="accent mono-xs hover:underline">
          SET UP BILLING →
        </Link>
      ),
    },
  ];

  const doneCount = steps.filter((s) => s.done).length;
  if (doneCount === steps.length) return null; // fully set up — get out of the way

  return (
    <div className="panel p-5">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="sect-label">Getting started</h2>
        <span className="fg-3 mono-xs tnum">
          {doneCount} / {steps.length} done
        </span>
      </div>
      <ul className="mt-4 space-y-3" role="list">
        {steps.map((s) => (
          <li key={s.key} className="flex items-start gap-3">
            <span
              className={cn(
                "mt-0.5 grid size-4 shrink-0 place-items-center rounded-full border",
                s.done
                  ? "border-[var(--accent)] bg-[var(--accent)]"
                  : "border-[var(--rule)]",
              )}
              aria-hidden
            >
              {s.done && <Check size={11} className="text-[var(--accent-ink)]" />}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span
                  className={cn(
                    "text-sm font-medium",
                    s.done && "fg-3 line-through",
                  )}
                >
                  {s.label}
                </span>
                {!s.done && s.action}
              </div>
              {!s.done && (
                <p className="fg-3 mt-0.5 text-xs leading-relaxed">{s.hint}</p>
              )}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* Upgrade CTA — shown to anyone on Guard (free) or Essential (middle). During an
   active trial the tenant is already on Complete, so this stays hidden; once the
   trial lapses to Guard, or for a genuine free/Essential tenant, the higher
   plan(s) appear with a one-click upgrade. */
function UpgradePlans({
  tenant,
  onChanged,
}: {
  tenant: TenantInfo;
  onChanged: () => Promise<void>;
}) {
  const navigate = useNavigate();
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const currentRank = PLAN_RANK[tenant.plan] ?? 0;
  const upgrades = PLAN_TIERS.filter((p) => (PLAN_RANK[p.id] ?? 0) > currentRank);
  const planName =
    (tenant.subscribed_plan ?? tenant.plan).charAt(0).toUpperCase() +
    (tenant.subscribed_plan ?? tenant.plan).slice(1);

  async function upgrade(planId: string) {
    setBusy(planId);
    setNote(null);
    try {
      // During the trial this switches the plan instantly (no card needed). Once
      // the trial has lapsed the server returns 402 — send them to checkout to
      // add a payment method, which then activates the plan.
      await api.changePlan(planId);
      await onChanged();
    } catch (e) {
      if (e instanceof ApiError && e.status === 402) {
        navigate(`/billing?plan=${planId}`);
        return;
      }
      setNote(
        e instanceof ApiError
          ? e.message
          : "Could not change plan. Please try again.",
      );
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="panel p-5">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="sect-label">Your plan</h2>
        <Link to="/billing" className="accent mono-xs hover:underline">
          MANAGE BILLING →
        </Link>
      </div>
      <p className="fg-2 mt-2 text-sm">
        <span className="font-semibold">{planName}</span>
        {tenant.trial.active && (
          <span className="fg-3">
            {" "}
            · trial{tenant.trial.days_left !== null ? `, ${tenant.trial.days_left}d left` : ""}
          </span>
        )}
      </p>

      {upgrades.length === 0 ? (
        <p className="fg-3 mt-2 text-xs leading-relaxed">
          You're on Complete — the top plan, with full account-takeover protection.
          Change plan, update your card, or buy more mailbox seats from billing.
        </p>
      ) : (
        <>
          <p className="fg-3 mt-2 text-xs leading-relaxed">
            {tenant.plan === "guard"
              ? "You're on Guard (free) — domain & brand monitoring only. Add mailbox protection:"
              : "Move up to full account-takeover protection:"}
          </p>
          <div className="mt-4 space-y-3">
            {upgrades.map((p) => (
          <div key={p.id} className="rounded border border-[var(--rule)] p-4">
            <div className="flex items-baseline justify-between gap-2">
              <span className="text-sm font-semibold">{p.name}</span>
              <span className="tnum">
                <span className="font-mono text-base font-semibold">{p.price}</span>
                <span className="fg-3 text-[11px]">{p.per}</span>
              </span>
            </div>
            <p className="fg-3 mt-1 text-xs">{p.blurb}</p>
            <ul className="fg-2 mt-2.5 space-y-1" role="list">
              {p.features.map((f) => (
                <li key={f} className="flex items-start gap-1.5 text-xs">
                  <Check size={12} className="accent mt-0.5 shrink-0" aria-hidden />
                  {f}
                </li>
              ))}
            </ul>
            <Button
              size="sm"
              variant="accent"
              className="mt-3 w-full"
              disabled={busy !== null}
              onClick={() => upgrade(p.id)}
            >
              {busy === p.id ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : null}
              UPGRADE TO {p.name.toUpperCase()}
            </Button>
          </div>
        ))}
          </div>
          <p className="fg-3 mt-3 text-[11px] leading-relaxed">
            15 days free on signup. Pay monthly with no penalty, or save up to 20%
            yearly. Bigger teams pay much less per seat.
          </p>
        </>
      )}
      {note && (
        <p className="mt-3 text-xs text-[var(--warn,#d97706)]" role="status">
          {note}
        </p>
      )}
    </div>
  );
}

/* L1 browser-push toggle. Reflects THIS browser's real subscription state and lets
   the user turn Critical-alert push on/off. Hidden entirely when the browser can't
   do push or the deployment has no VAPID key configured — no dead controls. */
function PushAlerts() {
  const [state, setState] = useState<PushState | "loading">("loading");
  const [busy, setBusy] = useState(false);
  // Declared with the other hooks, NOT after the early return below. It used to
  // sit further down, so the first render (state === "loading") returned before
  // reaching it and ran two hooks, and the next one ran three — React's
  // "rendered more hooks than during the previous render" crash, which took the
  // whole dashboard down with it the moment the push state resolved.
  const [pushError, setPushError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    getPushState()
      .then((s) => live && setState(s))
      .catch(() => live && setState("unsupported"));
    return () => {
      live = false;
    };
  }, []);

  if (state === "loading" || state === "unsupported" || state === "unavailable")
    return null;

  async function enable() {
    setBusy(true);
    setPushError(null);
    try {
      setState(await enablePush());
    } catch (e) {
      // Silent flip-back taught users the toggle was broken; say why.
      setState("off");
      setPushError(
        e instanceof ApiError ? e.message : "Couldn't enable push — try again.",
      );
    } finally {
      setBusy(false);
    }
  }
  async function disable() {
    setBusy(true);
    try {
      setState(await disablePush());
    } catch {
      setState("on");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="panel p-5">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="sect-label">Browser alerts</h2>
        {state === "on" && <span className="mono-xs text-emerald-500">ON</span>}
      </div>
      {pushError && (
        <p role="alert" className="callout mt-3 px-3 py-2 text-xs">
          {pushError}
        </p>
      )}
      {state === "denied" ? (
        <p className="fg-3 mt-2 text-xs leading-relaxed">
          Notifications are blocked for this site. Turn them on in your browser's
          site settings, then reload to enable Critical-alert push.
        </p>
      ) : (
        <>
          <p className="fg-3 mt-2 text-xs leading-relaxed">
            Get Critical alerts as a browser notification even when the Envelock tab
            is closed. This device only.
          </p>
          <div className="mt-3">
            {state === "on" ? (
              <Button size="sm" variant="quiet" onClick={disable} disabled={busy}>
                {busy ? (
                  <Loader2 size={12} className="animate-spin" aria-hidden />
                ) : null}
                Turn off
              </Button>
            ) : (
              <Button size="sm" variant="accent" onClick={enable} disabled={busy}>
                {busy ? (
                  <Loader2 size={12} className="animate-spin" aria-hidden />
                ) : (
                  <Bell size={12} aria-hidden />
                )}
                Enable browser alerts
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}

/* The post-sign-in onboarding wizard shown until the domain is verified. Two
   steps you can move between with Back/Continue — the authenticator (MFA) step
   and the domain-verification step — so "Back" never dumps the user at sign-in.
   The dashboard only renders once the domain verifies. */
function OnboardingGate({
  domain,
  mfaEnabled,
  onVerified,
  onReload,
  onSignOut,
}: {
  domain: string;
  mfaEnabled: boolean;
  onVerified: () => void;
  onReload: () => Promise<void>;
  onSignOut: () => void;
}) {
  const [step, setStep] = useState<"mfa" | "domain">("domain");
  const [enrolling, setEnrolling] = useState(false);

  if (step === "mfa") {
    return (
      <main className="shell py-16">
        <div className="mx-auto max-w-lg">
          <div className="mb-6 text-center">
            <Fingerprint size={28} className="fg-3 mx-auto" aria-hidden />
            <h1 className="headline mt-5">Two-factor authentication</h1>
          </div>

          {mfaEnabled ? (
            <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4 text-sm">
              <span className="font-semibold text-emerald-500">
                ✓ Two-factor is on.
              </span>{" "}
              Your account is protected by your authenticator app.
            </div>
          ) : enrolling ? (
            <MfaEnroll
              onDone={async () => {
                setEnrolling(false);
                await onReload();
              }}
              onCancel={() => setEnrolling(false)}
            />
          ) : (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
              <p className="font-semibold text-amber-600 dark:text-amber-400">
                Two-factor isn't set up yet
              </p>
              <p className="mt-1 opacity-80">
                Add an authenticator app so a stolen password can't become a stolen
                account. You can do this now or later from your dashboard.
              </p>
              <Button
                variant="accent"
                size="sm"
                className="mt-3"
                onClick={() => setEnrolling(true)}
              >
                <KeyRound size={13} aria-hidden /> Set up two-factor
              </Button>
            </div>
          )}

          {!enrolling && (
            <div className="mt-5 flex items-center gap-3">
              <Button variant="accent" onClick={() => setStep("domain")}>
                Continue to domain verification →
              </Button>
              <button
                type="button"
                onClick={onSignOut}
                className="fg-3 mono-xs ml-auto cursor-pointer hover:text-[var(--fg)]"
              >
                SIGN OUT
              </button>
            </div>
          )}
        </div>
      </main>
    );
  }

  return (
    <main className="shell py-16">
      <div className="mx-auto max-w-lg">
        <div className="mb-6 text-center">
          <ShieldCheck size={28} className="fg-3 mx-auto" aria-hidden />
          <h1 className="headline mt-5">Verify your domain to continue</h1>
          <p className="lede mx-auto mt-3 text-base">
            One last step. Prove you control{" "}
            <span className="font-semibold">{domain}</span> and your dashboard opens
            automatically. This is what keeps everyone else out of your company's
            mail.
          </p>
        </div>
        <DomainVerify
          domain={domain}
          onVerified={onVerified}
          onBack={() => setStep("mfa")}
        />
        <p className="mt-6 text-center">
          <button
            type="button"
            onClick={onSignOut}
            className="fg-3 text-xs underline"
          >
            Sign out
          </button>
        </p>
      </div>
    </main>
  );
}

/* Is the tenant's primary (registered) domain DNS-verified right now? The whole
   dashboard is gated on this — no verified domain means the verify step, not the
   dashboard — and a change in it (a verified domain going unverified) means the
   DNS proof was pulled and the session must re-verify. False when there is no
   primary domain at all (nothing to verify → gate falls through). */
function primaryDomainVerified(t: TenantInfo): boolean {
  if (!t.primary_domain) return false;
  return t.domains.some(
    (d) => d.registrable_domain === t.primary_domain && d.verified,
  );
}

export default function Dashboard() {
  const navigate = useNavigate();
  // Tracks whether the primary domain was verified on the previous load, so we can
  // catch it flipping to unverified (its DNS record was deleted and the server
  // revoked it) and force a re-auth + re-verify. null = not yet known.
  const domainWasVerifiedRef = useRef<boolean | null>(null);
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [mailboxes, setMailboxes] = useState<MailboxRecord[]>([]);
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [stats, setStats] = useState<Oversight | null>(null);
  const [me, setMe] = useState<Me | null>(null);
  const [mfaOpen, setMfaOpen] = useState(false);
  const [mailboxQuery, setMailboxQuery] = useState("");
  const [filter, setFilter] = useState<"open" | "all">("open");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Monotonic request id. Every load stamps one and only writes state if it is
  // still the newest in flight. Without this, a slow earlier response lands
  // after a fast later one and silently reinstates stale alerts — the exact
  // failure a security queue must not have.
  const loadSeq = useRef(0);

  const load = useCallback(async (opts?: { background?: boolean }) => {
    const background = opts?.background === true;
    const seq = ++loadSeq.current;
    // A background poll must not flip the page into its skeleton state; that
    // would blank the queue an analyst is reading, once a minute.
    if (!background) {
      setLoading(true);
      setError(null);
    }
    try {
      const [a, m, t, who] = await Promise.all([
        api.alerts(),
        api.mailboxes(),
        api.tenant(),
        api.me(),
      ]);
      if (seq !== loadSeq.current) return;
      // Domain verification can be revoked between loads — the scheduler pulls it
      // when the DNS proof is deleted. If it was verified and now isn't, the trust
      // that gated this session is gone: sign the user out and send them back to
      // verify, rather than leaving a live session on an unverified domain.
      const nowVerified = primaryDomainVerified(t);
      if (domainWasVerifiedRef.current === true && !nowVerified) {
        domainWasVerifiedRef.current = null;
        auth.clear();
        navigate("/signin", {
          state: {
            notice:
              "Your domain verification was lost — the DNS record we check is no longer found. Sign in and verify your domain again to continue.",
          },
        });
        return;
      }
      domainWasVerifiedRef.current = nowVerified;

      setAlerts(a.alerts);
      setMailboxes(m.mailboxes);
      setTenant(t);
      setMe(who);
      if (background) setError(null);
      try {
        const o = await api.oversight();
        if (seq === loadSeq.current) setStats(o);
      } catch {
        if (seq === loadSeq.current) setStats(null); // member role: no oversight
      }
    } catch (e) {
      if (seq !== loadSeq.current) return;
      // A blip during a background poll must not tear down a queue the analyst
      // is working in. Keep what is on screen; the next tick will recover.
      if (background && !(e instanceof ApiError && e.unauthorized)) return;
      // 401 = no/invalid session → sign in. 403 = a valid session that isn't
      // allowed to see tenant data yet — a colleague still awaiting admin
      // approval. These are different screens: telling an approved-pending user
      // to "sign in" is a dead end, because they already are.
      if (e instanceof ApiError && e.status === 403)
        setError("pending-approval");
      else if (e instanceof ApiError && e.unauthorized) setError("signed-out");
      else setError("We couldn't reach Envelock. Check your connection and try again.");
    } finally {
      if (seq === loadSeq.current && !background) setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    // Fetch-on-mount: load() flips a loading flag before its first await. That's
    // the intended pattern here, not the cascading-render case the rule targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  // Keep the queue live. Until this existed, a new alert reached nobody: the
  // dashboard fetched once on mount and then never again, so a Critical raised
  // at 23:00 sat invisible behind a REFRESH button until someone happened to
  // press it. Every out-of-band rung (in-app, push, email, SMS) needs
  // configuration that a fresh deployment does not have, so in practice the
  // screen WAS the notification channel — and it was static.
  //
  // Poll while the tab is visible, stop when it is hidden (a backgrounded tab
  // should not hold a connection open all night), and refetch immediately on
  // becoming visible again so returning to the tab always shows current state.
  useEffect(() => {
    const REFRESH_MS = 45_000;
    let timer: ReturnType<typeof setInterval> | undefined;

    const start = () => {
      if (timer !== undefined) return;
      timer = setInterval(() => void load({ background: true }), REFRESH_MS);
    };
    const stop = () => {
      if (timer !== undefined) clearInterval(timer);
      timer = undefined;
    };
    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        void load({ background: true });
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("focus", onVisibility);
    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("focus", onVisibility);
    };
  }, [load]);

  const shown = useMemo(
    () =>
      // "Open" means "still needs someone": acknowledged-but-unresolved alerts
      // stay in the queue — acknowledging used to make a live Critical vanish.
      filter === "open"
        ? alerts.filter((a) => a.state === "open" || a.state === "acked")
        : alerts,
    [alerts, filter],
  );
  const open = alerts.filter((a) => a.state === "open");
  const critical = open.filter((a) => a.tier === "critical").length;

  async function acknowledge(id: string) {
    await api.acknowledgeAlert(id);
    await load();
  }

  async function quarantine(id: string) {
    const result = await api.quarantineAlert(id);
    // "queued" is progress, not failure: under split key custody the API records
    // the decision and the mail worker moves the message on its next cycle.
    if (!result.succeeded && !result.queued) throw new ApiError(409, result.reason);
    if (result.queued) throw new ApiError(202, result.reason);
    await load();
  }

  async function resolve(id: string, dismiss: boolean) {
    await api.resolveAlert(id, dismiss);
    await load();
  }

  // Two-step, because this deletes a stored credential and stops protection for
  // that address — a `window.confirm` is the control users dismiss reflexively.
  const [pendingRemoval, setPendingRemoval] = useState<MailboxRecord | null>(null);
  const [removing, setRemoving] = useState(false);

  function removeMailbox(id: string) {
    setPendingRemoval(mailboxes.find((m) => m.id === id) ?? null);
  }

  async function confirmRemoveMailbox() {
    const target = pendingRemoval;
    if (!target) return;
    setRemoving(true);
    try {
      await api.removeMailbox(target.id);
      setPendingRemoval(null);
      toast.success(`${target.address} removed. Its stored credential was deleted.`);
      await load();
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not remove that mailbox.",
      );
    } finally {
      setRemoving(false);
    }
  }

  if (error === "signed-out" || !auth.signedIn) {
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <h1 className="headline">Sign in to see your alerts</h1>
          <p className="lede mx-auto mt-4 text-base">
            The dashboard reads live data from your tenant, so it needs a
            session.
          </p>
          <Link to="/signin" className="mt-8 inline-block">
            <Button variant="accent" size="lg">
              SIGN IN
            </Button>
          </Link>
        </div>
      </main>
    );
  }

  // Signed in, but this account is a colleague who joined an existing tenant and
  // is still waiting for an admin to approve them (server returns 403 until then).
  // Show that plainly — not the "sign in" screen, which they'd read as a bug.
  if (error === "pending-approval") {
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <ShieldAlert size={28} className="fg-3 mx-auto" aria-hidden />
          <h1 className="headline mt-5">Waiting for approval</h1>
          <p className="lede mx-auto mt-4 text-base">
            You're signed in, but a workspace admin at your company still needs
            to approve your access. You'll see the alert queue and mailbox
            coverage as soon as they do — no need to sign up again.
          </p>
          <p className="fg-3 mt-6 text-sm">
            Already expecting access? Ask your Envelock admin to approve you
            from their Team page.
          </p>
          <Button
            variant="line"
            size="sm"
            className="mt-8"
            onClick={() => void load()}
          >
            <RefreshCw size={13} aria-hidden /> CHECK AGAIN
          </Button>
        </div>
      </main>
    );
  }

  // Hold the whole page on first load until we know the tenant's verification
  // state — otherwise an unverified user glimpses the dashboard shell for one
  // render before the gate below replaces it.
  if (loading && !tenant) {
    return (
      <main className="shell grid min-h-[60vh] place-items-center py-24">
        <Loader2 size={22} className="fg-3 animate-spin" aria-hidden />
      </main>
    );
  }

  // Domain-control gate (PRD signup funnel). A business tenant must prove it
  // controls its domain BEFORE it reaches any live data — this is what stops
  // someone signing up with a company address they don't own, and it is why the
  // verify step comes right after 2FA. Until the primary domain is DNS-verified
  // we render ONLY the verification screen, never the dashboard, so a mailbox
  // can't be added first either. A tenant with no primary domain (edge case)
  // falls through rather than being locked out.
  const primaryUnverified =
    !!tenant?.primary_domain && !primaryDomainVerified(tenant);

  if (tenant && primaryUnverified) {
    return (
      <OnboardingGate
        domain={tenant.primary_domain!}
        mfaEnabled={!!me?.mfa_enabled}
        onVerified={() => void load()}
        onReload={load}
        onSignOut={() => {
          auth.clear();
          navigate("/signin", {
            state: { notice: "Signed out. Sign back in to finish setting up." },
          });
        }}
      />
    );
  }

  // The tenant's own registered domain — falls back to a connected mailbox's
  // domain only if the tenant record somehow has none.
  const resolvedDomain =
    tenant?.primary_domain ?? mailboxes[0]?.address.split("@")[1] ?? null;
  const hasDomain = resolvedDomain !== null;
  const domain = resolvedDomain ?? "no domain yet";
  const domainCount = tenant?.domains.length ?? stats?.domains ?? 0;

  return (
    <main>
      <div className="shell pt-5">
        {/* Identity on the left, the four numbers that matter on the right. The
            cells are hairline-separated rather than spaced so the row reads as
            one instrument panel, not four floating cards. */}
        <div className="statstrip grid-cols-2 sm:grid-cols-3 lg:grid-cols-5">
          <div className="stat-cell col-span-2 flex flex-col justify-center sm:col-span-3 lg:col-span-1">
            <span className="sect-label truncate">
              {tenant?.name && tenant.name !== domain ? tenant.name : "Tenant"}
            </span>
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              <p className="truncate text-sm font-semibold">{domain}</p>
              {tenant && <PlanBadge tenant={tenant} />}
            </div>
          </div>
          {(
            [
              ["OPEN", String(open.length), open.length > 0 ? "is-warn" : "is-quiet"],
              ["CRITICAL", String(critical), critical > 0 ? "is-hot" : "is-quiet"],
              ["MAILBOXES", String(mailboxes.length), "is-quiet"],
              ["DOMAINS", String(domainCount), "is-quiet"],
            ] as const
          ).map(([label, value, tone]) => (
            <div key={label} className="stat-cell">
              <div className="sect-label">{label}</div>
              <div className={cn("stat-figure mt-2", tone)}>{value}</div>
            </div>
          ))}
        </div>
        <PreventedPanel prevented={stats?.prevented_loss} />

        <div className="mt-2 flex items-center justify-end">
          <button
            onClick={() => void load()}
            aria-label="Refresh"
            className="fg-3 mono-xs flex cursor-pointer items-center gap-1.5 p-2 transition-colors hover:text-[var(--fg)]"
          >
            <RefreshCw
              size={13}
              className={cn(loading && "animate-spin")}
              aria-hidden
            />
            REFRESH
          </button>
        </div>
      </div>

      {me && !me.mfa_enabled && (
        <div className="border-b border-[var(--warn)]/30">
          <div className="shell py-4">
            <div className="callout flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
              <ShieldAlert size={18} className="shrink-0" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold">
                  Two-factor authentication is off
                </p>
                <p className="mt-0.5 text-xs leading-relaxed">
                  A stolen password is enough to take this account. Turn on your
                  authenticator app — it takes about a minute.
                </p>
              </div>
              <Button
                size="sm"
                variant={mfaOpen ? "quiet" : "accent"}
                className="shrink-0"
                onClick={() => setMfaOpen((o) => !o)}
                aria-expanded={mfaOpen}
              >
                {mfaOpen ? (
                  <>
                    <X size={13} aria-hidden /> CLOSE
                  </>
                ) : (
                  <>
                    <ShieldAlert size={13} aria-hidden /> SET UP TWO-FACTOR
                  </>
                )}
              </Button>
            </div>

            {mfaOpen && (
              <div className="panel rise mt-3 p-5">
                <MfaEnroll
                  onDone={async () => {
                    setMfaOpen(false);
                    await load();
                  }}
                  onCancel={() => setMfaOpen(false)}
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Domain verification is handled by a full-screen gate above (the dashboard
          only renders once the primary domain is DNS-verified), so there is no
          inline verify banner here. */}

      {error && error !== "signed-out" && (
        <div className="shell py-4">
          <p role="alert" className="text-sm text-[var(--danger)]">
            {error}
          </p>
        </div>
      )}

      {/* Teammates awaiting approval — admins/owners are told here so they don't
          have to stumble onto the Team page to find a pending colleague. */}
      {/* Unparked: /team is in the console rail (App.tsx APP_NAV), so this no
          longer points at a hidden page. It matters more now that email
          verification is on — a colleague confirms their address, lands in
          `pending`, and without this nobody is ever told they are waiting. */}
      {tenant &&
        tenant.pending_members > 0 &&
        (auth.role === "owner" || auth.role === "admin") && (
          <div className="shell pt-4">
            <div className="callout flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
              <ShieldAlert size={18} className="shrink-0" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold">
                  {tenant.pending_members} teammate
                  {tenant.pending_members === 1 ? "" : "s"} awaiting approval
                </p>
                <p className="mt-0.5 text-xs leading-relaxed">
                  Someone from your company signed up and needs access. Review them,
                  set their role, or decline — from your Team page.
                </p>
              </div>
              <Link to="/team" className="shrink-0">
                <Button size="sm" variant="accent">
                  REVIEW TEAM
                </Button>
              </Link>
            </div>
          </div>
        )}

      {/* Trial countdown. Unparked with the billing router and the /billing
          route, which are both live: the trial runs 15 days and then drops to
          Guard, and this was the only thing in the product that said so while
          there was still time to act. A customer discovering the drop by losing
          protection is a churn event we caused. */}
      {tenant?.trial.active &&
        tenant.trial.days_left !== null &&
        !tenant.trial.payment_method_ok && (
          <div className="shell pt-4">
            <div
              className={cn(
                "callout flex flex-col gap-3 p-4 sm:flex-row sm:items-center",
                tenant.trial.days_left <= 3 && "border-[var(--danger)]",
              )}
            >
              <Banknote size={18} className="shrink-0" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold">
                  {tenant.trial.days_left} day
                  {tenant.trial.days_left === 1 ? "" : "s"} left in your{" "}
                  {(tenant.subscribed_plan ?? "complete").toString().replace(/^\w/, (c) => c.toUpperCase())}{" "}
                  trial
                </p>
                <p className="mt-0.5 text-xs leading-relaxed">
                  Add a payment method to keep full protection when it ends —
                  otherwise you drop to Guard (free), never locked out.
                </p>
              </div>
              <Link to="/billing" className="shrink-0">
                <Button size="sm" variant="accent">
                  <CreditCard size={13} aria-hidden /> SET UP BILLING
                </Button>
              </Link>
            </div>
          </div>
        )}

      <div className="shell grid12 py-8">
        <section className="col-span-12 lg:col-span-8">
          {/* The queue header is a ruled label rather than a panel lid: each
              alert is now its own bordered card carrying a tier bar, and
              nesting cards inside a panel gave every alert two competing
              borders. */}
          <div className="ruled-label">
            <h2 className="sect-label">
              Alert queue
              {shown.length > 0 && (
                <span className="fg-3 tnum ml-2 normal-case">
                  {shown.length}
                </span>
              )}
            </h2>
            <div className="flex gap-px" role="group" aria-label="Filter alerts">
              {(["open", "all"] as const).map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  aria-pressed={filter === f}
                  className={cn(
                    "font-mono cursor-pointer border px-3 py-1.5 text-[11px] tracking-wide uppercase transition-colors",
                    filter === f
                      ? "accent border-[var(--accent)]"
                      : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-4 space-y-3">
            {loading && alerts.length === 0 ? (
              <div className="panel p-12 text-center">
                <p className="fg-3 text-sm">Loading…</p>
              </div>
            ) : shown.length === 0 ? (
              <div className="panel p-12 text-center">
                <p className="text-sm font-semibold">
                  {filter === "all" ? "No alerts yet." : "Nothing open."}
                </p>
                <p className="fg-3 mx-auto mt-2 max-w-md text-sm leading-relaxed">
                  This is your alert queue. When Envelock spots changed bank
                  details, invoice fraud, or a dangerous link in a connected
                  mailbox, it appears here with the action to take — verify,
                  quarantine or dismiss. An empty queue means nothing needs you
                  right now; quiet is the correct state.
                </p>
              </div>
            ) : (
              shown.map((a) => (
                <AlertRow
                  key={a.id}
                  alert={a}
                  onAcknowledge={acknowledge}
                  onQuarantine={quarantine}
                  onResolve={resolve}
                />
              ))
            )}
          </div>
        </section>

        <aside className="col-span-12 mt-6 space-y-6 lg:col-span-4 lg:mt-0">
          {mailboxes.length > 0 && <CoverageSummary mailboxes={mailboxes} />}

          {tenant && me && (
            <OnboardingChecklist
              connectedCount={
                mailboxes.filter((m) => m.sources.some((s) => MAIL_SOURCES.has(s)))
                  .length
              }
              mfaEnabled={me.mfa_enabled}
              paymentOk={tenant.trial.payment_method_ok}
              onSetupMfa={() => {
                setMfaOpen(true);
                window.scrollTo({ top: 0, behavior: "smooth" });
              }}
            />
          )}

          {/* parked: not in two-feature v1 (billing)
          {tenant && <UpgradePlans tenant={tenant} onChanged={load} />}
          */}

          <PushAlerts />

          <ConnectionAdvisor defaultDomain={hasDomain ? domain : ""} />

          <AppPasswordNotice />

          {/* LookalikeWatch stays parked deliberately: the CT watcher that
              fills it is parked by ENVELOCK_FOCUS_CORE, so the panel would sit
              there empty and imply we are watching when we are not.
              AuditTrail is unparked — /api/v1/audit is live, it is E5's whole
              point ("IT can see who acted and who ignored it"), and the privacy
              notice now promises the customer an audit trail they can read. */}
          <AuditTrail />

          <div className="panel" id="coverage">
            <div className="border-b px-5 py-3.5">
              <div className="flex items-baseline justify-between gap-3">
                <h2 className="sect-label">Mailbox coverage</h2>
                {mailboxes.length > 0 && (
                  <span className="mono-xs fg-3 tnum">
                    {
                      mailboxes.filter((m) =>
                        m.sources.some((s) => MAIL_SOURCES.has(s)),
                      ).length
                    }
                    /{mailboxes.length} connected
                  </span>
                )}
              </div>
              <p className="fg-3 mt-1 text-xs">
                Derived from what each connection can do
              </p>
              {mailboxes.length > 6 && (
                <input
                  value={mailboxQuery}
                  onChange={(e) => setMailboxQuery(e.target.value)}
                  placeholder="Filter mailboxes…"
                  aria-label="Filter mailboxes"
                  className="field mt-3 h-9 text-sm"
                />
              )}
            </div>
            {mailboxes.length === 0 ? (
              <p className="fg-3 px-5 pt-5 text-xs leading-relaxed">
                No mailboxes connected yet. Add the ones that touch money first
                — finance, executives, accounts payable — then connect them
                below.
              </p>
            ) : (
              <ul
                className={cn(
                  "divide-y",
                  mailboxes.length > 8 && "max-h-[32rem] overflow-y-auto",
                )}
                role="list"
              >
                {mailboxes
                  .filter((m) =>
                    mailboxQuery
                      ? m.address
                          .toLowerCase()
                          .includes(mailboxQuery.toLowerCase())
                      : true,
                  )
                  .map((m) => (
                    <MailboxRow
                      key={m.id}
                      mailbox={m}
                      onChanged={load}
                      onRemove={removeMailbox}
                    />
                  ))}
              </ul>
            )}
            <BulkImapConnect
              mailboxes={mailboxes.filter(
                (m) => !m.sources.some((s) => MAIL_SOURCES.has(s)),
              )}
              domain={tenant?.primary_domain ?? null}
              onDone={load}
            />
            <AddMailbox onAdded={load} mailboxes={tenant?.mailboxes} />
          </div>

          {/* The client sensor: without a device reporting, the sign-in and
              silent-access alerts on the Complete plan have nothing to go on. */}
          {mailboxes.length > 0 && (
            <SensorPanel
              mailboxes={mailboxes}
              isAdmin={auth.role === "owner" || auth.role === "admin"}
              onChanged={load}
            />
          )}

          {/* Unparked: main.py mounts the governance router unconditionally
              *because* this panel reads /api/v1/metrics/quality — with the
              panel parked, that reasoning bought nothing. */}
          <GoverningMetrics />

          {stats && (
            <div className="panel p-5">
              <h2 className="sect-label">Oversight</h2>
              <ul className="mt-4 space-y-2.5" role="list">
                {[
                  ["Acknowledged", String(stats.acknowledged)],
                  [
                    "Unacked over 15 min",
                    String(stats.unacknowledged_over_15m),
                  ],
                  ["Full coverage", String(stats.coverage.full ?? 0)],
                  ["Limited coverage", String(stats.coverage.limited ?? 0)],
                ].map(([label, value]) => (
                  <li
                    key={label}
                    className="flex items-baseline justify-between gap-3 text-sm"
                  >
                    <span className="fg-2">{label}</span>
                    <span className="tnum font-mono font-semibold">
                      {value}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="fg-3 mt-5 border-t pt-4 text-xs leading-relaxed">
                Critical unacknowledged for 15 minutes escalates to IT; 60
                minutes to all admins, plus SMS.
              </p>
            </div>
          )}
        </aside>
      </div>

      <ConfirmDialog
        open={pendingRemoval !== null}
        title="Remove this mailbox?"
        body={
          pendingRemoval
            ? `${pendingRemoval.address} will stop being scanned and its stored ` +
              "credential is deleted. Alerts already raised are kept. You can " +
              "add and reconnect it again later."
            : ""
        }
        confirmLabel="REMOVE MAILBOX"
        busy={removing}
        onConfirm={() => void confirmRemoveMailbox()}
        onCancel={() => setPendingRemoval(null)}
      />
    </main>
  );
}

export type { Tier };

/* Still parked, and kept for later — referencing them keeps noUnusedLocals
   quiet. LookalikeWatch waits on the CT watcher (ENVELOCK_FOCUS_CORE);
   UpgradePlans is redundant while /billing carries the same flow. */
void LookalikeWatch;
void UpgradePlans;
