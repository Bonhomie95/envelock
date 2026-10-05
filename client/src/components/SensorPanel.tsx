import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Check, Copy, Laptop, Loader2, Plus, Trash2,
  Mail, KeyRound, Pin,
} from "lucide-react";
import {
  ApiError,
  api,
  type MailboxRecord,
  type SensorDevice,
  type SensorPairing,
} from "../lib/api";
import { toast } from "../lib/toast";
import { Button, cn } from "./primitives";
import ConfirmDialog from "./ConfirmDialog";

/* Sign-in protection — the Envelock sensor.
 *
 * No mail protocol tells Envelock who else is signed into a mailbox. The sensor
 * does: it runs where the person actually reads their mail — the browser
 * extension on their webmail, the Thunderbird add-on, the Outlook add-in — and
 * says "this device is here" and "the owner opened this message". From that
 * Envelock can raise a new-country sign-in, and a message read while none of
 * the owner's devices were anywhere near it.
 *
 * This panel is where a person pairs a device (a short code they type into the
 * sensor — the sensor never sees their session), sees which devices are
 * reporting, and — only once a mailbox has a device — decides whether a read
 * with none of them present should raise the alarm.
 */

const OUTLOOK_MANIFEST = `${window.location.origin}/addins/outlook/manifest.xml`;

/* Store listings, when they exist. Never a placeholder link: until the owner
   has a listing URL, the browser option says what is actually available. */
const STORES = {
  chrome: import.meta.env.VITE_SENSOR_CHROME_URL as string | undefined,
  edge: import.meta.env.VITE_SENSOR_EDGE_URL as string | undefined,
  firefox: import.meta.env.VITE_SENSOR_FIREFOX_URL as string | undefined,
};

/** The add-on's listing on addons.thunderbird.net, once it is published there.
 *
 * Until it is, the .xpi we build is UNSIGNED, and release Thunderbird refuses
 * to install an unsigned add-on — `xpinstall.signatures.required` only works on
 * Daily and developer builds. Offering it as a plain download was telling
 * people to do something that cannot work. */
const THUNDERBIRD_LISTING = import.meta.env.VITE_SENSOR_THUNDERBIRD_URL as
  | string
  | undefined;

const CLIENT_NAME: Record<SensorDevice["client"], string> = {
  browser: "Browser extension",
  thunderbird: "Thunderbird",
  outlook: "Outlook",
};

function ago(iso: string | null): string {
  if (!iso) return "never";
  const secs = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.round(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)} hr ago`;
  return new Date(iso).toLocaleDateString();
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      aria-label={label}
      className="fg-3 cursor-pointer p-1 transition-colors hover:text-[var(--fg)]"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(
          () => {
            setDone(true);
            window.setTimeout(() => setDone(false), 1500);
          },
          () => toast.error("Could not copy — select it and copy by hand."),
        );
      }}
    >
      {done ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
    </button>
  );
}

function Countdown({ until, onExpired }: { until: string; onExpired: () => void }) {
  const [left, setLeft] = useState(() => Math.max(0, Date.parse(until) - Date.now()));
  useEffect(() => {
    const id = window.setInterval(() => {
      const next = Math.max(0, Date.parse(until) - Date.now());
      setLeft(next);
      if (next === 0) onExpired();
    }, 1000);
    return () => window.clearInterval(id);
  }, [until, onExpired]);
  const m = Math.floor(left / 60000);
  const s = Math.floor((left % 60000) / 1000);
  return (
    <span className="tnum">
      {m}:{String(s).padStart(2, "0")}
    </span>
  );
}

function Step({
  n,
  icon,
  children,
}: {
  n: number;
  icon: ReactNode;
  children: ReactNode;
}) {
  return (
    <li className="flex gap-3">
      <span
        className="flex size-7 shrink-0 items-center justify-center rounded-full border border-[var(--accent)] text-sm font-semibold text-[var(--accent)]"
        aria-hidden
      >
        {n}
      </span>
      <div className="min-w-0 flex-1 pt-0.5 text-sm leading-relaxed">
        <span className="mr-1.5 inline-flex translate-y-0.5 text-[var(--accent)]" aria-hidden>
          {icon}
        </span>
        {children}
      </div>
    </li>
  );
}

/* Short, visual, Outlook-first. Everything that is a caveat rather than a step
   (Microsoft's propagation delays, "App launch failed", other mail apps) lives
   behind an expander, so the happy path is four lines a person can follow at a
   glance — not three dense paragraphs they have to read to find the one step
   that matters. */
function InstallSteps() {
  const anyStore = STORES.chrome || STORES.edge || STORES.firefox;
  return (
    <div className="mt-4">
      <ol className="space-y-3" role="list">
        <Step n={1} icon={<Copy size={15} />}>
          Copy the Outlook add-in link
          <div className="mt-1.5 flex items-center gap-2">
            <code className="flex-1 truncate rounded bg-[var(--bg-hover)] px-2 py-1 font-mono text-xs">
              {OUTLOOK_MANIFEST}
            </code>
            <CopyButton text={OUTLOOK_MANIFEST} label="Copy the Outlook add-in link" />
          </div>
        </Step>
        <Step n={2} icon={<Plus size={15} />}>
          In Outlook: <b>Get Add-ins → My add-ins → Add a custom add-in → From URL</b>,
          and paste it.
        </Step>
        <Step n={3} icon={<Mail size={15} />}>
          <b>Open any email</b>, then click <b>Envelock sensor</b> on the ribbon
          <span className="fg-3"> (under <b>…</b> on Mac and the web)</span>.
        </Step>
        <Step n={4} icon={<KeyRound size={15} />}>
          Type the code above, then <Pin size={13} className="inline translate-y-0.5" aria-hidden />{" "}
          <b>pin the pane</b> so it stays open.
        </Step>
      </ol>

      <details className="mt-3 text-sm">
        <summary className="fg-2 cursor-pointer select-none">Not showing up?</summary>
        <p className="fg-3 mt-2 leading-relaxed">
          The sensor only lives <b>inside an open email</b> — never in the Apps list or
          the app launcher, where Microsoft shows “App launch failed”. After a central
          deployment it can take a few hours to appear (and up to 24–72h to disappear
          after removal). Restarting Outlook usually brings it forward.
        </p>
      </details>

      <details className="mt-2 text-sm">
        <summary className="fg-2 cursor-pointer select-none">Thunderbird or webmail instead?</summary>
        <div className="fg-3 mt-2 space-y-2 leading-relaxed">
          <p>
            <b>Thunderbird:</b>{" "}
            {THUNDERBIRD_LISTING ? (
              <a className="accent underline underline-offset-4" href={THUNDERBIRD_LISTING} target="_blank" rel="noreferrer">
                get it from addons.thunderbird.net
              </a>
            ) : (
              <>in review — on Thunderbird Daily you can{" "}
                <a className="accent underline underline-offset-4" href="/downloads/envelock-sensor-thunderbird.xpi" download>
                  install the add-on from file
                </a>; on release Thunderbird, use the browser extension for now.
              </>
            )}
          </p>
          <p>
            <b>Webmail (Gmail, Outlook web):</b>{" "}
            {anyStore ? (
              <span className="inline-flex flex-wrap gap-x-3">
                {STORES.chrome && <a className="accent underline underline-offset-4" href={STORES.chrome} target="_blank" rel="noreferrer">Chrome</a>}
                {STORES.edge && <a className="accent underline underline-offset-4" href={STORES.edge} target="_blank" rel="noreferrer">Edge</a>}
                {STORES.firefox && <a className="accent underline underline-offset-4" href={STORES.firefox} target="_blank" rel="noreferrer">Firefox</a>}
              </span>
            ) : (
              <>
                in review — for a pilot,{" "}
                <a className="accent underline underline-offset-4" href="/downloads/envelock-sensor-chrome.zip" download>download it</a>,
                unzip, open <b>chrome://extensions</b>, turn on <b>Developer mode</b>, choose <b>Load unpacked</b>.
              </>
            )}
          </p>
        </div>
      </details>
    </div>
  );
}

export default function SensorPanel({
  mailboxes,
  isAdmin,
  planIncludesIdentity,
  onChanged,
}: {
  mailboxes: MailboxRecord[];
  isAdmin: boolean;
  /* Whether the plan includes Channel 2 (Complete). The sensor's only output is
     sign-in and silent-access detection, so on a smaller plan pairing installs
     an extension on someone's laptop that can never raise anything. Say that,
     rather than offering the button and letting the server refuse it. */
  planIncludesIdentity: boolean;
  onChanged: () => Promise<void>;
}) {
  const [devices, setDevices] = useState<SensorDevice[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [target, setTarget] = useState<string>("");
  const [pairing, setPairing] = useState<SensorPairing | null>(null);
  const [busy, setBusy] = useState(false);
  const [arming, setArming] = useState<MailboxRecord | null>(null);
  /* The pairing in flight and how many devices its mailbox had when the code
     was made. A ref, read where the device list arrives: that is the moment a
     pairing completes, so that is where it is noticed. */
  const waiting = useRef<{ mailbox: string; baseline: number } | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await api.sensorDevices();
      setDevices(r.devices);
      setLoadError(null);
      const w = waiting.current;
      if (w) {
        const now = r.devices.filter((d) => !d.revoked && d.mailbox === w.mailbox).length;
        if (now > w.baseline) {
          waiting.current = null;
          setPairing(null);
          toast.success(`Paired — ${w.mailbox} now has a device reporting.`);
        }
      }
    } catch (e) {
      setLoadError(e instanceof ApiError ? e.message : "Could not load devices.");
    }
  }, []);

  useEffect(() => {
    // Polling our own API — the subscribe-to-an-external-system case the rule
    // exempts; the state it sets lands after the request resolves.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void refresh();
    // Faster while a code is waiting to be typed in, so the new device appears
    // the moment it pairs instead of on the next slow tick.
    const id = window.setInterval(() => void refresh(), pairing ? 4000 : 30000);
    return () => window.clearInterval(id);
  }, [refresh, pairing]);

  const live = (devices ?? []).filter((d) => !d.revoked);
  const byMailbox = useMemo(() => {
    const map = new Map<string, SensorDevice[]>();
    for (const d of live) map.set(d.mailbox_id, [...(map.get(d.mailbox_id) ?? []), d]);
    return map;
  }, [live]);

  const selected = target || mailboxes[0]?.id || "";

  async function createCode() {
    if (!selected) return;
    setBusy(true);
    try {
      const code = await api.createSensorPairing(selected);
      waiting.current = {
        mailbox: code.mailbox,
        baseline: live.filter((d) => d.mailbox === code.mailbox).length,
      };
      setPairing(code);
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not create a pairing code.");
    } finally {
      setBusy(false);
    }
  }

  async function revoke(d: SensorDevice) {
    try {
      await api.revokeSensorDevice(d.id);
      toast.success(`${d.label ?? CLIENT_NAME[d.client]} removed — it stops reporting now.`);
      await refresh();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not remove the device.");
    }
  }

  async function setArmed(m: MailboxRecord, armed: boolean) {
    setBusy(true);
    try {
      await api.patchMailbox(m.id, { silent_access_armed: armed });
      toast.success(
        armed
          ? `${m.address}: a read with none of its devices present will now raise an alert.`
          : `${m.address}: silent-access alerts are off.`,
      );
      await onChanged();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not change the setting.");
    } finally {
      setBusy(false);
      setArming(null);
    }
  }

  const expire = useCallback(() => {
    waiting.current = null;
    setPairing(null);
  }, []);

  return (
    <div className="panel">
      <div className="border-b px-5 py-3.5">
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="sect-label">Sign-in protection</h2>
          {devices && (
            <span className="mono-xs fg-3 tnum">
              {live.filter((d) => d.live).length}/{live.length} LIVE
            </span>
          )}
        </div>
        <p className="fg-2 mt-2 text-xs leading-relaxed">
          Install the Envelock sensor where you read mail. It tells Envelock
          which devices are yours, so a sign-in from somewhere new — or a message
          read while none of them were open — raises an alert.
        </p>
        {!planIncludesIdentity && (
          <p className="fg-3 mt-2 text-xs leading-relaxed">
            Sign-in and account-takeover protection is included in the Complete
            plan.{" "}
            <a className="accent underline underline-offset-4" href="/billing">
              Compare plans
            </a>
          </p>
        )}
      </div>

      {loadError && <p className="fg-3 px-5 py-3 text-xs">{loadError}</p>}

      {live.length > 0 && (
        <ul className="divide-y" role="list">
          {live.map((d) => (
            <li key={d.id} className="flex items-center gap-3 px-5 py-3">
              <span
                className={cn(
                  "size-2 shrink-0 rounded-full",
                  d.live ? "bg-[var(--accent)]" : "bg-[var(--fg-3)]",
                )}
                aria-label={d.live ? "reporting" : "not reporting"}
              />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{d.label ?? CLIENT_NAME[d.client]}</p>
                <p className="fg-3 mono-xs mt-0.5 truncate">
                  {CLIENT_NAME[d.client].toUpperCase()} · {d.mailbox} ·{" "}
                  {d.live ? "REPORTING" : `LAST SEEN ${ago(d.last_seen_at).toUpperCase()}`}
                </p>
              </div>
              <button
                type="button"
                aria-label={`Remove ${d.label ?? "device"}`}
                className="fg-3 cursor-pointer p-1 transition-colors hover:text-[var(--danger)]"
                onClick={() => void revoke(d)}
              >
                <Trash2 size={14} aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}

      {/* The C11 switch, per mailbox, and only where there is a device to make
          it meaningful — with no sensor every read is unvouched. */}
      {mailboxes.some((m) => byMailbox.has(m.id)) && (
        <div className="border-t px-5 py-3.5">
          <p className="sect-label">Silent-access alerts</p>
          <ul className="mt-2 space-y-2" role="list">
            {mailboxes
              .filter((m) => byMailbox.has(m.id))
              .map((m) => (
                <li key={m.id} className="flex items-center gap-3">
                  <span className="min-w-0 flex-1 truncate text-xs">{m.address}</span>
                  {isAdmin ? (
                    <Button
                      size="sm"
                      variant={m.silent_access_armed ? "accent" : "line"}
                      disabled={busy}
                      onClick={() => (m.silent_access_armed ? void setArmed(m, false) : setArming(m))}
                    >
                      {m.silent_access_armed ? "ON" : "OFF"}
                    </Button>
                  ) : (
                    <span className="fg-3 mono-xs">{m.silent_access_armed ? "ON" : "OFF"}</span>
                  )}
                </li>
              ))}
          </ul>
        </div>
      )}

      <div className="border-t px-5 py-4">
        {pairing ? (
          <div>
            <p className="text-xs">
              Type this into the Envelock sensor for <b>{pairing.mailbox}</b>:
            </p>
            <div className="mt-3 flex items-center gap-3">
              <span className="font-mono accent text-2xl font-semibold tracking-[0.12em] tnum">
                {pairing.code}
              </span>
              <CopyButton text={pairing.code} label="Copy the pairing code" />
            </div>
            <p className="fg-3 mono-xs mt-2 flex items-center gap-1.5">
              <Loader2 size={11} className="animate-spin" aria-hidden />
              WAITING FOR THE DEVICE · EXPIRES IN{" "}
              <Countdown until={pairing.expires_at} onExpired={expire} />
            </p>
            <InstallSteps />
            <Button size="sm" variant="quiet" className="mt-3" onClick={expire}>
              Cancel
            </Button>
          </div>
        ) : mailboxes.length === 0 ? (
          <p className="fg-3 text-xs">Add a mailbox first, then pair the devices that read it.</p>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            {mailboxes.length > 1 && (
              <select
                aria-label="Mailbox to add a device for"
                className="field min-w-0 flex-1 py-1.5 text-xs"
                value={selected}
                onChange={(e) => setTarget(e.target.value)}
              >
                {mailboxes.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.address}
                  </option>
                ))}
              </select>
            )}
            <Button
              size="sm"
              variant="accent"
              disabled={busy || !planIncludesIdentity}
              title={
                planIncludesIdentity
                  ? undefined
                  : "Included in the Complete plan."
              }
              onClick={() => void createCode()}
            >
              {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Plus size={12} aria-hidden />}
              ADD A DEVICE
            </Button>
            {live.length === 0 && planIncludesIdentity && (
              <p className="fg-3 mt-1 flex w-full items-center gap-1.5 text-xs">
                <Laptop size={12} aria-hidden /> No devices yet — sign-in alerts need at least one.
              </p>
            )}
          </div>
        )}
      </div>

      <ConfirmDialog
        open={arming !== null}
        title="Alert when this mailbox is read with none of its devices present?"
        body={`Only turn this on if ${arming?.address ?? "this mailbox"} is read exclusively on devices with the Envelock sensor. A read anywhere else — a phone's mail app, a colleague's laptop — will look exactly like an intruder, because to Envelock it is one.`}
        confirmLabel="Turn on"
        busy={busy}
        onConfirm={() => arming && void setArmed(arming, true)}
        onCancel={() => setArming(null)}
      />
    </div>
  );
}
