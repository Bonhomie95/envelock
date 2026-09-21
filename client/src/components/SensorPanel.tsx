import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Check, Copy, Laptop, Loader2, Plus, Trash2 } from "lucide-react";
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

function InstallSteps() {
  const anyStore = STORES.chrome || STORES.edge || STORES.firefox;
  return (
    <ol className="mt-4 space-y-4 text-xs leading-relaxed" role="list">
      <li>
        <p className="font-semibold">Outlook — Microsoft 365, Exchange or Outlook.com</p>
        <p className="fg-2 mt-1">
          In Outlook, <b>Get Add-ins → My add-ins → Add a custom add-in → From URL</b>,
          and paste this. IT can deploy it to everyone from the Microsoft 365 admin
          centre with the same address.
        </p>
        <div className="mt-2 flex items-center gap-2">
          <code className="flex-1 truncate font-mono text-[11px]">{OUTLOOK_MANIFEST}</code>
          <CopyButton text={OUTLOOK_MANIFEST} label="Copy the Outlook add-in address" />
        </div>
        <p className="fg-3 mt-1">Pin the Envelock pane so it stays open between messages.</p>
      </li>
      <li>
        <p className="font-semibold">Thunderbird</p>
        <p className="fg-2 mt-1">
          <a className="accent underline underline-offset-4" href="/downloads/envelock-sensor-thunderbird.xpi" download>
            Download the add-on
          </a>
          , then in Thunderbird <b>Add-ons and Themes → ⚙ → Install Add-on From File</b>.
        </p>
      </li>
      <li>
        <p className="font-semibold">Webmail in a browser — Gmail, Outlook on the web, your provider's webmail</p>
        {anyStore ? (
          <p className="fg-2 mt-1 flex flex-wrap gap-x-3 gap-y-1">
            {STORES.chrome && (
              <a className="accent underline underline-offset-4" href={STORES.chrome} target="_blank" rel="noreferrer">
                Chrome
              </a>
            )}
            {STORES.edge && (
              <a className="accent underline underline-offset-4" href={STORES.edge} target="_blank" rel="noreferrer">
                Edge
              </a>
            )}
            {STORES.firefox && (
              <a className="accent underline underline-offset-4" href={STORES.firefox} target="_blank" rel="noreferrer">
                Firefox
              </a>
            )}
          </p>
        ) : (
          <p className="fg-2 mt-1">
            The extension is in review with the browser stores. For a pilot on
            Chrome or Edge now:{" "}
            <a className="accent underline underline-offset-4" href="/downloads/envelock-sensor-chrome.zip" download>
              download it
            </a>
            , unzip it, open <b>chrome://extensions</b>, turn on <b>Developer mode</b> and
            choose <b>Load unpacked</b>.
          </p>
        )}
      </li>
    </ol>
  );
}

export default function SensorPanel({
  mailboxes,
  isAdmin,
  onChanged,
}: {
  mailboxes: MailboxRecord[];
  isAdmin: boolean;
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
            <Button size="sm" variant="accent" disabled={busy} onClick={() => void createCode()}>
              {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Plus size={12} aria-hidden />}
              ADD A DEVICE
            </Button>
            {live.length === 0 && (
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
