import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  BadgeCheck,
  KeyRound,
  Loader2,
  Lock,
  LogOut,
  Phone,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { ApiError, api, auth, type TenantInfo } from "../lib/api";
import { checkPassphrase } from "../lib/passphrase";
import { Button } from "../components/primitives";
import MfaEnroll from "../components/MfaEnroll";

interface Me {
  email: string;
  role: string;
  tenant_id: string;
  is_admin: boolean;
  mfa_enabled: boolean;
  phone: string | null;
  phone_verified: boolean;
  recovery_codes_remaining: number;
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-b py-4 last:border-0">
      <span className="fg-2 text-sm">{label}</span>
      <div className="flex items-center gap-2 text-sm font-medium">{children}</div>
    </div>
  );
}

function PhoneSetup({ me, onChanged }: { me: Me; onChanged: () => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [phone, setPhone] = useState(me.phone ?? "");
  const [code, setCode] = useState("");
  // Step-up (only when changing an already-verified number).
  const [pw, setPw] = useState("");
  const [stepCode, setStepCode] = useState("");
  const [sent, setSent] = useState<string | null>(null); // dev code, if returned
  const [delivered, setDelivered] = useState(true);
  const [stage, setStage] = useState<"enter" | "verify">("enter");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const changing = me.phone_verified; // swapping a trusted number is sensitive

  async function start() {
    if (changing && !pw) {
      setNote("Enter your current password to change a verified phone.");
      return;
    }
    setBusy(true);
    setNote(null);
    try {
      const r = await api.phoneStart({
        phone,
        ...(changing ? { current_password: pw } : {}),
        ...(changing ? { mfa_code: stepCode } : {}),
      });
      setSent(r.dev_code ?? null);
      setDelivered(r.delivered);
      setPw("");
      setStepCode("");
      setStage("verify");
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not send the code.");
    } finally {
      setBusy(false);
    }
  }

  async function verify() {
    setBusy(true);
    setNote(null);
    try {
      await api.phoneVerify(code);
      setOpen(false);
      setStage("enter");
      setCode("");
      await onChanged();
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Invalid code.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <Button size="sm" variant="line" onClick={() => setOpen(true)}>
        <Phone size={12} aria-hidden />
        {me.phone_verified ? "Change phone" : "Add a recovery phone"}
      </Button>
    );
  }

  // Changing a trusted number is a sensitive action → MFA required.
  if (changing && !me.mfa_enabled) {
    return (
      <div className="w-full">
        <p className="fg-3 flex items-start gap-2 text-xs leading-relaxed">
          <ShieldAlert size={13} className="mt-0.5 shrink-0" aria-hidden />
          Turn on two-factor authentication above to change your recovery phone.
        </p>
        <Button size="sm" variant="quiet" className="mt-2" onClick={() => setOpen(false)}>
          CLOSE
        </Button>
      </div>
    );
  }

  return (
    <div className="w-full">
      {stage === "enter" ? (
        <div className="w-full">
          {changing && (
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <input
                type="password"
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                placeholder="current password"
                className="field w-52 text-sm"
                autoComplete="current-password"
              />
              <input
                value={stepCode}
                onChange={(e) => setStepCode(e.target.value.replace(/\D/g, ""))}
                inputMode="numeric"
                maxLength={6}
                placeholder="auth code"
                className="field font-mono w-28 text-sm tracking-[0.2em]"
              />
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <input
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+1 415 555 0100"
              className="field w-52 text-sm"
              autoComplete="tel"
            />
            <Button size="sm" variant="accent" onClick={start} disabled={busy || phone.length < 8}>
              {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : null} SEND CODE
            </Button>
            <Button size="sm" variant="quiet" onClick={() => setOpen(false)} disabled={busy}>
              CANCEL
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            inputMode="numeric"
            maxLength={6}
            placeholder="000000"
            className="field font-mono w-28 text-sm tracking-[0.3em]"
          />
          <Button size="sm" variant="accent" onClick={verify} disabled={busy || code.length !== 6}>
            {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : null} VERIFY
          </Button>
          {sent && (
            <span className="fg-3 mono-xs">dev code: {sent}</span>
          )}
        </div>
      )}
      {stage === "verify" && !delivered && !sent && (
        <p className="callout mt-2 px-3 py-2 text-xs leading-relaxed">
          We couldn't send the SMS — this server has no SMS provider configured
          yet, so phone verification can't complete. Ask your admin to add one.
        </p>
      )}
      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}
    </div>
  );
}

/* Turn MFA off — gated behind the current password AND a fresh authenticator
   code, so a session alone can't strip the second factor. */
function MfaDisable({ onDone }: { onDone: () => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function submit() {
    setBusy(true);
    setNote(null);
    try {
      await api.mfaDisable({ password: pw, mfa_code: code });
      setOpen(false);
      setPw("");
      setCode("");
      await onDone();
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not disable two-factor.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fg-3 text-xs underline underline-offset-4 hover:text-[var(--danger)]"
      >
        Disable
      </button>
    );
  }

  return (
    <div className="w-full">
      <p className="fg-3 mb-2 text-xs">Confirm with your password and a current code.</p>
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="password"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="current password"
          className="field w-52 text-sm"
          autoComplete="current-password"
        />
        <input
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          inputMode="numeric"
          maxLength={6}
          placeholder="auth code"
          className="field font-mono w-28 text-sm tracking-[0.2em]"
        />
        <Button size="sm" variant="line" onClick={submit} disabled={busy || !pw || code.length !== 6}>
          {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : null} TURN OFF
        </Button>
        <Button size="sm" variant="quiet" onClick={() => setOpen(false)} disabled={busy}>
          CANCEL
        </Button>
      </div>
      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}
    </div>
  );
}

/* Change the account password. Requires the current password (+ a code when MFA
   is on); on success every session is revoked, so we send the user back to
   sign-in. */
function ChangePassword({ me }: { me: Me }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const strength = checkPassphrase(next);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNote(null);
    try {
      await api.changePassword({
        current_password: cur,
        new_password: next,
        ...(me.mfa_enabled ? { mfa_code: code } : {}),
      });
      // Sessions were revoked server-side — re-authenticate.
      auth.clear();
      navigate("/signin", {
        state: { notice: "Password changed. Sign in with your new password." },
      });
    } catch (err) {
      setNote(err instanceof ApiError ? err.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  }

  // The password can be changed with just the current password when MFA is off;
  // with MFA on, a fresh code is also required (the field below is conditional).
  if (!open) {
    return (
      <Button size="sm" variant="line" onClick={() => setOpen(true)}>
        <Lock size={12} aria-hidden /> Change password
      </Button>
    );
  }

  return (
    <form onSubmit={submit} className="w-full space-y-3">
      <div>
        <label htmlFor="cur-pw" className="block text-xs font-semibold">
          Current password
        </label>
        <input
          id="cur-pw"
          type="password"
          value={cur}
          onChange={(e) => setCur(e.target.value)}
          autoComplete="current-password"
          className="field mt-1 text-sm"
        />
      </div>
      <div>
        <label htmlFor="new-pw" className="block text-xs font-semibold">
          New password
        </label>
        <input
          id="new-pw"
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          autoComplete="new-password"
          minLength={12}
          className="field mt-1 text-sm"
        />
        {next && (
          <p
            className="mt-1 text-xs font-medium"
            style={{ color: strength.ok ? "#16a34a" : "#d97706" }}
          >
            {strength.label}
            {strength.hint ? ` — ${strength.hint}` : ""}
          </p>
        )}
      </div>
      {me.mfa_enabled && (
        <div>
          <label htmlFor="pw-code" className="block text-xs font-semibold">
            Authenticator code
          </label>
          <input
            id="pw-code"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            inputMode="numeric"
            maxLength={6}
            placeholder="000000"
            className="field font-mono mt-1 w-40 text-sm tracking-[0.3em]"
          />
        </div>
      )}
      {note && <p className="text-xs text-red-600">{note}</p>}
      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          variant="accent"
          disabled={busy || !cur || !strength.ok || (me.mfa_enabled && code.length !== 6)}
        >
          {busy ? (
            <Loader2 size={12} className="animate-spin" aria-hidden />
          ) : (
            <KeyRound size={12} aria-hidden />
          )}
          UPDATE PASSWORD
        </Button>
        <Button type="button" size="sm" variant="quiet" onClick={() => setOpen(false)} disabled={busy}>
          CANCEL
        </Button>
      </div>
      <p className="fg-3 text-xs leading-relaxed">
        Changing your password signs out every other device.
      </p>
    </form>
  );
}

/* Full account deletion. Confirmed with the password (+ code when MFA is on) and
   a typed confirmation. The domain is kept in the anti-abuse ledger, so returning
   later means no fresh trial — surfaced honestly in the copy. */
function DeleteAccount({ me }: { me: Me }) {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [pw, setPw] = useState("");
  const [code, setCode] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setNote(null);
    try {
      await api.deleteTenant({
        password: pw,
        ...(me.mfa_enabled ? { mfa_code: code } : {}),
      });
      try {
        const { disablePush } = await import("../lib/push");
        await disablePush();
      } catch {
        /* best effort */
      }
      auth.clear();
      // /signin is the only page that reads location.state.notice — landing on
      // "/" showed nothing, so account deletion ended with zero confirmation.
      navigate("/signin", {
        state: { notice: "Your account and its data were deleted." },
      });
    } catch (err) {
      setNote(err instanceof ApiError ? err.message : "Could not delete the account.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs font-semibold text-[var(--danger)] underline underline-offset-4"
      >
        Delete account
      </button>
    );
  }

  return (
    <form onSubmit={submit} className="w-full space-y-3">
      <p className="fg-2 text-xs leading-relaxed">
        This permanently deletes your workspace — mailboxes, alerts, and audit
        trail. It cannot be undone. Your domain stays on our anti-abuse ledger, so
        if you come back after using a trial you'll subscribe from the start (no
        second free trial).
      </p>
      <input
        type="password"
        value={pw}
        onChange={(e) => setPw(e.target.value)}
        placeholder="current password"
        autoComplete="current-password"
        className="field text-sm"
      />
      {me.mfa_enabled && (
        <input
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          inputMode="numeric"
          maxLength={6}
          placeholder="authenticator code"
          className="field font-mono w-44 text-sm tracking-[0.3em]"
        />
      )}
      <div>
        <label htmlFor="del-confirm" className="fg-3 block text-xs">
          Type <span className="font-mono font-semibold">DELETE</span> to confirm
        </label>
        <input
          id="del-confirm"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          className="field mt-1 w-44 text-sm"
          autoComplete="off"
        />
      </div>
      {note && <p className="text-xs text-red-600">{note}</p>}
      <div className="flex gap-2">
        <Button
          type="submit"
          size="sm"
          variant="line"
          className="border-[var(--danger)] text-[var(--danger)] hover:bg-[var(--danger)]/10"
          disabled={busy || !pw || confirm !== "DELETE" || (me.mfa_enabled && code.length !== 6)}
        >
          {busy ? <Loader2 size={12} className="animate-spin" aria-hidden /> : <Trash2 size={12} aria-hidden />}
          DELETE FOREVER
        </Button>
        <Button type="button" size="sm" variant="quiet" onClick={() => setOpen(false)} disabled={busy}>
          CANCEL
        </Button>
      </div>
    </form>
  );
}

export default function Profile() {
  const navigate = useNavigate();
  const [me, setMe] = useState<Me | null>(null);
  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [mfaOpen, setMfaOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [m, t] = await Promise.all([api.me(), api.tenant()]);
      setMe(m as Me);
      setTenant(t);
    } catch (e) {
      setError(e instanceof ApiError && e.unauthorized ? "signed-out" : "Could not load your profile.");
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: load() flips a loading flag before its first await. That's
    // the intended pattern here, not the cascading-render case the rule targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  async function signOut() {
    try {
      const { disablePush } = await import("../lib/push");
      await disablePush();
    } catch {
      /* best effort */
    }
    try {
      await api.logout();
    } catch {
      /* best-effort */
    }
    auth.clear();
    navigate("/");
  }

  if (error && error !== "signed-out") {
    // A 500 on /auth/me used to render "Loading…" forever — the error state
    // existed and nothing displayed it.
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <h1 className="headline">Couldn't load your profile</h1>
          <p className="fg-2 mt-3 text-sm">{error}</p>
          <Button className="mt-6" onClick={() => window.location.reload()}>
            Try again
          </Button>
        </div>
      </main>
    );
  }

  if (error === "signed-out" || !auth.signedIn) {
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <h1 className="headline">Sign in to manage your profile</h1>
          <Link to="/signin" className="mt-8 inline-block">
            <Button variant="accent" size="lg">
              SIGN IN
            </Button>
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="shell max-w-2xl py-12">
      <div className="flex items-center gap-3">
        <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
        <span className="sect-label">Your account</span>
      </div>
      <h1 className="headline mt-5">Profile &amp; security</h1>

      {!me ? (
        <p className="fg-3 mt-8 text-sm">Loading…</p>
      ) : (
        <>
          {/* Account */}
          <section className="panel mt-8 px-6 py-2">
            <Row label="Email">{me.email}</Row>
            <Row label="Role">
              <span className="font-mono text-xs uppercase">{me.role}</span>
            </Row>
            <Row label="Organisation">{tenant?.name ?? tenant?.primary_domain ?? "—"}</Row>
            <Row label="Plan">
              <span className="font-mono text-xs uppercase">{tenant?.plan ?? "guard"}</span>
              {tenant?.trial.active && tenant.trial.days_left !== null && (
                <span className="fg-3 text-xs">
                  · trial ends in {tenant.trial.days_left} day
                  {tenant.trial.days_left === 1 ? "" : "s"}
                </span>
              )}
            </Row>
          </section>

          {/* Security */}
          <div className="mt-8 flex items-center gap-2">
            <ShieldCheck size={16} className="accent" aria-hidden />
            <h2 className="text-sm font-semibold">Two-factor &amp; recovery</h2>
          </div>
          {!me.mfa_enabled && (
            <div className="callout mt-3 flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
              <ShieldAlert size={18} className="shrink-0" aria-hidden />
              <p className="min-w-0 flex-1 text-xs leading-relaxed">
                <span className="font-semibold">Two-factor is off.</span> A stolen
                password is enough to take this account. Turn it on below.
              </p>
            </div>
          )}
          <section className="panel mt-3 px-6 py-2">
            <Row label="Authenticator app (TOTP)">
              {me.mfa_enabled ? (
                <>
                  <span className="accent flex items-center gap-1.5 text-xs font-semibold">
                    <BadgeCheck size={14} aria-hidden /> ACTIVE
                  </span>
                  <MfaDisable onDone={load} />
                </>
              ) : mfaOpen ? (
                <Button size="sm" variant="quiet" onClick={() => setMfaOpen(false)}>
                  CANCEL
                </Button>
              ) : (
                <Button size="sm" variant="accent" onClick={() => setMfaOpen(true)}>
                  <ShieldAlert size={12} aria-hidden /> SET UP NOW
                </Button>
              )}
            </Row>
            {!me.mfa_enabled && mfaOpen && (
              <div className="rise border-b py-4">
                <MfaEnroll
                  onDone={async () => {
                    setMfaOpen(false);
                    await load();
                  }}
                  onCancel={() => setMfaOpen(false)}
                />
              </div>
            )}
            <Row label="Recovery codes">
              {me.mfa_enabled ? (
                <span className="fg-3 text-xs">
                  {me.recovery_codes_remaining} remaining · single-use
                </span>
              ) : (
                <span className="fg-3 text-xs">Issued when you turn on two-factor</span>
              )}
            </Row>
            <Row label={me.phone_verified ? `Recovery phone (${me.phone})` : "Recovery phone"}>
              {me.phone_verified ? (
                <span className="accent flex items-center gap-1.5 text-xs font-semibold">
                  <BadgeCheck size={14} aria-hidden /> VERIFIED
                </span>
              ) : (
                <PhoneSetup me={me} onChanged={load} />
              )}
            </Row>
            {me.phone_verified && (
              <Row label="">
                <PhoneSetup me={me} onChanged={load} />
              </Row>
            )}
          </section>
          <p className="fg-3 mt-3 text-xs leading-relaxed">
            A hardware passkey (WebAuthn) is on the roadmap. Until then, your
            authenticator app is the primary factor, with recovery codes and a
            verified phone as backups.
          </p>

          {/* Password */}
          <div className="mt-8 flex items-center gap-2">
            <Lock size={16} className="accent" aria-hidden />
            <h2 className="text-sm font-semibold">Password</h2>
          </div>
          <section className="panel mt-3 p-6">
            <ChangePassword me={me} />
          </section>

          <div className="mt-10 flex items-center gap-3">
            <Button variant="line" onClick={signOut}>
              <LogOut size={14} aria-hidden /> SIGN OUT
            </Button>
            <Link to="/dashboard">
              <Button variant="quiet">BACK TO DASHBOARD</Button>
            </Link>
          </div>

          {/* Danger zone — owner only, since deletion removes the whole tenant. */}
          {me.role === "owner" && (
            <>
              <div className="mt-12 flex items-center gap-2">
                <Trash2 size={16} className="text-[var(--danger)]" aria-hidden />
                <h2 className="text-sm font-semibold text-[var(--danger)]">
                  Danger zone
                </h2>
              </div>
              <section className="panel mt-3 border-[var(--danger)]/40 p-6">
                <DeleteAccount me={me} />
              </section>
            </>
          )}
        </>
      )}
    </main>
  );
}
