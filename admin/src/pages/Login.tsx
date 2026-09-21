import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, Lock, Moon, ShieldCheck, Sun } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { ApiError, api, auth } from "../lib/api";
import { Button } from "../components/ui";

/* Operator sign-in.
 *
 * Four steps rather than two, because an operator account reaches every tenant's
 * metadata and cannot be allowed to skip either control:
 *
 *   credentials → (enrol an authenticator, if they have none)
 *               → verify a code
 *               → (replace the one-time password, if they were just created)
 *
 * A customer's Envelock login does not work here at all — this is a separate
 * account store with its own token type. */
type Step = "credentials" | "enrol" | "code" | "password" | "recovery";

export default function Login({
  theme,
}: {
  theme: { dark: boolean; toggle: () => void };
}) {
  const navigate = useNavigate();
  const [step, setStep] = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [code, setCode] = useState("");
  const [otpauth, setOtpauth] = useState("");
  const [secret, setSecret] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  //: Carried from the verify response: a brand-new operator still has to
  //: replace their one-time password after saving their recovery codes.
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Good news gets its own channel: "Password set" used to go through the
  // error state and render in red.
  const [info, setInfo] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function submitCredentials(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.login(email.trim(), password);
      setMfaToken(r.mfa_token);
      // A code is single-use; one left in the box from an earlier step only
      // fails. Always start the code step empty.
      setCode("");
      setInfo(null);
      if (r.mfa_setup_required) {
        const s = await api.mfaSetup(r.mfa_token);
        setOtpauth(s.otpauth_uri);
        setSecret(s.secret);
        setStep("enrol");
      } else {
        setStep("code");
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Sign in failed.");
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const v = await api.mfaVerify(mfaToken, code.trim());
      auth.set(v.access_token, v.refresh_token);
      setMustChangePassword(v.must_change_password);
      if (v.recovery_codes?.length) {
        setRecoveryCodes(v.recovery_codes);
        setStep("recovery");
        return;
      }
      if (v.must_change_password) {
        setStep("password");
        return;
      }
      navigate("/");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Invalid code.");
      setCode("");
    } finally {
      setBusy(false);
    }
  }

  async function submitPassword(e: FormEvent) {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      setError("Those two passwords don't match.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.setOwnPassword(password, newPassword);
      // Setting a password revokes every session, including this one — so sign
      // in again cleanly rather than letting the next call 401.
      auth.clear();
      setStep("credentials");
      setPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setInfo("Password set. Sign in with it now.");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not set the password.");
    } finally {
      setBusy(false);
    }
  }

  const TITLES: Record<Step, string> = {
    credentials: "Operator sign in",
    enrol: "Set up your authenticator",
    code: "Two-factor code",
    password: "Choose your password",
    recovery: "Save your recovery codes",
  };
  const LEDES: Record<Step, string> = {
    credentials:
     "Envelock staff only. This is a separate account from any customer login.",
    enrol:
     "Scan this with your authenticator app, then enter the code it shows. Two-factor is required for operators — it cannot be deferred.",
    code: "Enter the 6-digit code from your authenticator app.",
    password:
     "You signed in with a one-time password. Choose your own before continuing.",
    recovery:
     "Store these somewhere safe. Each one signs you in once if you lose your authenticator, and they are shown only now.",
  };

  return (
    <div className="grid min-h-dvh place-items-center px-4 py-10">
      <button
        onClick={theme.toggle}
        aria-label="Toggle theme"
        className="fg-3 fixed top-4 right-4 flex size-10 cursor-pointer items-center justify-center hover:text-[var(--fg)]"
      >
        {theme.dark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
      </button>

      <div className="panel w-full max-w-sm p-8">
        <div className="flex items-center gap-2.5">
          <ShieldCheck size={22} className="accent" aria-hidden />
          <span className="text-lg font-bold tracking-tight">ENVELOCK</span>
          <span className="sect-label border-l pl-2.5">ADMIN</span>
        </div>
        <h1 className="mt-6 text-xl font-bold">{TITLES[step]}</h1>
        <p className="fg-2 mt-2 text-sm leading-relaxed">{LEDES[step]}</p>

        {step === "credentials" && (
          <form onSubmit={submitCredentials} className="mt-6 space-y-4">
            <div>
              <label htmlFor="email" className="sect-label">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@envelock.com"
                className="field mt-1.5"
                autoComplete="username"
              />
            </div>
            <div>
              <label htmlFor="password" className="sect-label">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="field mt-1.5"
                autoComplete="current-password"
              />
            </div>
            <Button variant="accent" className="w-full" disabled={busy}>
              {busy ? (
                <Loader2 size={14} className="animate-spin" aria-hidden />
              ) : (
                <Lock size={14} aria-hidden />
              )}
              CONTINUE
            </Button>
          </form>
        )}

        {step === "enrol" && (
          <div className="mt-6 space-y-4">
            <div className="flex justify-center bg-white p-4">
              <QRCodeSVG value={otpauth} size={168} />
            </div>
            <details>
              <summary className="fg-3 mono cursor-pointer text-xs">
                Can't scan? Enter this key instead
              </summary>
              <code className="mono mt-2 block break-all text-xs">{secret}</code>
            </details>
            <Button
              variant="accent"
              className="w-full"
              onClick={() => setStep("code")}
            >
              I'VE ADDED IT
            </Button>
          </div>
        )}

        {step === "code" && (
          <form onSubmit={submitCode} className="mt-6 space-y-4">
            <input
              inputMode="numeric"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="000000"
              aria-label="Authenticator code"
              className="field mono tnum text-center text-lg tracking-[0.3em]"
            />
            <Button
              variant="accent"
              className="w-full"
              disabled={busy || code.length < 6}
            >
              {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
              VERIFY
            </Button>
            <button
              type="button"
              onClick={() => {
                setStep("credentials");
                setCode("");
                setError(null);
              }}
              className="fg-3 mono w-full text-center text-xs hover:text-[var(--fg)]"
            >
              ← Back
            </button>
          </form>
        )}

        {step === "recovery" && (
          <div className="mt-6 space-y-4">
            <ul className="mono grid grid-cols-2 gap-1.5 text-xs" role="list">
              {recoveryCodes.map((c) => (
                <li key={c} className="border px-2 py-1.5 text-center">
                  {c}
                </li>
              ))}
            </ul>
            <div className="flex gap-2">
              <Button
                variant="line"
                className="flex-1"
                onClick={() => {
                  void navigator.clipboard.writeText(recoveryCodes.join("\n"));
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
              >
                {copied ? "COPIED" : "COPY ALL"}
              </Button>
              <Button
                variant="line"
                className="flex-1"
                onClick={() => {
                  const url = URL.createObjectURL(
                    new Blob(
                      [
                        `Envelock operator recovery codes for ${email}\n` +
                          "Each code works once.\n\n" +
                          recoveryCodes.join("\n") +
                          "\n",
                      ],
                      { type: "text/plain" },
                    ),
                  );
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = "envelock-operator-recovery-codes.txt";
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                DOWNLOAD
              </Button>
            </div>
            <Button
              variant="accent"
              className="w-full"
              onClick={() => (mustChangePassword ? setStep("password") : navigate("/"))}
            >
              I'VE SAVED THEM
            </Button>
          </div>
        )}

        {step === "password" && (
          <form onSubmit={submitPassword} className="mt-6 space-y-4">
            <div>
              <label htmlFor="new-password" className="sect-label">
                New password
              </label>
              <input
                id="new-password"
                type="password"
                required
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="field mt-1.5"
                autoComplete="new-password"
              />
            </div>
            <div>
              <label htmlFor="confirm-password" className="sect-label">
                Confirm
              </label>
              <input
                id="confirm-password"
                type="password"
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="field mt-1.5"
                autoComplete="new-password"
              />
            </div>
            <Button variant="accent" className="w-full" disabled={busy}>
              {busy ? <Loader2 size={14} className="animate-spin" aria-hidden /> : null}
              SET PASSWORD
            </Button>
          </form>
        )}

        {info && !error && (
          <p role="status" className="mt-4 text-sm text-[var(--ok)]">
            {info}
          </p>
        )}
        {error && (
          <p role="alert" className="mt-4 text-sm text-[var(--danger)]">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}
