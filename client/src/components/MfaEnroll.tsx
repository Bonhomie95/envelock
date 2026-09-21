import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy, KeyRound, Loader2 } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { ApiError, api } from "../lib/api";
import { Button } from "./primitives";

/* Turn MFA on from inside an authenticated session — the path for a user who
   deferred it at sign-in. Drives /auth/mfa/enroll → /auth/mfa/activate and then
   shows the one-time recovery codes. Reused by the dashboard alert and Profile. */
export default function MfaEnroll({
  onDone,
  onCancel,
}: {
  onDone: () => void | Promise<void>;
  onCancel?: () => void;
}) {
  const [stage, setStage] = useState<"scan" | "recovery">("scan");
  const [secret, setSecret] = useState("");
  const [otpauthUri, setOtpauthUri] = useState("");
  const [showSecret, setShowSecret] = useState(false);
  const [copied, setCopied] = useState(false);
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState<string[]>([]);
  // Starts busy: the enrolment request fires immediately on mount.
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function fail(e: unknown) {
    setError(e instanceof ApiError ? e.message : "Something went wrong — try again.");
  }

  // Request the enrolment secret once when the card opens.
  useEffect(() => {
    let live = true;
    api
      .mfaEnroll()
      .then((r) => {
        if (!live) return;
        setSecret(r.secret);
        setOtpauthUri(r.otpauth_uri);
      })
      .catch((e) => live && fail(e))
      .finally(() => live && setBusy(false));
    return () => {
      live = false;
    };
  }, []);

  async function activate(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.mfaActivate(code);
      setRecovery(r.recovery_codes);
      setStage("recovery");
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  function copySecret() {
    void navigator.clipboard.writeText(secret);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  if (stage === "recovery") {
    return (
      <div>
        <h3 className="text-sm font-semibold">Save your recovery codes</h3>
        <p className="fg-3 mt-1 text-xs leading-relaxed">
          Shown once. Each works a single time if you lose your authenticator.
        </p>
        <div className="panel mt-3 grid grid-cols-2 gap-2 p-4">
          {recovery.map((c) => (
            <code key={c} className="font-mono text-sm">
              {c}
            </code>
          ))}
        </div>
        <Button
          variant="accent"
          size="sm"
          className="mt-4"
          onClick={() => void onDone()}
        >
          <Check size={13} aria-hidden /> I'VE SAVED THEM
        </Button>
      </div>
    );
  }

  return (
    <div>
      <p className="fg-3 text-xs leading-relaxed">
        Scan this with your authenticator app (Google Authenticator, Authy,
        1Password, …), then enter the 6-digit code it shows.
      </p>

      <div className="mt-4 flex flex-col gap-4 sm:flex-row sm:items-start">
        <div className="shrink-0 self-center rounded-lg bg-white p-3 sm:self-start">
          {otpauthUri ? (
            <QRCodeSVG value={otpauthUri} size={140} marginSize={0} />
          ) : (
            <div className="flex size-[140px] items-center justify-center">
              <Loader2 size={20} className="animate-spin text-black" aria-hidden />
            </div>
          )}
        </div>

        <form onSubmit={activate} className="flex-1 space-y-3">
          <div>
            <label htmlFor="mfa-enroll-code" className="block text-xs font-semibold">
              Authentication code
            </label>
            <input
              id="mfa-enroll-code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              className="field font-mono mt-1.5 tracking-[0.4em]"
            />
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              type="submit"
              variant="accent"
              size="sm"
              disabled={busy || code.length !== 6}
            >
              {busy ? (
                <Loader2 size={12} className="animate-spin" aria-hidden />
              ) : (
                <KeyRound size={12} aria-hidden />
              )}
              TURN ON
            </Button>
            {onCancel && (
              <Button type="button" variant="quiet" size="sm" onClick={onCancel} disabled={busy}>
                CANCEL
              </Button>
            )}
          </div>

          <button
            type="button"
            onClick={() => setShowSecret((v) => !v)}
            className="fg-2 cursor-pointer text-xs font-semibold underline underline-offset-4"
          >
            {showSecret ? "Hide setup key" : "Can't scan? Enter a key instead"}
          </button>
          {showSecret && (
            <div className="flex items-center gap-2">
              <code className="font-mono flex-1 text-xs break-all">{secret}</code>
              <Button size="sm" variant="line" onClick={copySecret} type="button">
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
        </form>
      </div>

      {error && (
        <p role="alert" className="mt-3 text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}
