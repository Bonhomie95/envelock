import { useEffect, useRef, useState, type FormEvent } from "react";
import { ShieldCheck } from "lucide-react";
import { useModalFocus } from "../lib/useModalFocus";
import type { ReauthCreds } from "../lib/api";
import { Button } from "./primitives";

export type { ReauthCreds };

/** The one re-authentication prompt, reused by every sensitive action.
 *
 * The server forces a fresh re-auth (SENSITIVE_ACTIONS + the supplier
 * ground-truth writes) so a stolen session can't quietly bind a second factor,
 * delete a mailbox and its stored credential, or point a supplier's known-good
 * account at an attacker. This collects the current password, plus an
 * authenticator code the server needs only when two-factor is on.
 *
 * Controlled, like ConfirmDialog: the parent runs the action, and on a 401 keeps
 * the dialog open with `error` set so the person can correct the password.
 */
export default function ReAuthDialog({
  open,
  title,
  body,
  confirmLabel = "CONFIRM",
  busy = false,
  error = null,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: string;
  confirmLabel?: string;
  busy?: boolean;
  error?: string | null;
  onConfirm: (creds: ReauthCreds) => void;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const dialogRef = useModalFocus<HTMLFormElement>(open, onCancel, busy);
  const everOpen = useRef(false);

  // Clear the fields each time the dialog opens, so a password is never left
  // sitting in a re-rendered field after a previous action.
  useEffect(() => {
    if (open && !everOpen.current) {
      setPassword("");
      setCode("");
    }
    everOpen.current = open;
  }, [open]);

  if (!open) return null;

  function submit(e: FormEvent) {
    e.preventDefault();
    if (busy || !password) return;
    onConfirm({
      current_password: password,
      ...(code ? { mfa_code: code } : {}),
    });
  }

  return (
    <div
      className="motion-backdrop fixed inset-0 z-[90] flex items-end justify-center bg-black/60 p-3 backdrop-blur-sm sm:items-center"
      onClick={(e) => {
        if (!busy && e.target === e.currentTarget) onCancel();
      }}
    >
      <form
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="reauth-title"
        aria-describedby="reauth-body"
        onSubmit={submit}
        className="motion-dialog w-full max-w-md rounded-xl border bg-[var(--bg-raised)] p-5 shadow-xl"
      >
        <div className="flex items-start gap-3">
          <ShieldCheck size={18} className="mt-0.5 shrink-0 text-[var(--accent)]" aria-hidden />
          <div className="min-w-0">
            <h2 id="reauth-title" className="text-base font-semibold">
              {title}
            </h2>
            <p id="reauth-body" className="fg-2 mt-2 text-sm leading-relaxed">
              {body}
            </p>
          </div>
        </div>

        <div className="mt-4 space-y-3">
          <div>
            <label htmlFor="reauth-password" className="block text-xs font-semibold">
              Current password
            </label>
            <input
              id="reauth-password"
              data-initial-focus
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="field mt-1.5"
              placeholder="Your password"
            />
          </div>
          <div>
            <label htmlFor="reauth-code" className="block text-xs font-semibold">
              Authenticator code{" "}
              <span className="fg-3 font-normal">(only if two-factor is on)</span>
            </label>
            <input
              id="reauth-code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
              inputMode="numeric"
              autoComplete="one-time-code"
              maxLength={6}
              placeholder="000000"
              className="field font-mono mt-1.5 tracking-[0.4em]"
            />
          </div>
        </div>

        {error && (
          <p role="alert" className="mt-3 text-xs text-red-600">
            {error}
          </p>
        )}

        <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="quiet" onClick={onCancel} disabled={busy}>
            CANCEL
          </Button>
          <Button type="submit" variant="accent" disabled={busy || !password}>
            {busy ? "WORKING…" : confirmLabel}
          </Button>
        </div>
      </form>
    </div>
  );
}
