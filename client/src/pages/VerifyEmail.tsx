import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CheckCircle2, Loader2, Mail, ShieldAlert } from "lucide-react";
import { ApiError, api } from "../lib/api";
import { Button } from "../components/primitives";

/**
 * Email-ownership verification (anti tenant-squatting).
 *
 * Two ways in:
 *  - **Emailed link** (`?token=…`): confirms immediately.
 *  - **No token**: a resend form, for an expired or lost link. The server never
 *    says whether the address exists.
 */
type Phase = "verifying" | "done" | "resend" | "sent" | "failed";

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const token = params.get("token");

  const [phase, setPhase] = useState<Phase>(token ? "verifying" : "resend");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    (async () => {
      try {
        await api.verifyEmail(token);
        if (!cancelled) setPhase("done");
      } catch (e) {
        if (cancelled) return;
        setError(
          e instanceof ApiError
            ? e.message
            : "The link could not be verified. It may have expired.",
        );
        setPhase("failed");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [token]);

  async function resend(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.resendVerification(email.trim().toLowerCase());
      setPhase("sent");
    } catch (err) {
      setError(
        err instanceof ApiError ? err.message : "Something went wrong. Try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md px-4 py-16">
      <h1 className="text-xl font-semibold">Confirm your email</h1>

      {phase === "verifying" && (
        <p className="fg-2 mt-6 flex items-center gap-2 text-sm">
          <Loader2 size={16} className="animate-spin" aria-hidden />
          Checking your link…
        </p>
      )}

      {phase === "done" && (
        <div className="mt-6">
          <p className="flex items-center gap-2 text-sm">
            <CheckCircle2 size={16} aria-hidden />
            Your email is confirmed — your workspace is active.
          </p>
          <Link to="/signin" className="mt-4 inline-block">
            <Button>Sign in</Button>
          </Link>
        </div>
      )}

      {phase === "sent" && (
        <p className="fg-2 mt-6 flex items-start gap-2 text-sm leading-relaxed">
          <Mail size={16} className="mt-0.5 shrink-0" aria-hidden />
          If that address has an unverified account, a fresh link is on its way.
          Check your inbox, then sign in.
        </p>
      )}

      {(phase === "resend" || phase === "failed") && (
        <form onSubmit={resend} className="mt-6 space-y-4">
          {phase === "failed" && (
            <p role="alert" className="callout flex items-start gap-2 px-4 py-3 text-xs">
              <ShieldAlert size={14} className="mt-0.5 shrink-0" aria-hidden />
              {error ?? "That link didn't work."} Enter your email and we'll send
              a new one.
            </p>
          )}
          <label className="block text-sm">
            <span className="fg-2 mb-1 block text-xs">Work email</span>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="field w-full"
              placeholder="you@yourcompany.com"
            />
          </label>
          {error && phase !== "failed" && (
            <p role="alert" className="callout px-4 py-3 text-xs">
              {error}
            </p>
          )}
          <Button type="submit" disabled={busy}>
            {busy ? "Sending…" : "Send verification link"}
          </Button>
        </form>
      )}

      <p className="fg-3 mt-8 text-xs">
        Already confirmed? <Link to="/signin" className="underline">Sign in</Link>.
      </p>
    </div>
  );
}
