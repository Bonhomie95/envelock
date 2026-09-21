import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { CheckCircle2, KeyRound, Loader2, Mail, ShieldAlert } from "lucide-react";
import { ApiError, api } from "../lib/api";
import { Button } from "../components/primitives";

/**
 * Password reset.
 *
 * Two routes in, because a deployment without an SMTP relay must not be a dead
 * end — which is exactly what it was: the server always answered "a link has
 * been sent", nothing was ever sent, and there was no other way through.
 *
 *  - **Emailed link** (`?token=…`): set a new password, plus an authenticator
 *    code if the account has one.
 *  - **Authenticator only**: email + code + new password, no link involved. The
 *    server hands out nothing here, so it is safe to offer to everyone.
 *
 * The "does this account exist" question is never answered either way. What the
 * page does say is whether email delivery works at all, which is a property of
 * the deployment, not of the account.
 */
type Phase = "enter-email" | "set-new" | "code-reset" | "email-sent" | "done";

export default function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const linkToken = params.get("token");

  const [phase, setPhase] = useState<Phase>(linkToken ? "set-new" : "enter-email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPass, setNewPass] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [devLink, setDevLink] = useState<string | null>(null);
  const [emailWorks, setEmailWorks] = useState(true);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function fail(e: unknown) {
    setError(e instanceof ApiError ? e.message : "Something went wrong. Try again.");
  }

  async function submitEmail(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.forgotPassword(email.trim().toLowerCase());
      setNotice(r.message);
      setDevLink(r.reset_link ?? null);
      const canEmail = r.email_delivery === "available";
      setEmailWorks(canEmail);
      // With no relay, sending the customer to "check your email" is a lie.
      // Put them straight on the path that actually works.
      setPhase(canEmail ? "email-sent" : "code-reset");
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  async function submitFromLink(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.resetPassword({
        token: linkToken ?? "",
        new_password: newPass,
        // Sent only when supplied: the server requires it for an account with an
        // authenticator and ignores it otherwise, and the page cannot know which
        // this is without asking the server to tell it — which would leak.
        ...(code.trim() ? { code: code.trim() } : {}),
      });
      setPhase("done");
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  async function submitWithCode(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.resetPasswordWithCode({
        email: email.trim().toLowerCase(),
        code: code.trim(),
        new_password: newPass,
      });
      setPhase("done");
    } catch (e) {
      fail(e);
    } finally {
      setBusy(false);
    }
  }

  const heading =
    phase === "done"
      ? "Password updated"
      : phase === "email-sent"
        ? "Check your email"
        : "Reset your password";

  return (
    <main className="grid12 shell min-h-[calc(100dvh-4rem)] items-center py-16">
      <div className="col-span-12 mx-auto w-full max-w-md md:col-span-6 md:col-start-4">
        <div className="flex items-center gap-3">
          <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
          <span className="sect-label">Account recovery</span>
        </div>
        <h1 className="headline mt-5 text-balance">{heading}</h1>

        {error && (
          <div
            role="alert"
            className="mt-5 border border-[var(--danger)] px-4 py-3 text-xs leading-relaxed text-[var(--danger)]"
          >
            {error}
          </div>
        )}

        {/* Step 1 — who are you */}
        {phase === "enter-email" && (
          <form onSubmit={submitEmail} className="mt-8 space-y-5">
            <p className="lede text-base">
              Enter your work email. We&rsquo;ll send you a reset link — and if
              your account has an authenticator, you can reset with a code
              instead.
            </p>
            <div>
              <label htmlFor="email" className="block text-sm font-semibold">
                Work email
              </label>
              <input
                id="email"
                type="email"
                required
                autoFocus
                value={email}
                onChange={(ev) => setEmail(ev.target.value)}
                placeholder="you@yourcompany.com"
                className="field mt-2"
                autoComplete="username"
              />
            </div>
            <Button variant="accent" size="lg" className="w-full" disabled={busy}>
              {busy ? (
                <Loader2 size={15} className="animate-spin" aria-hidden />
              ) : (
                <Mail size={15} aria-hidden />
              )}
              CONTINUE
            </Button>
            <button
              type="button"
              onClick={() => setPhase("code-reset")}
              className="fg-3 mono-xs w-full cursor-pointer text-center hover:text-[var(--fg)]"
            >
              I HAVE AN AUTHENTICATOR — RESET WITH A CODE
            </button>
          </form>
        )}

        {/* Step 2a — the link was sent */}
        {phase === "email-sent" && (
          <div className="mt-8 space-y-5">
            <p className="lede text-base">{notice}</p>
            <p className="fg-3 text-sm leading-relaxed">
              The link works once and expires in 30 minutes. Check your spam
              folder before asking for another — requesting again too quickly
              won&rsquo;t send a second one.
            </p>
            {devLink && (
              <div className="callout px-4 py-3">
                <p className="mono-xs font-semibold">DEVELOPMENT ONLY</p>
                <a href={devLink} className="mono-xs accent mt-1 block break-all">
                  {devLink}
                </a>
              </div>
            )}
            <button
              type="button"
              onClick={() => setPhase("code-reset")}
              className="fg-3 mono-xs w-full cursor-pointer text-center hover:text-[var(--fg)]"
            >
              NO EMAIL? RESET WITH AN AUTHENTICATOR CODE
            </button>
          </div>
        )}

        {/* Step 2b — authenticator only, no email involved */}
        {phase === "code-reset" && (
          <form onSubmit={submitWithCode} className="mt-8 space-y-5">
            {!emailWorks && notice && (
              <div className="callout flex items-start gap-2.5 px-4 py-3">
                <ShieldAlert size={15} className="mt-0.5 shrink-0" aria-hidden />
                <p className="text-xs leading-relaxed">{notice}</p>
              </div>
            )}
            <p className="lede text-base">
              Enter your email, the six-digit code from your authenticator app,
              and a new password.
            </p>
            <div>
              <label htmlFor="code-email" className="block text-sm font-semibold">
                Work email
              </label>
              <input
                id="code-email"
                type="email"
                required
                value={email}
                onChange={(ev) => setEmail(ev.target.value)}
                placeholder="you@yourcompany.com"
                className="field mt-2"
                autoComplete="username"
              />
            </div>
            <div>
              <label htmlFor="code" className="block text-sm font-semibold">
                Authenticator code
              </label>
              <input
                id="code"
                inputMode="numeric"
                required
                value={code}
                onChange={(ev) =>
                  setCode(ev.target.value.replace(/\D/g, "").slice(0, 6))
                }
                placeholder="000000"
                className="field mono tnum mt-2 text-center text-lg tracking-[0.3em]"
                autoComplete="one-time-code"
              />
            </div>
            <div>
              <label htmlFor="new-pass-code" className="block text-sm font-semibold">
                New password
              </label>
              <input
                id="new-pass-code"
                type="password"
                required
                minLength={12}
                value={newPass}
                onChange={(ev) => setNewPass(ev.target.value)}
                className="field mt-2"
                autoComplete="new-password"
              />
              <p className="fg-3 mt-2 text-xs leading-relaxed">
                At least 12 characters. A passphrase of a few words is stronger
                than a short complicated one.
              </p>
            </div>
            <Button
              variant="accent"
              size="lg"
              className="w-full"
              disabled={busy || code.length < 6}
            >
              {busy ? (
                <Loader2 size={15} className="animate-spin" aria-hidden />
              ) : (
                <KeyRound size={15} aria-hidden />
              )}
              SET NEW PASSWORD
            </Button>
          </form>
        )}

        {/* Step 2c — arrived from the emailed link */}
        {phase === "set-new" && (
          <form onSubmit={submitFromLink} className="mt-8 space-y-5">
            <p className="lede text-base">
              Choose a new password. If your account uses an authenticator, add
              its current code as well.
            </p>
            <div>
              <label htmlFor="new-pass" className="block text-sm font-semibold">
                New password
              </label>
              <input
                id="new-pass"
                type="password"
                required
                minLength={12}
                autoFocus
                value={newPass}
                onChange={(ev) => setNewPass(ev.target.value)}
                className="field mt-2"
                autoComplete="new-password"
              />
              <p className="fg-3 mt-2 text-xs leading-relaxed">
                At least 12 characters. A passphrase of a few words is stronger
                than a short complicated one.
              </p>
            </div>
            <div>
              <label htmlFor="link-code" className="block text-sm font-semibold">
                Authenticator code{" "}
                <span className="fg-3 font-normal">— if you use one</span>
              </label>
              <input
                id="link-code"
                inputMode="numeric"
                value={code}
                onChange={(ev) =>
                  setCode(ev.target.value.replace(/\D/g, "").slice(0, 6))
                }
                placeholder="000000"
                className="field mono tnum mt-2 text-center text-lg tracking-[0.3em]"
                autoComplete="one-time-code"
              />
            </div>
            <Button variant="accent" size="lg" className="w-full" disabled={busy}>
              {busy ? (
                <Loader2 size={15} className="animate-spin" aria-hidden />
              ) : (
                <KeyRound size={15} aria-hidden />
              )}
              SET NEW PASSWORD
            </Button>
          </form>
        )}

        {/* Done */}
        {phase === "done" && (
          <div className="mt-8 space-y-6">
            <p className="flex items-start gap-2.5 text-sm leading-relaxed text-[var(--ok)]">
              <CheckCircle2 size={16} className="mt-0.5 shrink-0" aria-hidden />
              Your password is updated, and every other session has been signed
              out.
            </p>
            <Button
              variant="accent"
              size="lg"
              className="w-full"
              onClick={() => navigate("/signin")}
            >
              SIGN IN
            </Button>
          </div>
        )}

        {phase !== "done" && (
          <p className="fg-3 mt-8 text-sm">
            Remembered it?{" "}
            <Link to="/signin" className="accent font-semibold hover:underline">
              Sign in
            </Link>
          </p>
        )}
      </div>
    </main>
  );
}
