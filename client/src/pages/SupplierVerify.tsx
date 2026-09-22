import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { CheckCircle2, Loader2, ShieldCheck, XCircle } from "lucide-react";
import { ApiError, api } from "../lib/api";
import { Button } from "../components/primitives";

/**
 * The page a supplier opens from our text: "did you change your payment
 * details?" One question, two buttons, no account. The link is single-use,
 * expires, and only its hash is stored. Deliberately bare — the person reading
 * it is not our customer, and a page that looks like a sales site reads as spam.
 */
type View = { company: string; account: string | null; status: string };

export default function SupplierVerify() {
  const { token = "" } = useParams();
  const [view, setView] = useState<View | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"yes" | "no" | null>(null);

  useEffect(() => {
    let live = true;
    api
      .supplierVerification(token)
      .then((v) => live && setView(v))
      .catch((e) => live && setError(e instanceof ApiError ? e.message : "This link isn't valid."));
    return () => {
      live = false;
    };
  }, [token]);

  async function answer(a: "yes" | "no") {
    setBusy(a);
    setError(null);
    try {
      const r = await api.answerSupplierVerification(token, a);
      setView((v) => (v ? { ...v, status: r.status } : v));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Please try again.");
    } finally {
      setBusy(null);
    }
  }

  const company = view?.company ?? "Your customer";

  return (
    <main className="mx-auto max-w-md px-4 py-16">
      <div className="fg-3 mono-xs mb-6 flex items-center gap-2">
        <ShieldCheck size={14} aria-hidden /> PAYMENT CHECK · VIA ENVELOCK
      </div>
      <div className="panel p-6">
        {!view && !error && (
          <p className="fg-2 flex items-center gap-2 text-sm">
            <Loader2 size={14} className="animate-spin" aria-hidden /> Loading…
          </p>
        )}
        {error && !view && (
          <p className="text-sm" role="alert">
            {error}
          </p>
        )}
        {view && view.status === "pending" && (
          <>
            <h1 className="text-xl font-semibold">Did you change your payment details?</h1>
            <p className="fg-2 mt-3 text-sm leading-relaxed">
              <b>{company}</b> received an email, apparently from you, asking them to pay
              into a new bank account
              {view.account ? (
                <>
                  {" "}
                  (<span className="tnum font-mono">{view.account}</span>)
                </>
              ) : null}
              . Before they pay, they'd like you to confirm it was really you.
            </p>
            <div className="mt-6 grid gap-2">
              <Button variant="line" disabled={busy !== null} onClick={() => answer("yes")}>
                {busy === "yes" && <Loader2 size={13} className="animate-spin" aria-hidden />}
                YES — WE CHANGED OUR DETAILS
              </Button>
              <Button variant="accent" disabled={busy !== null} onClick={() => answer("no")}>
                {busy === "no" && <Loader2 size={13} className="animate-spin" aria-hidden />}
                NO — WE DIDN'T SEND THAT
              </Button>
            </div>
            <p className="fg-3 mt-4 text-xs leading-relaxed">
              If you answer no, please also check your own email account: requests like
              this often come from a mailbox someone else has got into.
            </p>
          </>
        )}
        {view && view.status === "confirmed" && (
          <p className="flex items-start gap-2 text-sm">
            <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-[var(--ok)]" aria-hidden />
            Thank you — {company} has your confirmation.
          </p>
        )}
        {view && view.status === "denied" && (
          <div className="text-sm">
            <p className="flex items-start gap-2">
              <XCircle size={16} className="mt-0.5 shrink-0 text-[var(--danger)]" aria-hidden />
              Thank you. {company} won't pay that account.
            </p>
            <p className="fg-2 mt-3 leading-relaxed">
              Someone sent that request in your name. Please change your email password,
              turn on two-factor sign-in, and check for mail-forwarding rules you didn't set up.
            </p>
          </div>
        )}
        {view && view.status === "expired" && (
          <p className="text-sm">This link has expired. {company} will call you instead.</p>
        )}
        {view && error && (
          <p className="mt-3 text-sm text-[var(--danger)]" role="alert">
            {error}
          </p>
        )}
      </div>
    </main>
  );
}
