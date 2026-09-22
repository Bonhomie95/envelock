import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2, MessageSquare, PhoneCall, XCircle } from "lucide-react";
import {
  ApiError,
  api,
  type PaymentVerificationInfo,
  type VerificationAttempt,
} from "../lib/api";
import { toast } from "../lib/toast";
import { Button, cn } from "./primitives";

/* Confirming a bank-detail change with the supplier — the step that actually
   stops the payment. Always through the number ON FILE, never one from the
   email; and never by emailing the supplier, because in the common version of
   this fraud their mailbox is the one that's been taken over. */

const STATUS: Record<VerificationAttempt["status"], { label: string; tone: string }> = {
  pending: { label: "Waiting for their answer", tone: "fg-2" },
  confirmed: { label: "Supplier confirmed the change", tone: "text-[var(--ok)]" },
  denied: { label: "Supplier said they did NOT change it", tone: "text-[var(--danger)]" },
  no_answer: { label: "No answer", tone: "fg-2" },
  expired: { label: "Link expired unanswered", tone: "fg-3" },
};

function when(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

export default function VerifyPanel({
  alertId,
  closed,
  onChanged,
}: {
  alertId: string;
  closed: boolean;
  onChanged: () => Promise<void> | void;
}) {
  const [info, setInfo] = useState<PaymentVerificationInfo | null>(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setInfo(await api.verification(alertId));
    } catch {
      setInfo(null);
    }
  }, [alertId]);

  useEffect(() => {
    // Fetch-on-mount; the setter runs after the await, not synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  if (!info) return null;
  const latest = info.attempts[0];
  const phone = info.phone_on_file;

  async function record(outcome: "confirmed" | "denied" | "no_answer") {
    setBusy(outcome);
    setError(null);
    try {
      await api.recordCallOutcome(alertId, outcome, note.trim() || undefined);
      setNote("");
      toast.success(
        outcome === "denied"
          ? "Recorded as fraud. Don't pay — every Envelock customer is now warned about that account."
          : outcome === "confirmed"
            ? "Recorded. If you're satisfied, dismiss the alert to close it."
            : "Recorded. Try again later, or send them a text.",
      );
      await load();
      await onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't record that. Try again.");
    } finally {
      setBusy(null);
    }
  }

  async function text() {
    setBusy("sms");
    setError(null);
    try {
      await api.sendVerificationText(alertId);
      toast.success(`Text sent to ${phone}. Their answer will show here.`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't send the text.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="callout mt-4 px-4 py-3">
      <div className="flex flex-wrap items-center gap-2.5">
        <PhoneCall size={14} className="shrink-0" aria-hidden />
        <span className="min-w-0 flex-1 text-xs font-semibold">
          {phone ? (
            <>
              Verify with {info.supplier_name ?? "the supplier"} on{" "}
              <a href={`tel:${phone.replace(/[^+\d]/g, "")}`} className="underline underline-offset-4">
                {phone}
              </a>{" "}
              — the number on file, not the one in the email.
            </>
          ) : (
            "Verify by phone before paying. There's no number on file for this supplier yet."
          )}
        </span>
        {!phone ? (
          <Link to="/suppliers" className="accent text-xs font-semibold underline underline-offset-4">
            Add their number →
          </Link>
        ) : (
          !closed && (
            <Button size="sm" variant="line" onClick={() => setOpen((v) => !v)} aria-expanded={open}>
              {open ? "HIDE" : "VERIFY NOW"}
            </Button>
          )
        )}
      </div>

      {latest && (
        <p className={cn("mono-xs mt-2 flex items-center gap-1.5", STATUS[latest.status].tone)}>
          {latest.status === "confirmed" ? (
            <CheckCircle2 size={12} aria-hidden />
          ) : latest.status === "denied" ? (
            <XCircle size={12} aria-hidden />
          ) : null}
          {latest.channel === "sms" ? "TEXT" : "CALL"} · {STATUS[latest.status].label} ·{" "}
          {when(latest.responded_at ?? latest.created_at)}
        </p>
      )}

      {open && phone && !closed && (
        <div className="mt-3 border-t border-[var(--rule)] pt-3">
          <p className="fg-2 text-xs leading-relaxed">
            Ask them: “We received an email asking us to pay
            {info.account ? ` into a new account (${info.account})` : " into a new account"}
            {info.amount != null && info.currency
              ? `, for ${info.currency} ${info.amount.toLocaleString()}`
              : ""}
            . Did you change your bank details?” Don't read them the new details —
            ask what their account is.
          </p>
          <label className="fg-3 mono-xs mt-3 block" htmlFor={`vnote-${alertId}`}>
            NOTE (OPTIONAL)
          </label>
          <input
            id={`vnote-${alertId}`}
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Who you spoke to, what they said"
            maxLength={2000}
            className="field mt-1 w-full text-sm"
          />
          <div className="mt-3 flex flex-wrap gap-2">
            <Button size="sm" variant="line" disabled={busy !== null} onClick={() => record("confirmed")}>
              {busy === "confirmed" && <Loader2 size={12} className="animate-spin" aria-hidden />}
              THEY CONFIRMED IT
            </Button>
            <Button size="sm" variant="accent" disabled={busy !== null} onClick={() => record("denied")}>
              {busy === "denied" && <Loader2 size={12} className="animate-spin" aria-hidden />}
              THEY DIDN'T — IT'S FRAUD
            </Button>
            <Button size="sm" variant="quiet" disabled={busy !== null} onClick={() => record("no_answer")}>
              NO ANSWER
            </Button>
          </div>
          {info.sms_available && (
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-[var(--rule)] pt-3">
              <span className="fg-2 text-xs">Can't get through?</span>
              <Button size="sm" variant="quiet" disabled={busy !== null} onClick={text}>
                {busy === "sms" ? (
                  <Loader2 size={12} className="animate-spin" aria-hidden />
                ) : (
                  <MessageSquare size={12} aria-hidden />
                )}
                TEXT THEM A CONFIRM LINK
              </Button>
            </div>
          )}
          {error && (
            <p className="mt-2 text-xs text-[var(--danger)]" role="alert">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
