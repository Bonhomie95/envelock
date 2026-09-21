import { useEffect, useRef } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "./primitives";

/** A real confirmation dialog for destructive actions.
 *
 * `window.confirm` blocks the whole tab, cannot say what will actually be
 * destroyed in the product's own language, is unstyled, and on mobile reads as
 * a browser warning rather than part of the app. It is also the one control a
 * user is trained to dismiss without reading — which is exactly wrong for
 * "delete this mailbox and its stored credential".
 */
export default function ConfirmDialog({
  open,
  title,
  body,
  confirmLabel = "CONFIRM",
  destructive = true,
  busy = false,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  body: string;
  confirmLabel?: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const confirmRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    // Focus the *cancel*-adjacent confirm only after mount, and let Escape out:
    // a dialog you cannot dismiss with the keyboard is a trap.
    confirmRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [open, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[90] flex items-end justify-center bg-black/60 p-3 backdrop-blur-sm sm:items-center"
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-title"
        aria-describedby="confirm-body"
        className="w-full max-w-md border bg-[var(--bg-raised)] p-5 shadow-xl"
      >
        <div className="flex items-start gap-3">
          <AlertTriangle
            size={18}
            className={destructive ? "mt-0.5 shrink-0 text-[var(--danger)]" : "mt-0.5 shrink-0"}
            aria-hidden
          />
          <div className="min-w-0">
            <h2 id="confirm-title" className="text-base font-semibold">
              {title}
            </h2>
            <p id="confirm-body" className="fg-2 mt-2 text-sm leading-relaxed">
              {body}
            </p>
          </div>
        </div>
        <div className="mt-5 flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button variant="quiet" onClick={onCancel} disabled={busy}>
            CANCEL
          </Button>
          <Button
            ref={confirmRef}
            variant={destructive ? "solid" : "accent"}
            onClick={onConfirm}
            disabled={busy}
            className={destructive ? "!bg-[var(--danger)] !text-white" : undefined}
          >
            {busy ? "WORKING…" : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
