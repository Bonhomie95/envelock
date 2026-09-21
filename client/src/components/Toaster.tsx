import { useEffect, useState } from "react";
import { Check, Info, X } from "lucide-react";
import { dismiss, subscribe, type Toast } from "../lib/toast";
import { cn } from "./primitives";

const ICON = { success: Check, error: X, info: Info } as const;
const TONE = {
  success: "border-[var(--ok)] text-[var(--ok)]",
  error: "border-[var(--danger)] text-[var(--danger)]",
  info: "border-[var(--rule)] fg-2",
} as const;

/** Rendered once at the app root. Live region so a screen reader announces the
 *  outcome of an action the user cannot see complete. */
export default function Toaster() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  useEffect(() => subscribe(setToasts), []);

  if (toasts.length === 0) return null;
  return (
    <div
      className="pointer-events-none fixed inset-x-3 bottom-3 z-[100] flex flex-col items-center gap-2 sm:inset-x-auto sm:right-4 sm:bottom-4 sm:items-end"
      role="status"
      aria-live="polite"
    >
      {toasts.map((t) => {
        const Icon = ICON[t.kind];
        return (
          <div
            key={t.id}
            className={cn(
              "pointer-events-auto flex w-full max-w-md items-start gap-2.5 border bg-[var(--bg-raised)] px-3.5 py-3 shadow-lg",
              TONE[t.kind],
            )}
          >
            <Icon size={14} className="mt-0.5 shrink-0" aria-hidden />
            <p className="min-w-0 flex-1 text-xs leading-relaxed break-words text-[var(--fg)]">
              {t.message}
            </p>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              className="fg-3 -m-1 shrink-0 cursor-pointer p-1 hover:text-[var(--fg)]"
            >
              <X size={13} aria-hidden />
            </button>
          </div>
        );
      })}
    </div>
  );
}
