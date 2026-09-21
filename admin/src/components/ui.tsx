import type { ButtonHTMLAttributes, ReactNode } from "react";

// `cn` lives beside the components that use it, exactly as in the client app.
// This only affects Fast Refresh granularity in dev, not correctness.
// eslint-disable-next-line react-refresh/only-export-components
export function cn(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

type Variant = "accent" | "line" | "quiet" | "danger";
type Size = "sm" | "md";

export function Button({
  variant = "line",
  size = "md",
  className,
  children,
  ...rest
}: {
  variant?: Variant;
  size?: Size;
} & ButtonHTMLAttributes<HTMLButtonElement>) {
  const base =
    "inline-flex cursor-pointer items-center justify-center gap-2 font-mono font-medium tracking-wide uppercase transition-colors disabled:cursor-not-allowed disabled:opacity-50";
  // Both clear the 44px touch target with their surrounding row padding;
  // `md` is 44px on its own.
  const sizes = { sm: "h-9 px-3 text-[11px]", md: "h-11 px-4 text-xs" };
  const variants: Record<Variant, string> = {
    accent: "bg-[var(--accent)] text-[var(--accent-ink)] hover:opacity-90",
    line: "border border-[var(--rule-strong)] text-[var(--fg)] hover:bg-[var(--bg-hover)] hover:border-[var(--fg-3)]",
    quiet: "text-[var(--fg-3)] hover:text-[var(--fg)]",
    danger: "border border-[var(--danger)] text-[var(--danger)] hover:bg-[var(--danger)] hover:text-white",
  };
  return (
    <button className={cn(base, sizes[size], variants[variant], className)} {...rest}>
      {children}
    </button>
  );
}

const TONE: Record<string, string> = {
  guard: "border-[var(--rule)] fg-3",
  essential: "border-[var(--accent)] accent",
  complete: "border-[var(--accent)] accent",
  solo: "border-[var(--rule)] fg-2",
  active: "border-[var(--ok)] text-[var(--ok)]",
  pending: "border-[var(--warn)] text-[var(--warn)]",
  suspended: "border-[var(--danger)] text-[var(--danger)]",
  critical: "border-[var(--danger)] text-[var(--danger)]",
  high: "border-[var(--warn)] text-[var(--warn)]",
  medium: "border-[var(--rule)] fg-2",
  low: "border-[var(--rule)] fg-3",
  owner: "border-[var(--accent)] accent",
  admin: "border-[var(--rule)] fg-2",
  member: "border-[var(--rule)] fg-3",
};

export function Badge({ label, tone }: { label: string; tone?: string }) {
  const cls = TONE[(tone ?? label).toLowerCase()] ?? "border-[var(--rule)] fg-3";
  return (
    <span
      className={cn(
        "mono inline-flex items-center border px-1.5 py-0.5 text-[10px] font-semibold tracking-wide uppercase",
        cls,
      )}
    >
      {label}
    </span>
  );
}

/** One cell of a `.statstrip`. The label sits ABOVE the figure so a row of
 *  numbers can be scanned without re-reading what each one counts. */
export function Stat({
  label,
  value,
  tone = "quiet",
}: {
  label: string;
  value: ReactNode;
  tone?: "quiet" | "hot" | "warn" | "good" | "accent";
}) {
  return (
    <div className="stat-cell">
      <div className="sect-label">{label}</div>
      <div className={cn("stat-figure mt-2", `is-${tone}`)}>{value}</div>
    </div>
  );
}
