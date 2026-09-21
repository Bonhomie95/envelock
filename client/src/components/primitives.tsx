import { forwardRef, type ReactNode } from "react";
import {
  AlertTriangle,
  Info,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon,
} from "lucide-react";
import type { Tier } from "../lib/api";

// `cn` lives here beside the components that use it most; it's imported across
// the app. This only affects Fast Refresh granularity in dev, not correctness.
// eslint-disable-next-line react-refresh/only-export-components
export function cn(...parts: (string | false | null | undefined)[]) {
  return parts.filter(Boolean).join(" ");
}

/* Meaning is carried by icon + label + colour, never colour alone
   (Quick Reference §1: color-not-only). */
const TIER_META: Record<
  Tier,
  { label: string; icon: LucideIcon; chip: string }
> = {
  low: { label: "Low", icon: Info, chip: "chip-low" },
  medium: { label: "Medium", icon: AlertTriangle, chip: "chip-medium" },
  high: { label: "High", icon: ShieldAlert, chip: "chip-high" },
  critical: { label: "Critical", icon: ShieldAlert, chip: "chip-critical" },
};

export function TierChip({
  tier,
  blink = false,
}: {
  tier: Tier;
  blink?: boolean;
}) {
  const meta = TIER_META[tier];
  const Icon = meta.icon;
  return (
    <span
      className={cn("chip", meta.chip, blink && tier === "critical" && "blink")}
    >
      <Icon size={11} aria-hidden />
      {meta.label}
    </span>
  );
}

export function LevelChip({
  level,
}: {
  level: "full" | "standard" | "limited";
}) {
  const map = {
    full: { label: "Full", chip: "chip-ok" },
    standard: { label: "Standard", chip: "chip-info" },
    limited: { label: "Limited", chip: "chip-medium" },
  }[level];
  return (
    <span className={cn("chip", map.chip)}>
      <ShieldCheck size={11} aria-hidden />
      {map.label}
    </span>
  );
}

export const Button = forwardRef<
  HTMLButtonElement,
  {
    children: ReactNode;
    variant?: "accent" | "solid" | "line" | "quiet";
    size?: "sm" | "md" | "lg";
  } & React.ButtonHTMLAttributes<HTMLButtonElement>
>(function Button(
  { children, variant = "line", size = "md", className, ...props },
  ref,
) {
  return (
    <button
      ref={ref}
      className={cn("btn", `btn-${variant}`, `btn-${size}`, className)}
      {...props}
    >
      {children}
    </button>
  );
});

/** Section header. A short accent rule sets the section apart without
 *  numbering it — numbers read as a manual, not a product. */
export function SectionHead({
  label,
  title,
  lede,
  align = "left",
}: {
  label: string;
  title: string;
  lede?: string;
  align?: "left" | "center";
}) {
  return (
    <div className={cn(align === "center" && "mx-auto text-center")}>
      <div
        className={cn(
          "flex items-center gap-3",
          align === "center" && "justify-center",
        )}
      >
        <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
        <span className="sect-label">{label}</span>
      </div>
      <h2 className="headline mt-4 max-w-4xl text-balance">{title}</h2>
      {lede && (
        <p className={cn("lede mt-5", align === "center" && "mx-auto")}>
          {lede}
        </p>
      )}
    </div>
  );
}

/** Bento cell. Spans are explicit so the grid stays deliberate rather than
 *  auto-flowing into a uniform card wall. */
export function Cell({
  children,
  span = 4,
  className,
}: {
  children: ReactNode;
  span?: 3 | 4 | 5 | 6 | 7 | 8 | 12;
  className?: string;
}) {
  const spans: Record<number, string> = {
    3: "md:col-span-6 lg:col-span-3",
    4: "md:col-span-6 lg:col-span-4",
    5: "md:col-span-6 lg:col-span-5",
    6: "md:col-span-6",
    7: "md:col-span-12 lg:col-span-7",
    8: "md:col-span-12 lg:col-span-8",
    12: "col-span-12",
  };
  return (
    <div className={cn("col-span-12", spans[span], className)}>{children}</div>
  );
}

export function Metric({
  value,
  label,
  note,
}: {
  value: string;
  label: string;
  note?: string;
}) {
  return (
    <div>
      <div className="font-mono tnum text-3xl font-semibold tracking-tight sm:text-4xl">
        {value}
      </div>
      <div className="mt-2 text-sm font-semibold">{label}</div>
      {note && <p className="fg-3 mt-1 text-xs leading-relaxed">{note}</p>}
    </div>
  );
}

export function FeatureCell({
  icon: Icon,
  code,
  title,
  body,
  span = 4,
}: {
  icon: LucideIcon;
  code: string;
  title: string;
  body: string;
  span?: 3 | 4 | 6;
}) {
  return (
    <Cell
      span={span}
      className="group p-7 transition-colors hover:bg-[var(--bg-hover)]"
    >
      <div className="flex items-start justify-between">
        <Icon size={20} className="accent" aria-hidden />
        <span className="mono-xs fg-3">{code}</span>
      </div>
      <h3 className="mt-6 text-base font-semibold">{title}</h3>
      <p className="fg-2 mt-2 text-sm leading-relaxed">{body}</p>
    </Cell>
  );
}
