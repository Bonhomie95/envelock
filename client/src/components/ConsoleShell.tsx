import { useEffect, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation } from "react-router-dom";
import { LogOut, Menu, X, type LucideIcon } from "lucide-react";

/* The signed-in console chrome: a persistent left rail, a page header, and an
 * off-canvas drawer below `lg`.
 *
 * This replaces a top navigation bar that had already outgrown itself — the
 * destinations were in a horizontal strip that overflowed into a scroll on a
 * laptop, so the active item could be off-screen. A rail holds every
 * destination at full label width, keeps the current one obvious, and hands the
 * vertical space back to the content, which on this product is a queue of
 * alerts that wants all of it.
 */

export interface RailItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Rendered to the right of the label — a pending count, a warning dot. */
  badge?: number;
  end?: boolean;
}

function RailLinks({
  items,
  onNavigate,
}: {
  items: RailItem[];
  onNavigate?: () => void;
}) {
  return (
    <nav className="flex flex-col gap-0.5 px-2" aria-label="Console">
      {items.map(({ to, label, icon: Icon, badge, end }) => (
        <NavLink key={to} to={to} end={end} onClick={onNavigate} className="rail-link">
          <Icon size={17} aria-hidden className="shrink-0" />
          <span className="truncate">{label}</span>
          {badge !== undefined && badge > 0 && (
            <span
              className="font-mono ml-auto grid min-w-5 place-items-center rounded-full bg-[var(--accent)] px-1.5 py-0.5 text-[10px] leading-none font-semibold text-[var(--accent-ink)]"
              aria-label={`${badge} awaiting attention`}
            >
              {badge}
            </span>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

export default function ConsoleShell({
  items,
  /** Shown under the wordmark — the tenant, or the operator's department. */
  subtitle,
  /** Rendered at the top right: theme toggle, account, whatever the app needs. */
  actions,
  /** Rendered at the bottom of the rail, above sign-out. */
  railFooter,
  onSignOut,
  children,
}: {
  items: RailItem[];
  subtitle?: string;
  actions?: ReactNode;
  railFooter?: ReactNode;
  onSignOut: () => void;
  children: ReactNode;
}) {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);

  // Close the drawer on navigation. A drawer left open over the page the user
  // just asked for is the commonest mobile-nav bug there is.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("keydown", onKey);
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = previous;
    };
  }, [open]);

  const brand = (
    <Link
      to="/dashboard"
      className="flex items-center gap-2.5 px-4 py-4"
      aria-label="Envelock console"
    >
      <span className="grid size-9 shrink-0 place-items-center border border-[var(--rule-strong)]">
        <svg viewBox="0 0 32 32" width="18" height="18" aria-hidden fill="none">
          <path
            d="M16 4l9 3.6v7.2c0 5.4-3.7 10.3-9 12-5.3-1.7-9-6.6-9-12V7.6L16 4z"
            stroke="var(--accent)"
            strokeWidth="2.4"
            strokeLinejoin="round"
          />
          <path
            d="M11.6 16.2l3 3 5.6-6"
            stroke="var(--accent)"
            strokeWidth="2.4"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </span>
      <span className="min-w-0">
        <span className="block truncate text-[13px] font-bold tracking-[0.12em] uppercase">
          Envelock
        </span>
        <span className="mono-xs fg-3 block truncate">{subtitle ?? "Console"}</span>
      </span>
    </Link>
  );

  const railBody = (onNavigate?: () => void) => (
    <>
      {brand}
      <div className="mt-2 flex-1 overflow-y-auto pb-4">
        <RailLinks items={items} onNavigate={onNavigate} />
      </div>
      <div className="border-t p-2">
        {railFooter}
        <button
          onClick={onSignOut}
          className="rail-link w-full cursor-pointer text-left"
        >
          <LogOut size={17} aria-hidden className="shrink-0" />
          <span>Sign out</span>
        </button>
      </div>
    </>
  );

  return (
    <div className="flex min-h-dvh">
      {/* Desktop rail */}
      <aside className="rail sticky top-0 hidden h-dvh lg:flex">{railBody()}</aside>

      {/* Mobile drawer */}
      {open && (
        <div className="fixed inset-0 z-60 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setOpen(false)}
            aria-hidden
          />
          <aside
            className="rail rise absolute inset-y-0 left-0 h-full"
            role="dialog"
            aria-modal="true"
            aria-label="Console navigation"
          >
            <button
              onClick={() => setOpen(false)}
              aria-label="Close navigation"
              className="fg-2 absolute top-4 right-3 grid size-9 cursor-pointer place-items-center hover:text-[var(--fg)]"
            >
              <X size={18} aria-hidden />
            </button>
            {railBody(() => setOpen(false))}
          </aside>
        </div>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-50 flex h-14 items-center gap-2 border-b bg-[var(--bg-raised)] px-3 sm:px-5">
          <button
            onClick={() => setOpen(true)}
            aria-label="Open navigation"
            aria-expanded={open}
            className="fg-2 grid size-11 shrink-0 cursor-pointer place-items-center hover:text-[var(--fg)] lg:hidden"
          >
            <Menu size={19} aria-hidden />
          </button>
          <span className="mono-xs fg-3 truncate tracking-[0.14em] uppercase lg:hidden">
            Envelock
          </span>
          <div className="ml-auto flex items-center gap-1.5">{actions}</div>
        </header>

        <main id="main" className="min-w-0 flex-1">
          {children}
        </main>

        <footer className="border-t px-5 py-3.5">
          <div className="flex items-center gap-4">
            <p className="fg-3 mono-xs">© {new Date().getFullYear()} ENVELOCK</p>
            <span className="fg-3 mono-xs ml-auto flex items-center gap-1.5">
              <span className="size-1.5 rounded-full bg-[var(--ok)]" aria-hidden />
              SIGNED IN
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
