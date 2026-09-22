import { Suspense, lazy, useEffect, useState, type ReactNode } from "react";
import {
  Link,
  NavLink,
  Navigate,
  Outlet,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import {
  BookOpen,
  Building2,
  CreditCard,
  FlaskConical,
  LayoutDashboard,
  Loader2,
  LogOut,
  Menu,
  Moon,
  Sun,
  UserRound,
  Users,
  X,
} from "lucide-react";
import { api, auth } from "./lib/api";
import { Button, cn } from "./components/primitives";
import ConsoleShell from "./components/ConsoleShell";
import ErrorBoundary from "./components/ErrorBoundary";
import Toaster from "./components/Toaster";
import Landing from "./pages/Landing";
import SignIn from "./pages/SignIn";
import ResetPassword from "./pages/ResetPassword";
import VerifyEmail from "./pages/VerifyEmail";

function Mark({ size = 26 }: { size?: number }) {
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} aria-hidden fill="none">
      <rect width="32" height="32" fill="var(--accent)" />
      <path
        d="M16 7l7 3v5.6c0 4.2-2.9 8-7 9.4-4.1-1.4-7-5.2-7-9.4V10l7-3z"
        stroke="var(--accent-ink)"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M12.6 16.2l2.6 2.6 4.3-4.7"
        stroke="var(--accent-ink)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Logo() {
  return (
    <Link
      to="/"
      className="flex items-center gap-2.5"
      aria-label="Envelock home"
    >
      <Mark />
      <span className="text-[15px] font-bold tracking-tight">ENVELOCK</span>
    </Link>
  );
}

const THEME_KEY = "envelock.theme";

/** The stored choice, else the operating system's. Reading this at module load
 *  (not in an effect) means the first paint is already the right theme instead
 *  of flashing dark and correcting itself. */
function initialTheme(): boolean {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === "dark" || stored === "light") return stored === "dark";
  } catch {
    /* private mode / storage disabled — fall through to the OS preference */
  }
  return !window.matchMedia?.("(prefers-color-scheme: light)").matches;
}

function ThemeToggle() {
  const [dark, setDark] = useState(initialTheme);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    try {
      localStorage.setItem(THEME_KEY, dark ? "dark" : "light");
    } catch {
      /* not being able to remember the theme must never break the page */
    }
  }, [dark]);
  return (
    <button
      onClick={() => setDark((d) => !d)}
      aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      className="fg-2 flex size-11 cursor-pointer items-center justify-center transition-colors hover:bg-[var(--bg-hover)] hover:text-[var(--fg)]"
    >
      {dark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
    </button>
  );
}

const NAV = [
  { to: "/", label: "Product", end: true },
  { to: "/docs#ai", label: "AI analyst", end: false },
  { to: "/#pricing", label: "Pricing", end: false },
  { to: "/docs", label: "Documentation", end: false },
  { to: "/analyse", label: "Sandbox", end: false },
];

/** Whether a main-nav item is the page you are on. NavLink compares only the
 *  path, so "/#pricing" lit up alongside "/" and "/docs#ai" alongside "/docs":
 *  two items marked current at once. A hash item is current only when its hash
 *  is; a plain item is current unless a sibling hash item has claimed it. */
function navIsActive(
  item: (typeof NAV)[number],
  pathname: string,
  hash: string,
): boolean {
  const [path, itemHash = ""] = item.to.split("#");
  const onPath = item.end ? pathname === path : pathname.startsWith(path);
  if (!onPath) return false;
  if (itemHash) return hash === `#${itemHash}`;
  return !NAV.some((other) => {
    const [otherPath, otherHash] = other.to.split("#");
    return otherHash && otherPath === path && hash === `#${otherHash}`;
  });
}

function Header() {
  const [open, setOpen] = useState(false);
  const { pathname, hash } = useLocation();
  const navigate = useNavigate();
  // Close the mobile menu when the route changes — a deliberate sync to the
  // router, not the derived-state anti-pattern the rule guards against.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setOpen(false), [pathname]);

  // Re-read on every navigation (useLocation re-renders the header), so signing
  // in or out flips the controls immediately.
  const signedIn = auth.signedIn;

  // A stored session can be long dead (expired, revoked, or from another
  // environment), and the header showed SIGN OUT / DASHBOARD for it until the
  // visitor clicked through. Check it once; the API client drops tokens it
  // cannot refresh, and the re-render then shows SIGN IN.
  const [, recheck] = useState(0);
  useEffect(() => {
    if (!auth.signedIn) return;
    api
      .me()
      .catch(() => {})
      .finally(() => recheck((n) => n + 1));
  }, []);

  async function signOut() {
    try {
      // Stop this browser's push subscription first (it needs the session):
      // a signed-out shared computer kept receiving the user's Critical
      // alerts until someone found the toggle.
      const { disablePush } = await import("./lib/push");
      await disablePush();
    } catch {
      /* best effort */
    }
    try {
      await api.logout();
    } catch {
      /* revoke best-effort; clearing the local token is what matters */
    }
    auth.clear();
    navigate("/");
  }

  return (
    <header className="sticky top-0 z-50 border-b bg-[var(--bg)]/92 backdrop-blur">
      <div className="shell flex h-16 items-center gap-8">
        <Logo />

        <nav className="hidden items-center gap-1 md:flex" aria-label="Main">
          {NAV.map((i) => {
            const active = navIsActive(i, pathname, hash);
            return (
              <Link
                key={i.to}
                to={i.to}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "font-mono px-3 py-2 text-xs font-medium tracking-wide uppercase transition-colors",
                  active ? "accent" : "fg-2 hover:text-[var(--fg)]",
                )}
              >
                {i.label}
              </Link>
            );
          })}
          {signedIn && (
            <NavLink
              to="/dashboard"
              className={({ isActive }) =>
                cn(
                  "font-mono px-3 py-2 text-xs font-medium tracking-wide uppercase transition-colors",
                  isActive ? "accent" : "fg-2 hover:text-[var(--fg)]",
                )
              }
            >
              Dashboard
            </NavLink>
          )}
        </nav>

        <div className="ml-auto flex items-center gap-1">
          <ThemeToggle />
          {signedIn ? (
            <>
              <Link to="/profile" className="hidden md:block">
                <Button variant="quiet" size="sm" aria-label="Profile">
                  <UserRound size={15} aria-hidden />
                </Button>
              </Link>
              <Button
                variant="line"
                size="sm"
                className="hidden md:flex"
                onClick={signOut}
              >
                <LogOut size={13} aria-hidden /> SIGN OUT
              </Button>
            </>
          ) : (
            <Link to="/signin" className="hidden md:block">
              <Button variant="line" size="sm">
                SIGN IN
              </Button>
            </Link>
          )}
          <button
            onClick={() => setOpen((o) => !o)}
            aria-label={open ? "Close menu" : "Open menu"}
            aria-expanded={open}
            className="fg-2 flex size-11 cursor-pointer items-center justify-center md:hidden"
          >
            {open ? (
              <X size={18} aria-hidden />
            ) : (
              <Menu size={18} aria-hidden />
            )}
          </button>
        </div>
      </div>

      {open && (
        <nav className="border-t md:hidden" aria-label="Mobile">
          <div className="shell flex flex-col divide-y">
            {NAV.map((i) => {
              const active = navIsActive(i, pathname, hash);
              return (
                <Link
                  key={i.to}
                  to={i.to}
                  aria-current={active ? "page" : undefined}
                  className={cn(
                    "font-mono py-4 text-sm font-medium tracking-wide uppercase",
                    active ? "accent" : "fg-2",
                  )}
                >
                  {i.label}
                </Link>
              );
            })}
            {signedIn ? (
              <>
                <NavLink
                  to="/dashboard"
                  className={({ isActive }) =>
                    cn(
                      "font-mono flex items-center gap-2 py-4 text-sm font-medium tracking-wide uppercase",
                      isActive ? "accent" : "fg-2",
                    )
                  }
                >
                  <LayoutDashboard size={14} aria-hidden /> Dashboard
                </NavLink>
                <NavLink
                  to="/profile"
                  className={({ isActive }) =>
                    cn(
                      "font-mono flex items-center gap-2 py-4 text-sm font-medium tracking-wide uppercase",
                      isActive ? "accent" : "fg-2",
                    )
                  }
                >
                  <UserRound size={14} aria-hidden /> Profile
                </NavLink>
                <div className="py-4">
                  <Button variant="line" className="w-full" onClick={signOut}>
                    <LogOut size={13} aria-hidden /> SIGN OUT
                  </Button>
                </div>
              </>
            ) : (
              <Link to="/signin" className="py-4">
                <Button variant="accent" className="w-full">
                  SIGN IN
                </Button>
              </Link>
            )}
          </div>
        </nav>
      )}
    </header>
  );
}

const FOOTER = [
  {
    title: "Product",
    links: [
      ["What we stop", "/#problems"],
      ["AI fraud analyst", "/docs#ai"],
      ["Pricing", "/#pricing"],
      ["Documentation", "/docs"],
      ["Detection sandbox", "/analyse"],
      ["Sign in", "/signin"],
    ],
  },
  {
    title: "Protects against",
    links: [
      ["Changed bank details", "/docs#protection"],
      ["Invoice fraud", "/docs#protection"],
      ["Compromised vendors", "/docs#protection"],
      ["Phishing links", "/docs#protection"],
      ["Malicious links", "/docs#protection"],
    ],
  },
  {
    title: "Works with",
    links: [
      ["Microsoft 365", "/docs#connect"],
      ["Google Workspace", "/docs#connect"],
      ["HiNet · hiBox", "/docs#connect"],
      ["263 · SingNet", "/docs#connect"],
      ["Any IMAP provider", "/docs#connect"],
    ],
  },
  {
    title: "Company",
    links: [
      ["Documentation", "/docs"],
      ["System status", "/status"],
      ["Our security", "/docs#security"],
      ["Terms of service", "/terms"],
      ["Privacy notice", "/privacy"],
      ["Sub-processors", "/subprocessors"],
    ],
  },
];

function Footer() {
  return (
    <footer className="border-t">
      <div className="shell py-16">
        <div className="grid12">
          <div className="col-span-12 lg:col-span-4">
            <Logo />
            <p className="fg-2 mt-5 max-w-xs text-sm leading-relaxed">
              Payment-fraud and phishing-link protection for businesses on any
              mail provider.
            </p>
            <p className="fg-3 mono-xs mt-6">
              WE STOP YOUR MONEY GOING
              <br />
              TO THE WRONG BANK ACCOUNT
            </p>
          </div>

          {FOOTER.map((col) => (
            <div
              key={col.title}
              className="col-span-6 mt-10 lg:col-span-2 lg:mt-0"
            >
              <h3 className="sect-label">{col.title}</h3>
              <ul className="mt-5 space-y-3" role="list">
                {col.links.map(([label, href]) => (
                  <li key={label}>
                    <Link
                      to={href}
                      className="fg-2 text-sm transition-colors hover:text-[var(--fg)]"
                    >
                      {label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div className="mt-16 flex flex-col gap-4 border-t pt-8 sm:flex-row sm:items-center">
          <p className="fg-3 mono-xs">
            © {new Date().getFullYear()} ENVELOCK — ALL RIGHTS RESERVED
          </p>
          {/* These were four dead <span>s, then links into the documentation
              because the real pages did not exist. They exist now — see
              pages/Legal.tsx — so this links them. The rule that produced the
              earlier comment still stands: never link a page that is not there. */}
          <div className="fg-3 mono-xs flex flex-wrap gap-x-6 gap-y-2 sm:ml-auto">
            <Link to="/terms" className="transition-colors hover:text-[var(--fg)]">
              TERMS
            </Link>
            <Link to="/privacy" className="transition-colors hover:text-[var(--fg)]">
              PRIVACY
            </Link>
            <Link to="/dpa" className="transition-colors hover:text-[var(--fg)]">
              DPA
            </Link>
            <Link to="/status" className="transition-colors hover:text-[var(--fg)]">
              STATUS
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}

function ScrollToTop() {
  const { pathname, hash } = useLocation();
  useEffect(() => {
    if (hash) {
      // Lazy routes (/docs) mount after this effect runs — retry briefly so a
      // #section link actually lands on the section instead of doing nothing.
      let tries = 0;
      const attempt = () => {
        const el = document.querySelector(hash);
        if (el) {
          el.scrollIntoView({ behavior: "smooth" });
          return;
        }
        if (tries++ < 20) setTimeout(attempt, 100);
      };
      attempt();
      return;
    }
    window.scrollTo(0, 0);
  }, [pathname, hash]);
  return null;
}

/* The public marketing site: full nav, product/company footer. */
function MarketingLayout() {
  return (
    <>
      <Header />
      <div id="main" className="flex-1">
        {/* Per-layout boundary: the header and footer stay put while a lazy
            page downloads, instead of the whole screen going blank. */}
        <Suspense fallback={<RouteFallback />}>
          <Outlet />
        </Suspense>
      </div>
      <Footer />
    </>
  );
}

/* The signed-in console. Deliberately NOT the landing chrome: no product /
   documentation / sandbox links, no marketing footer — a self-contained
   workspace so it never reads as "still on the landing page". */
const APP_NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, adminOnly: false },
  // Payment safety is one of the two v1 features; the registry behind it is
  // where a customer records what makes it work, so it sits in the main rail.
  { to: "/suppliers", label: "Suppliers", icon: Building2, adminOnly: false },
  { to: "/team", label: "Team", icon: Users, adminOnly: true },
  { to: "/billing", label: "Billing", icon: CreditCard, adminOnly: true },
  { to: "/profile", label: "Profile", icon: UserRound, adminOnly: false },
  { to: "/analyse", label: "Sandbox", icon: FlaskConical, adminOnly: false },
  { to: "/docs", label: "Documentation", icon: BookOpen, adminOnly: false },
];

function AppLayout() {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const signedIn = auth.signedIn;
  const isAdmin = auth.role === "owner" || auth.role === "admin";

  /* A colleague who self-registers lands in `pending` and sees nothing until an
     admin approves them. With the Team page hidden there was no admin surface to
     approve from, so those people were stuck in a waiting room permanently. The
     badge is how an admin finds out someone is waiting. */
  const [pending, setPending] = useState(0);
  useEffect(() => {
    if (!signedIn || !isAdmin) return;
    let live = true;
    const refresh = () =>
      api
        .members()
        .then((r) => {
          if (live)
            setPending(
              r.members.filter((m) => m.status === "pending" && !m.pending_password)
                .length,
            );
        })
        .catch(() => {});
    void refresh();
    window.addEventListener("envelock:team-changed", refresh);
    return () => {
      live = false;
      window.removeEventListener("envelock:team-changed", refresh);
    };
  }, [signedIn, isAdmin, pathname]);

  async function signOut() {
    try {
      const { disablePush } = await import("./lib/push");
      await disablePush();
    } catch {
      /* best effort */
    }
    try {
      await api.logout();
    } catch {
      /* best-effort revoke; clearing the local token is what matters */
    }
    auth.clear();
    navigate("/");
  }

  const items = APP_NAV.filter((i) => !i.adminOnly || isAdmin).map((i) => ({
    to: i.to,
    label: i.label,
    icon: i.icon,
    badge: i.to === "/team" && pending > 0 ? pending : undefined,
  }));

  return (
    <ConsoleShell
      items={items}
      subtitle="Console"
      actions={<ThemeToggle />}
      onSignOut={() => void signOut()}
    >
      <Suspense fallback={<RouteFallback />}>
        <Outlet />
      </Suspense>
    </ConsoleShell>
  );
}

/* Console routes are for signed-in people. Without this the pages mounted for
   anyone, fired their API calls, took 401s and left the visitor on a broken
   half-rendered dashboard instead of the sign-in screen. `replace` keeps Back
   working: it returns to wherever they came from, not into a redirect loop.
   `from` lets sign-in send them on to what they originally asked for. */
function RequireAuth({ children }: { children: ReactNode }) {
  const location = useLocation();
  if (!auth.signedIn) {
    return <Navigate to="/signin" replace state={{ from: location.pathname }} />;
  }
  return <>{children}</>;
}

/* Any unknown path used to render a blank page under the header — the worst
   possible answer, because it looks like the app crashed. */
function NotFound() {
  return (
    <section className="shell py-24 sm:py-32">
      <p className="fg-3 mono-xs">ERROR 404</p>
      <h1 className="headline mt-4">This page doesn&rsquo;t exist.</h1>
      <p className="lede mt-5">
        The link may be out of date, or the address mistyped.
      </p>
      <div className="mt-8 flex flex-wrap gap-2">
        <Link to="/">
          <Button variant="accent">GO TO HOMEPAGE</Button>
        </Link>
        <Link to="/docs">
          <Button variant="line">READ THE DOCS</Button>
        </Link>
      </div>
    </section>
  );
}

/* Lazy routes only render for people who navigate to them. Before this the
   marketing page shipped the whole 2,500-line console to every first-time
   visitor, on whatever connection they happened to be on. */
const LazyDashboard = lazy(() => import("./pages/Dashboard"));
const LazySuppliers = lazy(() => import("./pages/Suppliers"));
const LazyTeam = lazy(() => import("./pages/Team"));
const LazyBilling = lazy(() => import("./pages/Billing"));
const LazyProfile = lazy(() => import("./pages/Profile"));
const LazyDocs = lazy(() => import("./pages/Docs"));
// Legal and status: rarely visited, never on the critical path, and the legal
// bundle in particular is pure prose — no reason for it to cost the landing
// page a byte.
const LazyLegal = lazy(() => import("./pages/Legal"));
const LazyStatus = lazy(() => import("./pages/Status"));
const LazyAnalyse = lazy(() => import("./pages/Analyse"));
const LazySupplierVerify = lazy(() => import("./pages/SupplierVerify"));

function RouteFallback() {
  return (
    <div className="shell flex items-center gap-2 py-24" role="status">
      <Loader2 size={16} className="animate-spin" aria-hidden />
      <span className="fg-3 mono-xs">LOADING…</span>
    </div>
  );
}

export default function App() {
  return (
    <div id="top" className="flex min-h-dvh flex-col">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-3 focus:z-60 focus:bg-[var(--accent)] focus:px-4 focus:py-2 focus:text-white"
      >
        Skip to main content
      </a>
      <ScrollToTop />
      {/* Inside Suspense so a lazy chunk that fails to evaluate is caught too,
          and outside Routes so no single page can take the app down. */}
      <Suspense fallback={<RouteFallback />}>
        <ErrorBoundary>
        <Routes>
          {/* A supplier answering our "did you change your details?" text —
              not our customer, so no marketing chrome at all. */}
          <Route path="/v/:token" element={<LazySupplierVerify />} />
          <Route element={<MarketingLayout />}>
            <Route path="/" element={<Landing />} />
            <Route path="/signin" element={<SignIn />} />
            <Route path="/reset-password" element={<ResetPassword />} />
            <Route path="/verify-email" element={<VerifyEmail />} />
          </Route>

          {/* The sandbox and the docs are public, but a signed-in person reaching
              them from the console rail should not be thrown back out to the
              marketing chrome. Same URLs, chrome chosen by who is asking. */}
          <Route element={auth.signedIn ? <AppLayout /> : <MarketingLayout />}>
            <Route path="/analyse" element={<LazyAnalyse />} />
            <Route path="/docs" element={<LazyDocs />} />
            <Route path="/status" element={<LazyStatus />} />
            {/* One component, four routes — it switches on the pathname. */}
            <Route path="/terms" element={<LazyLegal />} />
            <Route path="/privacy" element={<LazyLegal />} />
            <Route path="/dpa" element={<LazyLegal />} />
            <Route path="/subprocessors" element={<LazyLegal />} />
          </Route>
          <Route element={<AppLayout />}>
            <Route
              path="/dashboard"
              element={
                <RequireAuth>
                  <LazyDashboard />
                </RequireAuth>
              }
            />
            <Route
              path="/suppliers"
              element={
                <RequireAuth>
                  <LazySuppliers />
                </RequireAuth>
              }
            />
            <Route
              path="/team"
              element={
                <RequireAuth>
                  <LazyTeam />
                </RequireAuth>
              }
            />
            <Route
              path="/billing"
              element={
                <RequireAuth>
                  <LazyBilling />
                </RequireAuth>
              }
            />
            <Route
              path="/profile"
              element={
                <RequireAuth>
                  <LazyProfile />
                </RequireAuth>
              }
            />
          </Route>
          <Route element={<MarketingLayout />}>
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
        </ErrorBoundary>
      </Suspense>
      <Toaster />
    </div>
  );
}
