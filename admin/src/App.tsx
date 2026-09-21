import { useEffect, useState } from "react";
import {
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { Activity,
  Building2,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Sun,
  UserCog,
  Users,
  X,
} from "lucide-react";
import { api, auth, type Me } from "./lib/api";
import { setMe } from "./lib/permissions";
import { Button } from "./components/ui";
import Login from "./pages/Login";
import Overview from "./pages/Overview";
import Tenants from "./pages/Tenants";
import TenantDetail from "./pages/TenantDetail";
import UsersPage from "./pages/Users";
import Staff from "./pages/Staff";
import Security from "./pages/Security";
import Audit from "./pages/Audit";
import Status from "./pages/Status";

function useTheme() {
  const [dark, setDark] = useState(
    () => (localStorage.getItem("envelock.admin_theme") ?? "dark") === "dark",
  );
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    localStorage.setItem("envelock.admin_theme", dark ? "dark" : "light");
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

/* Every tab names the permission it needs. An operator who cannot do the thing
   does not see the tab — and the server refuses it anyway, so hiding it is a
   courtesy rather than the control. */
const NAV = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true, needs: "platform:read" },
  { to: "/tenants", label: "Tenants", icon: Building2, end: false, needs: "tenant:read" },
  { to: "/users", label: "Users", icon: Users, end: false, needs: "user:read" },
  { to: "/staff", label: "Staff", icon: UserCog, end: false, needs: "staff:read" },
  { to: "/security", label: "Security", icon: ShieldAlert, end: false, needs: "security:read" },
  { to: "/audit", label: "Audit", icon: ScrollText, end: false, needs: "audit:read" },
  { to: "/status", label: "Status", icon: Activity, end: false, needs: "platform:read" },
];

function Shell({
  children,
  theme,
  me,
}: {
  children: React.ReactNode;
  theme: ReturnType<typeof useTheme>;
  me: Me | null;
}) {
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const allowed = NAV.filter(
    (i) => !me || me.break_glass || me.permissions.includes(i.needs),
  );

  // Close the drawer on navigation — a drawer left open over the page the
  // operator just asked for is the commonest mobile-nav bug there is.
  // Fetch-on-mount: the loading flag flips before the first await. That is
  // the pattern the rule explicitly allows ("subscribe to an external
  // system"), not the derived-state cascade it targets.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open]);

  async function signOut() {
    try {
      await api.logout();
    } catch {
      /* clearing the token is what matters */
    }
    auth.clear();
    navigate("/login");
  }

  const railBody = (
    <>
      <div className="flex items-center gap-2.5 px-4 py-4">
        <span className="grid size-9 shrink-0 place-items-center border border-[var(--rule-strong)]">
          <ShieldCheck size={18} className="accent" aria-hidden />
        </span>
        <span className="min-w-0">
          <span className="block truncate text-[13px] font-bold tracking-[0.12em] uppercase">
            Operator
          </span>
          <span className="mono-xs fg-3 block truncate">Internal control</span>
        </span>
      </div>

      <nav className="mt-2 flex flex-1 flex-col gap-0.5 overflow-y-auto px-2 pb-4" aria-label="Console">
        {allowed.map(({ to, label, icon: Icon, end }) => (
          <NavLink key={to} to={to} end={end} className="rail-link">
            <Icon size={17} aria-hidden className="shrink-0" />
            <span className="truncate">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="border-t p-2">
        {/* Who am I acting as. During an incident this must never be a guess —
            a support agent and a security lead see different controls, and the
            wrong assumption is how the wrong button gets pressed. */}
        {me && (
          <div className="px-3 py-2">
            <p className="truncate text-xs font-medium">{me.email}</p>
            <p className="mono-xs fg-3 mt-0.5 truncate uppercase">
              {me.break_glass ? "break-glass" : me.department}
            </p>
          </div>
        )}
        <button onClick={signOut} className="rail-link w-full cursor-pointer text-left">
          <LogOut size={17} aria-hidden className="shrink-0" />
          <span>Sign out</span>
        </button>
      </div>
    </>
  );

  return (
    <div className="flex min-h-dvh">
      <aside className="rail sticky top-0 hidden h-dvh lg:flex">{railBody}</aside>

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
            {railBody}
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
            Envelock Admin
          </span>
          <div className="ml-auto flex items-center gap-1">
            <button
              onClick={theme.toggle}
              aria-label="Toggle theme"
              className="fg-2 flex size-11 cursor-pointer items-center justify-center hover:text-[var(--fg)]"
            >
              {theme.dark ? <Sun size={16} aria-hidden /> : <Moon size={16} aria-hidden />}
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </div>
  );
}

function NoPermission({ needs, department }: { needs: string; department: string }) {
  return (
    <div className="shell py-16">
      <div className="panel mx-auto max-w-md p-8 text-center">
        <ShieldCheck size={24} className="fg-3 mx-auto" aria-hidden />
        <h1 className="mt-4 text-lg font-bold">Not part of your role</h1>
        <p className="fg-2 mt-3 text-sm leading-relaxed">
          This page needs <code className="mono">{needs}</code>, which the{" "}
          {department} department does not carry. Ask a workspace lead if you need
          it added.
        </p>
      </div>
    </div>
  );
}

/* Guards the admin routes: needs a session AND super-admin (whoami). A valid but
   non-admin session is bounced to a clear "not authorized" screen. */
function Protected({ theme }: { theme: ReturnType<typeof useTheme> }) {
  const [state, setState] = useState<
    "checking" | "ok" | "denied" | "blocked" | "signedout"
  >("checking");
  const [blockedReason, setBlockedReason] = useState("");
  const [me, setOperator] = useState<Me | null>(null);
  useEffect(() => {
    if (!auth.signedIn) {
      // Fetch-on-mount: the loading flag flips before the first await. That is
      // the pattern the rule explicitly allows ("subscribe to an external
      // system"), not the derived-state cascade it targets.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setState("signedout");
      return;
    }
    api
      .whoami()
      .then((who) => {
        setOperator(who);
        setMe(who); // share it with every page (lib/permissions)
        setState("ok");
      })
      .catch((e) => {
        if (e?.status === 404) return setState("denied");
        if (e?.status === 403) {
          // The account exists but is not usable yet (a one-time password that
          // was never replaced) or has been suspended. Say which, rather than
          // bouncing to sign-in, which just loops.
          setBlockedReason(e.message ?? "");
          return setState("blocked");
        }
        return setState("signedout");
      });
  }, []);

  if (state === "checking") {
    return (
      <div className="grid min-h-dvh place-items-center">
        <span className="fg-3 mono text-sm">Loading…</span>
      </div>
    );
  }
  if (state === "signedout") return <Navigate to="/login" replace />;
  if (state === "blocked") {
    return (
      <div className="grid min-h-dvh place-items-center px-4">
        <div className="panel max-w-md p-8 text-center">
          <ShieldCheck size={28} className="fg-3 mx-auto" aria-hidden />
          <h1 className="mt-4 text-xl font-bold">This account isn't ready</h1>
          <p className="fg-2 mt-3 text-sm leading-relaxed">{blockedReason}</p>
          <Button
            variant="line"
            size="sm"
            className="mt-6"
            onClick={() => {
              auth.clear();
              window.location.assign("/login");
            }}
          >
            SIGN IN AGAIN
          </Button>
        </div>
      </div>
    );
  }
  if (state === "denied") {
    return (
      <div className="grid min-h-dvh place-items-center px-4">
        <div className="panel max-w-md p-8 text-center">
          <ShieldCheck size={28} className="fg-3 mx-auto" aria-hidden />
          <h1 className="mt-4 text-xl font-bold">Not authorized</h1>
          <p className="fg-2 mt-3 text-sm leading-relaxed">
            This account isn't a platform administrator. The admin console is
            restricted to operators on the allowlist.
          </p>
          <Button
            variant="line"
            size="sm"
            className="mt-6"
            onClick={() => {
              auth.clear();
              window.location.assign("/login");
            }}
          >
            SIGN OUT
          </Button>
        </div>
      </div>
    );
  }
  /* A route the operator has no permission for would render, fire its call and
     show a bare 403 — so it is replaced by a page that says which permission is
     missing and who to ask. */
  const gate = (needs: string, element: React.ReactNode) =>
    !me || me.break_glass || me.permissions.includes(needs) ? (
      element
    ) : (
      <NoPermission needs={needs} department={me.department} />
    );

  return (
    <Shell theme={theme} me={me}>
      <Routes>
        <Route path="/" element={gate("platform:read", <Overview />)} />
        <Route path="/tenants" element={gate("tenant:read", <Tenants />)} />
        <Route path="/tenants/:id" element={gate("tenant:read", <TenantDetail />)} />
        <Route path="/users" element={gate("user:read", <UsersPage />)} />
        <Route path="/staff" element={gate("staff:read", <Staff />)} />
        <Route path="/security" element={gate("security:read", <Security />)} />
        <Route path="/audit" element={gate("audit:read", <Audit />)} />
        <Route path="/status" element={gate("platform:read", <Status />)} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}

export default function App() {
  const theme = useTheme();
  const { pathname } = useLocation();
  return (
    <Routes>
      <Route path="/login" element={<Login theme={theme} />} />
      <Route path="/*" element={<Protected key={pathname === "/login" ? "l" : "a"} theme={theme} />} />
    </Routes>
  );
}
