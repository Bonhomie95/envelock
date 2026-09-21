import { useCallback, useEffect, useState } from "react";
import {
  Copy,
  KeyRound,
  Loader2,
  Plus,
  RotateCcw,
  ShieldCheck,
  UserMinus,
  UserPlus,
} from "lucide-react";
import {
  ApiError,
  api,
  type DepartmentInfo,
  type Me,
  type StaffRow,
} from "../lib/api";
import { Badge, Button, cn } from "../components/ui";

/* Who at Envelock can operate the product, and how much.
 *
 * The form leads with the department rather than a permission checklist,
 * because "Ada is in Support" is the decision a manager actually makes — the
 * permissions follow from it and are shown, so nobody hands over more than they
 * meant to. Individual exceptions exist for the cases a real team always has,
 * but they are the second screen, not the first. */

function timeOf(iso: string | null): string {
  if (!iso) return "never";
  const d = new Date(iso);
  const days = Math.floor((Date.now() - d.getTime()) / 86_400_000);
  if (days === 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

/* The one-time password, shown once. Deliberately loud and deliberately not
   emailed: an emailed console password is a standing phishing target. */
function TemporaryPassword({
  email,
  password,
  onDone,
}: {
  email: string;
  password: string;
  onDone: () => void;
}) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="panel mt-4 border-[var(--accent)] p-5">
      <div className="flex items-start gap-3">
        <KeyRound size={18} className="accent mt-0.5 shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold">
            One-time password for {email}
          </p>
          <p className="fg-2 mt-1 text-xs leading-relaxed">
            Hand this over directly — in person, or over a channel you already
            trust. It is not stored and will not be shown again. They must
            replace it and enrol an authenticator before the console answers.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <code className="mono min-w-0 flex-1 border px-3 py-2 text-sm break-all">
              {password}
            </code>
            <Button
              size="sm"
              onClick={() => {
                void navigator.clipboard.writeText(password);
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
            >
              <Copy size={12} aria-hidden /> {copied ? "COPIED" : "COPY"}
            </Button>
            <Button size="sm" variant="quiet" onClick={onDone}>
              DONE
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AddOperator({
  departments,
  onCreated,
}: {
  departments: DepartmentInfo[];
  onCreated: (row: StaffRow & { temporary_password: string }) => void;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [department, setDepartment] = useState("support");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chosen = departments.find((d) => d.id === department);

  async function submit() {
    if (!email.trim()) {
      setError("Enter their work email.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await api.createStaff({
        email: email.trim(),
        name: name.trim() || undefined,
        department,
      });
      setEmail("");
      setName("");
      setOpen(false);
      onCreated(created);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create that account.");
    } finally {
      setBusy(false);
    }
  }

  if (!open) {
    return (
      <Button variant="accent" size="sm" onClick={() => setOpen(true)}>
        <UserPlus size={13} aria-hidden /> ADD AN OPERATOR
      </Button>
    );
  }

  return (
    <div className="panel w-full p-5">
      <h3 className="text-sm font-semibold">Add an operator</h3>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="staff-email" className="sect-label">
            Work email
          </label>
          <input
            id="staff-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="ada@envelock.com"
            className="field mt-1.5"
            autoComplete="off"
          />
        </div>
        <div>
          <label htmlFor="staff-name" className="sect-label">
            Name (optional)
          </label>
          <input
            id="staff-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="field mt-1.5"
            autoComplete="off"
          />
        </div>
      </div>

      <label className="sect-label mt-5 block">Department</label>
      <div className="mt-2 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {departments.map((d) => (
          <button
            key={d.id}
            type="button"
            onClick={() => setDepartment(d.id)}
            aria-pressed={department === d.id}
            className={cn(
             "cursor-pointer border p-3 text-left transition-colors",
              department === d.id
                ? "border-[var(--accent)]"
                : "border-[var(--rule)] hover:border-[var(--fg-3)]",
            )}
          >
            <span className="mono text-xs font-semibold tracking-wide uppercase">
              {d.name}
            </span>
            <span className="fg-3 mono ml-2 text-[10px]">
              {d.permissions.length} permissions
            </span>
            <p className="fg-2 mt-1.5 text-xs leading-relaxed">{d.description}</p>
          </button>
        ))}
      </div>

      {chosen && (
        <div className="mt-4 border p-3">
          <p className="sect-label">They will be able to</p>
          <ul className="mono fg-2 mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px]" role="list">
            {chosen.permissions.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-5 flex flex-wrap gap-2">
        <Button variant="accent" size="sm" disabled={busy} onClick={() => void submit()}>
          {busy ? <Loader2 size={13} className="animate-spin" aria-hidden /> : <Plus size={13} aria-hidden />}
          CREATE ACCOUNT
        </Button>
        <Button variant="quiet" size="sm" onClick={() => setOpen(false)}>
          CANCEL
        </Button>
      </div>
      {error && (
        <p role="alert" className="mt-3 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}
    </div>
  );
}

export default function Staff() {
  const [rows, setRows] = useState<StaffRow[]>([]);
  const [breakGlass, setBreakGlass] = useState<string[]>([]);
  const [departments, setDepartments] = useState<DepartmentInfo[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [issued, setIssued] = useState<{ email: string; password: string } | null>(null);
  const [acting, setActing] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [list, roles] = await Promise.all([api.staff(), api.staffRoles()]);
      setRows(list.staff);
      setBreakGlass(list.break_glass_emails);
      setMe(list.you);
      setDepartments(roles.departments);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load staff.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: the loading flag flips before the first await. That is
    // the pattern the rule explicitly allows ("subscribe to an external
    // system"), not the derived-state cascade it targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const canManage = Boolean(me?.permissions.includes("staff:manage"));

  async function act(id: string, fn: () => Promise<unknown>) {
    setActing(id);
    try {
      await fn();
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "That didn't work.");
    } finally {
      setActing(null);
    }
  }

  async function resetPassword(row: StaffRow) {
    setActing(row.id);
    try {
      const r = await api.resetStaffPassword(row.id);
      setIssued({ email: r.email, password: r.temporary_password });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reset that password.");
    } finally {
      setActing(null);
    }
  }

  return (
    <div className="shell py-8">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold">Staff</h1>
          <p className="fg-2 mt-1.5 max-w-2xl text-sm leading-relaxed">
            Envelock's own operators. Each department carries the permissions its
            job needs and no more, so a support agent can approve a customer user
            without also being able to suspend a company.
          </p>
        </div>
        {canManage && (
          <AddOperator
            departments={departments}
            onCreated={(row) => {
              setIssued({ email: row.email, password: row.temporary_password });
              // Show the new row straight away — waiting for the password panel
              // to be dismissed makes it look like nothing happened.
              void load();
            }}
          />
        )}
      </div>

      {issued && (
        <TemporaryPassword
          email={issued.email}
          password={issued.password}
          onDone={() => {
            setIssued(null);
            void load();
          }}
        />
      )}

      {error && (
        <p role="alert" className="mt-4 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}

      {loading ? (
        <p className="fg-3 mono mt-8 text-sm">Loading…</p>
      ) : (
        <div className="panel mt-6 overflow-x-auto">
          <table className="dtable min-w-[52rem]">
            <thead>
              <tr>
                {["Operator", "Department", "Two-factor", "Last seen", ""].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b last:border-0">
                  <td className="px-4 py-3">
                    <div className="font-medium">{row.name ?? row.email}</div>
                    <div className="fg-3 mono text-xs">{row.email}</div>
                    {row.must_change_password && (
                      <div className="mono mt-1 text-[10px] text-[var(--warn)]">
                        AWAITING FIRST SIGN-IN
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {/* Changing an operator's department is the real-world
                        permission control, and `updateStaff` had no caller at
                        all — the whole endpoint was unreachable from the UI. */}
                    {canManage && row.id !== me?.id ? (
                      <select
                        value={row.department}
                        disabled={acting === row.id}
                        aria-label={`Department for ${row.email}`}
                        className="field py-1 text-xs"
                        onChange={(e) =>
                          void act(row.id, () =>
                            api.updateStaff(row.id, { department: e.target.value }),
                          )
                        }
                      >
                        {departments.map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <Badge label={row.department} />
                    )}
                    <div className="fg-3 mono mt-1 text-[10px]">
                      {row.permissions.length} permissions
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    {row.mfa_enabled ? (
                      <span className="mono text-xs text-[var(--ok)]">ENROLLED</span>
                    ) : (
                      <span className="mono text-xs text-[var(--warn)]">NOT SET UP</span>
                    )}
                  </td>
                  <td className="fg-2 px-4 py-3 text-xs">{timeOf(row.last_login_at)}</td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1.5">
                      <Badge label={row.status} />
                      {canManage && row.id !== me?.id && (
                        <>
                          <Button
                            size="sm"
                            variant="quiet"
                            disabled={acting === row.id}
                            onClick={() => void resetPassword(row)}
                            title="Issue a new one-time password and clear their authenticator"
                          >
                            <RotateCcw size={12} aria-hidden /> RESET
                          </Button>
                          {row.status === "active" ? (
                            <Button
                              size="sm"
                              variant="danger"
                              disabled={acting === row.id}
                              onClick={() =>
                                void act(row.id, () => api.suspendStaff(row.id))
                              }
                            >
                              <UserMinus size={12} aria-hidden /> SUSPEND
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              disabled={acting === row.id}
                              onClick={() =>
                                void act(row.id, () => api.reinstateStaff(row.id))
                              }
                            >
                              REINSTATE
                            </Button>
                          )}
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="fg-3 px-4 py-8 text-center text-sm">
                    No operator accounts yet — the console is running on
                    break-glass access. Add one so access is per-person and
                    auditable.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {breakGlass.length > 0 && (
        <div className="panel mt-6 p-5">
          <div className="flex items-start gap-3">
            <ShieldCheck size={16} className="fg-3 mt-0.5 shrink-0" aria-hidden />
            <div>
              <p className="text-sm font-semibold">Break-glass access</p>
              <p className="fg-2 mt-1 text-xs leading-relaxed">
                These addresses are on the deployment allowlist
                (<code className="mono">ENVELOCK_SUPERADMIN_EMAILS</code>) and hold
                every permission regardless of anything on this page. They exist so
                a misconfiguration can never lock the team out — and they can only
                be changed by whoever controls the deployment, never in-product.
              </p>
              <ul className="mono fg-3 mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs" role="list">
                {breakGlass.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
