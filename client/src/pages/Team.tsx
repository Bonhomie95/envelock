import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  BadgeCheck,
  Check,
  Copy,
  Loader2,
  ShieldCheck,
  Trash2,
  UserCheck,
  UserPlus,
  Users,
} from "lucide-react";
import { ApiError, api, auth } from "../lib/api";
import { Button, cn } from "../components/primitives";
import ConfirmDialog from "../components/ConfirmDialog";
import { toast } from "../lib/toast";

type Member = {
  id: string;
  email: string;
  role: string;
  status: string;
  pending_password: boolean;
  is_self: boolean;
};
type Seats = { used: number; cap: number; entitled: boolean; protected_mailboxes: number };

/* Shows the one-time temporary password after creating a teammate. It is never
   retrievable again, so copying it here is the only chance to hand it over. */
function CreatedCredential({
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
    <div className="callout rise mt-4 p-4">
      <p className="text-sm font-semibold">Account created for {email}</p>
      <p className="mt-1 text-xs leading-relaxed">
        Share this temporary password once, in person or over a trusted channel.
        It won't be shown again, and they must change it at first sign-in.
      </p>
      <div className="mt-3 flex items-center gap-2">
        <code className="font-mono flex-1 text-sm break-all">{password}</code>
        <Button
          size="sm"
          variant="line"
          onClick={() => {
            void navigator.clipboard.writeText(password);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          }}
        >
          {copied ? (
            <>
              <Check size={12} aria-hidden /> COPIED
            </>
          ) : (
            <>
              <Copy size={12} aria-hidden /> COPY
            </>
          )}
        </Button>
      </div>
      <Button size="sm" variant="quiet" className="mt-3" onClick={onDone}>
        DONE
      </Button>
    </div>
  );
}

function CreateMember({
  isOwner,
  seats,
  onCreated,
  domain,
}: {
  isOwner: boolean;
  seats: Seats | null;
  onCreated: () => Promise<void>;
  domain?: string;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<"member" | "admin">("member");
  const [busy, setBusy] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [created, setCreated] = useState<{ email: string; password: string } | null>(null);

  const full = seats ? seats.used >= seats.cap : false;

  async function submit() {
    if (!email.includes("@")) {
      setNote("Enter a full email address.");
      return;
    }
    setBusy(true);
    setNote(null);
    try {
      const r = await api.createMember({ email: email.trim(), role });
      setCreated({ email: r.email, password: r.temporary_password });
      setEmail("");
      await onCreated();
    } catch (e) {
      setNote(e instanceof ApiError ? e.message : "Could not create the account.");
    } finally {
      setBusy(false);
    }
  }

  if (created) {
    return (
      <CreatedCredential
        email={created.email}
        password={created.password}
        onDone={() => setCreated(null)}
      />
    );
  }

  return (
    <div className="mt-4">
      {full && seats && (
        <p className="callout mb-3 px-3 py-2 text-xs leading-relaxed">
          {seats.entitled
            ? `All ${seats.cap} team seats are in use. Add a protected mailbox to open another login.`
            : "Team logins need an active trial or a paid plan — Guard is owner-only."}
        </p>
      )}
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={`teammate@${domain || "yourcompany.com"}`}
          autoComplete="off"
          disabled={full}
          className="field flex-1 text-sm"
        />
        <div className="flex gap-px" role="group" aria-label="Role">
          {(["member", "admin"] as const).map((r) => {
            const disabled = r === "admin" && !isOwner;
            return (
              <button
                key={r}
                type="button"
                disabled={disabled || full}
                onClick={() => setRole(r)}
                aria-pressed={role === r}
                title={disabled ? "Only the owner can create admins" : undefined}
                className={cn(
                  "font-mono cursor-pointer border px-3 py-1.5 text-[11px] tracking-wide uppercase transition-colors disabled:cursor-not-allowed disabled:opacity-40",
                  role === r
                    ? "accent border-[var(--accent)]"
                    : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
                )}
              >
                {r}
              </button>
            );
          })}
        </div>
        <Button size="md" variant="accent" onClick={submit} disabled={busy || full}>
          {busy ? (
            <Loader2 size={13} className="animate-spin" aria-hidden />
          ) : (
            <UserPlus size={13} aria-hidden />
          )}
          ADD
        </Button>
      </div>
      <p className="fg-3 mt-2 text-xs leading-relaxed">
        {role === "admin"
          ? "Admins get oversight of every mailbox and the audit trail. One admin still uses a seat."
          : "Members see only their own mailbox. A member login can only be created for someone you're already protecting — the email must match one of your protected mailboxes."}
      </p>
      {note && <p className="mt-2 text-xs text-red-600">{note}</p>}
    </div>
  );
}

export default function Team() {
  const [members, setMembers] = useState<Member[]>([]);
  const [seats, setSeats] = useState<Seats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const isOwner = auth.role === "owner";

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.members();
      setMembers(r.members);
      setSeats(r.seats);
      setError(null);
    } catch (e) {
      setError(
        e instanceof ApiError && e.unauthorized
          ? "forbidden"
          : "Could not load your team.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: load() flips a loading flag before its first await. That's
    // the intended pattern here, not the cascading-render case the rule targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const [acting, setActing] = useState<string | null>(null);

  const [pendingRemoval, setPendingRemoval] = useState<Member | null>(null);
  const [removing, setRemoving] = useState(false);

  function remove(m: Member) {
    setPendingRemoval(m);
  }

  async function confirmRemove() {
    const target = pendingRemoval;
    if (!target) return;
    setRemoving(true);
    try {
      await api.removeMember(target.id);
      window.dispatchEvent(new Event("envelock:team-changed"));
      setPendingRemoval(null);
      toast.success(`${target.email} no longer has access.`);
      await load();
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not remove that person.",
      );
    } finally {
      setRemoving(false);
    }
  }

  async function approve(m: Member) {
    setActing(m.id);
    try {
      await api.approveMember(m.id);
      window.dispatchEvent(new Event("envelock:team-changed"));
      await load();
    } catch (e) {
      // load() clears the error on success, so nothing surfaced a rejected
      // approval (e.g. 402 seat cap) — the spinner stopped and that was all.
      setError(e instanceof ApiError ? e.message : "Couldn't approve — try again.");
    } finally {
      setActing(null);
    }
  }

  const pendingApproval = members.filter(
    (m) => m.status === "pending" && !m.pending_password,
  );

  if (!auth.signedIn || error === "forbidden") {
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <h1 className="headline">Admins only</h1>
          <p className="lede mx-auto mt-4 text-base">
            Team management is available to workspace admins and the owner.
          </p>
          <Link to="/dashboard" className="mt-8 inline-block">
            <Button variant="accent" size="lg">
              BACK TO DASHBOARD
            </Button>
          </Link>
        </div>
      </main>
    );
  }

  return (
    <main className="shell max-w-3xl py-12">
      <div className="flex items-center gap-3">
        <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
        <span className="sect-label">Your workspace</span>
      </div>
      <h1 className="headline mt-5">Team &amp; access</h1>
      <p className="lede mt-4 text-base">
        Create logins for your colleagues. You hand them a one-time password; they
        set their own at first sign-in.
      </p>

      {/* Seats */}
      <div className="panel mt-8 flex flex-wrap items-center gap-x-8 gap-y-3 p-5">
        <div>
          <div className="font-mono tnum text-2xl font-semibold">
            {seats ? `${seats.used}/${seats.cap}` : "—"}
          </div>
          <div className="sect-label mt-1">Team seats used</div>
        </div>
        <p className="fg-3 max-w-sm text-xs leading-relaxed">
          {seats && !seats.entitled
            ? "Guard is owner-only. Start a trial or add billing to invite your team."
            : "One login per protected mailbox. Add protected mailboxes on the dashboard to open more seats."}
        </p>
      </div>

      {/* Add */}
      <div className="mt-8 flex items-center gap-2">
        <UserPlus size={16} className="accent" aria-hidden />
        <h2 className="text-sm font-semibold">Add a teammate</h2>
      </div>
      <section className="panel mt-3 p-5">
        <CreateMember
          isOwner={isOwner}
          seats={seats}
          onCreated={load}
          domain={members.find((m) => m.email.includes("@"))?.email.split("@")[1]}
        />
      </section>

      {/* Pending approvals — the colleague-join loop the dashboard's
          "Waiting for approval" screen points admins to. */}
      {pendingApproval.length > 0 && (
        <div className="callout mt-8 flex flex-wrap items-center gap-3 p-4">
          <UserCheck size={18} className="shrink-0" aria-hidden />
          <span className="text-sm font-semibold">
            {pendingApproval.length} colleague
            {pendingApproval.length === 1 ? "" : "s"} waiting for approval
          </span>
          <span className="fg-2 text-xs">
            They joined on your company domain and can't see anything until you
            approve them below.
          </span>
        </div>
      )}

      {/* Members */}
      <div className="mt-8 flex items-center gap-2">
        <Users size={16} className="accent" aria-hidden />
        <h2 className="text-sm font-semibold">
          Everyone ({members.length})
        </h2>
      </div>
      <section className="panel mt-3">
        {loading && members.length === 0 ? (
          <p className="fg-3 p-6 text-center text-sm">Loading…</p>
        ) : (
          <ul className="divide-y" role="list">
            {members.map((m) => (
              <li key={m.id} className="flex flex-wrap items-center gap-3 px-5 py-4">
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">
                    {m.email}
                    {m.is_self && <span className="fg-3 text-xs"> · you</span>}
                  </p>
                  <p className="fg-3 mono-xs mt-0.5 flex flex-wrap items-center gap-x-2">
                    <span className="uppercase">{m.role}</span>
                    {m.pending_password ? (
                      <span className="text-[var(--warn,#d97706)]">
                        · awaiting first sign-in
                      </span>
                    ) : m.status === "pending" ? (
                      <span className="text-[var(--warn,#d97706)]">· awaiting approval</span>
                    ) : (
                      <span className="accent flex items-center gap-1">
                        · <BadgeCheck size={11} aria-hidden /> active
                      </span>
                    )}
                  </p>
                </div>
                {m.role === "owner" ? (
                  <span className="fg-3 mono-xs flex items-center gap-1">
                    <ShieldCheck size={12} aria-hidden /> OWNER
                  </span>
                ) : (
                  !m.is_self && (
                    <div className="flex items-center gap-2">
                      {m.status === "pending" && !m.pending_password && (
                        <Button
                          size="sm"
                          variant="accent"
                          disabled={acting !== null}
                          onClick={() => void approve(m)}
                        >
                          {acting === m.id ? (
                            <Loader2 size={12} className="animate-spin" aria-hidden />
                          ) : (
                            <UserCheck size={12} aria-hidden />
                          )}
                          APPROVE
                        </Button>
                      )}
                      <button
                        onClick={() => void remove(m)}
                        aria-label={`Remove ${m.email}`}
                        title="Remove"
                        className="fg-3 cursor-pointer p-1 transition-colors hover:text-[var(--danger)]"
                      >
                        <Trash2 size={15} aria-hidden />
                      </button>
                    </div>
                  )
                )}
              </li>
            ))}
          </ul>
        )}
      </section>

      {error && error !== "forbidden" && (
        <p role="alert" className="mt-4 text-sm text-[var(--danger)]">
          {error}
        </p>
      )}

      <ConfirmDialog
        open={pendingRemoval !== null}
        title="Remove this person?"
        body={
          pendingRemoval
            ? `${pendingRemoval.email} loses access to this workspace ` +
              "immediately, on every device. Their alert history is kept."
            : ""
        }
        confirmLabel="REMOVE ACCESS"
        busy={removing}
        onConfirm={() => void confirmRemove()}
        onCancel={() => setPendingRemoval(null)}
      />
    </main>
  );
}
