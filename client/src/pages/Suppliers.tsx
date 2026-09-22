/* The supplier registry.
 *
 * This is the product thesis, and it had no interface at all. The server has
 * held these endpoints since early on — bank records, verified callback numbers,
 * the counterparty table they hang off — and the app called exactly one of them,
 * the read-only list. So the one capability the incumbents' architecture cannot
 * reach was, in practice, unreachable for the customer too.
 *
 * The screen is built around the sentence a person in accounts payable actually
 * says: "this invoice says to pay a different account than last time". To answer
 * it the product needs two things on file, from a source the attacker cannot
 * influence: the account the supplier is really paid into, and a phone number to
 * ring that did not come out of the email. Everything here exists to get those
 * two facts recorded — and the fastest way is the import, because finance
 * already holds both in their accounting system.
 *
 * Deliberately NOT a card wall. A registry is scanned for gaps, so it is a dense
 * list with the incomplete suppliers pulled to the top and the missing piece
 * named on each row.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  Building2,
  Check,
  ChevronDown,
  Landmark,
  Loader2,
  Phone,
  Plus,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import {
  ApiError,
  api,
  auth,
  type BankRecord,
  type Counterparty,
  type SupplierDetail,
  type VendorImportResult,
} from "../lib/api";
import { Button, TierChip, cn } from "../components/primitives";
import AccountingPanel from "../components/AccountingPanel";
import ConfirmDialog from "../components/ConfirmDialog";
import { toast } from "../lib/toast";

const SCHEMES: { id: BankRecord["scheme"]; label: string; hint: string }[] = [
  { id: "iban", label: "IBAN", hint: "GB29 NWBK 6016 1331 9268 19" },
  { id: "account", label: "Account no.", hint: "12345678" },
  { id: "sortcode", label: "Sort / routing", hint: "12-34-56" },
  { id: "swift", label: "SWIFT / BIC", hint: "NWBKGB2L" },
  { id: "ach", label: "ACH", hint: "021000021" },
  { id: "crypto", label: "Wallet", hint: "bc1q…" },
];

const SCHEME_LABEL = Object.fromEntries(SCHEMES.map((s) => [s.id, s.label]));

/* ── Import: the five minutes that make the rest of the product work ─────── */
function VendorImport({ onDone }: { onDone: () => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [csv, setCsv] = useState("");
  const [preview, setPreview] = useState<VendorImportResult | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(dryRun: boolean) {
    if (!csv.trim()) return;
    setBusy(true);
    try {
      const result = await api.importVendors(csv, dryRun);
      if (dryRun) {
        setPreview(result);
      } else {
        toast.success(
          `Imported ${result.suppliers_created} supplier${
            result.suppliers_created === 1 ? "" : "s"
          } and ${result.bank_records_created} payment record${
            result.bank_records_created === 1 ? "" : "s"
          }.`,
        );
        setCsv("");
        setPreview(null);
        setOpen(false);
        await onDone();
      }
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not read that file.",
      );
    } finally {
      setBusy(false);
    }
  }

  function readFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setCsv(String(reader.result ?? ""));
      setPreview(null);
    };
    reader.readAsText(file);
  }

  if (!open) {
    return (
      <div className="callout mt-8 flex flex-wrap items-center gap-x-4 gap-y-3 p-4">
        <Upload size={18} className="shrink-0" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold">Import your supplier list</p>
          <p className="fg-2 mt-1 text-xs leading-relaxed">
            Export the vendor list from your accounting system and drop it in.
            We'll take the supplier, the account they're paid into and the
            contact number — which is everything we need to spot a change.
          </p>
        </div>
        <Button variant="accent" size="sm" onClick={() => setOpen(true)}>
          IMPORT A FILE
        </Button>
      </div>
    );
  }

  return (
    <section className="panel mt-8 p-5">
      <div className="flex items-center gap-2">
        <Upload size={16} className="accent" aria-hidden />
        <h2 className="text-sm font-semibold">Import your supplier list</h2>
      </div>
      <p className="fg-3 mt-2 text-xs leading-relaxed">
        A CSV with a column for the supplier's domain or email address. We also
        read columns named supplier, IBAN, account, sort code, SWIFT, bank and
        phone — under most of the names Sage, Xero, QuickBooks and NetSuite give
        them, so there is usually nothing to rename.
      </p>

      <label className="mt-4 block">
        <span className="sect-label">Choose a file</span>
        <input
          type="file"
          accept=".csv,text/csv,text/plain"
          className="fg-2 mt-2 block w-full text-xs file:mr-3 file:cursor-pointer file:border file:border-[var(--rule)] file:bg-transparent file:px-3 file:py-1.5 file:text-[11px] file:tracking-wide file:uppercase"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) readFile(file);
          }}
        />
      </label>

      <label className="mt-4 block">
        <span className="sect-label">…or paste it</span>
        <textarea
          value={csv}
          onChange={(e) => {
            setCsv(e.target.value);
            setPreview(null);
          }}
          rows={6}
          spellCheck={false}
          placeholder={
            "Supplier,Email,IBAN,Phone\nAcme Ltd,accounts@acme.com,GB29NWBK60161331926819,+44 20 7946 0000"
          }
          className="field font-mono mt-2 w-full text-xs"
        />
      </label>

      {/* Preview before writing. This is what makes the button safe to press:
          the person sees exactly what will be created, and nothing is. */}
      {preview && (
        <div className="callout mt-4 p-4">
          <p className="text-sm font-semibold">
            {preview.rows_parsed} row{preview.rows_parsed === 1 ? "" : "s"} read
          </p>
          <ul className="fg-2 mt-2 space-y-1 text-xs">
            <li>
              {preview.suppliers_created} new supplier
              {preview.suppliers_created === 1 ? "" : "s"}, {preview.suppliers_matched}{" "}
              already known
            </li>
            <li>
              {preview.bank_records_created} new payment record
              {preview.bank_records_created === 1 ? "" : "s"}
              {preview.bank_records_already_present > 0 &&
                `, ${preview.bank_records_already_present} already on file`}
            </li>
          </ul>
          {preview.problems.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-semibold">
                {preview.problems.length} row
                {preview.problems.length === 1 ? "" : "s"} we couldn't use
              </p>
              <ul className="fg-3 mt-1 space-y-0.5 text-[11px]">
                {preview.problems.slice(0, 6).map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div className="mt-5 flex flex-wrap gap-2">
        <Button
          variant="line"
          size="sm"
          disabled={busy || !csv.trim()}
          onClick={() => void run(true)}
        >
          {busy && !preview ? (
            <>
              <Loader2 size={12} className="animate-spin" aria-hidden /> CHECKING
            </>
          ) : (
            "CHECK THE FILE"
          )}
        </Button>
        <Button
          variant="accent"
          size="sm"
          disabled={busy || !preview || preview.rows_parsed === 0}
          onClick={() => void run(false)}
          title={!preview ? "Check the file first" : undefined}
        >
          {busy && preview ? (
            <>
              <Loader2 size={12} className="animate-spin" aria-hidden /> IMPORTING
            </>
          ) : (
            "IMPORT"
          )}
        </Button>
        <Button
          variant="quiet"
          size="sm"
          onClick={() => {
            setOpen(false);
            setPreview(null);
          }}
        >
          CANCEL
        </Button>
      </div>
    </section>
  );
}

/* ── Add one supplier by hand ────────────────────────────────────────────── */
function AddSupplier({ onAdded }: { onAdded: (domain: string) => Promise<void> }) {
  const [domain, setDomain] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit() {
    const value = domain.trim().toLowerCase();
    if (!value.includes(".")) {
      toast.error("Enter the supplier's domain, like acme.com.");
      return;
    }
    setBusy(true);
    try {
      const r = await api.addSupplier({
        domain: value,
        ...(name.trim() ? { display_name: name.trim() } : {}),
      });
      setDomain("");
      setName("");
      toast.success(
        r.created ? `Added ${r.domain}.` : `${r.domain} was already on file.`,
      );
      await onAdded(r.domain);
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not add that supplier.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex flex-col gap-2 sm:flex-row">
      <input
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && void submit()}
        placeholder="acme.com"
        autoComplete="off"
        aria-label="Supplier domain"
        className="field flex-1 text-sm"
      />
      <input
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && void submit()}
        placeholder="Acme Ltd (optional)"
        autoComplete="off"
        aria-label="Supplier name"
        className="field flex-1 text-sm"
      />
      <Button variant="accent" disabled={busy} onClick={() => void submit()}>
        {busy ? (
          <Loader2 size={14} className="animate-spin" aria-hidden />
        ) : (
          <>
            <Plus size={14} aria-hidden /> ADD
          </>
        )}
      </Button>
    </div>
  );
}

/* ── One supplier, expanded ──────────────────────────────────────────────── */
function SupplierDetailPanel({
  domain,
  canEdit,
  onChanged,
}: {
  domain: string;
  canEdit: boolean;
  onChanged: () => Promise<void>;
}) {
  const [detail, setDetail] = useState<SupplierDetail | null>(null);
  // Neutral default: IBAN first read as UK/EU-only to a US customer; every
  // scheme is still one click away.
  const [scheme, setScheme] = useState<BankRecord["scheme"]>("account");
  const [identifier, setIdentifier] = useState("");
  const [bankName, setBankName] = useState("");
  const [phone, setPhone] = useState("");
  const [busy, setBusy] = useState(false);
  const [retiring, setRetiring] = useState<BankRecord | null>(null);

  const load = useCallback(async () => {
    try {
      const d = await api.supplierRecords(domain);
      setDetail(d);
      setPhone(d.verified_phone ?? "");
    } catch {
      setDetail({ domain, display_name: null, verified_phone: null, records: [] });
    }
  }, [domain]);

  useEffect(() => {
    // Fetch-on-mount. The rule targets cascading renders from derived state;
    // this is the "subscribe to an external system" case it explicitly allows.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  async function addRecord() {
    if (!identifier.trim()) return;
    setBusy(true);
    try {
      await api.addBankRecord(domain, {
        scheme,
        identifier: identifier.trim(),
        ...(bankName.trim() ? { bank_name: bankName.trim() } : {}),
      });
      setIdentifier("");
      setBankName("");
      toast.success("Payment details recorded.");
      await load();
      await onChanged();
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not save those details.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function saveNumber() {
    setBusy(true);
    try {
      await api.setCallbackNumber(domain, phone.trim());
      toast.success("Callback number saved.");
      await load();
      await onChanged();
    } catch (e) {
      toast.error(
        e instanceof ApiError ? e.message : "Could not save that number.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function confirmRetire() {
    if (!retiring) return;
    setBusy(true);
    try {
      await api.retireBankRecord(domain, retiring.id);
      toast.success("Marked as no longer in use.");
      setRetiring(null);
      await load();
      await onChanged();
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not update that.");
    } finally {
      setBusy(false);
    }
  }

  const active = detail?.records.filter((r) => r.active) ?? [];
  const retired = detail?.records.filter((r) => !r.active) ?? [];

  return (
    <div className="border-t border-[var(--rule)] px-4 py-5">
      {/* Payment details on file */}
      <div className="flex items-center gap-2">
        <Landmark size={14} className="accent" aria-hidden />
        <h3 className="text-xs font-semibold tracking-wide uppercase">
          Accounts we expect to pay
        </h3>
      </div>

      {active.length === 0 ? (
        <p className="fg-3 mt-2 text-xs leading-relaxed">
          Nothing on file. Until there is, a changed account on an invoice from
          this supplier has nothing to be checked against.
        </p>
      ) : (
        <ul className="mt-3 space-y-2">
          {active.map((r) => (
            <li
              key={r.id}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 border border-[var(--rule)] px-3 py-2"
            >
              <span className="sect-label shrink-0">
                {SCHEME_LABEL[r.scheme] ?? r.scheme}
              </span>
              {/* Shown in full: this is the string a person compares against an
                  invoice by eye, and a masked one cannot be compared. */}
              <code className="font-mono min-w-0 flex-1 text-sm break-all">
                {r.identifier}
              </code>
              {r.bank_name && <span className="fg-3 text-xs">{r.bank_name}</span>}
              {canEdit && (
                <button
                  type="button"
                  onClick={() => setRetiring(r)}
                  aria-label={`Mark ${r.identifier} as no longer in use`}
                  className="fg-3 cursor-pointer p-1 transition-colors hover:text-[var(--fg)]"
                >
                  <Trash2 size={13} aria-hidden />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}

      {retired.length > 0 && (
        <p className="fg-3 mt-2 text-[11px]">
          {retired.length} account{retired.length === 1 ? "" : "s"} no longer in
          use, kept as history.
        </p>
      )}

      {canEdit && (
        <div className="mt-4 flex flex-col gap-2 sm:flex-row">
          <select
            value={scheme}
            onChange={(e) => setScheme(e.target.value as BankRecord["scheme"])}
            aria-label="Type of payment detail"
            className="field text-sm sm:w-40"
          >
            {SCHEMES.map((s) => (
              <option key={s.id} value={s.id}>
                {s.label}
              </option>
            ))}
          </select>
          <input
            value={identifier}
            onChange={(e) => setIdentifier(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void addRecord()}
            placeholder={SCHEMES.find((s) => s.id === scheme)?.hint}
            autoComplete="off"
            aria-label="Account identifier"
            className="field font-mono flex-1 text-sm"
          />
          <input
            value={bankName}
            onChange={(e) => setBankName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void addRecord()}
            placeholder="Bank (optional)"
            autoComplete="off"
            aria-label="Bank name"
            className="field text-sm sm:w-40"
          />
          <Button
            variant="line"
            disabled={busy || !identifier.trim()}
            onClick={() => void addRecord()}
          >
            SAVE
          </Button>
        </div>
      )}

      {/* Callback number — the half people forget, and the half that stops the
          payment. */}
      <div className="mt-6 flex items-center gap-2">
        <Phone size={14} className="accent" aria-hidden />
        <h3 className="text-xs font-semibold tracking-wide uppercase">
          Number to ring to check
        </h3>
      </div>
      <p className="fg-3 mt-2 text-xs leading-relaxed">
        Take this from a contract or a statement — never from an email. When we
        flag a change, this is the number we tell your team to call, precisely
        because whoever sent the email did not choose it.
      </p>
      {canEdit ? (
        <div className="mt-3 flex flex-col gap-2 sm:flex-row">
          <input
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void saveNumber()}
            placeholder="+1 212 555 0100"
            autoComplete="off"
            inputMode="tel"
            aria-label="Verified callback number"
            className="field font-mono flex-1 text-sm"
          />
          <Button
            variant="line"
            disabled={busy || !phone.trim() || phone.trim() === detail?.verified_phone}
            onClick={() => void saveNumber()}
          >
            SAVE
          </Button>
        </div>
      ) : (
        <p className="font-mono mt-2 text-sm">
          {detail?.verified_phone ?? "— not recorded —"}
        </p>
      )}

      <ConfirmDialog
        open={retiring !== null}
        title="No longer in use?"
        body={
          retiring
            ? `We'll stop treating ${retiring.identifier} as this supplier's expected account, and start flagging payments to it. The record is kept as history.`
            : ""
        }
        confirmLabel="MARK AS OLD"
        busy={busy}
        onConfirm={() => void confirmRetire()}
        onCancel={() => setRetiring(null)}
      />
    </div>
  );
}

/* ── The page ────────────────────────────────────────────────────────────── */
export default function Suppliers() {
  const [rows, setRows] = useState<Counterparty[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const canEdit = auth.role === "owner" || auth.role === "admin";

  const load = useCallback(async () => {
    try {
      const r = await api.counterparties();
      setRows(r.counterparties);
    } catch {
      setRows([]);
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount. The rule targets cascading renders from derived state;
    // this is the "subscribe to an external system" case it explicitly allows.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const { incomplete, complete } = useMemo(() => {
    const term = filter.trim().toLowerCase();
    const match = (c: Counterparty) =>
      !term ||
      c.domain.includes(term) ||
      (c.display_name ?? "").toLowerCase().includes(term);
    const all = (rows ?? []).filter(match);
    return {
      incomplete: all.filter((c) => c.needs.length > 0),
      complete: all.filter((c) => c.needs.length === 0),
    };
  }, [rows, filter]);

  const covered = rows?.filter((c) => c.needs.length === 0).length ?? 0;

  function row(c: Counterparty) {
    const open = expanded === c.domain;
    return (
      <li key={c.domain} className="border border-[var(--rule)]">
        <button
          type="button"
          onClick={() => setExpanded(open ? null : c.domain)}
          aria-expanded={open}
          className="flex w-full cursor-pointer flex-wrap items-center gap-x-3 gap-y-2 px-4 py-3 text-left transition-colors hover:bg-[var(--rule-soft,transparent)]"
        >
          <ChevronDown
            size={14}
            aria-hidden
            className={cn(
              "fg-3 shrink-0 transition-transform",
              open && "rotate-180",
            )}
          />
          <span className="min-w-0 flex-1">
            <span className="block text-sm font-semibold">
              {c.display_name || c.domain}
            </span>
            {c.display_name && (
              <span className="font-mono fg-3 block text-[11px]">{c.domain}</span>
            )}
          </span>

          {/* State in form as well as words, so a gap reads at a glance. */}
          {c.needs.length === 0 ? (
            <span className="chip chip-ok">
              <ShieldCheck size={11} aria-hidden />
              Covered
            </span>
          ) : (
            <span className="chip chip-medium">
              <AlertTriangle size={11} aria-hidden />
              {c.needs.includes("bank_details")
                ? "No account on file"
                : "No number to ring"}
            </span>
          )}
          <TierChip tier={c.tier} />
        </button>
        {open && (
          <SupplierDetailPanel
            domain={c.domain}
            canEdit={canEdit}
            onChanged={load}
          />
        )}
      </li>
    );
  }

  return (
    <main className="shell max-w-3xl py-12">
      <div className="flex items-center gap-3">
        <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
        <span className="sect-label">Payment safety</span>
      </div>
      <h1 className="headline mt-5">Suppliers</h1>
      <p className="lede mt-4 text-base">
        The accounts your suppliers are really paid into, and the numbers to ring
        to check. When an invoice asks for a different account, this is what we
        check it against.
      </p>

      {/* Coverage, stated plainly rather than as a decorative dial. */}
      <div className="panel mt-8 flex flex-wrap items-center gap-x-8 gap-y-3 p-5">
        <div>
          <div className="font-mono tnum text-2xl font-semibold">
            {rows ? `${covered}/${rows.length}` : "—"}
          </div>
          <div className="sect-label mt-1">Suppliers fully covered</div>
        </div>
        <p className="fg-3 max-w-sm text-xs leading-relaxed">
          A supplier is covered once we hold both an account and a number to ring.
          With one missing, a bank-change email from them is still caught — but
          your team has nothing trustworthy to verify it against.
        </p>
      </div>

      {canEdit && <AccountingPanel onSynced={load} />}
      {canEdit && <VendorImport onDone={load} />}

      {canEdit && (
        <>
          <div className="mt-8 flex items-center gap-2">
            <Building2 size={16} className="accent" aria-hidden />
            <h2 className="text-sm font-semibold">Add a supplier</h2>
          </div>
          <section className="panel mt-3 p-5">
            <AddSupplier
              onAdded={async (domain) => {
                await load();
                setExpanded(domain);
              }}
            />
          </section>
        </>
      )}

      {/* The list */}
      <div className="mt-10 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold">
          {rows === null
            ? "Loading…"
            : `${rows.length} supplier${rows.length === 1 ? "" : "s"}`}
        </h2>
        {(rows?.length ?? 0) > 6 && (
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name or domain"
            aria-label="Filter suppliers"
            className="field w-full text-sm sm:w-64"
          />
        )}
      </div>

      {rows !== null && rows.length === 0 && (
        <div className="panel mt-4 p-8 text-center">
          <p className="text-sm font-semibold">No suppliers yet</p>
          <p className="fg-3 mx-auto mt-2 max-w-md text-xs leading-relaxed">
            Suppliers appear here as they email you. Importing your list from
            accounting is faster — and it means we can check the very first
            invoice, not the tenth.
          </p>
        </div>
      )}

      {/* Incomplete first: this list is scanned for gaps, not browsed. */}
      {incomplete.length > 0 && (
        <>
          <p className="sect-label mt-6">Needs your attention</p>
          <ul className="mt-3 space-y-2">{incomplete.map(row)}</ul>
        </>
      )}
      {complete.length > 0 && (
        <>
          <p className="sect-label mt-8">Covered</p>
          <ul className="mt-3 space-y-2">{complete.map(row)}</ul>
        </>
      )}

      {rows !== null && rows.length > 0 && incomplete.length === 0 && (
        <p className="fg-3 mt-6 flex items-center gap-2 text-xs">
          <Check size={13} className="accent" aria-hidden />
          Every supplier has an account and a number on file.
        </p>
      )}
    </main>
  );
}
