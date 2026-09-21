import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Check, CreditCard, Loader2, Lock, Plus, ShieldCheck } from "lucide-react";
import { ApiError, api, auth, type TenantInfo } from "../lib/api";
import { PLAN_TIERS, planTier } from "../lib/plans";
import { Button, cn } from "../components/primitives";

/* Friendly names for the payment rails, one per region (PRD §12.8). "sandbox" is
   the development-only processor so the whole flow is demonstrable without keys. */
const PROVIDER_LABEL: Record<string, string> = {
  stripe: "Card (Stripe)",
  adyen: "Card (Adyen)",
  mercadopago: "Mercado Pago",
  razorpay: "Razorpay",
  sandbox: "Sandbox (test) card",
};

export default function Billing() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const requested = params.get("plan") ?? "";

  const [tenant, setTenant] = useState<TenantInfo | null>(null);
  const [providers, setProviders] = useState<string[] | null>(null);
  const [selected, setSelected] = useState<"essential" | "complete">(
    requested === "essential" ? "essential" : "complete",
  );
  const [provider, setProvider] = useState<string>("");
  const [reference, setReference] = useState("");
  const [seatCount, setSeatCount] = useState(1);
  const [seatBusy, setSeatBusy] = useState(false);
  const [seatMsg, setSeatMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const load = useCallback(async () => {
    try {
      const [t, p] = await Promise.all([api.tenant(), api.paymentProviders()]);
      setTenant(t);
      setProviders(p.configured);
      setProvider((prev) => prev || p.configured[0] || "");
    } catch (e) {
      setError(
        e instanceof ApiError && e.unauthorized
          ? "signed-out"
          : "We couldn't load your billing details. Please try again.",
      );
    }
  }, []);

  useEffect(() => {
    // Fetch-on-mount: load() flips a loading flag before its first await. That's
    // the intended pattern here, not the cascading-render case the rule targets.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const identifier = useMemo(() => tenant?.primary_domain ?? "", [tenant]);
  const isSandbox = provider === "sandbox";
  const isStripe = provider === "stripe";
  const status = params.get("status"); // "success" | "cancel" after Stripe redirect

  // Returning from Stripe Checkout: the webhook flips the plan server-side, which
  // can land a moment after the redirect. Poll briefly until the gate is open,
  // then show the success screen.
  useEffect(() => {
    if (status !== "success") return;
    let tries = 0;
    let live = true;
    const tick = async () => {
      try {
        const t = await api.tenant();
        if (!live) return;
        if (t.trial.payment_method_ok) {
          setDone(true);
          return;
        }
      } catch {
        /* keep polling */
      }
      if (live && tries++ < 6) setTimeout(() => void tick(), 1500);
    };
    void tick();
    return () => {
      live = false;
    };
  }, [status]);

  async function buySeats() {
    if (!provider) {
      setSeatMsg("No payment method is available on this deployment yet.");
      return;
    }
    setSeatBusy(true);
    setSeatMsg(null);
    try {
      const r = await api.buySeats(
        seatCount,
        provider,
        reference.trim() || "seat-purchase",
      );
      setSeatMsg(`Added ${r.purchased} seat${r.purchased === 1 ? "" : "s"}.`);
      await load();
    } catch (e) {
      setSeatMsg(e instanceof ApiError ? e.message : "Could not buy seats.");
    } finally {
      setSeatBusy(false);
    }
  }

  async function openPortal() {
    setBusy(true);
    setError(null);
    try {
      const { url } = await api.billingPortal();
      window.location.assign(url); // Stripe-hosted portal
    } catch (e) {
      setBusy(false);
      setError(
        e instanceof ApiError ? e.message : "Could not open the billing portal.",
      );
    }
  }

  async function startCheckout() {
    setBusy(true);
    setError(null);
    try {
      const { url } = await api.startCheckout(selected);
      window.location.assign(url); // hand off to Stripe's hosted page
    } catch (e) {
      setBusy(false);
      setError(
        e instanceof ApiError ? e.message : "Could not start checkout. Try again.",
      );
    }
  }

  async function submit() {
    if (!provider) {
      setError("No payment method is available on this deployment yet.");
      return;
    }
    if (!reference.trim()) {
      setError(
        isSandbox
          ? "Enter any test reference to simulate a card (e.g. 4242 4242 4242 4242)."
          : "Enter the payment reference from your card provider.",
      );
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // 1. Verify + store the payment method (opens the gate, records the ledger).
      await api.confirmPayment({
        provider,
        reference: reference.trim(),
        identifier,
      });
      // 2. Move the tenant onto the chosen plan now that a card is on file.
      await api.changePlan(selected);
      setDone(true);
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Could not complete billing setup.",
      );
    } finally {
      setBusy(false);
    }
  }

  if (error === "signed-out" || !auth.signedIn) {
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <h1 className="headline">Sign in to manage billing</h1>
          <Link to="/signin" className="mt-8 inline-block">
            <Button variant="accent" size="lg">
              SIGN IN
            </Button>
          </Link>
        </div>
      </main>
    );
  }

  if (done) {
    const tier = planTier(selected);
    return (
      <main className="shell py-24">
        <div className="panel mx-auto max-w-lg p-8 text-center">
          <ShieldCheck size={30} className="accent mx-auto" aria-hidden />
          <h1 className="headline mt-5">You're on {tier?.name ?? selected}.</h1>
          <p className="lede mx-auto mt-4 text-base">
            Payment method saved and your plan is active. Full protection stays on
            when your trial ends.
          </p>
          <Button
            variant="accent"
            size="lg"
            className="mt-8"
            onClick={() => navigate("/dashboard")}
          >
            BACK TO DASHBOARD
          </Button>
        </div>
      </main>
    );
  }

  const tier = planTier(selected);

  return (
    <main className="shell grid12 py-12">
      <div className="col-span-12 lg:col-span-7">
        <span className="sect-label">Billing</span>
        <h1 className="headline mt-2">
          {tenant?.trial.payment_method_ok ? "Billing" : "Set up billing"}
        </h1>
        <p className="lede mt-4 text-base">
          Add a payment method to keep full protection when your trial ends. You
          can change or cancel anytime — monthly, no penalty.
        </p>

        {/* Already have a card → self-service portal (update card, invoices, cancel). */}
        {tenant?.trial.payment_method_ok && (
          <div className="panel mt-6 flex flex-wrap items-center gap-3 p-4">
            <ShieldCheck size={18} className="accent shrink-0" aria-hidden />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold">A payment method is on file</p>
              <p className="fg-3 text-xs">
                Update your card, download invoices, or cancel anytime.
              </p>
            </div>
            <Button
              size="sm"
              variant="line"
              disabled={busy}
              onClick={openPortal}
              className="shrink-0"
            >
              {busy ? (
                <Loader2 size={13} className="animate-spin" aria-hidden />
              ) : (
                <CreditCard size={13} aria-hidden />
              )}
              MANAGE BILLING
            </Button>
          </div>
        )}

        {/* Plan chooser */}
        <div className="mt-8 space-y-3">
          {PLAN_TIERS.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => setSelected(p.id)}
              aria-pressed={selected === p.id}
              className={cn(
                "block w-full cursor-pointer rounded border p-4 text-left transition-colors",
                selected === p.id
                  ? "border-[var(--accent)] bg-[var(--bg-hover)]"
                  : "border-[var(--rule)] hover:border-[var(--fg-3)]",
              )}
            >
              <div className="flex items-baseline justify-between gap-2">
                <span className="flex items-center gap-2 text-sm font-semibold">
                  <span
                    className={cn(
                      "grid size-4 place-items-center rounded-full border",
                      selected === p.id
                        ? "border-[var(--accent)] bg-[var(--accent)]"
                        : "border-[var(--rule)]",
                    )}
                    aria-hidden
                  >
                    {selected === p.id && (
                      <Check size={11} className="text-[var(--accent-ink)]" />
                    )}
                  </span>
                  {p.name}
                </span>
                <span className="tnum">
                  <span className="font-mono text-base font-semibold">{p.price}</span>
                  <span className="fg-3 text-[11px]">{p.per}</span>
                </span>
              </div>
              <p className="fg-3 mt-1 pl-6 text-xs">{p.blurb}</p>
            </button>
          ))}
        </div>

        {/* Payment method */}
        <div className="mt-8">
          <h2 className="sect-label">Payment method</h2>
          {providers === null ? (
            <p className="fg-3 mt-3 text-sm">Loading…</p>
          ) : providers.length === 0 ? (
            <p className="callout mt-3 p-4 text-sm">
              Billing isn't enabled on this deployment yet — no payment provider is
              configured. Your trial and Guard (free) protection are unaffected.
            </p>
          ) : (
            <div className="mt-3 space-y-3">
              {providers.length > 1 && (
                <div className="flex flex-wrap gap-2" role="group" aria-label="Provider">
                  {providers.map((p) => (
                    <button
                      key={p}
                      type="button"
                      onClick={() => setProvider(p)}
                      aria-pressed={provider === p}
                      className={cn(
                        "font-mono cursor-pointer border px-3 py-1.5 text-[11px] tracking-wide transition-colors",
                        provider === p
                          ? "accent border-[var(--accent)]"
                          : "fg-3 border-[var(--rule)] hover:text-[var(--fg)]",
                      )}
                    >
                      {PROVIDER_LABEL[p] ?? p}
                    </button>
                  ))}
                </div>
              )}

              {status === "cancel" && (
                <p className="fg-3 text-xs">
                  Checkout was canceled — you haven't been charged. Pick up where you
                  left off below.
                </p>
              )}

              {isStripe ? (
                /* Real Stripe: hand off to the hosted card page. No card data
                   touches us; the webhook activates the plan on completion. */
                <>
                  <Button
                    variant="accent"
                    disabled={busy}
                    onClick={startCheckout}
                    className="mt-1"
                  >
                    {busy ? (
                      <Loader2 size={13} className="animate-spin" aria-hidden />
                    ) : (
                      <Lock size={13} aria-hidden />
                    )}
                    CONTINUE TO SECURE CHECKOUT
                  </Button>
                  <p className="fg-3 text-[11px] leading-relaxed">
                    You'll enter your card on Stripe's secure page and come straight
                    back. We never see or store your card number.
                  </p>
                </>
              ) : (
                <>
                  <label className="fg-3 mono-xs block" htmlFor="pay-ref">
                    {isSandbox ? "TEST CARD REFERENCE" : "PAYMENT REFERENCE"}
                  </label>
                  <div className="relative">
                    <CreditCard
                      size={15}
                      className="fg-3 absolute inset-y-0 left-3 my-auto"
                      aria-hidden
                    />
                    <input
                      id="pay-ref"
                      value={reference}
                      onChange={(e) => setReference(e.target.value)}
                      placeholder={
                        isSandbox ? "4242 4242 4242 4242" : "pm_… (from your card provider)"
                      }
                      autoComplete="off"
                      className="field w-full pl-10 text-sm"
                    />
                  </div>
                  <p className="fg-3 text-[11px] leading-relaxed">
                    {isSandbox
                      ? "Development sandbox — no real charge. Any value works; it stands in for the token a real card provider returns."
                      : "We never see your card number. Your provider's secure form returns a token (a payment-method reference), and that is all we store."}
                  </p>
                  <Button variant="accent" disabled={busy} onClick={submit} className="mt-1">
                    {busy ? (
                      <Loader2 size={13} className="animate-spin" aria-hidden />
                    ) : (
                      <Lock size={13} aria-hidden />
                    )}
                    ACTIVATE {tier?.name.toUpperCase() ?? "PLAN"}
                  </Button>
                </>
              )}
            </div>
          )}
          {error && error !== "signed-out" && (
            <p className="mt-3 text-sm text-[var(--danger)]" role="alert">
              {error}
            </p>
          )}
        </div>
      </div>

      {/* Summary */}
      <aside className="col-span-12 mt-8 lg:col-span-4 lg:col-start-9 lg:mt-0">
        <div className="panel p-5">
          <h2 className="sect-label">Summary</h2>
          {tier && (
            <>
              <div className="mt-4 flex items-baseline justify-between gap-2">
                <span className="text-sm font-semibold">{tier.name}</span>
                <span className="tnum font-mono text-lg font-semibold">
                  {tier.price}
                  <span className="fg-3 text-[11px]">{tier.per}</span>
                </span>
              </div>
              <ul className="fg-2 mt-4 space-y-1.5" role="list">
                {tier.features.map((f) => (
                  <li key={f} className="flex items-start gap-1.5 text-xs">
                    <Check size={12} className="accent mt-0.5 shrink-0" aria-hidden />
                    {f}
                  </li>
                ))}
              </ul>
            </>
          )}
          {tenant?.trial.active && tenant.trial.days_left !== null && (
            <div className="mt-5 flex items-baseline justify-between gap-3 border-t pt-4">
              <span className="fg-2 text-xs">Trial remaining</span>
              <span
                className={cn(
                  "font-mono tnum text-sm font-semibold",
                  tenant.trial.days_left <= 3 ? "text-[var(--danger)]" : "accent",
                )}
              >
                {tenant.trial.days_left} day{tenant.trial.days_left === 1 ? "" : "s"}
              </span>
            </div>
          )}
          <p className="fg-3 mt-3 text-[11px] leading-relaxed">
            {tenant?.trial.active
              ? "You won't be charged until your trial ends — adding a card now just keeps protection on when it does."
              : "Billed monthly. Cancel anytime; you drop to Guard (free), never locked out."}
          </p>
        </div>

        {/* Mailbox seats — buy capacity beyond the plan's included allowance. */}
        {tenant?.mailboxes && (
          <div className="panel mt-4 p-5">
            <h2 className="sect-label">Mailbox seats</h2>
            <div className="mt-3 flex items-baseline justify-between gap-3">
              <span className="fg-2 text-sm">In use</span>
              <span className="tnum font-mono text-sm font-semibold">
                {tenant.mailboxes.used} / {tenant.mailboxes.capacity}
                {tenant.mailboxes.extra_seats > 0 && (
                  <span className="fg-3 text-[11px]">
                    {" "}
                    (+{tenant.mailboxes.extra_seats} bought)
                  </span>
                )}
              </span>
            </div>
            <p className="fg-3 mt-2 text-[11px] leading-relaxed">
              Your {(tenant.subscribed_plan ?? tenant.plan)} plan includes{" "}
              {tenant.mailboxes.included}. Buy more to protect additional mailboxes.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <input
                type="number"
                min={1}
                max={500}
                value={seatCount}
                onChange={(e) =>
                  setSeatCount(Math.max(1, Math.min(500, Number(e.target.value) || 1)))
                }
                aria-label="Seats to buy"
                className="field w-20 text-sm"
              />
              <Button
                size="sm"
                variant="line"
                disabled={seatBusy || !provider}
                onClick={buySeats}
              >
                {seatBusy ? (
                  <Loader2 size={12} className="animate-spin" aria-hidden />
                ) : (
                  <Plus size={12} aria-hidden />
                )}
                BUY SEAT{seatCount === 1 ? "" : "S"}
              </Button>
            </div>
            {seatMsg && <p className="fg-3 mt-2 text-[11px]">{seatMsg}</p>}
          </div>
        )}
      </aside>
    </main>
  );
}
