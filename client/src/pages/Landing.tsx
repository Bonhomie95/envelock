import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Banknote,
  Check,
  Globe,
  Link2,
  Loader2,
  MessageSquareText,
  ScanEye,
  Search,
  ShieldCheck,
  Sparkles,
  UserCheck,
} from "lucide-react";
import { api, type NetworkStats, type ScanResult } from "../lib/api";
import { Button, SectionHead, TierChip, cn } from "../components/primitives";

/* Deliberately plain. Anything technical belongs in /docs — a landing page
   that reads like a manual convinces nobody. */

/* "registered 3 days ago" reads as urgency far better than a raw date — a
   lookalike registered this week is the one actively being weaponised. */
function registeredLabel(iso: string): string {
  const when = new Date(iso);
  if (Number.isNaN(when.getTime())) return "registered";
  const days = Math.floor((Date.now() - when.getTime()) / 86_400_000);
  if (days <= 0) return "registered today";
  if (days === 1) return "registered 1 day ago";
  if (days < 30) return `registered ${days} days ago`;
  if (days < 365) return `registered ${Math.floor(days / 30)} mo ago`;
  return `registered ${when.getFullYear()}`;
}

function Scanner() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!domain.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.scanDomain(domain.trim()));
    } catch {
      setError("Could not complete the scan. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="panel">
      <form onSubmit={onSubmit} className="p-6">
        <label htmlFor="scan" className="block text-base font-semibold">
          Is anyone impersonating your business?
        </label>
        <p className="fg-2 mt-2 text-sm leading-relaxed">
          Free to check. No account, no access to your email.
        </p>

        <div className="mt-5 flex flex-col gap-px sm:flex-row">
          <div className="relative flex-1">
            <Globe
              size={15}
              className="fg-3 pointer-events-none absolute top-1/2 left-3.5 -translate-y-1/2"
              aria-hidden
            />
            <input
              id="scan"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="yourcompany.com"
              autoComplete="url"
              className="field pl-10"
            />
          </div>
          <Button type="submit" variant="accent" size="lg" disabled={loading || !domain.trim()}>
            {loading ? (
              <>
                <Loader2 size={14} className="animate-spin" aria-hidden />
                CHECKING
              </>
            ) : (
              <>
                <Search size={14} aria-hidden />
                CHECK
              </>
            )}
          </Button>
        </div>

        {error && (
          <p role="alert" className="mt-3 text-sm text-[var(--danger)]">
            {error}
          </p>
        )}
      </form>

      {result && (
        <div className="rise border-t p-6">
          {/* Honest counts: the engine returns every plausible misspelling, and
              most are unregistered. "73 lookalike domains found" read as 73
              live impersonators when perhaps two exist. */}
          {(() => {
            const registered = result.hits.filter((h) => h.registered_at).length;
            const possible = result.hits.length - registered;
            return (
              <>
                <p className="text-sm font-semibold">
                  <span className="font-mono tnum accent text-xl">{registered}</span>{" "}
                  {registered === 1 ? "lookalike of" : "lookalikes of"}{" "}
                  {result.protected_domain} already registered
                </p>
                {possible > 0 && (
                  <p className="fg-3 mt-1 text-xs">
                    Plus {possible} close misspellings with no registration found —
                    we watch those too.
                  </p>
                )}
              </>
            );
          })()}
          {result.hits.length > 0 && (
            <ul className="mt-4 divide-y" role="list">
              {result.hits.slice(0, 4).map((hit) => (
                <li key={hit.candidate} className="flex items-center gap-3 py-2.5">
                  {hit.registered_at ? (
                    <TierChip tier={hit.tier} />
                  ) : (
                    // Unregistered can't be sending anything yet — a risk tier
                    // (HIGH for "5tripe.com") overstated it.
                    <span className="fg-3 mono-xs w-[4.5rem] shrink-0">WATCH</span>
                  )}
                  <code className="flex-1 truncate font-mono text-xs">{hit.candidate}</code>
                  <span className="fg-3 mono-xs shrink-0 tnum">
                    {hit.registered_at ? registeredLabel(hit.registered_at) : "no registration found"}
                  </span>
                </li>
              ))}
            </ul>
          )}
          <p className="fg-3 mt-4 text-xs">
            Newest registrations first — a domain registered days ago is the live
            threat. Some matches may be your own (a country version, say). We keep
            watching for free, and tell you if one starts sending mail.
          </p>
        </div>
      )}
    </div>
  );
}

/* Static illustration of the two features in the product's own visual language:
   a click-time link verdict list, and a held payment. No live calls — the hero
   must never depend on an API to render. */
function ClickCheckDemo() {
  const links = [
    ["invoices.yoursupplier.com/aug", "SAFE · OPENED", "accent"],
    ["secure-payment-update.net/login", "PHISHING · BLOCKED", "text-[var(--danger)]"],
    ["docs-share.icu/Invoice_884.exe", "MALWARE · BLOCKED", "text-[var(--danger)]"],
  ] as const;
  return (
    <div className="panel">
      <div className="p-6">
        <p className="flex items-center gap-2 text-base font-semibold">
          <ShieldCheck size={16} className="accent" aria-hidden />
          Every link, checked when it&rsquo;s clicked
        </p>
        <p className="fg-2 mt-2 text-sm leading-relaxed">
          Links in protected mail are rewritten to pass through Envelock. Safe
          pages open instantly. Phishing and malware stop at the click — on any
          device, even ones we&rsquo;ve never seen.
        </p>
        <ul className="mt-5 divide-y" role="list">
          {links.map(([url, verdict, tone]) => (
            <li key={url} className="flex items-center gap-3 py-2.5">
              <code className="flex-1 truncate font-mono text-xs">{url}</code>
              <span className={cn("mono-xs shrink-0", tone)}>{verdict}</span>
            </li>
          ))}
        </ul>
      </div>
      <div className="border-t p-6">
        <p className="flex items-center gap-2 text-sm font-semibold">
          <Banknote size={15} className="accent" aria-hidden />
          Bank details changed mid-thread
        </p>
        <p className="fg-2 mt-2 text-xs leading-relaxed">
          &ldquo;Please use our new account for this invoice.&rdquo; The account
          your supplier has always used is on file — the mail is quarantined and
          your team alerted before any money moves.
        </p>
      </div>
    </div>
  );
}

/* The shared graph's public counts.
 *
 * Real numbers or nothing. A network-effect claim propped up by a hardcoded
 * figure is the one kind of dishonesty a security buyer is guaranteed to test,
 * and an early-stage graph with small numbers is not embarrassing — the
 * mechanism is the point, and "growing" is a true and sufficient description of
 * a network that is genuinely growing. So if the call fails, or the graph is
 * still empty, this renders the sentence and no figures at all. */
function NetworkNumbers() {
  const [stats, setStats] = useState<NetworkStats | null>(null);

  useEffect(() => {
    let live = true;
    api
      .network()
      .then((s) => live && setStats(s))
      .catch(() => {
        /* No numbers is a fine outcome; a wrong number is not. */
      });
    return () => {
      live = false;
    };
  }, []);

  if (!stats || stats.domains_judged === 0) {
    return (
      <p className="fg-2 text-[15px] leading-relaxed">
        The network is live and growing with every confirmed fraud our customers
        report.
      </p>
    );
  }

  const cells: [string, number][] = [
    ["Domains judged", stats.domains_judged],
    ["Confirmed fraudulent", stats.domains_confirmed_fraudulent],
    ["Independently confirmed", stats.actionable],
  ];

  return (
    <dl className="grid grid-cols-2 gap-px bg-[var(--rule)] sm:grid-cols-3">
      {cells.map(([label, value]) => (
        <div key={label} className="bg-[var(--bg-raised)] p-5">
          <dd className="font-mono tnum text-3xl font-semibold tracking-tight">
            {value.toLocaleString()}
          </dd>
          <dt className="sect-label mt-2">{label}</dt>
        </div>
      ))}
    </dl>
  );
}

/* What an AI-written alert actually looks like. Static: this is marketing copy
   illustrating the real output shape (verdict, plain-English reason, the number
   we hold on file), not a live call. */
function AiVerdictDemo() {
  return (
    <div className="panel">
      <div className="flex items-center gap-2 border-b p-5">
        <Sparkles size={15} className="accent" aria-hidden />
        <span className="sect-label">AI analyst · verdict</span>
        <span className="mono-xs ml-auto text-[var(--danger)]">CRITICAL</span>
      </div>
      <div className="p-6">
        <p className="fg-3 mono-xs">FROM</p>
        <code className="mt-1 block truncate font-mono text-xs">
          accounts@yoursuppler.com
        </code>
        <p className="fg-3 mono-xs mt-4">SUBJECT</p>
        <p className="mt-1 truncate text-sm">Re: Invoice 4471 — updated remittance</p>

        <blockquote className="mt-5 border-l-2 border-[var(--accent)] pl-4 text-sm leading-relaxed">
          This looks like a scam. The bank account differs from the one this
          supplier has used for the last 14 invoices, the domain was registered
          six days ago, and the message presses for payment today and asks you to
          keep it between the two of you.
        </blockquote>

        <div className="mt-5 flex flex-wrap items-center gap-x-6 gap-y-2 border-t pt-4">
          <span className="fg-3 mono-xs">
            CONFIRM ON <span className="accent">+44 20 7946 0000</span> — THE
            NUMBER ON FILE WITH YOU
          </span>
        </div>
      </div>
    </div>
  );
}

const PROBLEMS = [
  {
    icon: Banknote,
    title: "The invoice that isn't from your supplier",
    body: "Someone asks you to pay a new bank account. It arrives inside a conversation you have been having for months, so it looks completely ordinary. We hold the account details your supplier has always used, and stop the payment when they change.",
  },
  {
    icon: Link2,
    title: "The link that isn't what it says",
    body: "A convincing email, a link that looks right, and a login page built to steal a password. Every link in protected mail passes through Envelock first — checked at the moment it's clicked, on any device, and blocked if it's phishing or malware.",
  },
  {
    icon: UserCheck,
    title: "The supplier whose mailbox was hijacked",
    body: "The scariest fraud comes from a real supplier's real address — their mailbox was broken into, and the 'updated bank details' are the criminal's. Because we verify the payment details, not just the sender, the switch is caught and the mail is quarantined.",
  },
];

const AI_POINTS = [
  {
    icon: Sparkles,
    title: "Reads intent, not just red flags",
    body: "It weighs the whole message the way a wary colleague would — is this really your supplier, or someone impersonating them to reroute a payment? Business email compromise (a fake invoice, changed bank details, a 'CEO' asking for an urgent transfer) is exactly what it's built to catch.",
  },
  {
    icon: ScanEye,
    title: "Used only where judgment is needed",
    body: "The fast rules settle the clear-cut cases on their own. The AI is held back for the genuine grey area — the clever fakes that fool people — so you get a sharper verdict without a flood of false alarms, and without running your mail through AI wholesale.",
  },
  {
    icon: MessageSquareText,
    title: "Explained in plain English",
    body: "Every alert reads like an analyst told you why — “this looks like a scam: the bank details changed and the sender's domain was registered last week” — never a mysterious score. Your team can act in seconds.",
  },
];

const PLANS = [
  {
    name: "Guard",
    price: "Free",
    unit: "no card needed",
    line: "We watch for people impersonating your business.",
    features: ["Lookalike domain monitoring", "Alerts when one starts sending mail"],
    cta: "Start free",
    variant: "line" as const,
  },
  {
    name: "Essential",
    price: "$25",
    unit: "per month, 5 mailboxes · $2/mo each extra",
    line: "Protects your mail from invoice fraud.",
    features: [
      "Everything in Guard",
      "Bank detail change alerts",
      "Fake supplier detection",
      "AI analyst on suspicious payment emails",
      "Dashboard for your IT team",
    ],
    cta: "Start free trial",
    variant: "accent" as const,
    featured: true,
  },
  {
    name: "Complete",
    price: "$47.50",
    unit: "per month, 5 mailboxes · $3.50/mo each extra",
    line: "Adds protection if a mailbox is broken into.",
    features: [
      "Everything in Essential",
      "AI analyst on phishing links too",
      "Unusual sign-in alerts (with the Envelock sensor)",
      "Silent access detection (with the Envelock sensor)",
      "Remove dangerous mail automatically",
    ],
    cta: "Start free trial",
    variant: "line" as const,
  },
];

export default function Landing() {
  return (
    <main>
      {/* Hero */}
      <section className="border-b">
        <div className="shell grid12 items-center py-16 md:py-24">
          <div className="col-span-12 lg:col-span-6">
            <span className="mono-xs accent inline-flex items-center gap-1.5 rounded-full border border-[var(--rule)] px-3 py-1">
              <Sparkles size={12} aria-hidden /> NOW WITH AN AI FRAUD ANALYST
            </span>
            <h1 className="display mt-6">
              We stop your money
              <br />
              going to the
              <br />
              <span className="accent">wrong bank account.</span>
            </h1>

            <p className="lede mt-8">
              And your team can&rsquo;t click a phishing link — we check every
              link at the moment it&rsquo;s clicked, on any device. Two frauds,
              stopped where they actually happen.
            </p>

            <div className="mt-10 flex flex-col gap-px sm:flex-row">
              <Link to="/signin">
                <Button variant="accent" size="lg" className="w-full sm:w-auto">
                  GET STARTED FREE
                  <ArrowRight size={14} aria-hidden />
                </Button>
              </Link>
              <Link to="/docs">
                <Button variant="line" size="lg" className="w-full sm:w-auto">
                  READ THE DOCS
                </Button>
              </Link>
            </div>

            <p className="fg-3 mt-6 text-sm">
              Works with the email you already use. Nothing to install.
            </p>
          </div>

          <div className="col-span-12 mt-12 lg:col-span-5 lg:col-start-8 lg:mt-0">
            {/* parked: not in two-feature v1 (brand protection) — <Scanner /> */}
            <ClickCheckDemo />
              <p className="fg-3 mono-xs mt-2">Illustrative example</p>
          </div>
        </div>
      </section>

      {/* What we stop */}
      <section id="problems" className="border-b">
        <div className="shell py-16 md:py-24">
          <SectionHead
            label="What we stop"
            title="Three ways businesses lose money to email."
          />

          {/* Numbered and ruled rather than boxed. The index gives the set an
              order to read in, and the hairline under each label does the
              separating a card border would otherwise do — which keeps three
              long paragraphs from reading as three heavy blocks. */}
          <div className="mt-12 grid gap-x-8 gap-y-12 md:grid-cols-3">
            {PROBLEMS.map((p, i) => {
              const Icon = p.icon;
              return (
                <article key={p.title}>
                  <div className="flex items-end justify-between gap-3 border-b border-[var(--rule-strong)] pb-2.5">
                    <span className="sect-label">
                      Vector {String(i + 1).padStart(2, "0")}
                    </span>
                    <Icon size={17} className="accent shrink-0" aria-hidden />
                  </div>
                  <h3 className="mt-5 text-base font-semibold text-balance">
                    {p.title}
                  </h3>
                  <p className="fg-2 mt-3 text-sm leading-relaxed">{p.body}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="border-b">
        <div className="shell py-16 md:py-24">
          <SectionHead
            label="How it works"
            title="Three steps, then it runs quietly."
            lede="You keep your existing email — Outlook, Gmail, or anything else. We sit alongside it, never in the way."
          />

          <ol className="mt-12 grid gap-px bg-[var(--rule)] md:grid-cols-3" role="list">
            {[
              ["Connect your email", "One click for Microsoft and Google. One simple rule for everything else. Your IT team gets exact instructions for your provider."],
              ["We learn what normal looks like", "Who you deal with, which bank accounts they use, how they write — from live mail, and from a history scan you can run at connection."],
              ["You hear from us only when it matters", "A quiet inbox is the point. When something is wrong, you know within seconds — and so does your IT team."],
            ].map(([title, body], i) => (
              <li key={title} className="bg-[var(--bg-raised)] p-8">
                <span className="font-mono accent text-sm font-semibold">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <h3 className="mt-5 text-base font-semibold">{title}</h3>
                <p className="fg-2 mt-3 text-sm leading-relaxed">{body}</p>
              </li>
            ))}
          </ol>

          <p className="fg-2 mt-10 text-sm">
            Curious about the detail?{" "}
            <Link to="/docs" className="accent underline underline-offset-4">
              The documentation
            </Link>{" "}
            covers every detection, integration and data-handling policy.
          </p>
        </div>
      </section>

      {/* AI analyst */}
      <section className="border-b">
        <div className="shell py-16 md:py-24">
          <SectionHead
            label="AI on your side"
            title="An AI fraud analyst on the emails built to fool people."
            lede="Rules catch the obvious. For the cleverly-disguised payment scams that slip past them, Envelock brings in an AI analyst to judge intent before you're ever asked to pay."
          />

          <div className="mt-12 grid gap-px bg-[var(--rule)] md:grid-cols-3">
            {AI_POINTS.map((p) => {
              const Icon = p.icon;
              return (
                <article key={p.title} className="bg-[var(--bg-raised)] p-8">
                  <Icon size={20} className="accent" aria-hidden />
                  <h3 className="mt-6 text-base font-semibold text-balance">
                    {p.title}
                  </h3>
                  <p className="fg-2 mt-3 text-sm leading-relaxed">{p.body}</p>
                </article>
              );
            })}
          </div>

          <div className="grid12 mt-14 items-start">
            <div className="col-span-12 lg:col-span-5">
              <h3 className="headline text-balance">
                The alert it writes is the whole product.
              </h3>
              <p className="fg-2 mt-4 text-sm leading-relaxed">
                The person holding the invoice does not need a score. They need a
                sentence that tells them what is wrong and what to do about it —
                and the supplier&rsquo;s real phone number, the one on file with
                you, not the one the attacker put in the email.
              </p>
              <ul className="mt-8 space-y-3" role="list">
                {[
                  "It can raise a verdict. It can never talk one down.",
                  "If the AI is slow, wrong or offline, protection is unchanged.",
                  "Only the uncertain messages are read — never your mail wholesale.",
                  "Your mail never trains anyone's model. Not ours, not a vendor's.",
                ].map((line) => (
                  <li key={line} className="flex gap-3 text-sm">
                    <Check size={14} className="accent mt-0.5 shrink-0" aria-hidden />
                    <span className="fg-2">{line}</span>
                  </li>
                ))}
              </ul>
              <Link
                to="/docs#ai"
                className="accent mt-8 inline-flex items-center gap-2 text-sm underline underline-offset-4"
              >
                How the AI analyst works <ArrowRight size={13} aria-hidden />
              </Link>
            </div>
            <div className="col-span-12 mt-10 lg:col-span-6 lg:col-start-7 lg:mt-0">
              <AiVerdictDemo />
              <p className="fg-3 mono-xs mt-2">Illustrative example</p>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing */}
      {/* The shared defence network (E8) and the free scanner.
          Both were invisible outside the codebase. The network is the one part
          of this product a competitor cannot reproduce on their first day,
          because it is made of other customers' confirmations — and nothing on
          the site said it existed. The scanner needs no account and no mailbox
          access, which makes it the best top-of-funnel asset we own; it was
          commented out. */}
      <section className="border-b">
        <div className="shell py-16 md:py-24">
          <SectionHead
            label="The network"
            title="Every customer's confirmation protects every other customer."
            lede="When one business confirms that a domain is being used for fraud, every other Envelock customer is protected from it — instantly, and without anyone sharing a single message."
          />

          <div className="grid12 mt-12 items-start">
            <div className="col-span-12 lg:col-span-6">
              <NetworkNumbers />
              <p className="fg-2 mt-8 text-sm leading-relaxed">
                What crosses between businesses is a domain name, a verdict and a
                count. Never a message, never an address, never who reported it.
                It is the smallest thing that could possibly work, which is why it
                is safe to share.
              </p>
              <p className="fg-2 mt-4 text-sm leading-relaxed">
                A rule engine is copyable. Six months of other people&rsquo;s
                confirmed frauds is not — and it is why the product gets better
                for you while you do nothing.
              </p>
            </div>

            <div className="col-span-12 mt-12 lg:col-span-5 lg:col-start-8 lg:mt-0">
              <Scanner />
              <p className="fg-3 mono-xs mt-2">
                LIVE — RUNS THE REAL LOOKALIKE ENGINE
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Pricing. Unparked: the billing router is mounted unconditionally
          server-side and /billing exists in the console, so a visitor who cannot
          see a price is the only thing standing between us and revenue. */}
      <section id="pricing" className="border-b">
        <div className="shell py-16 md:py-24">
          <SectionHead
            label="Pricing"
            title="Priced so a small business can afford it."
            lede="Five people and a thousand people should not pay the same. Bigger teams pay much less per person."
          />

          <div className="bento mt-12">
            {PLANS.map((p) => (
              <div
                key={p.name}
                className={cn(
                  "col-span-12 flex flex-col p-8 md:col-span-6 lg:col-span-4",
                  p.featured && "ring-1 ring-[var(--accent)]",
                )}
              >
                <div className="flex items-baseline justify-between">
                  <h3 className="text-lg font-semibold">{p.name}</h3>
                  {p.featured && <span className="mono-xs accent">POPULAR</span>}
                </div>
                <div className="mt-6 font-mono tnum text-4xl font-semibold tracking-tight">
                  {p.price}
                </div>
                <span className="fg-3 mt-1 text-xs">{p.unit}</span>
                <p className="fg-2 mt-4 text-sm">{p.line}</p>
                <ul className="mt-7 flex-1 space-y-3" role="list">
                  {p.features.map((f) => (
                    <li key={f} className="flex gap-3 text-sm">
                      <Check size={14} className="accent mt-0.5 shrink-0" aria-hidden />
                      <span className="fg-2">{f}</span>
                    </li>
                  ))}
                </ul>
                <Link to="/signin" className="mt-8">
                  <Button variant={p.variant} className="w-full">
                    {p.cta.toUpperCase()}
                  </Button>
                </Link>
              </div>
            ))}
          </div>

          <p className="fg-3 mt-8 text-sm">
            15 days free, then billed monthly — cancel anytime. Each plan includes
            5 mailboxes; add more whenever you need them.
          </p>
        </div>
      </section>

      {/* Close */}
      <section>
        <div className="shell grid12 items-center py-16 md:py-24">
          <div className="col-span-12 lg:col-span-7">
            <h2 className="headline text-balance">
              Two ways to lose money by email. Close both today.
            </h2>
            <p className="lede mt-4">
              Works with the mail you already use — protection starts the day
              you connect.
            </p>
          </div>
          <div className="col-span-12 mt-8 lg:col-span-4 lg:col-start-9 lg:mt-0 lg:justify-self-end">
            <Link to="/signin">
              <Button variant="accent" size="lg" className="w-full sm:w-auto">
                GET STARTED FREE
                <ArrowRight size={14} aria-hidden />
              </Button>
            </Link>
          </div>
        </div>
      </section>
    </main>
  );
}

