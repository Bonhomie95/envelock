import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  FlaskConical,
  Loader2,
  PhoneCall,
  Play,
  ShieldCheck,
  ShieldOff,
} from "lucide-react";
import { api, type AnalyseResult } from "../lib/api";
import { Button, SectionHead, TierChip, cn } from "../components/primitives";

const SAMPLES: Record<
  string,
  { label: string; hint: string; body: string; ctx: Partial<Ctx> }
> = {
  bankChange: {
    label: "Supplier changes bank details",
    hint: "The attack that actually takes the money",
    body: `From: "Gemini Accounts" <billing@gemini.com>
To: pay@acme.com
Subject: Re: Invoice 4471
Message-ID: <new@gemini.com>
In-Reply-To: <old@gemini.com>
References: <old@gemini.com>
Content-Type: text/plain

Hello,

Please note our bank account has changed. Kindly remit payment for
invoice 4471 to our new account:

IBAN: GB33BUKB20201555555555
Bank: Barclays

This is urgent, we need it today. Please keep this confidential.

Regards,
Gemini Accounts`,
    ctx: {
      counterparty_message_count: 47,
      counterparty_known_bank_ids: ["GB94BARC10201530093459"],
      counterparty_phone: "+1 803 000 0000",
    },
  },
  lookalike: {
    label: "Lookalike domain",
    hint: "gemini-invoices.com, replies redirected elsewhere",
    body: `From: "Gemini Ltd" <billing@gemini-invoices.com>
To: pay@acme.com
Subject: Updated payment instructions
Reply-To: finance@gemini-pay.net
Content-Type: text/plain

Kindly update our records. New account details below.

IBAN GB33BUKB20201555555555

Please treat as urgent and confidential.`,
    ctx: {},
  },
  hijack: {
    label: "Thread hijacking",
    hint: "Presents as a reply but has no thread chain",
    body: `From: <accounts@gemini.com>
To: pay@acme.com
Subject: Re: Purchase Order 8891
Content-Type: text/plain

Following up on the below — please send the payment to the account
provided earlier today.`,
    ctx: {},
  },
  phishing: {
    label: "Phishing link",
    hint: "A login-stealing link — the address behind the words is a bare IP",
    body: `From: "IT Helpdesk" <alerts@gemini.com>
To: admin@acme.com
Subject: Action required: verify your mailbox
Content-Type: text/plain

Your mailbox will be suspended within 24 hours. Verify now to keep access:

http://203.0.113.10/account-verify?u=admin

Thank you,
IT Helpdesk`,
    ctx: {},
  },
  identicalSender: {
    label: "Identical sender, wrong address",
    hint: "Looks exactly like the real vendor — but the address isn't theirs",
    body: `From: "Gemini Accounts" <billing@secure-mail-portal.example>
To: pay@acme.com
Subject: Invoice 9001
Content-Type: text/plain

Hello,

Please find Invoice 9001 attached. Kindly remit as usual.

Regards,
Gemini Accounts`,
    ctx: { counterparty_message_count: 47 },
  },
  clean: {
    label: "Ordinary email",
    hint: "Should produce nothing. Silence is a feature.",
    body: `From: <sara@gemini.com>
To: pay@acme.com
Subject: Lunch Thursday?
Content-Type: text/plain

Are you free around 1pm on Thursday?`,
    ctx: { counterparty_message_count: 47 },
  },
};

interface Ctx {
  counterparty_message_count: number;
  counterparty_known_bank_ids: string[];
  counterparty_phone: string | null;
}

export default function Analyse() {
  const resultsRef = useRef<HTMLDivElement>(null);
  const [raw, setRaw] = useState(SAMPLES.bankChange.body);
  const [ctx, setCtx] = useState<Partial<Ctx>>(SAMPLES.bankChange.ctx);
  const [active, setActive] = useState("bankChange");
  const [result, setResult] = useState<AnalyseResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (result || error) resultsRef.current?.focus();
  }, [result, error]);

  function pick(key: string) {
    setActive(key);
    setRaw(SAMPLES[key].body);
    setCtx(SAMPLES[key].ctx);
    setResult(null);
    setError(null);
  }

  async function run() {
    if (loading || !raw.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(
        await api.analyse({
          raw_message: raw,
          owned_domains: ["acme.com"],
          known_counterparties: ["gemini.com"],
          source: "imap_idle",
          ...ctx,
        }),
      );
    } catch {
      setError(
        "We couldn't run the scan just now. Please try again in a moment.",
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="shell detection-lab py-10 md:py-14">
      <div className="lab-heading">
        <span className="lab-icon">
          <FlaskConical size={25} />
        </span>
        <SectionHead
          as="h1"
          label="The detection lab"
          title="Put a suspicious email to the test."
          lede="Explore a sample attack or paste a raw email. Get the evidence, the risk assessment, and a practical next step."
        />
      </div>
      <div className="lab-notice">
        <ShieldCheck size={19} />
        <p>
          <strong>A limited preview of email analysis.</strong> This lab does
          not include AI review, live threat lookups, or your connected
          mailbox’s history. Sample supplier records are illustrative. Use
          synthetic or redacted messages.
        </p>
      </div>

      <div className="mt-8 flex flex-wrap gap-2">
        {Object.entries(SAMPLES).map(([key, s]) => (
          <button
            key={key}
            onClick={() => pick(key)}
            disabled={loading}
            aria-pressed={active === key}
            className={cn(
              "lab-scenario flex-1 cursor-pointer rounded-lg border px-4 py-3 text-left text-sm transition-colors disabled:opacity-60",
              active === key
                ? "border-[var(--accent)] accent"
                : "fg-2 hover:bg-[var(--bg-hover)]",
            )}
          >
            <span className="block font-semibold">{s.label}</span>
            <span className="fg-3 block text-xs">{s.hint}</span>
          </button>
        ))}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <div className="panel flex flex-col overflow-hidden">
          {/* The run button lives in the header: at the foot of a 26rem
              textarea it sat below the fold on a laptop, while the results
              appear at the top of the other column. */}
          <div className="flex items-center justify-between gap-3 border-b px-5 py-2.5">
            <div className="min-w-0">
              <label htmlFor="raw" className="text-sm font-semibold">
                Raw message
              </label>
              <span className="fg-3 ml-2 text-xs">to pay@acme.com</span>
            </div>
            <Button
              onClick={run}
              disabled={loading || !raw.trim()}
              variant="accent"
              size="sm"
            >
              {loading ? (
                <>
                  <Loader2 size={14} className="animate-spin" aria-hidden />{" "}
                  ANALYSING
                </>
              ) : (
                <>
                  <Play size={14} aria-hidden /> ANALYSE
                </>
              )}
            </Button>
          </div>
          <textarea
            id="raw"
            value={raw}
            onChange={(e) => {
              setRaw(e.target.value);
              setActive("custom");
              setCtx({});
              setResult(null);
              setError(null);
            }}
            disabled={loading}
            spellCheck={false}
            className="font-mono bg-base min-h-[23rem] flex-1 resize-y p-5 text-xs leading-relaxed focus-visible:outline-2 focus-visible:outline-[var(--accent)]"
          />
          {ctx.counterparty_known_bank_ids && (
            <div className="border-t px-5 py-3">
              <span className="fg-3 text-xs">
                Known account on file: {ctx.counterparty_known_bank_ids[0]}
              </span>
            </div>
          )}
        </div>

        <div
          ref={resultsRef}
          tabIndex={-1}
          aria-label="Analysis results"
          className="space-y-4 scroll-mt-24"
          aria-live="polite"
          aria-busy={loading}
        >
          {error && (
            <div className="panel border-[var(--danger)] p-5">
              <p role="alert" className="text-sm text-[var(--danger)]">
                {error}
              </p>
            </div>
          )}

          {!result && !error && (
            <div className="panel lab-empty p-8">
              {loading ? (
                <Loader2 size={30} className="accent animate-spin" />
              ) : (
                <ScanResultIcon />
              )}
              <h2>
                {loading
                  ? "Inspecting the message…"
                  : "The evidence belongs here."}
              </h2>
              <p>
                Run the scan to see the warning signs, why the message is
                suspicious, and what to do next.
              </p>
              <div>
                <span>Message</span>
                <ArrowRight size={14} />
                <span>Signals</span>
                <ArrowRight size={14} />
                <span>Assessment</span>
              </div>
            </div>
          )}

          {result?.assessment && (
            <div
              className={cn(
                "panel rise p-6",
                result.assessment.tier === "critical" &&
                  "ring-1 ring-[var(--danger)]",
              )}
            >
              <div className="flex items-center justify-between gap-3">
                <TierChip tier={result.assessment.tier} blink />
              </div>
              <h3 className="mt-4 text-lg font-bold text-balance">
                {result.assessment.title}
              </h3>

              {result.assessment.rationale.length > 0 && (
                <ul className="mt-4 space-y-1.5 border-t pt-4" role="list">
                  {result.assessment.rationale.map((r) => (
                    <li key={r} className="fg-2 text-sm leading-relaxed">
                      {r}
                    </li>
                  ))}
                </ul>
              )}

              {result.assessment.requires_callback && (
                <div className="callout mt-5 border p-4">
                  <div className="flex items-start gap-2.5">
                    <PhoneCall
                      size={16}
                      className="mt-0.5 shrink-0"
                      aria-hidden
                    />
                    <div>
                      <p className="text-sm font-bold">
                        Verify by phone before paying
                      </p>
                      <p className="mt-1 text-sm opacity-90">
                        Call{" "}
                        <span className="tnum font-semibold">
                          {result.assessment.callback_phone ??
                            "the number on file"}
                        </span>
                        {" — "}the number on record with us, never the one in
                        this email.
                      </p>
                    </div>
                  </div>
                </div>
              )}

              {!result.message.remediable && (
                <p className="fg-3 mt-4 flex items-center gap-2 text-xs">
                  <ShieldOff size={13} aria-hidden />
                  This source cannot quarantine — alert only.
                </p>
              )}
            </div>
          )}

          {result && result.findings.length > 0 && (
            <div className="panel overflow-hidden">
              <p className="border-b px-5 py-3 text-sm font-semibold">
                {result.findings.length} finding
                {result.findings.length === 1 ? "" : "s"}
              </p>
              <ul className="divide-y" role="list">
                {result.findings.map((f, i) => (
                  <li
                    key={`${f.service}-${i}`}
                    className="rise p-5"
                    style={{ animationDelay: `${i * 50}ms` }}
                  >
                    {/* Internal detection codes (A1, C11, …) are deliberately
                        withheld from anonymous callers server-side (PRD §16) —
                        the plain-English category and finding convince a visitor
                        without handing a competitor our taxonomy. */}
                    <div className="flex items-center gap-2">
                      <TierChip tier={f.tier} />
                      {f.category && (
                        <span className="fg-2 text-xs font-medium uppercase tracking-wide">
                          {f.category}
                        </span>
                      )}
                    </div>
                    <p className="mt-2.5 text-sm leading-relaxed">
                      {f.summary}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result && result.findings.length === 0 && (
            <div className="panel p-8">
              <p className="text-sm font-semibold">Nothing detected.</p>
              <p className="fg-2 mt-2 text-sm leading-relaxed">
                No warning was found in this preview. This is not a guarantee
                that the message or its links are safe. Connected-mailbox
                history, reputation checks, and AI review can add evidence
                outside this lab.
              </p>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}

function ScanResultIcon() {
  return <ShieldCheck size={30} className="accent" aria-hidden />;
}
