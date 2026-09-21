import { useState } from "react";
import { Loader2, PhoneCall, Play, ShieldOff } from "lucide-react";
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
  const [raw, setRaw] = useState(SAMPLES.bankChange.body);
  const [ctx, setCtx] = useState<Partial<Ctx>>(SAMPLES.bankChange.ctx);
  const [active, setActive] = useState("bankChange");
  const [result, setResult] = useState<AnalyseResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function pick(key: string) {
    setActive(key);
    setRaw(SAMPLES[key].body);
    setCtx(SAMPLES[key].ctx);
    setResult(null);
    setError(null);
  }

  async function run() {
    setLoading(true);
    setError(null);
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
      setError("We couldn't run the scan just now. Please try again in a moment.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="shell py-12 md:py-16">
      <SectionHead
        label="Detection sandbox"
        title="Run the detection suite on a real message"
        lede="Paste any raw email, or pick one of the scenarios below. The engine runs exactly as it does in production."
      />

      <div className="mt-8 flex flex-wrap gap-2">
        {Object.entries(SAMPLES).map(([key, s]) => (
          <button
            key={key}
            onClick={() => pick(key)}
            className={cn(
              "cursor-pointer border px-3.5 py-2.5 text-left text-sm transition-colors",
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
          <div className="flex items-center justify-between border-b px-5 py-3">
            <label htmlFor="raw" className="text-sm font-semibold">
              Raw message
            </label>
            <span className="fg-3 text-xs">Mailbox: pay@acme.com</span>
          </div>
          <textarea
            id="raw"
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            spellCheck={false}
            className="font-mono bg-base min-h-[26rem] flex-1 resize-y p-5 text-xs leading-relaxed outline-none"
          />
          <div className="flex items-center gap-3 border-t px-5 py-4">
            <Button onClick={run} disabled={loading} variant="accent">
              {loading ? (
                <>
                  <Loader2 size={15} className="animate-spin" aria-hidden />{" "}
                  Analysing
                </>
              ) : (
                <>
                  <Play size={15} aria-hidden /> Analyse
                </>
              )}
            </Button>
            {ctx.counterparty_known_bank_ids && (
              <span className="fg-3 text-xs">
                Known account on file: {ctx.counterparty_known_bank_ids[0]}
              </span>
            )}
          </div>
        </div>

        <div className="space-y-4">
          {error && (
            <div className="panel border-[var(--danger)] p-5">
              <p role="alert" className="text-sm text-[var(--danger)]">
                {error}
              </p>
            </div>
          )}

          {!result && !error && (
            <div className="panel p-8">
              <p className="fg-3 text-sm">
                Results appear here. Findings are individual detections; the
                assessment is what the customer actually sees.
              </p>
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
                <span className="fg-3 tnum text-xs">
                  score {result.assessment.score}/100
                </span>
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
                An ordinary email produces no alert. Products that cry wolf get
                muted, and a muted alert is worse than no alert.
              </p>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
