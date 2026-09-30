import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  ArrowDown,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronRight,
  Fingerprint,
  Globe2,
  Layers3,
  Link2,
  Loader2,
  LockKeyhole,
  Mail,
  ScanLine,
  Search,
  ShieldCheck,
  Sparkles,
  Users,
  Workflow,
} from "lucide-react";
import { PLAN_TIERS } from "../lib/plans";
import { useScrollReveal } from "../lib/useScrollReveal";
import { api, auth, type ScanResult } from "../lib/api";

const EXAMPLES = [
  {
    label: "Invoice fraud",
    subject: "Updated payment details · Invoice #4471",
    sender: "accounts@northstar.example",
    quote:
      "Please use our new bank account for today’s payment. Keep this between us for now.",
    title: "A familiar sender. An unfamiliar account.",
    reason:
      "The payment details differ from the supplier record. Urgency and a request for secrecy add to the risk.",
    signals: ["Bank details changed", "Urgency + secrecy", "Supplier context"],
    action: "Call the supplier using the number you already have on file.",
  },
  {
    label: "Phishing",
    subject: "Action required: your shared document",
    sender: "notifications@document-access.example",
    quote:
      "Your invoice is ready. Sign in through the link below to prevent access from expiring.",
    title: "An invoice invitation hiding a login lure.",
    reason:
      "The message pushes you to sign in on an unrelated domain. Link checks and contextual review help expose the mismatch.",
    signals: [
      "Unrelated login domain",
      "Credential request",
      "Pressure to act",
    ],
    action:
      "Do not enter credentials. Open the service from a trusted bookmark.",
  },
  {
    label: "Impersonation",
    subject: "Quick transfer before my next meeting",
    sender: "director@northstarr.example",
    quote:
      "I need you to arrange a transfer now. I’m in a meeting, so please don’t call.",
    title: "The name looks right. The domain doesn’t.",
    reason:
      "A lookalike domain is impersonating a known business. The transfer request also discourages independent verification.",
    signals: [
      "Lookalike domain",
      "Executive impersonation",
      "Callback discouraged",
    ],
    action: "Verify the request through an established, independent channel.",
  },
];

function DetectionPreview() {
  const [active, setActive] = useState(0);
  const example = EXAMPLES[active];
  return (
    <div className="detection-preview">
      <div className="preview-top">
        <span>
          <ScanLine size={16} /> Detection preview
        </span>
        <span className="preview-example">Illustrative example</span>
      </div>
      <div
        className="preview-tabs"
        role="group"
        aria-label="Choose a detection example"
      >
        {EXAMPLES.map((e, i) => (
          <button
            key={e.label}
            aria-pressed={active === i}
            onClick={() => setActive(i)}
          >
            {e.label}
          </button>
        ))}
      </div>
      <div className="preview-message" key={example.label}>
        <div className="preview-sender">
          <span className="mail-avatar">
            <Mail size={19} />
          </span>
          <div>
            <strong>{example.subject}</strong>
            <span>{example.sender}</span>
          </div>
        </div>
        <p>“{example.quote}”</p>
      </div>
      <div className="preview-connector">
        <span />
        <Sparkles size={16} />
        <span />
      </div>
      <div className="preview-verdict" aria-live="polite">
        <div className="flex items-center justify-between gap-2">
          <span className="eyebrow">
            <Sparkles size={13} /> AI-assisted assessment
          </span>
          <span className="risk-label">High risk</span>
        </div>
        <h2 className="motion-result" key={example.title}>
          {example.title}
        </h2>
        <p>{example.reason}</p>
        <div className="signal-tags">
          {example.signals.map((s) => (
            <span key={s}>
              <Check size={11} />
              {s}
            </span>
          ))}
        </div>
        <div className="preview-action">
          <ShieldCheck size={18} />
          <div>
            <strong>Your next step</strong>
            <span>{example.action}</span>
          </div>
        </div>
      </div>
      <Link className="preview-bottom" to="/analyse">
        Try a real message in the detection lab <ArrowUpRight size={16} />
      </Link>
    </div>
  );
}

function DomainScanner() {
  const [domain, setDomain] = useState("");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function scan(event: FormEvent) {
    event.preventDefault();
    if (!domain.trim() || busy) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      setResult(await api.scanDomain(domain.trim()));
    } catch {
      setError("The scan could not complete. Check the domain and try again.");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="domain-scanner">
      <Globe2 size={26} className="accent" />
      <h3>Start with your domain.</h3>
      <p>Find potential lookalikes. No account or mailbox access required.</p>
      <form onSubmit={scan}>
        <label htmlFor="domain-scan" className="sr-only">
          Business domain
        </label>
        <input
          id="domain-scan"
          className="field"
          placeholder="yourcompany.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          maxLength={253}
          required
          autoCapitalize="none"
          spellCheck={false}
        />
        <button
          className="btn btn-accent btn-lg"
          disabled={busy || !domain.trim()}
        >
          {busy ? (
            <Loader2 size={17} className="animate-spin" />
          ) : (
            <Search size={17} />
          )}
          <span>{busy ? "Scanning…" : "Scan domain"}</span>
        </button>
      </form>
      {error && (
        <p role="alert" className="text-[var(--danger)]">
          {error}
        </p>
      )}
      {result && (
        <div className="scan-results" aria-live="polite">
          <strong>
            {result.hits.length} potential lookalikes of{" "}
            {result.protected_domain}
          </strong>
          <ul>
            {result.hits.slice(0, 5).map((hit) => (
              <li key={hit.candidate}>
                <code>{hit.candidate}</code>
                <span>
                  {hit.registered_at
                    ? "Registration found"
                    : "Registration unconfirmed"}
                </span>
              </li>
            ))}
          </ul>
          <p>
            Similarity is not proof of fraud. Registration checks are limited
            and may be unavailable.
          </p>
        </div>
      )}
    </div>
  );
}

const COVERAGE = [
  {
    icon: Workflow,
    name: "Payment & invoice fraud",
    text: "Spot changed bank details, suspicious payment requests, and hijacked supplier conversations.",
  },
  {
    icon: Link2,
    name: "Phishing & malicious content",
    text: "Inspect links, attachments, and QR-code lures. Recheck rewritten links when they’re clicked.",
  },
  {
    icon: Users,
    name: "Sender impersonation",
    text: "Get warnings about lookalike senders and people pretending to be trusted contacts.",
  },
  {
    icon: Fingerprint,
    name: "Account takeover",
    text: "Surface unusual sign-ins, forwarding rules, and unexplained mailbox access with supported integrations.",
  },
];

export default function Landing() {
  const revealRef = useScrollReveal();
  const start = auth.signedIn ? "/dashboard" : "/signup";
  return (
    <main ref={revealRef} className="marketing-page">
      <section className="hero-section">
        <div className="shell hero-grid">
          <div className="hero-copy">
            <span className="eyebrow hero-eyebrow">
              <span className="status-dot" /> AI-powered email threat detection
            </span>
            <h1>
              The email looks real.
              <br />
              <span>Know what’s behind it.</span>
            </h1>
            <p className="hero-description">
              An AI fraud analyst for your business inbox. Uncover payment
              scams, phishing, and impersonation with the context to explain the
              risk—and the next step to take.
            </p>
            <div className="hero-actions">
              <Link to={start} className="btn btn-accent btn-lg">
                {auth.signedIn
                  ? "Open your workspace"
                  : "Start protecting your team"}
                <ArrowRight size={17} />
              </Link>
              <Link to="/analyse" className="btn btn-line btn-lg">
                <ScanLine size={17} />
                Try the detection lab
              </Link>
            </div>
            <div className="hero-assurances">
              <span>
                <Check size={14} />
                15-day trial
              </span>
              <span>
                <Check size={14} />
                Keep your existing email
              </span>
              <span>
                <Check size={14} />
                Clear, actionable alerts
              </span>
            </div>
          </div>
          <DetectionPreview />
        </div>
        <div className="shell compatibility">
          <span>Built around the email you already use</span>
          <div>
            <span>
              <Mail size={19} />
              Microsoft 365
            </span>
            <span>
              <Mail size={19} />
              Google Workspace
            </span>
            <span>
              <Globe2 size={19} />
              IMAP & forwarding
            </span>
          </div>
          <a href="#protection" aria-label="Explore protection">
            <ArrowDown size={19} />
          </a>
        </div>
      </section>

      <section data-reveal id="protection" className="marketing-section shell">
        <div className="section-intro">
          <div>
            <span className="eyebrow" id="problems">
              One inbox. More than one kind of threat.
            </span>
            <h2>Look beyond the obvious.</h2>
          </div>
          <p>
            Modern email attacks borrow real names, real conversations, and
            convincing language. Envelock helps your team recognize suspicious
            requests and decide what to do next.
          </p>
        </div>
        <div className="coverage-grid">
          {COVERAGE.map(({ icon: Icon, name, text }, i) => (
            <article key={name}>
              <div className="coverage-icon">
                <Icon size={22} />
                <span>0{i + 1}</span>
              </div>
              <h3>{name}</h3>
              <p>{text}</p>
              <Link to="/docs#connect">
                Explore protection
                <ArrowUpRight size={15} />
              </Link>
            </article>
          ))}
        </div>
        <p className="coverage-note">
          <Layers3 size={15} />
          Available detections and response actions depend on your plan,
          connection permissions, and enabled services.
        </p>
      </section>

      <section data-reveal id="ai" className="ai-section">
        <div className="shell ai-grid">
          <div>
            <span className="eyebrow">Intelligence with evidence</span>
            <h2>
              AI assistance.
              <br />
              Clear next steps.
            </h2>
            <p>
              Understand suspicious payment and phishing emails with an
              AI-assisted assessment and a plain-language explanation. Review
              the evidence before you act.
            </p>
            <Link to="/docs#connect" className="text-link">
              Connect your email
              <ArrowRight size={17} />
            </Link>
          </div>
          <ol className="analysis-steps">
            <li>
              <span>01</span>
              <div>
                <h3>Connect your inbox</h3>
                <p>
                  Choose a supported connection and confirm your mailbox
                  coverage in the dashboard.
                </p>
              </div>
              <Layers3 size={21} />
            </li>
            <li>
              <span>02</span>
              <div>
                <h3>Review the warning</h3>
                <p>
                  See what needs your attention and why a request may put your
                  business at risk.
                </p>
              </div>
              <Sparkles size={21} />
            </li>
            <li>
              <span>03</span>
              <div>
                <h3>Make the next action clear</h3>
                <p>
                  See the reason for the alert. Verify a payment, investigate a
                  sender, or quarantine where supported.
                </p>
              </div>
              <ShieldCheck size={21} />
            </li>
          </ol>
        </div>
        <div className="shell ai-principles">
          <span>
            <ShieldCheck size={17} />
            Plain-language explanations
          </span>
          <span>
            <Workflow size={17} />
            Your team stays in control
          </span>
          <span>
            <ScanLine size={17} />
            Coverage shown for each mailbox
          </span>
        </div>
      </section>

      <section data-reveal className="marketing-section shell getting-started">
        <div>
          <span className="eyebrow">From inbox to insight</span>
          <h2>
            Your email.
            <br />
            An extra layer of defense.
          </h2>
          <p>
            Connect a supported provider or forward a copy. Add trusted supplier
            details, review your coverage, and bring your team into one
            workspace.
          </p>
          <div className="setup-list">
            <span>
              <Check size={17} />
              Provider-specific setup guidance
            </span>
            <span>
              <Check size={17} />
              Coverage and connection health in one place
            </span>
            <span>
              <Check size={17} />
              Supplier verification and an audit trail
            </span>
          </div>
          <Link to="/docs#connect" className="text-link">
            Find your connection options
            <ArrowRight size={16} />
          </Link>
        </div>
        <DomainScanner />
      </section>

      <section data-reveal id="pricing" className="pricing-section">
        <div className="shell marketing-section">
          <div className="section-intro">
            <div>
              <span className="eyebrow">Simple plans. Serious protection.</span>
              <h2>A safer inbox starts here.</h2>
            </div>
            <p>
              Start with domain monitoring. Add AI-assisted email protection as
              your business grows.
            </p>
          </div>
          <div className="pricing-grid">
            {[
              {
                name: "Guard",
                price: "Free",
                unit: "Domain monitoring",
                description: "An early warning for your business identity.",
                features: [
                  "Lookalike domain monitoring",
                  "Domain impersonation warnings",
                  "No mailbox connection required",
                ],
                action: "Start with Guard",
                featured: false,
              },
              ...PLAN_TIERS.map((plan) => ({
                name: plan.name,
                price: plan.price,
                unit: plan.per,
                description: plan.blurb,
                features: [
                  ...plan.features,
                  `${plan.extra}/month per additional mailbox`,
                ],
                action: `Try ${plan.name}`,
                featured: plan.id === "essential",
              })),
            ].map((plan) => (
              <article
                className={plan.featured ? "price-card featured" : "price-card"}
                key={plan.name}
              >
                <div className="flex items-center justify-between">
                  <h3>{plan.name}</h3>
                  {plan.featured && (
                    <span className="plan-recommended">Start here</span>
                  )}
                </div>
                <p>{plan.description}</p>
                <div className="price-amount">{plan.price}</div>
                <span className="price-unit">{plan.unit}</span>
                <Link
                  to={start}
                  className={`btn btn-lg ${plan.featured ? "btn-accent" : "btn-line"}`}
                >
                  {auth.signedIn ? "Open workspace" : plan.action}
                  <ArrowRight size={16} />
                </Link>
                <ul>
                  {plan.features.map((feature) => (
                    <li key={feature}>
                      <Check size={15} />
                      {feature}
                    </li>
                  ))}
                </ul>
              </article>
            ))}
          </div>
          <p className="pricing-footnote">
            Paid plans: 15-day trial, cancel anytime. Prices shown are monthly,
            for one mail domain; pay annually and save 20%. AI review is subject
            to usage limits. Identity protection requires supported provider logs
            or the Envelock sensor.
          </p>
        </div>
      </section>

      <section data-reveal className="shell marketing-section trust-section">
        <div className="trust-heading">
          <LockKeyhole size={26} />
          <h2>Trust should be inspectable.</h2>
          <p>
            Understand what connects, what gets processed, and what your team
            can control.
          </p>
        </div>
        <div className="trust-links">
          {[
            ["Security & data handling", "/docs#security"],
            ["AI processing & subprocessors", "/subprocessors"],
            ["Service status", "/status"],
          ].map(([label, url]) => (
            <Link key={url} to={url}>
              {label}
              <ArrowUpRight size={19} />
            </Link>
          ))}
        </div>
      </section>
      <section data-reveal className="closing-section">
        <div className="shell">
          <span className="eyebrow">Stay one step ahead of the request.</span>
          <h2>
            Before you click.
            <br />
            Before you pay.
          </h2>
          <Link to={start} className="btn btn-accent btn-lg">
            {auth.signedIn
              ? "Open your workspace"
              : "Get started with Envelock"}
            <ChevronRight size={18} />
          </Link>
        </div>
      </section>
    </main>
  );
}
