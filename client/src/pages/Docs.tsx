import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { Button, cn } from "../components/primitives";

/* Public documentation.
 *
 * Guiding rule: describe OUTCOMES, never mechanisms. A buyer needs to know what
 * we protect them from and how to operate the product. A competitor must not be
 * able to read this and rebuild our detection logic or learn how to evade it.
 * Anything that names a signal, threshold, comparison method or the specific
 * combination of factors we weigh stays out of here — that lives only in the
 * private codebase and PRD. */

type Section = { id: string; title: string; body: React.ReactNode };

function P({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <p className={cn("fg-2 mt-4 text-[15px] leading-relaxed", className)}>
      {children}
    </p>
  );
}

function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="mt-10 text-base font-semibold">{children}</h3>;
}

function Table({
  head,
  rows,
}: {
  head: string[];
  rows: (string | React.ReactNode)[][];
}) {
  return (
    <div className="mt-5 overflow-x-auto">
      <table className="w-full min-w-[34rem] text-sm">
        <thead>
          <tr className="border-b text-left">
            {head.map((h) => (
              <th key={h} scope="col" className="sect-label pb-3 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y">
          {rows.map((r, i) => (
            <tr key={i}>
              {r.map((cell, j) => (
                <td
                  key={j}
                  className={cn("py-3 pr-4 align-top", j === 0 && "font-medium")}
                >
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Code({ children }: { children: string }) {
  return (
    <pre className="panel mt-5 overflow-x-auto p-4 font-mono text-xs leading-relaxed">
      <code>{children}</code>
    </pre>
  );
}

const SECTIONS: Section[] = [
  {
    id: "overview",
    title: "Overview",
    body: (
      <>
        <P>
          Envelock protects businesses from email fraud and mailbox takeover. It
          works alongside your existing email — never in the delivery path — so it
          can never delay or lose a message, and an outage on our side leaves your
          mail flowing normally.
        </P>
        <P>
          It works with any mail provider. Microsoft 365 and Google connect in a
          single click; every other provider connects with one setup step. You
          keep your address, your password, your folders and your habits.
        </P>
      </>
    ),
  },
  {
    id: "protection",
    title: "What we protect against",
    body: (
      <>
        <P>
          Envelock is built for the fraud that ordinary spam filters miss —
          messages that carry no virus and no obvious bad link, and simply ask
          the right person to send money to the wrong place.
        </P>
        <H3>Financial fraud</H3>
        <P>
          We flag attempts to redirect a payment: a supplier's bank details
          changing, an invoice that doesn't add up, or pressure to pay quickly and
          quietly. When money is at risk, we give you the phone number we hold for
          that supplier so you can confirm before paying — never the number in the
          suspect email.
        </P>
        <H3>Impersonation</H3>
        <P>
          We identify senders pretending to be someone you trust — a domain one
          character off from a real one, a name that looks identical on screen, or
          a stranger continuing a conversation that was really with your supplier.
        </P>
        <H3>Compromised accounts</H3>
        <P>
          We notice when a genuine contact's account has been taken over, and when
          your own mailboxes are being accessed or altered by someone who
          shouldn't have them — including quiet changes an attacker makes to hide
          their tracks.
        </P>
        <H3>Malicious content</H3>
        <P>
          We check links and attachments for phishing and malware, including the
          techniques designed to slip past a standard email gateway.
        </P>
        <H3>Brand abuse</H3>
        <P>
          We watch the wider internet for domains registered to impersonate your
          business, and warn you the moment one is capable of sending mail in your
          name — often before it is ever used.
        </P>
        <P className="fg-3">
          We publish what we protect against, not how the detection works. The
          specific signals and how they are weighed are deliberately not
          documented, so that describing our protection never becomes a guide to
          evading it.
        </P>
      </>
    ),
  },
  {
    id: "ai",
    title: "The AI fraud analyst",
    body: (
      <>
        <P>
          Most fraud is caught by deterministic checks: they are fast, free,
          repeatable, and they never change their mind about the same message
          twice. What they are poor at is judgement — the carefully written
          invoice from a real-looking supplier that breaks no single rule badly
          enough to be certain about, but reads wrong to an experienced person.
        </P>
        <P>
          That is the gap the AI analyst fills. On the messages that land in the
          genuine grey area, it reads the email the way a wary colleague would
          and answers one question: is someone trying to move money to the wrong
          place, or harvest a login? It returns a verdict, a confidence, and one
          plain-English sentence of reasoning that is attached to the alert.
        </P>
        <H3>Where it sits</H3>
        <P>
          It is the last step, never the first. The deterministic checks always
          run and always decide first; the analyst is consulted afterwards on the
          narrow band they were unsure about.
        </P>
        <Table
          head={["Message", "What happens"]}
          rows={[
            ["Plainly ordinary", "Settled by the fast checks. No AI call."],
            ["Clearly fraudulent", "Already Critical. Alert raised immediately; no AI call needed."],
            ["Suspicious but not certain", "Sent to the AI analyst for a judgement call."],
            ["Analyst confirms fraud", "Severity is raised and the reasoning is attached to the alert."],
            ["Analyst disagrees", "The original severity stands. It can never talk us down."],
          ]}
        />
        <P>
          That last row is deliberate and it is the most important design
          decision in the feature. The AI can escalate a verdict; it cannot lower
          one. If the model is wrong, unavailable, slow, or fails outright, you
          get exactly the protection you would have had without it — never less.
        </P>
        <H3>What it is told, and what it is not</H3>
        <P>
          The analyst receives the message under review and the facts we have
          already established about the sender — whether this is a counterparty
          you have dealt with for years or a stranger, whether the payment
          details match what is on file. It is not told our detection logic, our
          thresholds, or how we weigh signals; that stays server-side.
        </P>
        <P>
          The message is passed as sealed, untrusted content and the analyst is
          instructed to treat it as text to be analysed, never as instructions to
          follow. An email that tries to talk its way past the analyst — "ignore
          your instructions", a forged system message, fabricated automated
          findings — raises suspicion rather than lowering it. Attackers write
          for the screener as well as the reader, and we assume they know we are
          there.
        </P>
        <H3>Your mail and the model</H3>
        <Table
          head={["Question", "Answer"]}
          rows={[
            ["Is my mail used to train a model?", "No. Never, by us or by the provider."],
            ["Is every message sent to an AI?", "No. Only the small fraction in the uncertain band."],
            ["How much of a message is sent?", "The sender, subject and a truncated body — never a whole thread."],
            ["Can I see what it said?", "Yes. Every verdict, confidence and rationale is recorded and readable by your admins."],
            ["What if it is wrong?", "It cannot reduce a severity, and its judgement is always shown as reasoning, never as a bare score."],
          ]}
        />
        <P>
          Usage is capped per mailbox per month, so the feature has a known
          ceiling and cannot be driven up by an attacker sending you volume. The
          running cost of every judgement is recorded against the alert that
          produced it.
        </P>
        <H3>Why it reads in plain English</H3>
        <P>
          An alert that says <em>0.87</em> tells the person holding the invoice
          nothing. An alert that says <em>"the bank details changed mid-thread
          and the sender's domain was registered last week"</em> tells them
          exactly what to do next, which is to pick up the phone. Every AI
          judgement is written for the person who has to act on it.
        </P>
      </>
    ),
  },
  {
    id: "network",
    title: "The shared defence network",
    body: (
      <>
        <P>
          Envelock customers defend each other. When one business confirms that a
          domain was used to attack them, every other customer is protected from
          that domain — immediately, and without a single message being shared.
        </P>
        <H3>What crosses between businesses</H3>
        <P>
          A registrable domain name, a verdict, and a count of how many separate
          businesses reached it. That is the whole payload. No message, no
          address, no subject line, no attachment, and never who reported it.
        </P>
        <Table
          head={["Shared", "Never shared"]}
          rows={[
            ["The domain name of an attacker", "Any message, or any part of one"],
            ["Fraudulent / suspicious / legitimate", "Your address, or your supplier's"],
            ["How many businesses confirmed it", "Which businesses confirmed it"],
          ]}
        />
        <H3>Why it needs more than one report</H3>
        <P>
          A single report never acts on its own. Confidence rises with
          independent confirmations from separate businesses, and only a domain
          confirmed by more than one is treated as actionable. A workspace has to
          have proven control of its own domain before its confirmations count at
          all — otherwise two throwaway accounts could vote any domain
          fraudulent for everybody.
        </P>
        <H3>What this means for you</H3>
        <P>
          The protection you get on your first day is the accumulated experience
          of everyone who came before you, and it improves while you do nothing.
          Confirming a fraud costs you one click you were going to make anyway,
          and it is the most useful thing any customer does for any other.
        </P>
        <P>
          The running count is on the{" "}
          <Link to="/#pricing" className="accent underline underline-offset-4">
            home page
          </Link>
          . We publish the numbers, never the names — a list of accused domains
          is a target list, and being wrong about one in public is a different
          kind of problem from being wrong about it privately.
        </P>
      </>
    ),
  },
  {
    id: "connect",
    title: "Connecting your email",
    body: (
      <>
        <P>
          Nobody changes their email program. How you connect depends on your mail
          provider, which we identify automatically from your domain. During setup
          we show your IT team the exact steps for your provider.
        </P>
        <Table
          head={["Method", "Who sets it up", "Effort", "Can remove bad mail"]}
          rows={[
            ["Microsoft 365", "Global admin", "One click", "Yes"],
            ["Google Workspace", "Super admin", "One click", "Yes"],
            ["Business mail host", "Mail administrator", "One key", "Yes"],
            ["Direct connection", "Mailbox owner", "One credential", "Yes"],
            ["Forwarding", "Mailbox owner", "One rule", "Alert only"],
          ]}
        />
        <P>
          A forwarding connection receives a copy after delivery, so it can warn
          you but cannot pull a message back. That is the only difference between
          methods, and the product shows each mailbox's exact protection level
          rather than hiding it.
        </P>
        <H3>How your credentials are protected</H3>
        <P>
          Where a connection needs a mailbox credential, it is encrypted under a
          key held in a hardware security module, decrypted only inside an isolated
          service that does nothing else, and never written to logs or returned by
          our API. Use an app-specific password wherever your provider offers one.
        </P>
      </>
    ),
  },
  {
    id: "sensor",
    title: "The Envelock sensor",
    body: (
      <>
        <P>
          Reading a mailbox tells Envelock what arrives. It does not tell it who
          else is signed in — no mail protocol does. The sensor fills that gap: a
          small add-on that runs where you actually read your mail and tells
          Envelock two things about one mailbox, and nothing else: <em>this
          device is here</em>, and <em>the owner opened this message</em>.
        </P>
        <P>
          From that, Envelock can raise the account-takeover alerts on the
          Complete plan: a sign-in from a new device or a new country, travel
          that is impossible between two sign-ins, and — the one people remember
          — a message marked as read while none of your devices were open.
        </P>
        <H3>Where it runs</H3>
        <Table
          head={["You read mail in", "Install", "What it can see"]}
          rows={[
            ["Outlook (Microsoft 365, Exchange, Outlook.com)", "The Outlook add-in — pin its pane", "The exact message you open, while the pane is pinned"],
            ["Thunderbird", "The Thunderbird add-on", "The exact message you open, whenever Thunderbird runs"],
            ["Gmail or Outlook on the web", "The browser extension", "That your webmail is open, and that you are reading"],
            ["Your provider's webmail (Roundcube and similar)", "The browser extension", "The exact message you open, on most providers"],
          ]}
        />
        <P>
          Pair a device from the dashboard: choose <b>Add a device</b> on the
          mailbox and type the short code it shows into the add-on. The code works
          once, for ten minutes. The sensor gets a key of its own that can report
          for that one mailbox and do nothing else — it cannot read your alerts,
          your mail or your settings, and removing the device in the dashboard
          switches it off immediately.
        </P>
        <H3>Silent-access alerts are yours to switch on</H3>
        <P>
          An alert for "read while none of your devices were open" is exactly
          right for a mailbox that is only read on devices with the sensor — and
          a false alarm every evening for one that is also read on a phone
          without it. Only you know which kind of mailbox it is, so this alert is
          off until you turn it on, per mailbox, once it has a device reporting.
        </P>
        <H3>What it never sends</H3>
        <P>
          Never the content of a message, never a password, nothing from any
          website other than the webmail you choose. The only identifier of a
          message it sends is the Message-ID header — a label every email already
          carries — and only where your mail program exposes it. Where it does
          not, the sensor says only that you are reading.
        </P>
        <H3>Honest limits</H3>
        <P>
          Read flags can only show the first read of mail that was sitting
          unread: re-opening a message you had already read changes nothing
          Envelock can see, and a message opened within about a minute of
          arriving may be read before it was ever seen unread. The Outlook add-in
          reports only while its pane is pinned, because Outlook gives add-ins no
          way to run in the background.
        </P>
      </>
    ),
  },
  {
    id: "alerts",
    title: "Alerts and escalation",
    body: (
      <>
        <P>
          Every alert has a severity that describes what you need to do, not how
          alarming it sounds. A product that cries wolf gets ignored, so we hold
          ourselves to a quiet inbox and treat a noisy one as a fault on our side.
        </P>
        <Table
          head={["Level", "Meaning", "How it reaches you"]}
          rows={[
            ["Critical", "Money or access at risk now", "Interrupt; bad mail removed where possible"],
            ["High", "Probable attack — act within the hour", "Push and dashboard"],
            ["Medium", "Worth a look", "Dashboard and daily digest"],
            ["Low", "Recorded for context", "No notification"],
          ]}
        />
        <H3>Reaching the right people</H3>
        <P>
          Alerts never depend on the mailbox being protected. Notifications run in
          our own systems and, for serious alerts, go to a separate address you
          register at setup — so a compromised inbox cannot suppress the warning
          about itself.
        </P>
        <Table
          head={["When", "Who is told"]}
          rows={[
            ["Immediately", "You and your IT team, in-app and by push"],
            ["Serious alerts", "Also emailed to your registered backup address"],
            ["Not acknowledged in 15 min", "Escalated to your IT admin"],
            ["Not acknowledged in 60 min", "Escalated to all admins, plus SMS"],
          ]}
        />
        <P>
          Escalation is driven by whether someone has acknowledged the alert, not
          by whether a message was delivered — reaching a device proves nothing
          about a person having seen it.
        </P>
        <H3>Your month, once a month</H3>
        <P>
          Workspace admins get a monthly summary: what was caught, what it was
          worth, and one plain-English line on each of the serious ones. Where a
          payment-fraud alert named a sum, we record it, and the summary reports
          what was stopped from leaving — per currency, counting only the
          incidents your own team confirmed, and saying out loud how many carried
          no figure.
        </P>
        <P>
          A month with nothing in it does not produce an email. A digest that
          arrives to report nothing is an advert, and it teaches people to filter
          the sender — which is how the next one, about a real fraud, ends up
          unread.
        </P>
      </>
    ),
  },
  {
    id: "dashboard",
    title: "For IT teams",
    body: (
      <>
        <P>
          Administrators see every alert across every mailbox on the domain, with
          a record of who read each one, who acted, and who ignored it — so a
          warning that a single user dismisses is never lost.
        </P>
        <H3>Roles</H3>
        <Table
          head={["Role", "Can see and do"]}
          rows={[
            ["Owner", "Everything, including billing and account deletion"],
            ["Admin", "Every mailbox, the full alert history and audit trail"],
            ["Member", "Their own mailbox only"],
          ]}
        />
        <P>
          Every account is offered multi-factor authentication at sign-up and we
          strongly recommend it, but you can defer it and turn it on later from
          your profile. Envelock's own staff console does not allow that: an
          operator cannot reach it without an authenticator enrolled.
        </P>
        <P>
          Single sign-on (SAML/OIDC) and SCIM provisioning are not available yet.
          If your procurement process requires them, tell us — it changes what we
          build next.
        </P>
        <H3>Coverage transparency</H3>
        <P>
          Each mailbox displays its protection level and names anything that isn't
          active for it. You will never believe a mailbox is fully covered when it
          is not.
        </P>
      </>
    ),
  },
  {
    id: "api",
    title: "API",
    body: (
      <>
        <P>
          REST over HTTPS, JSON in and out. Authentication is a bearer token.
          Multi-factor authentication is offered on every account and can be
          deferred; refresh tokens rotate on use, so a stolen one is caught and
          every session for that user is ended.
        </P>
        <Code>{`POST /api/v1/auth/login
{ "email": "you@acme.com", "password": "..." }

→ { "mfa_required": true, "mfa_token": "..." }

POST /api/v1/auth/mfa/verify
{ "mfa_token": "...", "code": "123456" }

→ { "access_token": "...", "refresh_token": "...", "expires_in": 900 }`}</Code>
        <H3>Common endpoints</H3>
        <Table
          head={["Method", "Path", "Purpose"]}
          rows={[
            ["POST", "/api/v1/domains/scan", "Lookalike domains for a domain"],
            ["GET", "/api/v1/domains/{d}/connect", "Setup steps for that provider"],
            ["GET", "/api/v1/coverage", "A mailbox's protection level"],
            ["POST", "/api/v1/pricing/quote", "Price for a given seat mix"],
            ["GET", "/api/v1/retention/schedule", "Data retention policy"],
          ]}
        />
        <H3>Rate limits</H3>
        <P>
          Endpoints are rate limited, and sign-in is protected by account lockout
          with an increasing backoff. Exceeding a limit returns{" "}
          <code className="font-mono">429</code> with a{" "}
          <code className="font-mono">Retry-After</code> header.
        </P>
      </>
    ),
  },
  {
    id: "integrations",
    title: "Export and SIEM",
    body: (
      <>
        <P>
          Alerts are worth more inside the tools your security team already
          watches. Administrators can export in four formats.
        </P>
        <Table
          head={["Format", "Endpoint", "Use"]}
          rows={[
            ["CSV", "/api/v1/export/alerts.csv", "Audit and review"],
            ["JSON Lines", "/api/v1/export/alerts.jsonl", "Log pipelines"],
            ["CEF", "/api/v1/export/alerts.cef", "ArcSight, Splunk, QRadar, Sentinel"],
            ["Syslog", "?syslog=true", "RFC 5424 framing"],
          ]}
        />
        <H3>Webhooks</H3>
        <P>
          Deliveries are signed with HMAC-SHA256 over the timestamp and body, so a
          captured payload cannot be replayed later. Verify before trusting, and
          reject anything whose timestamp is more than five minutes from now:
        </P>
        <Code>{`signed   = f"{timestamp}.".encode() + raw_body
expected = "v1=" + hmac.new(secret, signed, sha256).hexdigest()

hmac.compare_digest(expected, received_signature)`}</Code>
      </>
    ),
  },
  {
    id: "data",
    title: "Data handling",
    body: (
      <>
        <P>
          Retention is set per type of data, and deletion is something we can
          demonstrate rather than merely promise.
        </P>
        <Table
          head={["Data", "Kept for", "Note"]}
          rows={[
            ["Message contents", "30 days", "Not stored at all in metadata-only mode"],
            ["Attachments", "30 days", "Stored once even when sent to many people"],
            ["Message summaries", "12 months", "No message content"],
            ["Sign-in and audit records", "12 months", "Access history"],
            ["Alerts", "24 months", "Your incident record"],
          ]}
        />
        <P>
          If you cancel, there is a 30-day grace period followed by full deletion
          within 60 days. We keep only aggregate billing totals, which contain no
          personal data.
        </P>
        <H3>Metadata-only mode</H3>
        <P>
          For organisations that require it, message contents and attachments are
          never stored — only the summary information needed to detect fraud.
          Protection runs in full; nothing sensitive is kept afterwards.
        </P>
        <H3>Where your data lives</H3>
        <P>
          Today Envelock runs in a single region and we will tell you which one
          before you connect a mailbox. Customer-selectable regions and separate
          EU infrastructure are on the roadmap, not in place — if you have a data
          residency requirement, raise it before you buy rather than after.
        </P>
        <P>
          We will sign a data-processing agreement on request. Ask and we will
          send the current version.
        </P>
      </>
    ),
  },
  {
    id: "security",
    title: "Our own security",
    body: (
      <>
        <P>
          A service trusted with email access for many businesses has to hold
          itself to a higher standard than the companies it protects. These
          controls apply to us.
        </P>
        <Table
          head={["Area", "Control"]}
          rows={[
            ["Sign-in", "Multi-factor authentication available to every account; required for Envelock staff"],
            ["Sessions", "Short-lived tokens; refresh reuse is detected and ends every session"],
            ["Brute force", "Rate limiting and per-account lockout on sign-in"],
            ["Stored credentials", "Envelope encryption; on our hosted service the decryption key is held only by the worker, so the internet-facing API cannot read a stored mailbox password"],
            ["Separation", "Every customer's data is scoped and re-checked on each request"],
            ["Mail transport", "IMAP certificates are verified; we refuse to fall back to an unencrypted session"],
            ["Transport", "Enforced HTTPS, strict browser security policy"],
          ]}
        />
        <P>
          We hold ourselves to published quality targets — a very low rate of false
          alarms on the most serious alerts, and high accuracy on payment fraud —
          and every serious false alarm is formally reviewed.
        </P>
        <P className="fg-3">
          What we do not have yet, stated plainly because you should not have to
          ask: no SOC 2 or ISO 27001 certification, no third-party penetration
          test report we can hand you, and no SSO or SCIM. We have run our own
          adversarial testing against the live product and fixed what it found.
          If a control here is a condition of your purchase, ask us for the
          current status rather than assuming it.
        </P>
      </>
    ),
  },
];

export default function Docs() {
  const [active, setActive] = useState(SECTIONS[0].id);
  const [navOpen, setNavOpen] = useState(false);
  const ids = useMemo(() => SECTIONS.map((s) => s.id), []);

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      { rootMargin: "-80px 0px -70% 0px" },
    );
    ids.forEach((id) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });
    return () => observer.disconnect();
  }, [ids]);

  return (
    <main className="shell py-10 md:py-14">
      <div className="grid12">
        <aside className="col-span-12 lg:col-span-3">
          <button
            onClick={() => setNavOpen((v) => !v)}
            aria-expanded={navOpen}
            className="panel fg-2 flex w-full items-center justify-between px-4 py-3 text-sm font-medium lg:hidden"
          >
            Contents
            {navOpen ? <X size={16} aria-hidden /> : <Menu size={16} aria-hidden />}
          </button>

          <nav
            aria-label="Documentation"
            className={cn("lg:sticky lg:top-24 lg:block", navOpen ? "block" : "hidden")}
          >
            <p className="sect-label hidden lg:block">Contents</p>
            <ul className="mt-4 space-y-1" role="list">
              {SECTIONS.map((s) => (
                <li key={s.id}>
                  <a
                    href={`#${s.id}`}
                    onClick={() => setNavOpen(false)}
                    className={cn(
                      "block border-l py-1.5 pl-3 text-sm transition-colors",
                      active === s.id
                        ? "accent border-[var(--accent)] font-medium"
                        : "fg-2 border-[var(--rule)] hover:text-[var(--fg)]",
                    )}
                  >
                    {s.title}
                  </a>
                </li>
              ))}
            </ul>

            <div className="mt-8 hidden border-t pt-6 lg:block">
              <Link to="/analyse">
                <Button variant="line" size="sm" className="w-full">
                  TRY THE SANDBOX
                  <ArrowUpRight size={13} aria-hidden />
                </Button>
              </Link>
            </div>
          </nav>
        </aside>

        <div className="col-span-12 mt-8 lg:col-span-8 lg:col-start-5 lg:mt-0">
          <header>
            <div className="flex items-center gap-3">
              <span className="h-px w-8 bg-[var(--accent)]" aria-hidden />
              <span className="sect-label">Documentation</span>
            </div>
            <h1 className="headline mt-4">How Envelock works</h1>
            <p className="lede mt-4">
              What we protect you from, how to connect your email, how alerts reach
              your team, and how your data is handled.
            </p>
          </header>

          <div className="mt-14 space-y-16">
            {SECTIONS.map((s) => (
              <section key={s.id} id={s.id} className="scroll-mt-24">
                <h2 className="border-b pb-3 text-xl font-bold">{s.title}</h2>
                {s.body}
              </section>
            ))}
          </div>

          <footer className="mt-16 border-t pt-8">
            <p className="fg-3 text-sm">
              Questions this doesn't answer? Talk to us — technical detail beyond
              this page is shared with customers under NDA.
            </p>
          </footer>
        </div>
      </div>
    </main>
  );
}
