import { useMemo } from "react";
import { Link, useLocation } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { cn } from "../components/primitives";

/* Terms, Privacy, DPA and the sub-processor list.
 *
 * The footer previously linked none of these, with a comment explaining — quite
 * correctly — that linking a placeholder is worse than linking nothing. That
 * reasoning holds only while the pages do not exist. A business asking another
 * business to hand over mailbox access, and taking a card for it, cannot do
 * either without publishing terms, a privacy notice and a processing addendum.
 *
 * The factual content here (what is processed, where, by whom, and how it is
 * secured) is written against the code and is the part engineering can attest
 * to — this file is now its only home. The contractual language around it has NOT been
 * through counsel, and the DPA page says so on its face rather than quietly.
 * Do not remove that notice on the strength of it looking unprofessional; a
 * customer's lawyer discovering it themselves is the more expensive version.
 */

const COMPANY = "Envelock, Inc.";
const CONTACT = "legal@envelock.org";
const SECURITY_CONTACT = "security@envelock.org";
const UPDATED = "20 September 2026";

function H2({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mt-12 border-b border-[var(--rule-strong)] pb-2.5 text-base font-semibold">
      {children}
    </h2>
  );
}

function H3({ children }: { children: React.ReactNode }) {
  return <h3 className="mt-8 text-sm font-semibold">{children}</h3>;
}

function P({ children }: { children: React.ReactNode }) {
  return <p className="fg-2 mt-4 text-[15px] leading-relaxed">{children}</p>;
}

function UL({ items }: { items: React.ReactNode[] }) {
  return (
    <ul className="fg-2 mt-4 space-y-2.5 text-[15px] leading-relaxed" role="list">
      {items.map((item, i) => (
        <li key={i} className="flex gap-3">
          <span className="accent mt-[0.45rem] size-1 shrink-0 rounded-full bg-current" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

function Table({ head, rows }: { head: string[]; rows: React.ReactNode[][] }) {
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
                <td key={j} className={cn("py-3 pr-4 align-top", j === 0 && "font-medium")}>
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

function DraftNotice({ children }: { children: React.ReactNode }) {
  return (
    <div className="callout mt-8 flex gap-3 px-5 py-4">
      <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden />
      <p className="text-sm leading-relaxed">{children}</p>
    </div>
  );
}

// ── Terms ────────────────────────────────────────────────────────────────────
function Terms() {
  return (
    <>
      <P>
        These terms govern your use of Envelock. By creating an account you agree
        to them on behalf of the organisation you are signing up.
      </P>

      <H2>1. What the service does</H2>
      <P>
        Envelock analyses mail in the mailboxes you connect, in order to detect
        payment fraud, impersonation, account takeover and malicious links, and
        alerts the people you nominate. It sits alongside your mail system and is
        never in the delivery path, so nothing we do can delay or lose a message.
      </P>

      <H2>2. What it does not do</H2>
      <P>
        This is the section to read twice. Envelock reduces the risk of email
        fraud; it does not eliminate it, and nothing here is a guarantee or an
        insurance policy.
      </P>
      <UL
        items={[
          "We do not guarantee that every fraudulent message will be detected. Attackers adapt, and some messages contain nothing that distinguishes them from legitimate mail.",
          "We do not guarantee that no legitimate message will be flagged.",
          "We are not your bank, your auditor or your insurer, and we do not indemnify you against a payment you choose to make.",
          "An alert is advice. The decision to pay, not to pay, or to verify by phone remains yours.",
        ]}
      />

      <H2>3. Your account</H2>
      <UL
        items={[
          "You must be a business, using an email address on a domain your organisation controls. We verify control of that domain by DNS before live mail can be connected.",
          "You are responsible for who you invite and what they can see. Admins can read every alert in the workspace.",
          "Keep your credentials secure, and turn on two-factor authentication. We strongly recommend it and will keep asking.",
          "You must have the authority to connect the mailboxes you connect. Connecting a mailbox you do not administer is a breach of these terms.",
        ]}
      />

      <H2>4. Acceptable use</H2>
      <P>
        Do not use Envelock to monitor individuals without a lawful basis, to
        analyse mailboxes you do not administer, to attack or probe the service,
        or to resell access without a written agreement. We may suspend an
        account that does, and will tell you why.
      </P>

      <H2>5. Trials, plans and payment</H2>
      <UL
        items={[
          "A trial starts when you register and runs on the top plan. When it ends the workspace drops to the free Guard tier rather than switching off — your data and your alert history stay.",
          "Paid plans bill monthly in advance through our payment processor. Each plan includes five mailboxes; additional mailboxes are billed per mailbox per month. Prices are shown before you pay.",
          "Changing your plan or number of mailboxes mid-period is pro-rated: an increase is charged for the rest of the period right away, and a reduction is credited to your next invoice.",
          "You can cancel at any time from the billing portal. Cancellation takes effect at the end of the paid period; we do not pro-rate a partial month.",
          "We will give at least 30 days' notice before a price change affects you.",
        ]}
      />

      <H2>6. Your data</H2>
      <P>
        Your mail is yours. We process it to provide the service and for nothing
        else — in particular, we do not use it to train any model, ours or a
        vendor's. The detail is in the{" "}
        <Link to="/privacy" className="accent underline underline-offset-4">
          privacy notice
        </Link>{" "}
        and the{" "}
        <Link to="/dpa" className="accent underline underline-offset-4">
          data processing addendum
        </Link>
        .
      </P>

      <H2>7. Availability</H2>
      <P>
        We aim for continuous availability and publish a{" "}
        <Link to="/status" className="accent underline underline-offset-4">
          live status page
        </Link>
        , but we do not currently offer a contractual uptime commitment. If you
        need one, raise it before you buy. Because we are never in the delivery
        path, an outage on our side stops analysis — it does not stop your mail.
      </P>

      <H2>8. Liability</H2>
      <P>
        To the fullest extent permitted by law, our total liability arising out of
        or relating to the service is limited to the fees you paid us in the
        twelve months before the claim. We are not liable for indirect or
        consequential loss, including money you transferred to a fraudulent
        account, whether or not we alerted you to it.
      </P>

      <H2>9. Ending the agreement</H2>
      <P>
        You may stop using Envelock at any time and delete your workspace from the
        dashboard. We may end the agreement for non-payment or a breach of section
        4, with notice where the circumstances allow. On termination you may
        export your data; deletion completes within 60 days.
      </P>

      <H2>10. Changes</H2>
      <P>
        We may update these terms. Material changes are announced at least 30 days
        in advance to workspace admins by email.
      </P>

      <H2>11. Contact</H2>
      <P>
        {COMPANY} — <a href={`mailto:${CONTACT}`} className="accent underline underline-offset-4">{CONTACT}</a>
      </P>

      <DraftNotice>
        These terms describe how the service actually behaves and are accurate
        against the product. They have not yet been reviewed by counsel. If you
        are procuring Envelock and need a lawyer-reviewed agreement or a signed
        MSA, contact us and we will provide one before you sign.
      </DraftNotice>
    </>
  );
}

// ── Privacy ──────────────────────────────────────────────────────────────────
function Privacy() {
  return (
    <>
      <P>
        This notice explains what Envelock does with personal data. For our
        customers we act as a <strong>processor</strong>: the organisation that
        connects a mailbox decides why, and we act on their instructions. The{" "}
        <Link to="/dpa" className="accent underline underline-offset-4">
          data processing addendum
        </Link>{" "}
        is the contractual version of this page.
      </P>

      <H2>What we process</H2>
      <Table
        head={["Data", "Why", "Kept for"]}
        rows={[
          ["Names and email addresses", "Accounts, alerts, and identifying senders", "12 months after the account closes"],
          ["Message metadata — subject, headers, authentication results", "The detections themselves", "12 months"],
          ["Message bodies", "Detecting payment fraud and malicious content", "30 days, or never in metadata-only mode"],
          ["Attachments", "Malware and lure analysis", "30 days"],
          ["Supplier bank identifiers and phone numbers", "Recognising when payment details change, and telling you who to call", "For the term"],
          ["Sign-in IP, approximate location, device fingerprint", "Detecting account takeover", "12 months"],
          ["IP and user agent of a click on a protected link", "Checking the link at the moment it is clicked", "30 days"],
          ["Alerts", "Your incident record", "24 months"],
        ]}
      />
      <P>
        We do not intentionally process special-category data. A message body may
        incidentally contain it; that is what the 30-day retention and the
        metadata-only mode are for.
      </P>

      <H2>What we never do</H2>
      <UL
        items={[
          <>
            <strong>We do not train models on your mail.</strong> Not our models,
            not a vendor's. Where the AI analyst is consulted, the provider is
            contractually bound not to train on the content either.
          </>,
          "We do not sell personal data, and we do not share it for advertising.",
          "We do not read your mail for any purpose other than detecting fraud against you.",
          "We do not put personal data in the cross-tenant fraud graph — it holds registrable domain names, a verdict and a count, and nothing else.",
        ]}
      />

      <H2>Who else sees it</H2>
      <P>
        Only the sub-processors listed on the{" "}
        <Link to="/subprocessors" className="accent underline underline-offset-4">
          sub-processors page
        </Link>
        , and several of those are engaged only when you turn the relevant
        feature on. A deployment with no AI provider, no SMS provider and no
        external reputation keys sends your data to nobody on that list except
        the hosting and payment providers.
      </P>

      <H2>Where it lives</H2>
      <P>
        Envelock currently runs in a single region, and we will tell you which one
        before you connect a mailbox. Customer-selectable regions and separate EU
        infrastructure are on the roadmap and are not in place — if you have a
        data-residency requirement, raise it before you buy rather than after.
      </P>

      <H2>Your rights</H2>
      <P>
        If your employer connected the mailbox, they are the controller and you
        should ask them first; we will assist them. You can also write to us
        directly and we will route it. Rights of access, correction, erasure,
        restriction, portability and objection apply where the law gives them to
        you, and we do not charge for a first request.
      </P>

      <H2>Security</H2>
      <P>
        Mailbox credentials are sealed with envelope encryption. Sessions are
        short-lived. Every alert and every operator action is written to an audit
        trail the customer can read. Report a vulnerability to{" "}
        <a href={`mailto:${SECURITY_CONTACT}`} className="accent underline underline-offset-4">
          {SECURITY_CONTACT}
        </a>{" "}
        — we will not pursue anyone acting in good faith.
      </P>

      <H2>Contact</H2>
      <P>
        {COMPANY} — <a href={`mailto:${CONTACT}`} className="accent underline underline-offset-4">{CONTACT}</a>
      </P>

      <DraftNotice>
        The factual content of this notice is accurate against the code. The
        formal wording has not yet been through counsel — if you need a
        lawyer-reviewed notice for a procurement process, ask and we will provide
        one.
      </DraftNotice>
    </>
  );
}

// ── DPA ──────────────────────────────────────────────────────────────────────
function Dpa() {
  return (
    <>
      <DraftNotice>
        <strong>This is a drafting aid, not a signable instrument.</strong> The
        factual sections — what is processed, where, by whom and for how long —
        are accurate against the code. The legal terms have not been reviewed by
        a lawyer. Ask us for the executed version before you sign anything.
      </DraftNotice>

      <H2>1. Roles</H2>
      <P>
        You are the <strong>controller</strong>. Envelock is the{" "}
        <strong>processor</strong>, processing personal data only on your
        documented instructions — which, for this service, means reading the
        mailboxes you connect in order to detect fraud and account takeover, and
        notifying the people you nominate.
      </P>

      <H2>2. Data subjects and categories</H2>
      <P>
        Your staff who hold Envelock logins or whose mailboxes are connected;
        senders and recipients of mail to and from those mailboxes, including
        your suppliers and their staff.
      </P>
      <P>
        Categories: names and email addresses; message metadata; message bodies
        for up to 30 days; supplier bank identifiers and contact numbers you
        supply; sign-in IP, approximate location and device fingerprints; IP and
        user agent of anyone clicking a protected link.
      </P>

      <H2>3. Duration and deletion</H2>
      <P>
        Processing lasts for the term. Retention is per class and is enforced by a
        scheduled job, not by policy alone. On termination you may export your
        data; deletion completes within 60 days.
      </P>
      <H3>Retained after workspace deletion</H3>
      <P>
        Two classes survive, and both are non-personal: the{" "}
        <strong>domain trial ledger</strong> (registrable domains only —
        permanence is the anti-abuse mechanism), and the{" "}
        <strong>cross-tenant fraud graph</strong> (registrable domain, verdict,
        count — no message, address or content).
      </P>

      <H2>4. Sub-processors</H2>
      <P>
        Listed on the{" "}
        <Link to="/subprocessors" className="accent underline underline-offset-4">
          sub-processors page
        </Link>
        . You consent to those listed. We give 30 days' notice before adding one
        that processes mailbox content.
      </P>

      <H2>5. Security</H2>
      <P>
        We will not materially decrease the security of the service during the
        term. We respond to reasonable security questionnaires.{" "}
        <strong>We do not currently hold a SOC 2 or ISO 27001 report</strong> — if
        your procurement requires one, tell us before you buy.
      </P>

      <H2>6. Personal data breach</H2>
      <P>
        We notify you without undue delay and within <strong>72 hours</strong> of
        becoming aware of a personal data breach affecting your data, with the
        nature of the breach, the categories and approximate number of records,
        likely consequences, and the measures taken.
      </P>

      <H2>7. International transfers</H2>
      <P>
        Where personal data leaves the EEA or UK, Standard Contractual Clauses
        apply. The applicable module depends on the deployment region and is
        completed before use.
      </P>

      <H2>8. Assistance</H2>
      <P>
        We assist you with data-subject requests, DPIAs and regulator
        consultations, taking into account the nature of the processing and the
        information available to us.
      </P>

      <H2>Contact</H2>
      <P>
        {COMPANY} — <a href={`mailto:${CONTACT}`} className="accent underline underline-offset-4">{CONTACT}</a>
      </P>
    </>
  );
}

// ── Sub-processors ───────────────────────────────────────────────────────────
function Subprocessors() {
  return (
    <>
      <P>
        A sub-processor is any third party that may process customer personal data
        on our behalf. This list forms part of the{" "}
        <Link to="/dpa" className="accent underline underline-offset-4">
          DPA
        </Link>
        .
      </P>
      <P>
        Several entries are <strong>conditional</strong> — they process data only
        when you or the deployment enables that feature. A deployment with no AI
        provider, no SMS provider and no external reputation keys sends customer
        data to nobody here except the hosting and payment providers.
      </P>

      <H2>Always in scope</H2>
      <Table
        head={["Sub-processor", "Purpose", "Data", "Location"]}
        rows={[
          ["Hosting provider", "Application and database hosting", "All stored data", "Named before you connect a mailbox"],
          ["Stripe, Inc.", "Payments and billing", "Billing contact email and payment metadata. Never mailbox content.", "US / global"],
        ]}
      />

      <H2>Only when the feature is enabled</H2>
      <Table
        head={["Sub-processor", "Enabled by", "Data"]}
        rows={[
          ["Microsoft (Graph API)", "You connecting a Microsoft 365 mailbox", "Mailbox content, via your own tenant"],
          ["Google (Gmail API)", "You connecting a Google Workspace mailbox", "Mailbox content, via your own tenant"],
          [
            "Anthropic or OpenAI",
            "The AI analyst being configured",
            "Sender, subject and up to 4,000 characters of body — only for messages the deterministic rules already flagged as ambiguous. Not used for training. A self-hosted model keeps this on your own infrastructure.",
          ],
          ["Google Safe Browsing", "A Safe Browsing key being set", "URL hashes only"],
          ["SMS provider", "SMS escalation being enabled", "Recipient phone number and alert title"],
          ["Geo-IP provider", "Geo-IP keys being set", "Sign-in IP addresses"],
          ["SMTP relay", "Outbound mail being configured", "Alert recipient address and alert content"],
        ]}
      />

      <H2>Not sub-processors</H2>
      <P>
        These are consulted without sending customer personal data: DNSBL zones
        (a sender's public domain name, over DNS), Certificate Transparency logs
        and RDAP (public registration data about lookalike domains), and URLhaus
        (a public feed we consume rather than query).
      </P>

      <H2>Changes</H2>
      <P>
        We give 30 days' notice before adding a sub-processor that processes
        mailbox content. Write to{" "}
        <a href={`mailto:${SECURITY_CONTACT}`} className="accent underline underline-offset-4">
          {SECURITY_CONTACT}
        </a>{" "}
        to subscribe to notifications.
      </P>
    </>
  );
}

const PAGES: Record<
  string,
  { title: string; lede: string; body: () => React.ReactNode }
> = {
  "/terms": {
    title: "Terms of service",
    lede: "What we promise, what we do not, and what happens if something goes wrong.",
    body: Terms,
  },
  "/privacy": {
    title: "Privacy notice",
    lede: "What we do with personal data, what we never do with it, and for how long.",
    body: Privacy,
  },
  "/dpa": {
    title: "Data processing addendum",
    lede: "The processor terms, for your legal and procurement teams.",
    body: Dpa,
  },
  "/subprocessors": {
    title: "Sub-processors",
    lede: "Every third party that may touch customer data, and what turns each one on.",
    body: Subprocessors,
  },
};

const NAV = Object.entries(PAGES).map(([to, p]) => ({ to, label: p.title }));

export default function Legal() {
  const { pathname } = useLocation();
  const page = useMemo(() => PAGES[pathname] ?? PAGES["/terms"], [pathname]);
  const Body = page.body;

  return (
    <main className="shell py-16 md:py-20">
      <div className="grid12">
        <nav className="col-span-12 lg:col-span-3" aria-label="Legal">
          <h2 className="sect-label">Legal</h2>
          <ul className="mt-5 space-y-2.5" role="list">
            {NAV.map((item) => (
              <li key={item.to}>
                <Link
                  to={item.to}
                  className={cn(
                    "text-sm transition-colors",
                    pathname === item.to ? "accent font-medium" : "fg-2 hover:text-[var(--fg)]",
                  )}
                >
                  {item.label}
                </Link>
              </li>
            ))}
          </ul>
          <p className="fg-3 mono-xs mt-8">UPDATED {UPDATED.toUpperCase()}</p>
        </nav>

        <article className="col-span-12 mt-12 lg:col-span-8 lg:col-start-5 lg:mt-0">
          <h1 className="headline text-balance">{page.title}</h1>
          <p className="lede mt-4">{page.lede}</p>
          <Body />
        </article>
      </div>
    </main>
  );
}
