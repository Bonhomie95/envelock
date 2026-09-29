import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, Menu, X } from "lucide-react";
import { Button, cn } from "../components/primitives";

/* Public setup and administration guide.
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
                  className={cn(
                    "py-3 pr-4 align-top",
                    j === 0 && "font-medium",
                  )}
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

const SECTIONS: Section[] = [
  {
    id: "overview",
    title: "Before you start",
    body: (
      <>
        <P>
          Have your company domain, work email address, and access to your
          domain’s DNS settings ready. Ask your mail administrator to help if
          you cannot approve provider permissions or change mailbox settings.
        </P>
        <P>
          Create your workspace, confirm your email, and add the DNS
          verification record shown during setup. Copy the exact name and value
          provided, then return to Envelock to check verification.
        </P>
        <P>
          Once your domain is verified, open the dashboard’s Mailboxes tab and
          add the addresses you want to protect. Adding an address does not
          connect it; complete a connection for each mailbox and check its
          coverage.
        </P>
      </>
    ),
  },
  {
    id: "connect",
    title: "Connect your email",
    body: (
      <>
        <P>
          Choose an available connection in your workspace. Keep using your
          existing email address and mail application. Available actions depend
          on your plan, provider, and approved permissions.
        </P>
        <Table
          head={["Connection", "What you need", "Setup"]}
          rows={[
            [
              "Microsoft 365",
              "An administrator who can approve the requested permissions",
              "Select Microsoft when offered and complete authorization on Microsoft’s sign-in page.",
            ],
            [
              "Google Workspace",
              "A Workspace administrator who can approve the requested access",
              "Select Google when offered and follow the provider-specific setup instructions.",
            ],
            [
              "IMAP",
              "Server hostname, security setting, username, and mailbox credential",
              "Choose Connect via IMAP and enter the settings supplied by your mail provider.",
            ],
            [
              "Forwarding",
              "Permission to create a forwarding rule",
              "Use the destination generated for that mailbox in Envelock and keep a copy in your inbox.",
            ],
          ]}
        />
        <P>
          If your provider’s connection option is unavailable, use a supported
          alternative shown in your workspace or{" "}
          <Link to="/contact" className="accent underline underline-offset-4">
            contact support
          </Link>
          . Do not share your provider password by email or chat.
        </P>
        <H3>IMAP server settings</H3>
        <Table
          head={["Setting", "What to enter"]}
          rows={[
            ["Hostname", "Your provider’s IMAP hostname, not its webmail URL."],
            [
              "Username",
              "Usually your full mailbox address; confirm with your provider.",
            ],
            ["SSL/TLS", "Normally port 993, when supported by your provider."],
            ["STARTTLS", "Normally port 143, when supported by your provider."],
            [
              "Credential",
              "Use a dedicated app password if your provider offers one. Your Envelock sign-in password is separate.",
            ],
          ]}
        />
        <P>
          IMAP must be enabled for the mailbox. The server must be reachable
          from Envelock and present a valid certificate for its hostname. Ask
          your IT team about firewall restrictions; do not disable certificate
          checks or use an unencrypted connection.
        </P>
        <H3>Forwarding</H3>
        <P>
          Copy the forwarding destination from the mailbox’s setup screen.
          Create the rule with your mail provider, complete any provider
          verification, and keep the original message in your inbox. Forwarded
          copies allow alerts but do not let Envelock remove the original
          message.
        </P>
        <H3>Confirm the connection</H3>
        <P>
          Return to Mailboxes and check the connection status and coverage
          details. Resolve any missing permissions or connection warnings before
          relying on that mailbox’s protection. Quarantine and other response
          actions are available only where the connection supports them.
        </P>
      </>
    ),
  },
  {
    id: "troubleshooting",
    title: "Connection troubleshooting",
    body: (
      <>
        <Table
          head={["Problem", "What to check"]}
          rows={[
            [
              "Domain verification is pending",
              "Confirm the DNS record name and value match the setup screen. Allow time for DNS changes to become visible, then retry.",
            ],
            [
              "Sign-in or consent is rejected",
              "Use the correct business account and ask your provider administrator to review the requested permissions.",
            ],
            [
              "IMAP authentication fails",
              "Check the username, ensure IMAP is enabled, and generate a fresh app password if required by your provider.",
            ],
            [
              "Server cannot be reached",
              "Check the hostname, port, TLS mode, and firewall policy with your mail administrator.",
            ],
            [
              "Certificate error",
              "Ask your provider to correct the certificate or supply the correct hostname. Do not bypass the warning.",
            ],
            [
              "Forwarded messages are missing",
              "Check the forwarding destination, rule scope, and your provider’s external-forwarding policy.",
            ],
            [
              "Previously connected mailbox needs attention",
              "Review its status, renew authorization or update the app password, then recheck coverage.",
            ],
          ]}
        />
        <P>
          When contacting support, include the affected mailbox, connection
          method, time of the failure, and the displayed error. Redact
          passwords, authorization codes, tokens, and message contents.
        </P>
      </>
    ),
  },
  {
    id: "sensor",
    title: "Set up the Envelock sensor",
    body: (
      <>
        <P>
          If your plan and workspace offer the sensor, install it on the devices
          where you read business email. Use the download and pairing
          instructions shown in the dashboard.
        </P>
        <Table
          head={["Mail application", "Setup"]}
          rows={[
            [
              "Outlook",
              "Install the Outlook add-in and keep its pane pinned while using it.",
            ],
            ["Thunderbird", "Install the Thunderbird add-on."],
            [
              "Supported webmail",
              "Install the browser extension and enable it only for the webmail sites you use.",
            ],
          ]}
        />
        <P>
          Choose Add a device for the mailbox, enter the displayed pairing code
          in the add-on, and confirm the device appears in your workspace. If
          the code expires, request a new one. Remove devices you no longer use.
        </P>
        <P>
          Review all ways the mailbox is accessed, including phones and shared
          devices, before enabling optional silent-access alerts. Follow the
          coverage guidance shown for that mailbox to avoid unnecessary
          warnings.
        </P>
      </>
    ),
  },
  {
    id: "alerts",
    title: "Review and respond to alerts",
    body: (
      <>
        <P>
          Open the alert queue, review the evidence and recommended action, and
          prioritize Critical and High alerts. Acknowledge alerts your team is
          handling and record the outcome after investigation.
        </P>
        <P>
          For payment requests, verify changes using an established supplier
          contact. Do not rely on a phone number or link supplied in the
          suspicious message. Keep supplier contact details current.
        </P>
        <P>
          Configure the notification options available in your workspace and
          keep administrator and backup contact details up to date. Quarantine
          is available only with supported connections and permissions.
        </P>
      </>
    ),
  },
  {
    id: "dashboard",
    title: "IT administration",
    body: (
      <>
        <Table
          head={["Role", "Access"]}
          rows={[
            [
              "Owner",
              "Workspace administration, billing, and account management.",
            ],
            [
              "Admin",
              "Workspace mailbox management, alerts, and administrative tools.",
            ],
            ["Member", "Access assigned to their own mailbox."],
          ]}
        />
        <P>
          Grant administrative access only to the people who need it. Enable
          two-factor authentication, store recovery codes securely, and review
          team membership when staff join, change roles, or leave.
        </P>
        <P>
          Check mailbox coverage regularly and after any provider permission,
          password, or mail-server change. Remove unused connections and revoke
          the corresponding access with your provider when offboarding.
        </P>
        <P>
          SSO and SCIM provisioning are not currently available. If either is
          required by your IT policy, discuss that requirement before rollout.
        </P>
      </>
    ),
  },
  {
    id: "integrations",
    title: "Exports and SIEM",
    body: (
      <>
        <P>
          Administrators can export alert records for review and supported
          security tools. Available formats include CSV, JSON Lines, and CEF,
          with syslog framing where supported.
        </P>
        <P>
          For an API, SIEM, or webhook integration, contact support with the
          destination system and required format. Request the applicable
          connection and signature-verification instructions before enabling
          ingestion. Keep integration credentials private and restrict access to
          exported records.
        </P>
      </>
    ),
  },
  {
    id: "data",
    title: "Privacy and procurement",
    body: (
      <>
        <P>
          Before connecting mailboxes, review the{" "}
          <Link to="/privacy" className="accent underline underline-offset-4">
            privacy notice
          </Link>
          ,{" "}
          <Link
            to="/subprocessors"
            className="accent underline underline-offset-4"
          >
            subprocessor list
          </Link>
          , and{" "}
          <Link to="/dpa" className="accent underline underline-offset-4">
            data-processing agreement
          </Link>{" "}
          with your IT or privacy team.
        </P>
        <P>
          Confirm any AI usage allowance, retention, deletion, AI-processing, or
          data-residency requirements before rollout. Contact support for
          current service details and procurement questions.
        </P>
      </>
    ),
  },
  {
    id: "security",
    title: "Security checklist for your IT team",
    body: (
      <>
        <ul className="fg-2 mt-4 list-disc space-y-3 pl-5 text-[15px] leading-relaxed">
          <li>Verify your company domain before connecting mailboxes.</li>
          <li>
            Review provider permissions and use dedicated app passwords where
            supported.
          </li>
          <li>Enable two-factor authentication and protect recovery codes.</li>
          <li>Use encrypted mail connections with valid certificates.</li>
          <li>
            Keep administrators, notification contacts, and paired devices
            current.
          </li>
          <li>
            Review coverage and connection warnings after configuration changes.
          </li>
        </ul>
        <P>
          If your organization requires SOC 2, ISO 27001, or an independent
          penetration-test report, request the current status before purchase.
          Envelock does not currently claim those certifications or provide such
          a report.
        </P>
        <P>
          Report a security concern through{" "}
          <Link to="/contact" className="accent underline underline-offset-4">
            our contact page
          </Link>
          . Do not include credentials or sensitive email contents in the
          initial report.
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
            {navOpen ? (
              <X size={16} aria-hidden />
            ) : (
              <Menu size={16} aria-hidden />
            )}
          </button>

          <nav
            aria-label="Documentation"
            className={cn(
              "lg:sticky lg:top-24 lg:block",
              navOpen ? "block" : "hidden",
            )}
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
                  TRY THE DETECTION LAB
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
            <h1 className="headline mt-4">Connect and manage your email</h1>
            <p className="lede mt-4">
              Setup instructions for mailbox owners and the IT teams supporting
              them.
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
              Need help with your provider or rollout? Contact us with your
              setup question.
            </p>
          </footer>
        </div>
      </div>
    </main>
  );
}
