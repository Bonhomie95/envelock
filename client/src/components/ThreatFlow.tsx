import { ChevronRight, Fingerprint, Globe, Mail, Phone, ShieldCheck } from "lucide-react";

/* The product in one picture: three independent signal sources feed one judge,
   which returns a single clear action. Pure presentation — no data, no props —
   so it is safe to drop into any marketing surface. Themed via CSS tokens and
   collapses to a vertical flow on narrow screens (see .threatflow in index.css). */

const SIGNALS = [
  { icon: Mail, name: "Mail content", text: "Payment fraud, phishing links, risky attachments" },
  { icon: Fingerprint, name: "Identity", text: "New-device & impossible-travel sign-ins, silent access" },
  { icon: Globe, name: "Domain & brand", text: "Lookalike domains and impersonation" },
];

export function ThreatFlow() {
  return (
    <div
      className="threatflow"
      role="img"
      aria-label="Three signal sources — mail content, identity, and domain — feed Envelock's rules and AI judge, which returns one clear next step."
    >
      <div className="tf-signals">
        {SIGNALS.map(({ icon: Icon, name, text }) => (
          <div className="tf-node" key={name}>
            <Icon size={18} aria-hidden />
            <div>
              <b>{name}</b>
              <span>{text}</span>
            </div>
          </div>
        ))}
      </div>

      <ChevronRight className="tf-arrow" size={22} aria-hidden />

      <div className="tf-core">
        <ShieldCheck size={22} aria-hidden />
        <b>Envelock</b>
        <span>Rules + AI judge, weighed together</span>
      </div>

      <ChevronRight className="tf-arrow" size={22} aria-hidden />

      <div className="tf-action">
        <span className="tf-tier">CRITICAL</span>
        <b>One clear next step</b>
        <span className="tf-step">
          <Phone size={13} aria-hidden /> Call the supplier before you pay.
        </span>
      </div>
    </div>
  );
}

export default ThreatFlow;
