/* Plan metadata shared by the dashboard upgrade panel and the billing page.
   Prices mirror the public pricing (Landing / PRD §12). */

export interface PlanTier {
  id: "essential" | "complete";
  name: string;
  price: string;
  per: string;
  /** Monthly price of each mailbox beyond the five included. */
  extra: string;
  extraCents: number;
  blurb: string;
  features: string[];
}

export const PLAN_RANK: Record<string, number> = {
  guard: 0,
  essential: 1,
  complete: 2,
};

export const PLAN_TIERS: PlanTier[] = [
  {
    id: "essential",
    name: "Essential",
    price: "$25",
    per: "/mo · 5 mailboxes",
    extra: "$2",
    extraCents: 200,
    blurb: "AI-assisted payment fraud detection.",
    features: [
      "Everything in Guard",
      "Bank-detail change & supplier fraud alerts",
      "AI review of suspicious payment emails",
      "Supplier records & verification workflow",
    ],
  },
  {
    id: "complete",
    name: "Complete",
    price: "$49",
    // Matches server/billing/pricing.py PLAN_MAILBOX_SEATS and EXTRA_MAILBOX_CENTS.
    per: "/mo · 5 mailboxes",
    extra: "$3.50",
    extraCents: 350,
    blurb: "Broader detection across email and identity.",
    features: [
      "Everything in Essential",
      "AI review of phishing messages",
      "Account-takeover alerts with integrations",
      "Automatic quarantine where supported",
    ],
  },
];

export function planTier(id: string): PlanTier | undefined {
  return PLAN_TIERS.find((p) => p.id === id);
}
