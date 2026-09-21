/* Plan metadata shared by the dashboard upgrade panel and the billing page.
   Prices mirror the public pricing (Landing / PRD §12). */

export interface PlanTier {
  id: "essential" | "complete";
  name: string;
  price: string;
  per: string;
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
    blurb: "Stops invoice fraud.",
    features: ["Bank-detail-change alerts", "Fake supplier detection", "IT dashboard"],
  },
  {
    id: "complete",
    name: "Complete",
    price: "$47.50",
    per: "/mo · 5 mailboxes",
    blurb: "Adds account-takeover protection.",
    features: [
      "Everything in Essential",
      "Unusual sign-in alerts",
      "Silent access (ATO) detection",
      "Auto-remove dangerous mail",
    ],
  },
];

export function planTier(id: string): PlanTier | undefined {
  return PLAN_TIERS.find((p) => p.id === id);
}
