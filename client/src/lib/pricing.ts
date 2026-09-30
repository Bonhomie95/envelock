/** What the billing page shows, as arithmetic that can be tested.
 *
 * This lived inline in the summary panel and drifted: with an annual term
 * selected it printed a yearly headline, multiplied the extra seats by the
 * MONTHLY rate, and labelled the result "Total per month". Stripe billed
 * $316.80 a year while the page read $33.00 — on the one screen a customer
 * checks before paying.
 *
 * The server is the authority (`billing/pricing.self_serve_cents`); this mirrors
 * it for display only, and `pricing.test.ts` pins the two together.
 */

/** The annual term's discount. Must match `TERM_DISCOUNT[ANNUAL]` on the server. */
export const ANNUAL_DISCOUNT = 0.2;

export interface PlanTotals {
  /** Plan price for one billing period, in dollars. */
  base: number;
  /** One extra mailbox for one billing period, in dollars. */
  seat: number;
  /** All extra mailboxes for one billing period. */
  seats: number;
  /** What the customer pays each period. */
  total: number;
  /** "year" or "month" — the period every number above is expressed in. */
  period: "year" | "month";
}

export function planTotals(
  monthlyBase: number,
  monthlySeatCents: number,
  extraMailboxes: number,
  term: "monthly" | "annual",
): PlanTotals {
  const annual = term === "annual";
  // One multiplier for every line, which is what stops the three periods from
  // ever disagreeing again.
  const mul = annual ? 12 * (1 - ANNUAL_DISCOUNT) : 1;
  const base = monthlyBase * mul;
  const seat = (monthlySeatCents / 100) * mul;
  const seats = extraMailboxes * seat;
  return { base, seat, seats, total: base + seats, period: annual ? "year" : "month" };
}
