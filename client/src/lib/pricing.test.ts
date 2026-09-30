/** The billing summary must print what Stripe will charge.
 *
 * These figures are not invented here: each one was read off a real Stripe
 * Checkout session created by this app against the sandbox account. If the
 * server's `self_serve_cents` changes, these fail — which is the point, because
 * the alternative is a page that quotes one number and a card that is debited
 * another.
 */
import { describe, expect, it } from "vitest";

import { ANNUAL_DISCOUNT, planTotals } from "./pricing";

describe("planTotals", () => {
  it("matches the monthly figures Stripe charged", () => {
    // Stripe: "Then $25.00 per month" for the plan alone.
    expect(planTotals(25, 200, 0, "monthly").total).toBe(25);
    // Stripe: "$31.00 per month" — Qty 1 at $25.00 plus Qty 3 at $6.00.
    const three = planTotals(25, 200, 3, "monthly");
    expect(three.seats).toBe(6);
    expect(three.total).toBe(31);
    expect(three.period).toBe("month");
  });

  it("matches the annual figures Stripe charged", () => {
    // Stripe: "Then $240.00 per year" for the plan alone.
    expect(planTotals(25, 200, 0, "annual").total).toBeCloseTo(240, 2);
    // Stripe: "$316.80 per year" — $240.00 plus 4 seats at $76.80.
    const four = planTotals(25, 200, 4, "annual");
    expect(four.seat).toBeCloseTo(19.2, 2);
    expect(four.seats).toBeCloseTo(76.8, 2);
    expect(four.total).toBeCloseTo(316.8, 2);
    expect(four.period).toBe("year");
  });

  it("prices Complete the same way", () => {
    expect(planTotals(49, 350, 0, "monthly").total).toBe(49);
    expect(planTotals(49, 350, 0, "annual").total).toBeCloseTo(470.4, 2);
    expect(planTotals(49, 350, 2, "annual").total).toBeCloseTo(470.4 + 67.2, 2);
  });

  it("never mixes periods within one breakdown", () => {
    // The actual defect: an annual base beside monthly seats. Every line has to
    // scale by the same factor, so the ratio of base to seat is term-invariant.
    for (const [b, c] of [
      [25, 200],
      [49, 350],
    ] as const) {
      const m = planTotals(b, c, 7, "monthly");
      const a = planTotals(b, c, 7, "annual");
      expect(a.base / m.base).toBeCloseTo(a.seat / m.seat, 6);
      expect(a.total / m.total).toBeCloseTo(12 * (1 - ANNUAL_DISCOUNT), 6);
    }
  });

  it("charges nothing extra for zero extra mailboxes", () => {
    expect(planTotals(25, 200, 0, "annual").seats).toBe(0);
    expect(planTotals(49, 350, 0, "monthly").total).toBe(49);
  });
});
