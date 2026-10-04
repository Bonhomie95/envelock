import { render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import SimulationPanel from "./SimulationPanel";
import { api, type SimulationResult } from "../lib/api";

afterEach(cleanup);

const RESULT: SimulationResult = {
  plan: "complete",
  passed: 5,
  plan_locked: 0,
  total: 6,
  runs: [
    { id: "s1", name: "Supplier changes bank details", expected: "A1", detected: ["A1"], passed: true, plan_locked: false },
    { id: "s2", name: "Phishing link", expected: "B1", detected: ["B1"], passed: true, plan_locked: false },
    { id: "s3", name: "Identical sender, wrong address", expected: "A5", detected: ["A5"], passed: true, plan_locked: false },
    { id: "s4", name: "Account takeover", expected: "C11", detected: [], passed: false, plan_locked: true },
  ],
};

it("runs the simulation and shows caught attacks by name, not code", async () => {
  const spy = vi.spyOn(api, "simulate").mockResolvedValue(RESULT);
  render(<SimulationPanel domain="acme.com" />);
  await userEvent.click(screen.getByRole("button", { name: /RUN SIMULATION/ }));

  await screen.findByText(/5 of 6 attacks caught/);
  expect(spy).toHaveBeenCalledWith("acme.com");
  expect(screen.getByText("Phishing link")).toBeInTheDocument();
  expect(screen.getByText("Identical sender, wrong address")).toBeInTheDocument();
  // Internal codes are never shown to the customer.
  expect(screen.queryByText("B1")).not.toBeInTheDocument();
  expect(screen.queryByText("A5")).not.toBeInTheDocument();
});

it("explains a plan-locked miss instead of calling it a failure", async () => {
  vi.spyOn(api, "simulate").mockResolvedValue(RESULT);
  render(<SimulationPanel domain="acme.com" />);
  await userEvent.click(screen.getByRole("button", { name: /RUN SIMULATION/ }));
  await screen.findByText(/Account takeover/);
  expect(screen.getByText(/Your plan doesn't include this detection/)).toBeInTheDocument();
});

it("disables the button when there is no domain to test", () => {
  render(<SimulationPanel domain="" />);
  expect(screen.getByRole("button", { name: /RUN SIMULATION/ })).toBeDisabled();
});
