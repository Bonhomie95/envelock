import { render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import ConnectionAdvisor from "./ConnectionAdvisor";
import { api, type ConnectionPlan } from "../lib/api";

afterEach(cleanup);

const method = {
  id: "imap", name: "Direct mailbox connection", tier: 3, effort: "low",
  who: "IT", steps: [], remediation: true, identity_from: "sensor",
  protection_level: "standard" as const,
};

function plan(enablement: string | null): ConnectionPlan {
  return {
    domain: "acme.com", detected: true, mx_hosts: ["mx.zoho.com"],
    provider: { id: "zoho", name: "Zoho Mail", aliases: [], notes: null },
    imap: { host: "imappro.zoho.com", port: 993, enablement },
    dns: { dmarc_policy: null, spf_present: false },
    recommended: method, alternatives: [],
  };
}

it("warns before connecting when the provider ships IMAP off", async () => {
  vi.spyOn(api, "connect").mockResolvedValue(
    plan("Zoho ships IMAP turned OFF. Enable it first, then use an app password."),
  );
  render(<ConnectionAdvisor defaultDomain="acme.com" />);
  await userEvent.click(screen.getByRole("button", { name: /CHECK/ }));
  await screen.findByText(/Before you connect over IMAP/);
  expect(screen.getByText(/ships IMAP turned OFF/)).toBeInTheDocument();
});

it("shows no enablement warning for a provider without the caveat", async () => {
  vi.spyOn(api, "connect").mockResolvedValue(plan(null));
  render(<ConnectionAdvisor defaultDomain="acme.com" />);
  await userEvent.click(screen.getByRole("button", { name: /CHECK/ }));
  await screen.findByText(/imappro.zoho.com/);
  expect(screen.queryByText(/Before you connect over IMAP/)).not.toBeInTheDocument();
});
