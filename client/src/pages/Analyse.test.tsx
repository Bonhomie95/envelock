import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import Analyse from "./Analyse";
import { api, type AnalyseResult } from "../lib/api";

const clean: AnalyseResult = {
  message: {
    from: "a@example.com",
    display_name: null,
    reply_to: null,
    subject: "Hello",
    attachments: [],
    urls: [],
    remediable: false,
  },
  findings: [],
  assessment: null,
};
afterEach(() => vi.restoreAllMocks());

it("clears sample supplier history when a visitor edits the email", async () => {
  const scan = vi.spyOn(api, "analyse").mockResolvedValue(clean);
  render(<Analyse />);
  fireEvent.change(screen.getByLabelText("Raw message"), {
    target: { value: "From: a@example.com\n\nHello" },
  });
  await userEvent.click(
    screen.getByRole("button", { name: "ANALYSE" }),
  );
  await screen.findByText("Nothing detected.");
  expect(scan.mock.calls[0][0]).not.toHaveProperty(
    "counterparty_known_bank_ids",
  );
  expect(screen.queryByText(/Known account on file/)).not.toBeInTheDocument();
  expect(screen.getByLabelText("Analysis results")).toHaveFocus();
});

it("removes a previous verdict if a new scan fails", async () => {
  const scan = vi
    .spyOn(api, "analyse")
    .mockResolvedValueOnce(clean)
    .mockRejectedValueOnce(new Error("offline"));
  render(<Analyse />);
  await userEvent.click(
    screen.getByRole("button", { name: "ANALYSE" }),
  );
  await screen.findByText("Nothing detected.");
  await userEvent.click(
    screen.getByRole("button", { name: "ANALYSE" }),
  );
  await screen.findByRole("alert");
  expect(screen.queryByText("Nothing detected.")).not.toBeInTheDocument();
  expect(scan).toHaveBeenCalledTimes(2);
});

it("locks input while a scan is pending and refuses empty scans", async () => {
  let finish!: (result: AnalyseResult) => void;
  vi.spyOn(api, "analyse").mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve;
      }),
  );
  render(<Analyse />);
  await userEvent.click(
    screen.getByRole("button", { name: "ANALYSE" }),
  );
  expect(screen.getByLabelText("Raw message")).toBeDisabled();
  expect(screen.getByRole("button", { name: /Ordinary email/ })).toBeDisabled();
  finish(clean);
  await waitFor(() =>
    expect(screen.getByLabelText("Raw message")).toBeEnabled(),
  );
  fireEvent.change(screen.getByLabelText("Raw message"), {
    target: { value: " " },
  });
  expect(
    screen.getByRole("button", { name: "ANALYSE" }),
  ).toBeDisabled();
});

it("offers the phishing-link and identical-sender samples and sends their bodies", async () => {
  const scan = vi.spyOn(api, "analyse").mockResolvedValue(clean);
  render(<Analyse />);

  await userEvent.click(screen.getByRole("button", { name: /Phishing link/ }));
  await userEvent.click(screen.getByRole("button", { name: "ANALYSE" }));
  await screen.findByText("Nothing detected.");
  expect(scan.mock.calls[0][0].raw_message).toContain("203.0.113.10");

  await userEvent.click(
    screen.getByRole("button", { name: /Identical sender, wrong address/ }),
  );
  await userEvent.click(screen.getByRole("button", { name: "ANALYSE" }));
  await waitFor(() => expect(scan).toHaveBeenCalledTimes(2));
  expect(scan.mock.calls[1][0].raw_message).toContain(
    "billing@secure-mail-portal.example",
  );
});
