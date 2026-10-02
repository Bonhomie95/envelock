import { render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ConfirmDialog from "./ConfirmDialog";

afterEach(cleanup);

/** The seat UPDATE button charges a card the instant it is pressed, so it is
 * routed through this dialog. These pin the gate itself: a confirmation that
 * fires the action on cancel, or on backdrop click, is worse than none. */
describe("confirmation before a charge", () => {
  it("does not act until the confirm button is pressed", async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog
        open
        destructive={false}
        title="Add 4 mailbox seats?"
        body="Your card is charged today."
        confirmLabel="CHARGE MY CARD"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    );
    expect(screen.getByText("Add 4 mailbox seats?")).toBeInTheDocument();
    expect(onConfirm).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "CANCEL" }));
    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).toHaveBeenCalledTimes(1);

    await userEvent.click(screen.getByRole("button", { name: "CHARGE MY CARD" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("renders nothing while closed, so no stray charge is one keypress away", () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open={false}
        title="Add 4 mailbox seats?"
        body="Your card is charged today."
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByText("Add 4 mailbox seats?")).not.toBeInTheDocument();
  });

  it("cannot be confirmed twice while the charge is in flight", async () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog
        open
        busy
        destructive={false}
        title="Add 4 mailbox seats?"
        body="Your card is charged today."
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    await userEvent.click(screen.getByRole("button", { name: "WORKING…" }));
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
