import { render, screen, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import ReAuthDialog from "./ReAuthDialog";

afterEach(cleanup);

/** The shared re-auth prompt stands in front of every sensitive action (binding
 * a second factor, removing a mailbox, writing supplier ground truth). These pin
 * the contract the callers rely on: it hands back the password (and a code only
 * when one was typed), and cannot be confirmed empty. */
describe("the re-authentication prompt", () => {
  it("passes the password back, and a code only when entered", async () => {
    const onConfirm = vi.fn();
    render(
      <ReAuthDialog
        open
        title="Confirm it's you"
        body="Confirm your password."
        confirmLabel="CONTINUE"
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );

    // Empty → the confirm button is disabled, so no empty re-auth is submitted.
    expect(screen.getByRole("button", { name: "CONTINUE" })).toBeDisabled();

    await userEvent.type(screen.getByLabelText("Current password"), "my-password");
    await userEvent.click(screen.getByRole("button", { name: "CONTINUE" }));
    expect(onConfirm).toHaveBeenCalledWith({ current_password: "my-password" });
  });

  it("includes the authenticator code when one is typed", async () => {
    const onConfirm = vi.fn();
    render(
      <ReAuthDialog
        open
        title="Confirm it's you"
        body="Confirm your password."
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    );
    await userEvent.type(screen.getByLabelText("Current password"), "pw");
    await userEvent.type(screen.getByLabelText(/Authenticator code/), "123456");
    await userEvent.click(screen.getByRole("button", { name: "CONFIRM" }));
    expect(onConfirm).toHaveBeenCalledWith({
      current_password: "pw",
      mfa_code: "123456",
    });
  });

  it("renders nothing while closed", () => {
    render(
      <ReAuthDialog
        open={false}
        title="Confirm it's you"
        body="x"
        onConfirm={vi.fn()}
        onCancel={() => {}}
      />,
    );
    expect(screen.queryByText("Confirm it's you")).not.toBeInTheDocument();
  });
});
