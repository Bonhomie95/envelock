/* The supplier registry screen.
 *
 * Worth testing rather than eyeballing, because the things that make it useful
 * are the things that fail silently: whether an incomplete supplier is pulled to
 * the top and named as incomplete, whether the import previews before it writes,
 * and whether a member who cannot edit is shown the data anyway (they are the
 * person about to pay the invoice).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import Suppliers from "./Suppliers";
import { api, auth, type Counterparty } from "../lib/api";

function supplier(over: Partial<Counterparty> = {}): Counterparty {
  return {
    domain: "acme.example",
    display_name: "Acme Supplies",
    message_count: 12,
    verified_phone: "+1 555 0100",
    bank_records: 1,
    risk_score: 10,
    tier: "low",
    advice: "No elevated risk.",
    needs: [],
    ...over,
  };
}

function signInAs(role: "owner" | "member") {
  const payload = btoa(
    JSON.stringify({ sub: "u", tenant: "t", role, typ: "access", exp: 9e9, jti: "j" }),
  )
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  auth.set(`${payload}.sig`);
}

beforeEach(() => {
  signInAs("owner");
  vi.spyOn(api, "supplierRecords").mockResolvedValue({
    domain: "acme.example",
    display_name: "Acme Supplies",
    verified_phone: "+1 555 0100",
    records: [
      {
        id: "r1",
        scheme: "iban",
        identifier: "GB29NWBK60161331926819",
        bank_name: "NatWest",
        country: null,
        active: true,
        first_seen_at: null,
        verified_at: null,
      },
    ],
  });
});

describe("coverage", () => {
  it("counts a supplier as covered only with both an account and a number", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [
        supplier(),
        supplier({
          domain: "globex.example",
          display_name: "Globex",
          verified_phone: null,
          needs: ["callback_number"],
        }),
      ],
    });
    render(<Suppliers />);
    expect(await screen.findByText("1/2")).toBeVisible();
  });

  it("pulls incomplete suppliers above complete ones and names what is missing", async () => {
    // The list is scanned for gaps, not browsed. A supplier missing its callback
    // number must not be buried under twenty complete ones.
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [
        supplier(),
        supplier({
          domain: "globex.example",
          display_name: "Globex",
          verified_phone: null,
          needs: ["callback_number"],
        }),
        supplier({
          domain: "initech.example",
          display_name: "Initech",
          bank_records: 0,
          needs: ["bank_details"],
        }),
      ],
    });
    render(<Suppliers />);

    expect(await screen.findByText("Needs your attention")).toBeVisible();
    expect(screen.getByText("No number to ring")).toBeVisible();
    expect(screen.getByText("No account on file")).toBeVisible();

    const headings = screen.getAllByRole("button", { name: /Globex|Initech|Acme/ });
    // Both incomplete rows come before the complete one.
    expect(headings[0]).toHaveTextContent(/Globex|Initech/);
    expect(headings[2]).toHaveTextContent("Acme");
  });

  it("says so plainly when nothing needs attention", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [supplier()],
    });
    render(<Suppliers />);
    expect(
      await screen.findByText(/Every supplier has an account and a number on file/),
    ).toBeVisible();
  });

  it("points a new customer at the import rather than showing an empty box", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({ counterparties: [] });
    render(<Suppliers />);
    expect(await screen.findByText("No suppliers yet")).toBeVisible();
    expect(screen.getByText(/Importing your list from/)).toBeVisible();
  });
});

describe("supplier detail", () => {
  it("shows the account in full so it can be compared against an invoice", async () => {
    // Masking would make the one comparison this screen exists for impossible.
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [supplier()],
    });
    render(<Suppliers />);
    await userEvent.click(await screen.findByRole("button", { name: /Acme/ }));
    expect(await screen.findByText("GB29NWBK60161331926819")).toBeVisible();
  });

  it("warns when there is nothing to check a changed account against", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [supplier({ bank_records: 0, needs: ["bank_details"] })],
    });
    vi.spyOn(api, "supplierRecords").mockResolvedValue({
      domain: "acme.example",
      display_name: "Acme Supplies",
      verified_phone: null,
      records: [],
    });
    render(<Suppliers />);
    await userEvent.click(await screen.findByRole("button", { name: /Acme/ }));
    expect(
      await screen.findByText(/has nothing to be checked against/),
    ).toBeVisible();
  });
});

describe("permissions", () => {
  it("lets a member read the registry without the edit controls", async () => {
    // The person about to pay is usually not the person who may edit — but the
    // answer to "what account do we have on file?" is what stops the payment.
    signInAs("member");
    vi.spyOn(api, "counterparties").mockResolvedValue({
      counterparties: [supplier()],
    });
    render(<Suppliers />);
    await userEvent.click(await screen.findByRole("button", { name: /Acme/ }));

    expect(await screen.findByText("GB29NWBK60161331926819")).toBeVisible();
    expect(screen.queryByText("IMPORT A FILE")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: "Account identifier" }),
    ).not.toBeInTheDocument();
  });
});

describe("importing the vendor master", () => {
  it("previews without writing, then writes only on confirmation", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({ counterparties: [] });
    const importVendors = vi.spyOn(api, "importVendors").mockResolvedValue({
      dry_run: true,
      rows_parsed: 3,
      suppliers_created: 3,
      suppliers_matched: 0,
      bank_records_created: 2,
      bank_records_already_present: 0,
      problems: [],
      suppliers: [],
    });

    render(<Suppliers />);
    await userEvent.click(await screen.findByText("IMPORT A FILE"));
    await userEvent.type(
      screen.getByPlaceholderText(/Supplier,Email/),
      "Vendor,Email\nAcme,ap@acme.example",
    );

    await userEvent.click(screen.getByText("CHECK THE FILE"));
    await waitFor(() => expect(importVendors).toHaveBeenCalledWith(expect.any(String), true));
    expect(await screen.findByText("3 rows read")).toBeVisible();

    importVendors.mockResolvedValueOnce({
      dry_run: false,
      rows_parsed: 3,
      suppliers_created: 3,
      suppliers_matched: 0,
      bank_records_created: 2,
      bank_records_already_present: 0,
      problems: [],
      suppliers: [],
    });
    await userEvent.click(screen.getByText("IMPORT"));
    await waitFor(() =>
      expect(importVendors).toHaveBeenLastCalledWith(expect.any(String), false),
    );
  });

  it("cannot import before the file has been checked", async () => {
    // The preview is what makes the button safe to press.
    vi.spyOn(api, "counterparties").mockResolvedValue({ counterparties: [] });
    render(<Suppliers />);
    await userEvent.click(await screen.findByText("IMPORT A FILE"));
    expect(screen.getByText("IMPORT").closest("button")).toBeDisabled();
  });

  it("reports the rows it could not use instead of failing the whole file", async () => {
    vi.spyOn(api, "counterparties").mockResolvedValue({ counterparties: [] });
    vi.spyOn(api, "importVendors").mockResolvedValue({
      dry_run: true,
      rows_parsed: 1,
      suppliers_created: 1,
      suppliers_matched: 0,
      bank_records_created: 0,
      bank_records_already_present: 0,
      problems: ["line 3: 'not-a-domain' is not a usable domain"],
      suppliers: [],
    });

    render(<Suppliers />);
    await userEvent.click(await screen.findByText("IMPORT A FILE"));
    await userEvent.type(
      screen.getByPlaceholderText(/Supplier,Email/),
      "Vendor,Email\nAcme,ap@acme.example",
    );
    await userEvent.click(screen.getByText("CHECK THE FILE"));

    const note = await screen.findByText("1 row we couldn't use");
    expect(within(note.parentElement as HTMLElement).getByText(/line 3/)).toBeVisible();
  });
});
