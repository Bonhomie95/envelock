import { render, screen, cleanup } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { AlertRecord } from "../lib/api";
import TodayPanel from "./TodayPanel";

afterEach(cleanup);
describe("threat summary", () => {
  it("prioritizes a critical alert over a more recent high alert", () => {
    const open = [
      { tier: "high", title: "Recent high risk" },
      { tier: "critical", title: "Critical payment change" },
    ] as AlertRecord[];
    render(<TodayPanel open={open} stats={null} issues={[]} onShowAlerts={() => {}} />);
    expect(screen.getByText("Critical payment change")).toBeInTheDocument();
    expect(screen.queryByText("Recent high risk")).not.toBeInTheDocument();
    expect(open[0].tier).toBe("high");
  });
  it("does not show an all-clear when the alert request fails", () => {
    render(<TodayPanel open={[]} stats={null} issues={[]} onShowAlerts={() => {}} unavailable />);
    expect(screen.getByText(/Alerts could not be refreshed/)).toBeInTheDocument();
    expect(screen.queryByText(/Nothing needs you right now/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Everything connected and working/)).not.toBeInTheDocument();
  });
});
