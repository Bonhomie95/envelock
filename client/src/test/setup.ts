/* Shared test setup.
 *
 * `jest-dom` gives the assertions that make a failure readable — `toBeVisible()`
 * reports what the element actually was, where a bare truthiness check reports
 * "expected null to be truthy" and tells you nothing.
 */
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

beforeEach(() => {
  // Every test starts signed out. The auth helpers read localStorage directly,
  // so a token left behind by one test silently changes what the next one
  // renders — the classic source of a suite that passes only in order.
  localStorage.clear();
});
