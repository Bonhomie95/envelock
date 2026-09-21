/* Test configuration, deliberately separate from vite.config.ts.
 *
 * Vitest bundles its own copy of Vite, and this project is on a newer major
 * (rolldown-based) than the one Vitest vendors. Importing `defineConfig` from
 * `vitest/config` inside vite.config.ts therefore makes `tsc -b` compare two
 * incompatible `Plugin` types and produce a wall of errors about
 * `rolldownVersion` — nothing to do with our code.
 *
 * Keeping the two files apart means the build config type-checks against the
 * Vite the app actually uses, and the test config is read only by Vitest, which
 * resolves its own types happily. `tsconfig.node.json` includes only
 * vite.config.ts, so this file is never fed to the build type-check.
 */
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    // jsdom, not happy-dom: the components under test use focus management and
    // dialog semantics, and jsdom's implementations are the closer match.
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    // The app's tests only. `sensor/` has its own suite on Node's built-in
    // runner (`npm run test:sensor`) — those files use `node:test`, and the
    // default pattern would otherwise pick them up and fail them here.
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
  },
});
