import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // Without this, a busy 5173 silently becomes 5174 — you then open 5173,
    // hit a stale server, and it looks like the CSS broke. Fail loudly.
    strictPort: true,
    proxy: {
      "/api": "http://localhost:8010",
      "/health": "http://localhost:8010",
    },
  },
});