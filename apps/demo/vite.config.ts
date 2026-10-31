import { defineConfig } from "vitest/config";

// base './' keeps the built dist/ relocatable: it works from /demo/ on the Go
// server or from any static host.
export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    rollupOptions: { input: { main: "index.html", widget: "widget-host.html" } },
  },
  test: { environment: "node", exclude: ["e2e/**", "node_modules/**", "dist/**"] },
});
