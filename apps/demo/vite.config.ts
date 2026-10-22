import { defineConfig } from "vite";

// base './' keeps the built dist/ relocatable: it works from /demo/ on the Go
// server or from any static host.
export default defineConfig({
  base: "./",
  build: { target: "es2022" },
  test: { environment: "node" },
});
