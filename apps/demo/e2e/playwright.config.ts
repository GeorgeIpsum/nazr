import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  globalSetup: "./global-setup.ts",
  retries: 0,
  workers: 1,
  fullyParallel: false,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:4173",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command:
      "pnpm --filter @nazr/demo build && pnpm --filter @nazr/demo preview --port 4173 --strictPort",
    cwd: "../../..",
    url: "http://localhost:4173",
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
