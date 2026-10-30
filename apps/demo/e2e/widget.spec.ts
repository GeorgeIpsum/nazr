import { execFileSync } from "node:child_process";
import { expect, test } from "@playwright/test";
import { apiKey, endpoint } from "./helpers";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

interface WidgetSummary {
  window_days: number;
  reports: number;
  matched: number;
  unmatched: number;
  ip_mismatch: number;
  ja4_mismatch: number;
  ja4_unknown: number;
  ua_mismatch: number;
}

function admin<T>(path: string): T {
  // Ignore the self-signed certificate, as global-setup's readiness probe does.
  const out = execFileSync(
    "curl",
    [
      "-ksS",
      "--fail",
      "-H",
      `Authorization: Bearer ${process.env.NAZR_E2E_ADMIN_TOKEN}`,
      `${endpoint()}${path}`,
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  ).toString();
  return JSON.parse(out) as T;
}

test("widget report correlates with the host page's /thumbmark call", async ({ page }) => {
  const frameResponse = page.waitForResponse((r) => r.url().includes("/widget/v1/frame?"));
  const reportResponse = page.waitForResponse(
    (r) => r.url().endsWith("/widget/report") && r.request().method() === "POST",
  );
  const apiResponse = page.waitForResponse(
    (r) => r.url().endsWith("/thumbmark") && r.request().method() === "POST",
  );
  const q = new URLSearchParams({ key: apiKey(), endpoint: endpoint() });
  await page.goto(`/widget-host.html?${q}`);
  await page.waitForFunction(
    () => (window as unknown as { __nazrHostDone?: unknown }).__nazrHostDone != null,
    undefined,
    { timeout: 30_000 },
  );

  const frame = await frameResponse;
  expect(frame.status()).toBe(200);
  expect((await frame.allHeaders())["content-security-policy"]).toMatch(/^frame-ancestors \*/);
  expect((await reportResponse).status()).toBe(204);
  const api = await apiResponse;
  expect(api.status()).toBe(200);

  const state = await page.evaluate(() => {
    const w = window as unknown as {
      __nazrWidget?: { nonce: string };
      __nazrHostDone: { nonce: string; thumbmark: string; error?: unknown };
    };
    return {
      iframe: document.querySelector("iframe") === null,
      widgetNonce: w.__nazrWidget?.nonce,
      done: w.__nazrHostDone,
    };
  });
  // The frame lives in a closed shadow root, invisible to the host document.
  expect(state.iframe).toBe(true);
  expect(state.done.error).toBeUndefined();
  expect(state.done.thumbmark).toMatch(/^[0-9a-f]{32}$/);
  expect(state.widgetNonce).toMatch(UUID);
  expect(state.done.nonce).toBe(state.widgetNonce);
  expect((api.request().postDataJSON() as { nonce?: string }).nonce).toBe(state.widgetNonce);

  // Match the prefix too: a reused NAZR_E2E_DATABASE_URL holds older "e2e" keys.
  const keys = admin<{ id: string; label: string; prefix: string }[]>("/admin/keys");
  const key = keys.find((k) => k.label === "e2e" && apiKey().startsWith(`nzr_${k.prefix}`));
  expect(key).toBeDefined();

  let summary: WidgetSummary | undefined;
  await expect
    .poll(
      () => {
        summary = admin<WidgetSummary>(`/admin/keys/${key?.id}/widget`);
        return summary.matched;
      },
      { timeout: 10_000 },
    )
    .toBeGreaterThanOrEqual(1);
  // Terminate mode observes JA4 on both connections, so nothing is unknown.
  expect(summary).toMatchObject({
    ip_mismatch: 0,
    ja4_mismatch: 0,
    ua_mismatch: 0,
    ja4_unknown: 0,
  });
});
