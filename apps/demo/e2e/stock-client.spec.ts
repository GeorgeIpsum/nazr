import { expect, test } from "@playwright/test";
import { apiKey, endpoint } from "./helpers";

test("stock upstream ThumbmarkJS 1.12.0 works against the API", async ({ page }) => {
  const urls: string[] = [];
  page.on("request", (r) => urls.push(r.url()));

  const apiResponse = page.waitForResponse(
    (r) => r.url().endsWith("/thumbmark") && r.request().method() === "POST",
  );
  const q = new URLSearchParams({ key: apiKey(), endpoint: endpoint() });
  await page.goto(`/e2e/stock-client.html?${q}`);
  await page.waitForFunction(
    () => (window as unknown as { __stockDone: boolean }).__stockDone,
    undefined,
    {
      timeout: 30_000,
    },
  );

  expect((await apiResponse).status()).toBe(200);
  const state = await page.evaluate(() => {
    const w = window as unknown as {
      __stockResult?: {
        thumbmark?: string;
        visitorId?: string;
        info?: { classification?: unknown };
      };
      __stockError?: string;
    };
    return { result: w.__stockResult, error: w.__stockError };
  });
  expect(state.error).toBeUndefined();
  expect(state.result?.thumbmark).toMatch(/^[0-9a-f]{32}$/);
  expect(state.result?.visitorId).toBeTruthy();
  expect(state.result?.info?.classification).toBeTruthy();

  expect(urls.some((u) => u.includes("cdn.jsdelivr.net"))).toBe(true);
  expect(urls.filter((u) => u.includes("thumbmarkjs.com"))).toEqual([]);
});
