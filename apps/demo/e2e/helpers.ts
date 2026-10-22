import { expect, type Page } from "@playwright/test";

export interface Result {
  thumbmark: string;
  visitorId?: string;
  components: Record<string, Record<string, unknown>>;
  info?: {
    visitor?: { isNew?: boolean; id?: string };
    classification?: unknown;
  };
  error?: unknown[];
}

export const endpoint = () => process.env.NAZR_E2E_ENDPOINT as string;
export const apiKey = () => process.env.NAZR_E2E_KEY as string;

export async function openDemo(page: Page): Promise<void> {
  await page.goto("/");
  await page.fill("#endpoint", endpoint());
  await page.fill("#apiKey", apiKey());
}

/** Clicks Run and returns the client's result once the run completes. */
export async function run(page: Page): Promise<Result> {
  await page.evaluate(() => {
    (window as unknown as { __nazrLast: unknown }).__nazrLast = null;
  });
  await page.click("#run");
  await page.waitForFunction(
    () => (window as unknown as { __nazrLast: unknown }).__nazrLast != null,
    undefined,
    { timeout: 30_000 },
  );
  const result = await page.evaluate(
    () => (window as unknown as { __nazrLast: Result }).__nazrLast,
  );
  expect(result.error ?? []).toEqual([]);
  expect(result.thumbmark).toMatch(/^[0-9a-f]{32}$/);
  return result;
}
