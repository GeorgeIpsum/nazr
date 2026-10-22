import { expect, test } from "@playwright/test";
import { openDemo, run } from "./helpers";

test("server thumbmark equals the in-page hash of the merged components", async ({ page }) => {
  await openDemo(page);
  const first = await run(page);

  await expect(page.locator("#thumbmark")).toHaveText(first.thumbmark);

  // Computed in the page with the fork's own exports, over the client's merged components.
  const local = await page.evaluate(() => {
    const w = window as unknown as {
      __nazr: { stableStringify: (v: unknown) => string; hash: (s: string) => string };
      __nazrLast: { components: unknown };
    };
    return w.__nazr.hash(w.__nazr.stableStringify(w.__nazrLast.components));
  });
  expect(local).toBe(first.thumbmark);

  const tls = first.components.tls as { ja4?: string };
  expect(tls.ja4).toMatch(/^[tq][0-9]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/);
  const h2 = first.components.h2 as { fingerprint?: string };
  expect(h2.fingerprint).toBeTruthy();

  const second = await run(page);
  expect(second.thumbmark).toBe(first.thumbmark);
  expect(second.visitorId).toBeTruthy();
  expect(second.visitorId).toBe(first.visitorId);
  expect(second.info?.visitor?.isNew).toBe(false);
});
