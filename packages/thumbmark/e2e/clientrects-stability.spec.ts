import { expect, test } from "@playwright/test";

test("clientrects hash is stable across scroll position and body margin", async ({ page }) => {
    await page.goto("http://localhost:3333/index.html");
    await page.addStyleTag({ content: "body{margin:8px;position:relative;height:5000px}" });

    const run = () =>
        page.evaluate(async () => {
            // @ts-expect-error - ThumbmarkJS is loaded via script tag
            const tm = new ThumbmarkJS.Thumbmark({ include: ["clientrects"] });
            const data = await tm.get();
            return data.components.clientrects as { rects: string[]; hash: string };
        });

    const first = await run();
    await page.evaluate(() => window.scrollTo(0, 500));
    expect(await page.evaluate(() => window.scrollY)).toBe(500);
    const second = await run();
    await page.addStyleTag({ content: "body{margin:40px}" });
    const third = await run();

    expect(first.hash).toMatch(/^[0-9a-f]{32}$/);
    expect(second.hash).toBe(first.hash);
    expect(third.hash).toBe(first.hash);
    expect(second.rects).toEqual(first.rects);
});
