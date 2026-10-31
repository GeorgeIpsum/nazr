import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";

const UMD = resolve(import.meta.dirname, "../dist/thumbmark.umd.js");

test.describe("obfuscated UMD bundle", () => {
    test("ships no source map and no readable string literals", () => {
        const src = readFileSync(UMD, "utf8");
        expect(src).not.toContain("sourceMappingURL");
        // Plain literals and dotted property names in the readable build. The
        // rc4 string array must hide every one. Component registry keys are
        // not checked: the obfuscator cannot move them (see obfuscate.mjs),
        // and they travel in plain JSON on every request regardless.
        for (const literal of [
            "getHighEntropyValues",
            "fullVersionList",
            "maxTextureDimension2D",
            "api_endpoint",
            "sendBeacon",
        ]) {
            expect(src, literal).not.toContain(literal);
        }
    });

    test("produces the same components and thumbmark as the readable ESM build", async ({
        page,
    }) => {
        await page.goto("http://localhost:3333/index.html");

        const result = await page.evaluate(async () => {
            const umd = await new (globalThis as any).ThumbmarkJS.Thumbmark().get();
            const esmModule = await import("/dist/thumbmark.esm.js" as string);
            const esm = await new esmModule.Thumbmark().get();
            return { umd, esm };
        });

        expect(result.umd.thumbmark).toMatch(/^[0-9a-f]{32}$/);
        expect(result.umd.components).toEqual(result.esm.components);
        expect(result.umd.thumbmark).toBe(result.esm.thumbmark);
    });

    test("runs under a strict CSP without unsafe-eval", async ({ page }) => {
        const violations: string[] = [];
        page.on("pageerror", (e) => violations.push(String(e)));
        page.on("console", (m) => {
            if (m.type() === "error") violations.push(m.text());
        });
        await page.goto("http://localhost:3333/csp.html");

        const thumbmark = await page.evaluate(async () => {
            return (await new (globalThis as any).ThumbmarkJS.Thumbmark().get()).thumbmark;
        });

        expect(thumbmark).toMatch(/^[0-9a-f]{32}$/);
        expect(violations).toEqual([]);
    });
});
