import { expect, test } from "@playwright/test";

test.describe("canvas_probe", () => {
    test("is stable across calls and never affects clientHash", async ({ page }) => {
        const bodies: Record<string, unknown>[] = [];
        await page.route("**/thumbmark", async (route) => {
            // Read the body before fulfilling.
            bodies.push(JSON.parse(route.request().postData() ?? "{}"));
            await route.fulfill({
                status: 200,
                contentType: "application/json",
                body: JSON.stringify({
                    thumbmark: "mock-thumbmark",
                    visitorId: "mock-visitor",
                }),
            });
        });

        await page.goto("http://localhost:3333/index.html");

        await page.evaluate(async () => {
            const base = {
                api_endpoint: "http://localhost:3333/thumbmark",
                api_key: "test",
                cache_api_call: false,
            };
            const draw = (ctx: CanvasRenderingContext2D) => {
                ctx.fillStyle = "#123456";
                ctx.fillRect(2, 3, 20, 10);
            };
            // @ts-expect-error - ThumbmarkJS is loaded via script tag
            const T = ThumbmarkJS.Thumbmark;
            await new T({ ...base, canvas_probe: { draw } }).get();
            await new T({ ...base, canvas_probe: { draw } }).get();
            await new T({ ...base }).get();
        });

        expect(bodies).toHaveLength(3);
        const [a, b, none] = bodies;

        // (a) stability
        expect(a.canvas_probe).toMatch(/^[0-9a-f]{1,64}$/);
        expect(b.canvas_probe).toBe(a.canvas_probe);

        // (b) isolation
        expect("canvas_probe" in none).toBe(false);
        expect(a.clientHash).toBeTruthy();
        expect(a.clientHash).toBe(none.clientHash);
        expect(b.clientHash).toBe(none.clientHash);
    });
});
