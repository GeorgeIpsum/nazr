import { buildFixtures } from "./fixtures";

describe("buildFixtures", () => {
    const f = buildFixtures();

    it("has the required stringify cases", () => {
        const names = f.stringify.map((c) => c.name);
        expect(names.length).toBeGreaterThanOrEqual(12);
        for (const n of [
            "nested-sorted-keys",
            "unicode-keys-and-values",
            "floats",
            "integers-large",
            "arrays-with-nulls",
            "empty-objects-pruned",
            "negative-zero",
            "exponent-small",
            "exponent-large",
            "booleans",
            "server-merge-example",
            "escape-chars",
        ]) {
            expect(names).toContain(n);
        }
    });

    it("has the required number values", () => {
        const values = f.numbers.map((n) => n.value);
        for (const v of [
            0.1, 1e21, 1e-7, 123456789012345680000, -0, 5e-324, 1.7976931348623157e308, 0.000001,
            100, 1.5,
        ]) {
            expect(values.some((x) => Object.is(x, v) || (v === 0 && x === 0))).toBe(true);
        }
        for (const n of f.numbers) expect(n.expected).toBe(String(n.value));
    });

    it("drops canvas, fonts and speech for Firefox with stabilize private", () => {
        const c = f.filter.find(
            (x) =>
                (x.options.stabilize as string[] | undefined)?.includes("private") &&
                (x.components as any).system?.browser?.name === "Firefox",
        );
        expect(c).toBeDefined();
        expect(c?.filtered).not.toHaveProperty("canvas");
        expect(c?.filtered).not.toHaveProperty("fonts");
        expect(c?.filtered).not.toHaveProperty("speech");
        expect(c?.filtered).toHaveProperty("math");
    });

    it("keeps only tls.ja4 for include/exclude case", () => {
        const c = f.filter.find(
            (x) => x.options.include?.includes("tls.ja4") && x.options.exclude?.includes("tls"),
        );
        expect(c).toBeDefined();
        const ja4 = (c?.components as any)?.tls?.ja4;
        expect(ja4).toBeDefined();
        expect((c?.filtered as any)?.tls).toEqual({ ja4 });
    });

    it("is deterministic", () => {
        expect(JSON.stringify(buildFixtures())).toBe(JSON.stringify(buildFixtures()));
    });
});
