import { filterThumbmarkData } from "../src/functions/filterComponents";
import { hash } from "../src/utils/hash";
import { stableStringify } from "../src/utils/stableStringify";
import { buildFixtures, withoutNavigator } from "./fixtures";

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
            "empty-containers-kept",
            "line-separators",
            "del-char",
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

    it("has the required filter cases", () => {
        const names = f.filter.map((c) => c.name);
        for (const n of ["include-only", "stabilize-vpn", "stabilize-iframe", "unknown-browser"]) {
            expect(names).toContain(n);
        }
        expect(f.filter.find((c) => c.name === "stabilize-vpn")?.filtered).not.toHaveProperty("ip");
        const iframe: any = f.filter.find((c) => c.name === "stabilize-iframe")?.filtered;
        expect(iframe).not.toHaveProperty("permissions");
        expect(iframe.system).not.toHaveProperty("applePayVersion");
        expect(iframe.system).not.toHaveProperty("cookieEnabled");
        // `include` only overrides `exclude`; it is not an allowlist, so alone it is a no-op.
        const inc = f.filter.find((c) => c.name === "include-only");
        expect(inc?.filtered).toEqual(inc?.components);
    });

    it("stringify cases match stableStringify and hash", () => {
        for (const c of f.stringify) {
            expect(c.stringified).toBe(stableStringify(c.input));
            expect(c.hash).toBe(hash(c.stringified));
        }
    });

    it("filter cases match filterThumbmarkData without navigator", () => {
        for (const c of f.filter) {
            expect(c.filtered).toEqual(
                withoutNavigator(() => filterThumbmarkData(c.components, c.options)),
            );
        }
    });

    it("restores navigator after building", () => {
        const before = Object.getOwnPropertyDescriptor(globalThis, "navigator");
        buildFixtures();
        expect(Object.getOwnPropertyDescriptor(globalThis, "navigator")).toEqual(before);
        expect(typeof navigator).toBe("object");
    });

    it("is deterministic", () => {
        expect(JSON.stringify(buildFixtures())).toBe(JSON.stringify(buildFixtures()));
    });
});
