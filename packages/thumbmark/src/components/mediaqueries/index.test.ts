import getMediaQueries from "./index";

const origMatchMedia = window.matchMedia;
const origDpr = window.devicePixelRatio;

function mockMatch(truthy: string[]) {
    window.matchMedia = jest.fn((q: string) => ({ matches: truthy.includes(q) })) as any;
}
function setDpr(v: number) {
    Object.defineProperty(window, "devicePixelRatio", { value: v, configurable: true });
}

afterEach(() => {
    window.matchMedia = origMatchMedia;
    setDpr(origDpr);
});

test("resolves null when window.matchMedia is undefined", async () => {
    (window as any).matchMedia = undefined;
    expect(await getMediaQueries()).toBeNull();
});

test("resolves null when matchMedia throws", async () => {
    window.matchMedia = jest.fn(() => {
        throw new Error("boom");
    }) as any;
    expect(await getMediaQueries()).toBeNull();
});

test("picks the widest gamut that matches", async () => {
    mockMatch(["(color-gamut: p3)", "(color-gamut: srgb)"]);
    expect(((await getMediaQueries()) as any).colorGamut).toBe("p3");
    mockMatch(["(color-gamut: rec2020)", "(color-gamut: p3)", "(color-gamut: srgb)"]);
    expect(((await getMediaQueries()) as any).colorGamut).toBe("rec2020");
    mockMatch(["(color-gamut: srgb)"]);
    expect(((await getMediaQueries()) as any).colorGamut).toBe("srgb");
});

test("reports 'none' when nothing matches", async () => {
    mockMatch([]);
    expect(await getMediaQueries()).toEqual({
        colorGamut: "none",
        dynamicRange: "none",
        videoDynamicRange: "none",
        colorScheme: "none",
        displayMode: "none",
        reducedData: "none",
        dprBucket: String(Math.round(origDpr * 100) / 100),
    });
});

test("maps the other features to their matching values", async () => {
    mockMatch([
        "(dynamic-range: high)",
        "(dynamic-range: standard)",
        "(video-dynamic-range: standard)",
        "(prefers-color-scheme: dark)",
        "(display-mode: standalone)",
        "(display-mode: browser)",
        "(prefers-reduced-data: no-preference)",
    ]);
    const r: any = await getMediaQueries();
    expect(r.dynamicRange).toBe("high");
    expect(r.videoDynamicRange).toBe("standard");
    expect(r.colorScheme).toBe("dark");
    expect(r.displayMode).toBe("standalone");
    expect(r.reducedData).toBe("no-preference");
});

test("dprBucket is '2' for DPR 2 and rounds to 2 decimals", async () => {
    mockMatch([]);
    setDpr(2);
    expect(((await getMediaQueries()) as any).dprBucket).toBe("2");
    setDpr(1.3333333);
    expect(((await getMediaQueries()) as any).dprBucket).toBe("1.33");
});
