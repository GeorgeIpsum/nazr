import type { componentInterface } from "../../factory";

// Values are listed in priority order; the first match wins.
const FEATURES: Record<string, [feature: string, values: string[]]> = {
    colorGamut: ["color-gamut", ["rec2020", "p3", "srgb"]],
    dynamicRange: ["dynamic-range", ["high", "standard"]],
    videoDynamicRange: ["video-dynamic-range", ["high", "standard"]],
    colorScheme: ["prefers-color-scheme", ["dark", "light"]],
    displayMode: ["display-mode", ["fullscreen", "standalone", "minimal-ui", "browser"]],
    reducedData: ["prefers-reduced-data", ["reduce", "no-preference"]],
};

export default async function getMediaQueries(): Promise<componentInterface | null> {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return null;

    try {
        const result: componentInterface = {};
        for (const [key, [feature, values]] of Object.entries(FEATURES)) {
            result[key] =
                values.find((v) => window.matchMedia(`(${feature}: ${v})`).matches) ?? "none";
        }
        return result;
    } catch {
        return null;
    }
}
