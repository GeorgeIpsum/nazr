import type { componentInterface } from "../../factory";

type Brand = { brand: string; version: string };

const HIGH_ENTROPY_KEYS = [
    "architecture",
    "bitness",
    "model",
    "platformVersion",
    "fullVersionList",
    "wow64",
];

function formatBrands(list: Brand[] | undefined): string[] {
    return (list ?? []).map((b) => `${b.brand}/${b.version}`).sort();
}

export default async function getClientHints(): Promise<componentInterface | null> {
    const uad = (navigator as any).userAgentData;
    if (!uad) return null;

    const result: componentInterface = {
        brands: formatBrands(uad.brands),
        mobile: uad.mobile === true,
        platform: typeof uad.platform === "string" ? uad.platform : "",
    };

    try {
        const high = await uad.getHighEntropyValues(HIGH_ENTROPY_KEYS);
        for (const key of ["architecture", "bitness", "model", "platformVersion"]) {
            if (typeof high[key] === "string") result[key] = high[key];
        }
        if (Array.isArray(high.fullVersionList)) {
            result.fullVersionList = formatBrands(high.fullVersionList);
        }
        if (typeof high.wow64 === "boolean") result.wow64 = high.wow64;
    } catch {
        // high-entropy hints unavailable or denied; keep low-entropy fields
    }
    return result;
}
