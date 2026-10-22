import getClientHints from "./index";

function setUAD(value: unknown) {
    Object.defineProperty(navigator, "userAgentData", { value, configurable: true });
}

afterEach(() => {
    delete (navigator as any).userAgentData;
});

const low = {
    brands: [
        { brand: "Chromium", version: "120" },
        { brand: "Google Chrome", version: "120" },
        { brand: "Not A Brand", version: "8" },
    ],
    mobile: false,
    platform: "macOS",
};

test("resolves null without navigator.userAgentData", async () => {
    delete (navigator as any).userAgentData;
    expect(await getClientHints()).toBeNull();
});

test("resolves low-entropy fields when getHighEntropyValues rejects", async () => {
    setUAD({ ...low, getHighEntropyValues: jest.fn().mockRejectedValue(new Error("denied")) });
    expect(await getClientHints()).toEqual({
        brands: ["Chromium/120", "Google Chrome/120", "Not A Brand/8"],
        mobile: false,
        platform: "macOS",
    });
});

test("merges high-entropy values and sorts brand lists", async () => {
    const getHigh = jest.fn().mockResolvedValue({
        architecture: "arm",
        bitness: "64",
        model: "",
        platformVersion: "14.1.0",
        wow64: false,
        fullVersionList: [
            { brand: "Not A Brand", version: "8.0.0.0" },
            { brand: "Chromium", version: "120.0.1.2" },
        ],
    });
    setUAD({ ...low, brands: [...low.brands].reverse(), getHighEntropyValues: getHigh });
    expect(await getClientHints()).toEqual({
        brands: ["Chromium/120", "Google Chrome/120", "Not A Brand/8"],
        mobile: false,
        platform: "macOS",
        architecture: "arm",
        bitness: "64",
        model: "",
        platformVersion: "14.1.0",
        fullVersionList: ["Chromium/120.0.1.2", "Not A Brand/8.0.0.0"],
        wow64: false,
    });
    expect(getHigh).toHaveBeenCalledWith([
        "architecture",
        "bitness",
        "model",
        "platformVersion",
        "fullVersionList",
        "wow64",
    ]);
});
