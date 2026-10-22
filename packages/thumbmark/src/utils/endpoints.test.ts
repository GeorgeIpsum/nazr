import { resolveCollectEndpoint, resolveLogEndpoint } from "./endpoints";

test.each([
    ["https://api.example.com", "https://api.example.com/log"],
    ["https://api.example.com/", "https://api.example.com/log"],
    ["https://api.example.com/nazr/", "https://api.example.com/nazr/log"],
])("resolveLogEndpoint(%s)", (ep, want) =>
    expect(resolveLogEndpoint({ api_endpoint: ep })).toBe(want),
);
test("resolveLogEndpoint falls back to hosted default", () =>
    expect(resolveLogEndpoint({})).toBe("https://api.thumbmarkjs.com/log"));
test("resolveCollectEndpoint prefers explicit collect_endpoint", () =>
    expect(
        resolveCollectEndpoint({ api_endpoint: "https://a", collect_endpoint: "https://c/b" }),
    ).toBe("https://c/b"));
test("resolveCollectEndpoint derives /beacon from api_endpoint", () =>
    expect(resolveCollectEndpoint({ api_endpoint: "https://a/" })).toBe("https://a/beacon"));
test("resolveCollectEndpoint falls back to hosted default", () =>
    expect(resolveCollectEndpoint({})).toBe("https://collect.thumbmarkjs.com/beacon"));
