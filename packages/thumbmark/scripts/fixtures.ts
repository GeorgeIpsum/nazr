import { filterThumbmarkData } from "../src/functions/filterComponents";
import type { optionsInterface } from "../src/options";
import { hash } from "../src/utils/hash";
import { stableStringify } from "../src/utils/stableStringify";

export interface StringifyCase {
    name: string;
    input: unknown;
    stringified: string;
    hash: string;
}
export interface NumberCase {
    value: number;
    expected: string;
}
export interface FilterCase {
    name: string;
    components: Record<string, any>;
    options: optionsInterface;
    filtered: Record<string, any>;
}

const serverMerge = {
    system: {
        applePayVersion: 0,
        browser: { name: "Chrome", version: "126.0.0" },
        cookieEnabled: true,
        hardwareConcurrency: 8,
        language: "en-US",
        platform: "MacIntel",
        productSub: "20030107",
        useragent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        vendor: "Google Inc.",
    },
    screen: { colorDepth: 24, pixelDepth: 24, width: 1728, height: 1117, is_touchscreen: false },
    locales: { languages: "en-US", timezone: "America/New_York" },
    math: { acos: 1.0471975511965979, asinh: 0.881373587019543, cosh: 1.5430806348152437 },
    webgl: {
        vendor: "Google Inc. (Apple)",
        renderer: "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
    },
    tls: {
        version: "TLSv1.3",
        ja4: "t13d1516h2_8daaf6152771_02713d6af862",
        ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        ja3_hash: "cd08e31494f9531f560d64c695473da9",
        ciphers: [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        extensions: ["0", "23", "65281", "10", "11", "35", "16", "5", "13", "18", "51", "45", "43"],
        sni: true,
        alpn: ["h2", "http/1.1"],
        sig_algs: ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256"],
        groups: ["x25519", "secp256r1", "secp384r1"],
    },
    h2: {
        fingerprint: "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
        settings: { "1": 65536, "2": 0, "4": 6291456, "6": 262144 },
        window_update: 15663105,
        priorities: [],
        pseudo_header_order: [":method", ":authority", ":scheme", ":path"],
    },
    header: {
        ja4h: "ge11cn20enus_a1b2c3d4e5f6_000000000000_000000000000",
        order: ["host", "connection", "user-agent", "accept", "accept-encoding", "accept-language"],
        userAgent:
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        acceptLanguage: { raw: "en-US,en;q=0.9", q: { "en-US": 1, en: 0.9 } },
    },
    ip: {
        address: "203.0.113.42",
        version: 4,
        asn: 64496,
        as_org: "Example Networks",
        country: "US",
        region: "NY",
        city: "New York",
        tor: false,
        vpn: false,
        datacenter: false,
        private_relay: false,
    },
};

const stringifyInputs: [string, unknown][] = [
    ["nested-sorted-keys", { b: { z: 1, y: [3, { d: 1, c: 2 }], x: "s" }, a: 1, C: 2 }],
    [
        "unicode-keys-and-values",
        {
            "￿": 1,
            "\u{1F600}": 2,
            é: 3,
            z: "a b \u{1F600}   end",
            "퟿": 4,
            "": 5,
        },
    ],
    ["floats", { a: 0.1, b: 1.5, c: -2.25, d: Math.PI, e: 0.000001, f: 1 / 3 }],
    [
        "integers-large",
        { a: 0, b: 100, c: 9007199254740991, d: -9007199254740991, e: 123456789012345680000 },
    ],
    ["arrays-with-nulls", { a: [1, null, "x", [null, []], {}], b: null }],
    ["empty-containers-kept", { a: {}, b: { c: {} }, d: [], e: [{}], f: { g: 1 } }],
    ["exponent-small", { a: 1e-7, b: 5e-324, c: 1.5e-10, d: -1e-7 }],
    ["exponent-large", { a: 1e21, b: 1.7976931348623157e308, c: 1.5e300, d: -1e21 }],
    ["booleans", { t: true, f: false, arr: [true, false] }],
    ["server-merge-example", serverMerge],
    [
        "escape-chars",
        {
            quote: 'say "hi"',
            backslash: "a\\b",
            newline: "l1\nl2",
            tab: "a\tb",
            ctrl: "x\u0001y",
            html: '<a href="x">&</a>',
            'k"ey\\': "v",
        },
    ],
    ["line-separators", { ls: "a\u2028b", ps: "c\u2029d", both: "\u2028\u2029" }],
    ["del-char", { del: "x\u007Fy", only: "\u007F" }],
    ["empty-string-and-root-values", { "": "", a: "" }],
    ["root-array", [3, "a", { b: 1, a: 2 }]],
];

const numberValues = [
    0,
    -0,
    1,
    -1,
    100,
    1.5,
    0.1,
    0.2,
    0.30000000000000004,
    0.000001,
    1e-7,
    1.5e-7,
    123456789,
    9007199254740991,
    1e20,
    123456789012345680000,
    1e21,
    1.5e21,
    5e-324,
    1.7976931348623157e308,
    2.2250738585072014e-308,
    4.35,
    1.005,
    1 / 3,
];

const baseClient = {
    system: { browser: { name: "Chrome", version: "126.0.0" }, platform: "MacIntel" },
    canvas: { commonImageDataHash: "abc123", dataURL: "data:image/png;base64,AAAA" },
    fonts: { Arial: 120.5, Helvetica: 98.25 },
    speech: { default: "Samantha", voices: ["Samantha", "Alex"] },
    audio: { sampleHash: 124.04347527516074, maxChannels: 6 },
    math: { acos: 1.0471975511965979 },
};

function withBrowser(name: string, version: string) {
    return { ...baseClient, system: { ...baseClient.system, browser: { name, version } } };
}

const filterInputs: [string, Record<string, any>, optionsInterface][] = [
    ["no-options", baseClient, {}],
    ["firefox-stabilize-private", withBrowser("Firefox", "128.0"), { stabilize: ["private"] }],
    ["chrome-stabilize-private", withBrowser("Chrome", "126.0.0"), { stabilize: ["private"] }],
    ["safari-17-stabilize-private", withBrowser("Safari", "17.4"), { stabilize: ["private"] }],
    ["safari-16-stabilize-private", withBrowser("Safari", "16.6"), { stabilize: ["private"] }],
    ["firefox-always-only", withBrowser("Firefox", "128.0"), {}],
    [
        "exclude-prefix",
        { ...baseClient, hardware: { deviceMemory: 8, cores: 8 } },
        { exclude: ["hardware.deviceMemory", "fonts"] },
    ],
    [
        "include-overrides-exclude",
        {
            tls: {
                ja4: "t13d1516h2_8daaf6152771_02713d6af862",
                ja3: "771,4865",
                version: "TLSv1.3",
            },
            math: { a: 1 },
        },
        { include: ["tls.ja4"], exclude: ["tls"] },
    ],
    [
        "server-merge-brave-private",
        {
            ...serverMerge,
            system: { ...serverMerge.system, browser: { name: "Brave", version: "1.67.0" } },
        },
        { stabilize: ["private"] },
    ],
    ["server-merge-chrome-private", serverMerge, { stabilize: ["private"] }],
    ["include-only", { ...serverMerge }, { include: ["screen", "tls"] }],
    [
        "stabilize-vpn",
        { ...baseClient, ip: { address: "203.0.113.42", version: 4, vpn: true } },
        { stabilize: ["vpn"] },
    ],
    [
        "stabilize-iframe",
        {
            ...baseClient,
            system: {
                browser: { name: "Safari", version: "17.4" },
                platform: "MacIntel",
                applePayVersion: 14,
                cookieEnabled: true,
            },
            permissions: { geolocation: "prompt", notifications: "denied" },
        },
        { stabilize: ["iframe"] },
    ],
    [
        "unknown-browser",
        {
            system: { platform: "MacIntel", cookieEnabled: true },
            canvas: baseClient.canvas,
            fonts: baseClient.fonts,
            speech: baseClient.speech,
            audio: baseClient.audio,
        },
        { stabilize: ["private"] },
    ],
];

/**
 * filterThumbmarkData reads the browser from `navigator` first and only falls
 * back to components.system.browser when navigator is undefined (the server
 * path the Go API reproduces). Under jsdom navigator exists, so hide it while
 * computing filter cases to keep the fixtures environment independent.
 */
export function withoutNavigator<T>(fn: () => T): T {
    const g = globalThis as any;
    const own = Object.getOwnPropertyDescriptor(g, "navigator");
    Object.defineProperty(g, "navigator", { value: undefined, configurable: true, writable: true });
    try {
        return fn();
    } finally {
        if (own) Object.defineProperty(g, "navigator", own);
        else delete g.navigator;
    }
}

export function buildFixtures(): {
    stringify: StringifyCase[];
    numbers: NumberCase[];
    filter: FilterCase[];
} {
    const stringify = stringifyInputs.map(([name, input]) => {
        const stringified = stableStringify(input);
        return { name, input, stringified, hash: hash(stringified) };
    });
    const numbers = numberValues.map((value) => ({ value, expected: String(value) }));
    const filter = withoutNavigator(() =>
        filterInputs.map(([name, components, options]) => ({
            name,
            components,
            options,
            filtered: filterThumbmarkData(components, options),
        })),
    );
    return { stringify, numbers, filter };
}
