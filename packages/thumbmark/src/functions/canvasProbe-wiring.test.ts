import * as hashModule from "../utils/hash";
import { getThumbmark } from "./index";

class MockImageData {
    data: Uint8ClampedArray;
    width: number;
    height: number;

    constructor(pixelData: Uint8ClampedArray | number[], width: number, height: number) {
        this.width = width;
        this.height = height;
        this.data = new Uint8ClampedArray(pixelData);
    }
}

(global as any).ImageData = MockImageData;

let returnNullContext = false;
const originalGetContext = HTMLCanvasElement.prototype.getContext;

function makeFakeContext() {
    const ops: string[] = [];
    return {
        set fillStyle(v: string) {
            ops.push(`fillStyle=${v}`);
        },
        fillRect(x: number, y: number, w: number, h: number) {
            ops.push(`fillRect(${x},${y},${w},${h})`);
        },
        getImageData(_x: number, _y: number, w: number, h: number) {
            const bytes = new Uint8ClampedArray(w * h * 4);
            const joined = ops.join("|");
            for (let i = 0; i < bytes.length; i++) {
                bytes[i] = joined.charCodeAt(i % Math.max(joined.length, 1)) || 0;
            }
            return new ImageData(bytes, w, h);
        },
    };
}

const fillRect = (ctx: CanvasRenderingContext2D) => {
    ctx.fillStyle = "red";
    ctx.fillRect(0, 0, 10, 10);
};

// include a nonexistent component so no real component runs; only the API call matters.
const baseOpts = {
    simple_request: true,
    cache_api_call: false,
    include: ["__none__"],
    timeout: 5000,
};

let mockFetch: jest.Mock;
let warnSpy: jest.SpyInstance;

beforeAll(() => {
    if (typeof TextEncoder === "undefined") {
        const util = require("node:util");
        global.TextEncoder = util.TextEncoder;
        global.TextDecoder = util.TextDecoder;
    }
});

beforeEach(() => {
    returnNullContext = false;
    HTMLCanvasElement.prototype.getContext = (() =>
        returnNullContext ? null : makeFakeContext()) as any;
    localStorage.clear();
    mockFetch = jest.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ thumbmark: "ok" }),
    });
    global.fetch = mockFetch;
    // Avoid TextEncoder/realm issues in jsdom (same approach as api.test.ts).
    jest.spyOn(hashModule, "hash").mockImplementation((v: any) => {
        // Input-dependent stand-in so blank vs drawn probes hash differently.
        const str = String(v);
        let h = 0;
        for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
        return `h${h}`;
    });
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
});

afterEach(() => {
    warnSpy.mockRestore();
    jest.restoreAllMocks();
});

afterAll(() => {
    HTMLCanvasElement.prototype.getContext = originalGetContext;
});

function sentBody() {
    expect(mockFetch).toHaveBeenCalledTimes(1);
    return JSON.parse(mockFetch.mock.calls[0][1].body);
}

describe("canvas_probe wiring", () => {
    test("sends a non-empty canvas_probe when the option is set", async () => {
        await getThumbmark({ ...baseOpts, canvas_probe: { draw: fillRect } });
        const body = sentBody();
        expect(typeof body.canvas_probe).toBe("string");
        expect(body.canvas_probe.length).toBeGreaterThan(0);
        expect(body.components.canvas_probe).toBeUndefined();
        expect(body.options.canvas_probe).toBeUndefined();
        expect(warnSpy).not.toHaveBeenCalled();
    });

    test("omits the field when the option is not set", async () => {
        await getThumbmark({ ...baseOpts });
        expect("canvas_probe" in sentBody()).toBe(false);
    });

    test("warns exactly once, mentioning canvas_probe, for a blank draw", async () => {
        await getThumbmark({ ...baseOpts, canvas_probe: { draw: () => {} } });
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(String(warnSpy.mock.calls[0][0])).toContain("canvas_probe");
    });

    test("does not warn and omits the field when there is no 2d context", async () => {
        returnNullContext = true;
        await getThumbmark({ ...baseOpts, canvas_probe: { draw: () => {} } });
        expect("canvas_probe" in sentBody()).toBe(false);
        expect(warnSpy).not.toHaveBeenCalled();
    });
});
