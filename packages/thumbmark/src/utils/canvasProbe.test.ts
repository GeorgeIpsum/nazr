import { computeCanvasProbe, isBlankProbe } from "./canvasProbe";

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

beforeEach(() => {
    returnNullContext = false;
    HTMLCanvasElement.prototype.getContext = (() =>
        returnNullContext ? null : makeFakeContext()) as any;
});

afterAll(() => {
    HTMLCanvasElement.prototype.getContext = originalGetContext;
});

const fillRed = (ctx: CanvasRenderingContext2D) => {
    ctx.fillStyle = "red";
    ctx.fillRect(0, 0, 10, 10);
};
const fillBlue = (ctx: CanvasRenderingContext2D) => {
    ctx.fillStyle = "blue";
    ctx.fillRect(0, 0, 10, 10);
};

describe("computeCanvasProbe", () => {
    test("returns a 32-hex-char hash", () => {
        expect(computeCanvasProbe({ draw: fillRed })).toMatch(/^[0-9a-f]{32}$/);
    });
    test("same draw gives same hash, different draw gives different hash", () => {
        expect(computeCanvasProbe({ draw: fillRed })).toBe(computeCanvasProbe({ draw: fillRed }));
        expect(computeCanvasProbe({ draw: fillRed })).not.toBe(
            computeCanvasProbe({ draw: fillBlue }),
        );
    });
    test("returns null when draw throws", () => {
        expect(
            computeCanvasProbe({
                draw: () => {
                    throw new Error("boom");
                },
            }),
        ).toBeNull();
    });
    test("returns null when the context is unavailable", () => {
        returnNullContext = true;
        expect(computeCanvasProbe({ draw: fillRed })).toBeNull();
    });
});

describe("isBlankProbe", () => {
    test("true for a no-op draw", () => {
        expect(isBlankProbe({ draw: () => {} })).toBe(true);
    });
    test("false for a draw that fills a rect", () => {
        expect(isBlankProbe({ draw: fillRed })).toBe(false);
    });
});
