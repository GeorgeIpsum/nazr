import { getCommonPixels } from "./commonPixels";
import { hash } from "./hash";

export interface CanvasProbe {
    draw: (ctx: CanvasRenderingContext2D, canvas: HTMLCanvasElement) => void;
    width?: number;
    height?: number;
}

export const PROBE_DEFAULT_WIDTH = 280;
export const PROBE_DEFAULT_HEIGHT = 20;

const _RUNS = 3;

function renderProbe(probe: CanvasProbe, width: number, height: number): ImageData | null {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext("2d");
    if (!ctx) {
        return null;
    }
    probe.draw(ctx, canvas);
    return ctx.getImageData(0, 0, canvas.width, canvas.height);
}

/**
 * Hash of the consumer-drawn canvas, or null on any failure. Never throws.
 */
export function computeCanvasProbe(probe: CanvasProbe): string | null {
    try {
        const width = probe.width ?? PROBE_DEFAULT_WIDTH;
        const height = probe.height ?? PROBE_DEFAULT_HEIGHT;
        const images: ImageData[] = [];
        for (let i = 0; i < _RUNS; i++) {
            const image = renderProbe(probe, width, height);
            if (!image) {
                return null;
            }
            images.push(image);
        }
        const common = getCommonPixels(images, width, height);
        return hash(common.data.toString());
    } catch {
        return null;
    }
}

/** True when the probe renders identically to a same-size no-op draw. */
export function isBlankProbe(probe: CanvasProbe): boolean {
    return computeCanvasProbe(probe) === computeCanvasProbe({ ...probe, draw: () => {} });
}
