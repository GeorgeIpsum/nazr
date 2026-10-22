import type { componentInterface } from "../../factory";

const LIMIT_KEYS = [
    "maxTextureDimension2D",
    "maxBufferSize",
    "maxComputeWorkgroupSizeX",
    "maxBindGroups",
    "maxStorageBufferBindingSize",
] as const;

export default async function getWebGPU(): Promise<componentInterface | null> {
    const gpu = (navigator as any).gpu;
    if (!gpu) return null;

    try {
        const adapter = await gpu.requestAdapter();
        if (!adapter) return { supported: false };

        let info = adapter.info;
        if (!info && typeof adapter.requestAdapterInfo === "function") {
            info = await adapter.requestAdapterInfo();
        }

        const result: componentInterface = { supported: true };
        if (info) {
            for (const key of ["vendor", "architecture", "device", "description"]) {
                if (typeof info[key] === "string") result[key] = info[key];
            }
        }
        result.features = adapter.features ? (Array.from(adapter.features) as string[]).sort() : [];

        const limits: componentInterface = {};
        for (const key of LIMIT_KEYS) {
            const v = adapter.limits?.[key];
            if (typeof v === "number") limits[key] = v;
        }
        result.limits = limits;
        return result;
    } catch {
        return { supported: false };
    }
}
