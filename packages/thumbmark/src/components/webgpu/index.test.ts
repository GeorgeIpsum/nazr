import getWebGPU from "./index";

function setGpu(value: unknown) {
    Object.defineProperty(navigator, "gpu", { value, configurable: true });
}

afterEach(() => {
    delete (navigator as any).gpu;
});

const limits = {
    maxTextureDimension2D: 16384,
    maxBufferSize: 4294967296,
    maxComputeWorkgroupSizeX: 1024,
    maxBindGroups: 4,
    maxStorageBufferBindingSize: 134217728,
    maxOther: 1,
};

test("resolves null when navigator.gpu is absent", async () => {
    delete (navigator as any).gpu;
    expect(await getWebGPU()).toBeNull();
});

test("resolves { supported: false } when requestAdapter resolves null", async () => {
    setGpu({ requestAdapter: jest.fn().mockResolvedValue(null) });
    expect(await getWebGPU()).toEqual({ supported: false });
});

test("resolves { supported: false } when requestAdapter rejects", async () => {
    setGpu({ requestAdapter: jest.fn().mockRejectedValue(new Error("nope")) });
    expect(await getWebGPU()).toEqual({ supported: false });
});

test("reports adapter info, sorted features and selected limits", async () => {
    setGpu({
        requestAdapter: jest.fn().mockResolvedValue({
            info: { vendor: "apple", architecture: "metal-3", device: "", description: "M1" },
            features: new Set(["b", "a"]),
            limits,
        }),
    });
    expect(await getWebGPU()).toEqual({
        supported: true,
        vendor: "apple",
        architecture: "metal-3",
        device: "",
        description: "M1",
        features: ["a", "b"],
        limits: {
            maxTextureDimension2D: 16384,
            maxBufferSize: 4294967296,
            maxComputeWorkgroupSizeX: 1024,
            maxBindGroups: 4,
            maxStorageBufferBindingSize: 134217728,
        },
    });
});

test("falls back to requestAdapterInfo for legacy adapters", async () => {
    setGpu({
        requestAdapter: jest.fn().mockResolvedValue({
            requestAdapterInfo: jest
                .fn()
                .mockResolvedValue({ vendor: "nvidia", architecture: "ampere" }),
            features: new Set(),
            limits,
        }),
    });
    const r: any = await getWebGPU();
    expect(r.supported).toBe(true);
    expect(r.vendor).toBe("nvidia");
    expect(r.architecture).toBe("ampere");
    expect(r.features).toEqual([]);
});
