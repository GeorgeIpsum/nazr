import { tm_component_promises } from "./factory";

test("registers exactly the 18 built-in components", () => {
    expect(Object.keys(tm_component_promises).sort()).toEqual(
        [
            "audio",
            "canvas",
            "clienthints",
            "clientrects",
            "fonts",
            "hardware",
            "locales",
            "math",
            "mediaqueries",
            "permissions",
            "plugins",
            "privacy",
            "screen",
            "speech",
            "system",
            "webgl",
            "webgpu",
            "webrtc",
        ].sort(),
    );
});
