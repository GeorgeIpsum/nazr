import { defaultOptions } from "../options";
import { logThumbmarkData } from "./log";

describe("logThumbmarkData", () => {
    let fetchMock: jest.Mock;

    function loggedPayload() {
        const call = fetchMock.mock.calls.find(([url]) => url.includes("/log"));
        return JSON.parse(call![1].body);
    }

    beforeEach(() => {
        sessionStorage.clear();
        fetchMock = jest.fn(() => Promise.resolve({ ok: true, status: 200 }));
        global.fetch = fetchMock as unknown as typeof fetch;
    });

    test("posts to ${api_endpoint}/log when api_endpoint is provided", async () => {
        await logThumbmarkData(
            "abc123",
            {},
            { ...defaultOptions, api_endpoint: "https://self.example/" },
        );

        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(fetchMock.mock.calls[0][0]).toBe("https://self.example/log");
    });

    test("does not send api_key in the logged options", async () => {
        await logThumbmarkData("abc123", {}, { ...defaultOptions, api_key: "secret-key" });

        expect(loggedPayload().options).not.toHaveProperty("api_key");
        expect(JSON.stringify(fetchMock.mock.calls[0][1])).not.toContain("secret-key");
    });

    test("sends experimental as null and never contacts the experimental host", async () => {
        await logThumbmarkData("abc123", { screen: { width: 100 } }, defaultOptions);

        expect(loggedPayload().experimental).toBeNull();
        expect(loggedPayload().thumbmark).toBe("abc123");
        for (const [url] of fetchMock.mock.calls) {
            expect(url).not.toContain("experimental.thumbmarkjs.com");
        }
    });

    test("marks the session before doing any network work", async () => {
        let markedDuringFetch: string | null = null;
        fetchMock.mockImplementation(() => {
            markedDuringFetch = sessionStorage.getItem("_tmjs_l");
            return Promise.resolve({ ok: true, status: 200 });
        });

        await logThumbmarkData("abc123", {}, defaultOptions);

        expect(markedDuringFetch).toBe("1");
    });

    test("never rejects when the log endpoint is down", async () => {
        fetchMock.mockImplementation(() => Promise.reject(new TypeError("Failed to fetch")));

        await expect(logThumbmarkData("abc123", {}, defaultOptions)).resolves.toBeUndefined();
    });

    test("posts errors only when there are some", async () => {
        await logThumbmarkData("abc123", {}, defaultOptions);
        expect(loggedPayload()).not.toHaveProperty("errors");

        fetchMock.mockClear();
        await logThumbmarkData("abc123", {}, defaultOptions, [
            {
                type: "component_timeout",
                message: "Component 'audio' timed out",
                component: "audio",
            },
        ]);
        expect(loggedPayload().errors).toHaveLength(1);
    });
});
