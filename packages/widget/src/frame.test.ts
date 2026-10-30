import { describe, expect, it, vi } from "vitest";
import { reportFromFrame } from "./frame";

type Deps = Parameters<typeof reportFromFrame>[0];

function makeDeps(search: string, fetchImpl?: () => Promise<Response>) {
  const getThumbmark = vi.fn(async () => ({
    thumbmark: "deadbeef",
    components: { a: 1 },
  }));
  const fetch = vi.fn(fetchImpl ?? (async () => new Response(null, { status: 204 })));
  const deps = {
    location: { search } as Location,
    fetch: fetch as unknown as typeof globalThis.fetch,
    getThumbmark: getThumbmark as unknown as Deps["getThumbmark"],
  };
  return { deps, fetch, getThumbmark };
}

describe("reportFromFrame", () => {
  it("posts the components, nonce and client hash to /widget/report", async () => {
    const { deps, fetch } = makeDeps("?k=nzr_x&n=abc");
    await reportFromFrame(deps);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/widget/report");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "x-api-key": "nzr_x", "Content-Type": "application/json" });
    expect(JSON.parse(init.body as string)).toEqual({
      nonce: "abc",
      components: { a: 1 },
      clientHash: "deadbeef",
    });
  });

  it("computes locally without an api_key", async () => {
    const { deps, getThumbmark } = makeDeps("?k=nzr_x&n=abc");
    await reportFromFrame(deps);
    expect(getThumbmark).toHaveBeenCalledTimes(1);
    const options = (getThumbmark.mock.calls[0] as unknown[])[0];
    expect(options).toEqual({ collect_beacon: false, cache_api_call: false });
    expect(options).not.toHaveProperty("api_key");
  });

  it("does not fetch when k is missing", async () => {
    const { deps, fetch } = makeDeps("?n=abc");
    await reportFromFrame(deps);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("resolves without throwing when fetch rejects", async () => {
    const { deps, fetch } = makeDeps("?k=nzr_x&n=abc", () =>
      Promise.reject(new TypeError("network")),
    );
    await expect(reportFromFrame(deps)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
