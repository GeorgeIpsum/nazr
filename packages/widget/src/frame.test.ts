import { describe, expect, it, vi } from "vitest";
import { type FrameMessage, reportFromFrame } from "./frame";

type Deps = Parameters<typeof reportFromFrame>[0];

const ID = "01HXABCDEFGHJKMNPQRSTVWXYZ";

function b64url(s: string): string {
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const CHALLENGE = `${b64url(
  JSON.stringify({ id: ID, exp: 1893456000, bits: 8, kid: "k", origin: "https://shop.example" }),
)}.mac`;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

interface Opts {
  search?: string;
  challenge?: string | null;
  fetchImpl?: () => Promise<Response>;
  solveImpl?: () => Promise<string>;
}

function makeDeps(o: Opts = {}) {
  const script = document.createElement("script");
  const challenge = o.challenge === undefined ? CHALLENGE : o.challenge;
  if (challenge !== null) script.dataset.challenge = challenge;
  script.dataset.powBits = "8";
  script.dataset.origin = "https://shop.example";
  script.dataset.worker = "/widget/v1/worker.x.js";
  const getThumbmark = vi.fn(async () => ({ thumbmark: "deadbeef", components: { a: 1 } }));
  const fetch = vi.fn(o.fetchImpl ?? (async () => json({ verdict: "pass", token: "t.o.k" })));
  const solve = vi.fn(o.solveImpl ?? (async () => "42"));
  const messages: FrameMessage[] = [];
  const deps: Deps = {
    script,
    location: { search: o.search ?? "?k=nzr_x" } as Location,
    fetch: fetch as unknown as typeof globalThis.fetch,
    getThumbmark: getThumbmark as unknown as Deps["getThumbmark"],
    solve,
    post: (m) => messages.push(m),
  };
  return { deps, fetch, getThumbmark, solve, messages };
}

describe("reportFromFrame", () => {
  it("posts the challenge, reports, then posts the token", async () => {
    const { deps, fetch, solve, getThumbmark, messages } = makeDeps();
    await reportFromFrame(deps);
    expect(messages).toEqual([
      { type: "nazr:challenge", id: ID },
      { type: "nazr:token", token: "t.o.k" },
    ]);
    expect(solve).toHaveBeenCalledWith(ID, 8);
    expect((getThumbmark.mock.calls[0] as unknown[])[0]).toEqual({
      collect_beacon: false,
      cache_api_call: false,
    });
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/widget/report");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "x-api-key": "nzr_x", "Content-Type": "application/json" });
    expect(JSON.parse(init.body as string)).toEqual({
      challenge: CHALLENGE,
      pow: "42",
      components: { a: 1 },
      clientHash: "deadbeef",
    });
  });

  it.each(["inconclusive", "pow_failed", "invalid"])("relays verdict %s", async (verdict) => {
    const { deps, messages } = makeDeps({ fetchImpl: async () => json({ verdict }) });
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: verdict });
  });

  it("maps an unknown verdict to network", async () => {
    const { deps, messages } = makeDeps({ fetchImpl: async () => json({ verdict: "weird" }) });
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "network" });
  });

  it("reports network when fetch rejects", async () => {
    const { deps, messages } = makeDeps({ fetchImpl: () => Promise.reject(new TypeError("x")) });
    await expect(reportFromFrame(deps)).resolves.toBeUndefined();
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "network" });
  });

  it("reports network on a 500", async () => {
    const { deps, messages } = makeDeps({ fetchImpl: async () => json({}, 500) });
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "network" });
  });

  it("reports network on unparsable JSON", async () => {
    const { deps, messages } = makeDeps({ fetchImpl: async () => new Response("nope") });
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "network" });
  });

  it("reports network when the worker fails", async () => {
    const { deps, fetch, messages } = makeDeps({ solveImpl: () => Promise.reject(new Error("w")) });
    await expect(reportFromFrame(deps)).resolves.toBeUndefined();
    expect(fetch).not.toHaveBeenCalled();
    expect(messages).toEqual([
      { type: "nazr:challenge", id: ID },
      { type: "nazr:error", reason: "network" },
    ]);
  });

  it("reports invalid without fetching for a malformed challenge", async () => {
    const { deps, fetch, messages } = makeDeps({ challenge: "!!!.mac" });
    await reportFromFrame(deps);
    expect(fetch).not.toHaveBeenCalled();
    expect(messages).toEqual([{ type: "nazr:error", reason: "invalid" }]);
  });

  it("stays silent when k is missing", async () => {
    const { deps, fetch, messages } = makeDeps({ search: "?n=abc" });
    await reportFromFrame(deps);
    expect(fetch).not.toHaveBeenCalled();
    expect(messages).toEqual([]);
  });

  it("stays silent when data-challenge is missing or empty", async () => {
    for (const challenge of [null, ""]) {
      const { deps, fetch, messages } = makeDeps({ challenge });
      await reportFromFrame(deps);
      expect(fetch).not.toHaveBeenCalled();
      expect(messages).toEqual([]);
    }
  });
});
