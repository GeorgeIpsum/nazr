import { afterEach, describe, expect, it, vi } from "vitest";
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
  solveImpl?: (id: string, bits: number) => Promise<string>;
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
    doc: document,
    now: () => performance.now(),
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

const STAGED = "c3RhZ2Vk.mac";
const OFFER = { verdict: "inconclusive", interactive: { challenge: STAGED, bits: 12 } };

/** Answers each fetch with the next body in turn. */
function sequence(...bodies: unknown[]): () => Promise<Response> {
  let i = 0;
  return async () => json(bodies[Math.min(i++, bodies.length - 1)]);
}

async function button(): Promise<HTMLButtonElement> {
  return vi.waitFor(() => {
    const b = document.querySelector("button");
    if (!b) throw new Error("no button yet");
    return b;
  });
}

function press(b: HTMLButtonElement): void {
  b.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true, cancelable: true }));
}

describe("reportFromFrame interactive step", () => {
  afterEach(() => {
    document.body.innerHTML = "";
  });

  it("renders, records, solves the harder challenge and relays the token", async () => {
    const { deps, fetch, solve, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence(OFFER, { verdict: "interactive", token: "t.o.k" }),
      solveImpl: async (_id, bits) => (bits === 12 ? "4242" : "42"),
    });
    const done = reportFromFrame(deps);
    const b = await button();
    expect(b.textContent).toBe("Verify you are human");
    press(b);
    await done;
    expect(messages).toEqual([
      { type: "nazr:challenge", id: ID },
      { type: "nazr:interactive" },
      { type: "nazr:token", token: "t.o.k" },
    ]);
    expect(solve.mock.calls).toEqual([
      [ID, 8],
      [ID, 12],
    ]);
    expect(fetch).toHaveBeenCalledTimes(2);
    const [url, init] = fetch.mock.calls[1] as unknown as [string, RequestInit];
    expect(url).toBe("/widget/interact");
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual({ "x-api-key": "nzr_x", "Content-Type": "application/json" });
    const body = JSON.parse(init.body as string);
    expect(Object.keys(body).sort()).toEqual(["challenge", "pow", "trace"]);
    expect(body.challenge).toBe(STAGED);
    expect(body.pow).toBe("4242");
    expect(body.trace.input).toBe("keyboard");
    expect(Object.keys(body.trace).sort()).toEqual([
      "click_ms",
      "input",
      "moves",
      "path_px",
      "pointer_type",
      "shown_ms",
      "straightness",
      "trusted",
      "visible",
    ]);
    expect(b.textContent).toContain("Verified");
  });

  it("waits for the solution when the click comes first", async () => {
    let resolveSecond: (c: string) => void = () => {};
    const { deps, fetch, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence(OFFER, { verdict: "interactive", token: "t.o.k" }),
      solveImpl: (_id, bits) =>
        bits === 12
          ? new Promise<string>((r) => {
              resolveSecond = r;
            })
          : Promise.resolve("42"),
    });
    const done = reportFromFrame(deps);
    const b = await button();
    press(b);
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(b.textContent).toBe("Verifying…");
    expect(b.disabled).toBe(true);
    resolveSecond("777");
    await done;
    expect(fetch).toHaveBeenCalledTimes(2);
    const [, init] = fetch.mock.calls[1] as unknown as [string, RequestInit];
    expect(JSON.parse(init.body as string).pow).toBe("777");
    expect(messages[2]).toEqual({ type: "nazr:token", token: "t.o.k" });
  });

  it.each(["interactive_failed", "invalid"])("relays interact verdict %s", async (verdict) => {
    const { deps, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence(OFFER, { verdict }),
    });
    const done = reportFromFrame(deps);
    const b = await button();
    press(b);
    await done;
    expect(messages[2]).toEqual({ type: "nazr:error", reason: verdict });
    expect(b.textContent).toBe("Verification failed");
  });

  it.each([
    ["an unknown verdict", () => sequence(OFFER, { verdict: "pass", token: "t" })],
    ["interactive without a token", () => sequence(OFFER, { verdict: "interactive" })],
    [
      "a 500",
      () => {
        let i = 0;
        return async () => (i++ === 0 ? json(OFFER) : json({}, 500));
      },
    ],
    [
      "a rejected fetch",
      () => {
        let i = 0;
        return async () => {
          if (i++ === 0) return json(OFFER);
          throw new TypeError("x");
        };
      },
    ],
  ])("maps %s to network", async (_name, make) => {
    const { deps, messages } = makeDeps({ search: "?k=nzr_x&i=1", fetchImpl: make() });
    const done = reportFromFrame(deps);
    const b = await button();
    press(b);
    await expect(done).resolves.toBeUndefined();
    expect(messages[2]).toEqual({ type: "nazr:error", reason: "network" });
    expect(b.textContent).toBe("Verification failed");
  });

  it("maps a failed interactive proof-of-work to network without posting", async () => {
    const { deps, fetch, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence(OFFER),
      solveImpl: (_id, bits) =>
        bits === 12 ? Promise.reject(new Error("w")) : Promise.resolve("42"),
    });
    const done = reportFromFrame(deps);
    press(await button());
    await done;
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(messages[2]).toEqual({ type: "nazr:error", reason: "network" });
  });

  it("fails with invalid once the staged challenge expires before the click", async () => {
    vi.useFakeTimers({ now: 1_000_000_000_000 });
    try {
      const staged = `${b64url(JSON.stringify({ id: ID, exp: 1_000_000_060, bits: 12 }))}.mac`;
      const { deps, fetch, messages } = makeDeps({
        search: "?k=nzr_x&i=1",
        fetchImpl: sequence({
          verdict: "inconclusive",
          interactive: { challenge: staged, bits: 12 },
        }),
      });
      const done = reportFromFrame(deps);
      const b = await button();
      await vi.advanceTimersByTimeAsync(59_000);
      expect(messages).toHaveLength(2);
      await vi.advanceTimersByTimeAsync(1_000);
      await done;
      expect(messages).toEqual([
        { type: "nazr:challenge", id: ID },
        { type: "nazr:interactive" },
        { type: "nazr:error", reason: "invalid" },
      ]);
      expect(b.textContent).toBe("Verification failed");
      press(b);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(messages).toHaveLength(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it("answers inconclusive without i=1 and never renders", async () => {
    const { deps, fetch, solve, messages } = makeDeps({ fetchImpl: sequence(OFFER) });
    await reportFromFrame(deps);
    expect(messages).toEqual([
      { type: "nazr:challenge", id: ID },
      { type: "nazr:error", reason: "inconclusive" },
    ]);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(solve).toHaveBeenCalledTimes(1);
    expect(document.querySelector("button")).toBeNull();
  });

  it("answers inconclusive with i=1 but no offer", async () => {
    const { deps, fetch, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence({ verdict: "inconclusive" }),
    });
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "inconclusive" });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(document.querySelector("button")).toBeNull();
  });

  it("answers inconclusive with i=1 but no document", async () => {
    const { deps, fetch, messages } = makeDeps({
      search: "?k=nzr_x&i=1",
      fetchImpl: sequence(OFFER),
    });
    deps.doc = null;
    await reportFromFrame(deps);
    expect(messages[1]).toEqual({ type: "nazr:error", reason: "inconclusive" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});
