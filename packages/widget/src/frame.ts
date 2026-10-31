import type { getThumbmark } from "@nazr/thumbmark";
import { renderInteractive } from "./interactive";

export type FrameMessage =
  | { type: "nazr:challenge"; id: string }
  | { type: "nazr:token"; token: string }
  | { type: "nazr:interactive" }
  | {
      type: "nazr:error";
      reason: "inconclusive" | "pow_failed" | "invalid" | "interactive_failed" | "network";
    };

export interface FrameDeps {
  script: HTMLScriptElement | null;
  location: Location;
  fetch: typeof fetch;
  getThumbmark: typeof getThumbmark;
  /** Solves the proof-of-work; an abort on signal stops the work and rejects. */
  solve: (id: string, bits: number, signal?: AbortSignal) => Promise<string>;
  post: (msg: FrameMessage) => void;
  doc: Document | null;
  now: () => number;
}

interface InteractiveOffer {
  challenge: string;
  bits: number;
  /** The challenge's remaining life by the server's clock; absent when the server sent none. */
  ttlMs?: number;
}

const REASONS = ["inconclusive", "pow_failed", "invalid"] as const;

const INTERACT_REASONS = ["interactive_failed", "invalid"] as const;

function asOffer(v: unknown): InteractiveOffer | null {
  if (typeof v !== "object" || v === null) return null;
  const { challenge, bits, ttl_ms } = v as {
    challenge?: unknown;
    bits?: unknown;
    ttl_ms?: unknown;
  };
  if (typeof challenge !== "string" || challenge === "" || typeof bits !== "number") return null;
  const ttlMs = typeof ttl_ms === "number" && Number.isFinite(ttl_ms) ? ttl_ms : undefined;
  return { challenge, bits, ttlMs };
}

/** Decodes the payload segment (base64url JSON) before the first dot; null when malformed. */
function challengePayload(challenge: string): { id?: unknown } | null {
  try {
    let b64 = challenge.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const payload: unknown = JSON.parse(atob(b64));
    return typeof payload === "object" && payload !== null ? payload : null;
  } catch {
    return null;
  }
}

/** Reads the challenge id from the payload. */
function challengeId(challenge: string): string | null {
  const id = challengePayload(challenge)?.id;
  return typeof id === "string" && id !== "" ? id : null;
}

const maxTimerMs = 2_147_483_647;

/**
 * Runs the widget handshake inside the nazr frame: announces the challenge, solves the
 * proof-of-work while computing the thumbmark, reports both, and relays the outcome to the
 * parent. Never rejects.
 */
export async function reportFromFrame(deps: FrameDeps): Promise<void> {
  let announced = false;
  try {
    const apiKey = new URLSearchParams(deps.location.search).get("k");
    const challenge = deps.script?.dataset.challenge;
    if (!apiKey || !challenge) return;

    const id = challengeId(challenge);
    if (!id) {
      deps.post({ type: "nazr:error", reason: "invalid" });
      return;
    }
    const bits = Number(deps.script?.dataset.powBits) || 0;

    deps.post({ type: "nazr:challenge", id });
    announced = true;

    const [pow, { thumbmark, components }] = await Promise.all([
      deps.solve(id, bits),
      deps.getThumbmark({ collect_beacon: false, cache_api_call: false }),
    ]);

    const res = await deps.fetch("/widget/report", {
      method: "POST",
      headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ challenge, pow, components, clientHash: thumbmark }),
    });
    if (!res.ok) {
      deps.post({ type: "nazr:error", reason: "network" });
      return;
    }
    const body = (await res.json()) as {
      verdict?: unknown;
      token?: unknown;
      interactive?: unknown;
    };
    if (body.verdict === "pass" && typeof body.token === "string") {
      deps.post({ type: "nazr:token", token: body.token });
      return;
    }
    const offer = body.verdict === "inconclusive" ? asOffer(body.interactive) : null;
    const doc = deps.doc;
    if (offer && doc && new URLSearchParams(deps.location.search).get("i") === "1") {
      await interact(deps, doc, apiKey, id, offer);
      return;
    }
    const reason = REASONS.find((r) => r === body.verdict) ?? "network";
    deps.post({ type: "nazr:error", reason });
  } catch {
    if (announced) deps.post({ type: "nazr:error", reason: "network" });
  }
}

/**
 * The interactive step (spec §3.2): shows the click-to-verify box, solves the harder
 * proof-of-work while the visitor reads it, then submits the trace once. Never rejects.
 */
async function interact(
  deps: FrameDeps,
  doc: Document,
  apiKey: string,
  id: string,
  offer: InteractiveOffer,
): Promise<void> {
  deps.post({ type: "nazr:interactive" });
  const ui = renderInteractive(doc, deps.now);
  await ui.shown;
  const abort = new AbortController();
  const solution = deps.solve(id, offer.bits, abort.signal);
  // Observed below, after the click; keep an early failure (or the abort) from surfacing as
  // unhandled.
  solution.catch(() => {});

  // ttl_ms is how long the staged challenge has left by the server's clock; once it passes the
  // server would answer invalid, so fail the box then instead of waiting for a click that
  // cannot succeed. The frame's own clock is never compared with exp, so a skewed clock cannot
  // cut the box short. Without ttl_ms no timer is armed.
  const ttl = offer.ttlMs;
  let expiry: ReturnType<typeof setTimeout> | undefined;
  const expired = new Promise<null>((resolve) => {
    if (ttl === undefined) return;
    expiry = setTimeout(() => resolve(null), Math.min(Math.max(0, ttl), maxTimerMs));
  });
  const trace = await Promise.race([ui.activated, expired]);
  clearTimeout(expiry);
  if (trace === null) {
    // Nothing will redeem the solution now, so stop the worker.
    abort.abort();
    ui.setState("failed");
    deps.post({ type: "nazr:error", reason: "invalid" });
    return;
  }
  ui.setState("working");
  try {
    const pow = await solution;
    const res = await deps.fetch("/widget/interact", {
      method: "POST",
      headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: offer.challenge, pow, trace }),
    });
    if (res.ok) {
      const body = (await res.json()) as { verdict?: unknown; token?: unknown };
      if (body.verdict === "interactive" && typeof body.token === "string") {
        ui.setState("verified");
        deps.post({ type: "nazr:token", token: body.token });
        return;
      }
      const reason = INTERACT_REASONS.find((r) => r === body.verdict);
      if (reason) {
        ui.setState("failed");
        deps.post({ type: "nazr:error", reason });
        return;
      }
    }
  } catch {
    // Falls through to network.
  }
  ui.setState("failed");
  deps.post({ type: "nazr:error", reason: "network" });
}
