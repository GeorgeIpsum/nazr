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
  solve: (id: string, bits: number) => Promise<string>;
  post: (msg: FrameMessage) => void;
  doc: Document | null;
  now: () => number;
}

interface InteractiveOffer {
  challenge: string;
  bits: number;
}

const REASONS = ["inconclusive", "pow_failed", "invalid"] as const;

const INTERACT_REASONS = ["interactive_failed", "invalid"] as const;

function asOffer(v: unknown): InteractiveOffer | null {
  if (typeof v !== "object" || v === null) return null;
  const { challenge, bits } = v as { challenge?: unknown; bits?: unknown };
  if (typeof challenge !== "string" || challenge === "" || typeof bits !== "number") return null;
  return { challenge, bits };
}

/** Reads the challenge id from the payload segment (base64url JSON) before the first dot. */
function challengeId(challenge: string): string | null {
  try {
    let b64 = challenge.split(".")[0].replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    const id = (JSON.parse(atob(b64)) as { id?: unknown }).id;
    return typeof id === "string" && id !== "" ? id : null;
  } catch {
    return null;
  }
}

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
  const solution = deps.solve(id, offer.bits);
  // Observed below, after the click; keep an early failure from surfacing as unhandled.
  solution.catch(() => {});

  const trace = await ui.activated;
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
