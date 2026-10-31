import type { getThumbmark } from "@nazr/thumbmark";

export type FrameMessage =
  | { type: "nazr:challenge"; id: string }
  | { type: "nazr:token"; token: string }
  | { type: "nazr:error"; reason: "inconclusive" | "pow_failed" | "invalid" | "network" };

export interface FrameDeps {
  script: HTMLScriptElement | null;
  location: Location;
  fetch: typeof fetch;
  getThumbmark: typeof getThumbmark;
  solve: (id: string, bits: number) => Promise<string>;
  post: (msg: FrameMessage) => void;
}

const REASONS = ["inconclusive", "pow_failed", "invalid"] as const;

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
    const body = (await res.json()) as { verdict?: unknown; token?: unknown };
    if (body.verdict === "pass" && typeof body.token === "string") {
      deps.post({ type: "nazr:token", token: body.token });
      return;
    }
    const reason = REASONS.find((r) => r === body.verdict) ?? "network";
    deps.post({ type: "nazr:error", reason });
  } catch {
    if (announced) deps.post({ type: "nazr:error", reason: "network" });
  }
}
