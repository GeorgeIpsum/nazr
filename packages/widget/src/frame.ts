import type { getThumbmark } from "@nazr/thumbmark";

export interface FrameDeps {
  location: Location;
  fetch: typeof fetch;
  getThumbmark: typeof getThumbmark;
}

/**
 * Computes the thumbmark locally inside the nazr frame and reports it, with the
 * host's nonce, to the nazr origin. Never rejects.
 */
export async function reportFromFrame(deps: FrameDeps): Promise<void> {
  try {
    const params = new URLSearchParams(deps.location.search);
    const apiKey = params.get("k");
    if (!apiKey) return;
    const nonce = params.get("n") ?? "";

    const { thumbmark, components } = await deps.getThumbmark({
      collect_beacon: false,
      cache_api_call: false,
    });

    await deps.fetch("/widget/report", {
      method: "POST",
      headers: { "x-api-key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ nonce, components, clientHash: thumbmark }),
    });
  } catch {
    // Reporting is best effort.
  }
}
