import type { ThumbmarkResponse } from "@nazr/thumbmark";

export interface State {
  endpoint: string;
  apiKey: string;
  lastResult: ThumbmarkResponse | null;
}

const KEYS = {
  endpoint: "nazr_demo_endpoint",
  apiKey: "nazr_demo_apiKey",
  lastResult: "nazr_demo_lastResult",
} as const;

export const DEFAULT_ENDPOINT = "https://localhost";

function get(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function set(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // storage unavailable or full; the demo still works without persistence
  }
}

export function loadState(): State {
  let lastResult: ThumbmarkResponse | null = null;
  const raw = get(KEYS.lastResult);
  if (raw) {
    try {
      lastResult = JSON.parse(raw) as ThumbmarkResponse;
    } catch {
      lastResult = null;
    }
  }
  return {
    endpoint: get(KEYS.endpoint) || DEFAULT_ENDPOINT,
    apiKey: get(KEYS.apiKey) ?? "",
    lastResult,
  };
}

export function saveState(s: State): void {
  set(KEYS.endpoint, s.endpoint);
  set(KEYS.apiKey, s.apiKey);
  set(KEYS.lastResult, JSON.stringify(s.lastResult));
}

/** Remove the client's visitor id and cached API responses (all `thumbmark_*` keys). */
export function clearVisitor(): string[] {
  const removed: string[] = [];
  try {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const k = localStorage.key(i);
      if (k && (k === "thumbmark_visitor_id" || k.startsWith("thumbmark_"))) {
        localStorage.removeItem(k);
        removed.push(k);
      }
    }
  } catch {
    // ignore
  }
  return removed;
}
