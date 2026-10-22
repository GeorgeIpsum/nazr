import type { ThumbmarkResponse } from "@nazr/thumbmark";

export interface Diff {
  added: string[];
  removed: string[];
  changed: string[];
}

function leaves(value: unknown, prefix: string, out: Map<string, string>): void {
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 0) {
      for (const [k, v] of entries) leaves(v, prefix ? `${prefix}.${k}` : k, out);
      return;
    }
  }
  if (prefix) out.set(prefix, JSON.stringify(value));
}

function flatten(r: ThumbmarkResponse | null): Map<string, string> {
  const out = new Map<string, string>();
  if (r) leaves(r.components, "", out);
  return out;
}

/** Compare dotted leaf paths of `components` (not `info`) between two runs. */
export function diffResults(prev: ThumbmarkResponse | null, next: ThumbmarkResponse): Diff {
  const a = flatten(prev);
  const b = flatten(next);
  const added: string[] = [];
  const removed: string[] = [];
  const changed: string[] = [];
  for (const [k, v] of b) {
    if (!a.has(k)) added.push(k);
    else if (a.get(k) !== v) changed.push(k);
  }
  for (const k of a.keys()) if (!b.has(k)) removed.push(k);
  return { added: added.sort(), removed: removed.sort(), changed: changed.sort() };
}
