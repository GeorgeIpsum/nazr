import type { ThumbmarkResponse } from "@nazr/thumbmark";
import { describe, expect, it } from "vitest";
import { diffResults } from "./diff";

function res(components: Record<string, unknown>): ThumbmarkResponse {
  return { thumbmark: "x", components, info: {}, version: "1" } as unknown as ThumbmarkResponse;
}

describe("diffResults", () => {
  const base = res({ screen: { colorDepth: 24, width: 100 }, tls: { ja4: "a" }, flag: true });

  it("treats everything as added when there is no previous run", () => {
    expect(diffResults(null, base)).toEqual({
      added: ["flag", "screen.colorDepth", "screen.width", "tls.ja4"],
      removed: [],
      changed: [],
    });
  });

  it("reports changed leaves by dotted path", () => {
    const next = res({ screen: { colorDepth: 30, width: 100 }, tls: { ja4: "a" }, flag: true });
    expect(diffResults(base, next)).toEqual({
      added: [],
      removed: [],
      changed: ["screen.colorDepth"],
    });
  });

  it("reports removed keys", () => {
    const next = res({ screen: { colorDepth: 24 }, tls: { ja4: "a" }, flag: true });
    expect(diffResults(base, next).removed).toEqual(["screen.width"]);
  });

  it("returns empty lists for identical results", () => {
    expect(diffResults(base, structuredClone(base))).toEqual({
      added: [],
      removed: [],
      changed: [],
    });
  });

  it("handles arrays and ignores info", () => {
    const a = res({ list: [1, 2] });
    const b = { ...res({ list: [1, 3] }), info: { x: 1 } } as unknown as ThumbmarkResponse;
    expect(diffResults(a, b).changed).toEqual(["list.1"]);
  });
});
