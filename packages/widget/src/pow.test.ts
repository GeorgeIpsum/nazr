import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";
import { leadingZeroBits, solve } from "./pow";

describe("leadingZeroBits", () => {
  it("counts leading zero bits", () => {
    expect(leadingZeroBits(new Uint8Array([0, 0, 0x0f]))).toBe(20);
    expect(leadingZeroBits(new Uint8Array([0x80]))).toBe(0);
    expect(leadingZeroBits(new Uint8Array([0, 0]))).toBe(16);
  });
});

describe("solve", () => {
  it("finds a counter whose hash has enough leading zero bits", () => {
    const counter = solve("abc", 10);
    expect(counter).toMatch(/^\d+$/);
    const hash = sha256(new TextEncoder().encode(`abc:${counter}`));
    expect(leadingZeroBits(hash)).toBeGreaterThanOrEqual(10);
  });

  it("returns 0 immediately when no bits are required", () => {
    expect(solve("abc", 0)).toBe("0");
  });
});
