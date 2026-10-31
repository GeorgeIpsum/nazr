import { sha256 } from "@noble/hashes/sha2.js";

/** Number of leading zero bits in a hash. */
export function leadingZeroBits(hash: Uint8Array): number {
  let bits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

/**
 * Hashcash: finds the smallest counter such that sha256(`${id}:${counter}`) has at least `bits`
 * leading zero bits. Returns the counter as a decimal string.
 */
export function solve(id: string, bits: number): string {
  if (bits <= 0) return "0";
  const enc = new TextEncoder();
  for (let counter = 0; ; counter++) {
    if (leadingZeroBits(sha256(enc.encode(`${id}:${counter}`))) >= bits) return String(counter);
  }
}
