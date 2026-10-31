import { describe, expect, it } from "vitest";
import { solve } from "./pow";
import { handleMessage } from "./worker";

describe("handleMessage", () => {
  it("answers with the solved counter", () => {
    expect(handleMessage({ id: "abc", bits: 8 })).toEqual({ counter: solve("abc", 8) });
  });
});
