import { solve } from "./pow";

export function handleMessage(data: { id: string; bits: number }): { counter: string } {
  return { counter: solve(data.id, data.bits) };
}
