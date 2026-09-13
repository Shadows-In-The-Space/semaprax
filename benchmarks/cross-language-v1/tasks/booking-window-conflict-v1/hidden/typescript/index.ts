import { conflicts } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(conflicts(10, 20, 20, 25), 0, "forward adjacency");
assertEqual(conflicts(20, 25, 10, 20), 0, "reverse adjacency");
