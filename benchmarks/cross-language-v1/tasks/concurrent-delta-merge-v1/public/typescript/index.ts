import { mergeConcurrentDeltas } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(mergeConcurrentDeltas(100, 50, -30), 120, "well inside the bound");
assertEqual(mergeConcurrentDeltas(500_000, 100, 100), 500_200, "midrange sum");
assertEqual(mergeConcurrentDeltas(10, -5, -3), 2, "negative deltas away from the floor");
assertEqual(mergeConcurrentDeltas(0, 0, 0), 0, "identity");
