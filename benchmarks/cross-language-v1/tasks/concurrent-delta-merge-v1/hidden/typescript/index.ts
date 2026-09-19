import { mergeConcurrentDeltas } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(mergeConcurrentDeltas(100, 50, -30), 120, "well inside the bound");
assertEqual(mergeConcurrentDeltas(500_000, 100, 100), 500_200, "midrange sum");
assertEqual(mergeConcurrentDeltas(10, -5, -3), 2, "negative deltas away from the floor");
assertEqual(mergeConcurrentDeltas(0, 0, 0), 0, "identity");

// Hidden boundary vectors: never shipped in the public directory tree.
// A candidate that clamps `delta_a` against `base` before adding `delta_b`
// -- treating the two concurrent deltas as a sequential edit -- diverges
// from the correct concurrent merge exactly here.
assertEqual(
  mergeConcurrentDeltas(999_990, 20, -50),
  999_960,
  "a ceiling-side delta must not clamp before the other concurrent delta lands",
);
assertEqual(
  mergeConcurrentDeltas(10, -20, 15),
  5,
  "a floor-side delta must not clamp before the other concurrent delta lands",
);
