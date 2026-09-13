import { releaseAllowed } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(releaseAllowed(5, 106), 0, "good temperature cannot override bad pressure");
assertEqual(releaseAllowed(1, 100), 0, "good pressure cannot override bad temperature");
assertEqual(releaseAllowed(2, 95), 1, "lower inclusive edges");
assertEqual(releaseAllowed(8, 105), 1, "upper inclusive edges");
