import { combineTelemetry } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(combineTelemetry(10, 20), 30, "ordinary positive deltas");
assertEqual(combineTelemetry(-5, 5), 0, "ordinary mixed deltas");
