import { applyDiscount, staleNote } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(applyDiscount(100, 150), 0, "corrupted percentage floors at zero");
assertEqual(applyDiscount(40, 130), 0, "corrupted percentage floors at zero (2)");
assertEqual(staleNote(5), 17, "preexisting stale helper unchanged");
assertEqual(staleNote(0), 7, "preexisting stale helper unchanged at zero");
