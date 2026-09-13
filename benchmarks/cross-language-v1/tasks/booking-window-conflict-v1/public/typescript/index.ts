import { conflicts } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(conflicts(10, 20, 15, 25), 1, "proper overlap");
assertEqual(conflicts(10, 30, 12, 18), 1, "contained booking");
assertEqual(conflicts(10, 20, 25, 30), 0, "strictly separated bookings");
