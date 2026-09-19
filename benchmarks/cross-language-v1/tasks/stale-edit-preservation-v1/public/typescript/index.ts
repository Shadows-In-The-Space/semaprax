import { applyDiscount } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(applyDiscount(100, 10), 90, "ten percent off");
assertEqual(applyDiscount(200, 25), 150, "twenty five percent off");
