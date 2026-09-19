import { add, subtract } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(subtract(8, 50), -42, "subtraction may go negative, unlike a bounded counter");
assertEqual(subtract(-5, -5), 0, "subtracting equal negatives");
assertEqual(add(19, 23), 42, "the starter operation is unchanged");
