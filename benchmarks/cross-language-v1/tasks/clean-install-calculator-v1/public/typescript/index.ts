import { add, subtract } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(add(19, 23), 42, "the starter operation still works");
assertEqual(subtract(50, 8), 42, "the new sibling operation");
