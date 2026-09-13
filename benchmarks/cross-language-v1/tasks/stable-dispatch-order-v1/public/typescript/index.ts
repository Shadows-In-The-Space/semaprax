import { dispatchOrder } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(dispatchOrder(1, 2, 3), 123, "already ordered distinct priorities");
assertEqual(dispatchOrder(3, 1, 2), 231, "middle arrival has smallest priority");
assertEqual(dispatchOrder(2, 3, 1), 312, "last arrival has smallest priority");
