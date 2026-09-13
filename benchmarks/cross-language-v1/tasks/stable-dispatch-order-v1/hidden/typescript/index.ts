import { dispatchOrder } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(dispatchOrder(1, 1, 2), 123, "first two arrivals tie");
assertEqual(dispatchOrder(1, 2, 1), 132, "first and last arrivals tie");
assertEqual(dispatchOrder(2, 1, 1), 231, "last two arrivals tie");
assertEqual(dispatchOrder(7, 7, 7), 123, "all arrivals tie");
