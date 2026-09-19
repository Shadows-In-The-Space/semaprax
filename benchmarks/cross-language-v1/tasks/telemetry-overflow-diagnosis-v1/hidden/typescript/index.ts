import { combineTelemetry } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(combineTelemetry(2147483647, 1), 2147483647, "saturates at the positive boundary");
assertEqual(combineTelemetry(-2147483648, -1), -2147483648, "saturates at the negative boundary");
