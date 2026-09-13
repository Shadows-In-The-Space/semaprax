import { invoiceTotal } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(invoiceTotal(10, 2, 10, 5), 27, "exact tax with shipping");
assertEqual(invoiceTotal(40, 2, 25, 0), 100, "exact tax without shipping");
assertEqual(invoiceTotal(25, 4, 20, 10), 130, "larger exact subtotal");
