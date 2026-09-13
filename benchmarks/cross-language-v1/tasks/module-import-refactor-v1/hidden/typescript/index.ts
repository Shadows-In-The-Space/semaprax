import { invoiceTotal } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(invoiceTotal(19, 3, 8, 10), 71, "whole subtotal tax before shipping");
assertEqual(invoiceTotal(7, 5, 13, 9), 48, "tax rounds once");
assertEqual(invoiceTotal(1, 64, 17, 3), 77, "bounded quantity");
