import { taxForSubtotal } from "./helper";

export function invoiceTotal(price: number, quantity: number, taxRate: number, shipping: number): number {
  const subtotal = price * quantity;
  return subtotal + taxForSubtotal(subtotal, taxRate) + shipping;
}
