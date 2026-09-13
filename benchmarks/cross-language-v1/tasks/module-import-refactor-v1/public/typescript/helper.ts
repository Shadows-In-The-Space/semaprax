export function taxForSubtotal(subtotal: number, taxRate: number): number {
  return Math.floor((subtotal * taxRate) / 100);
}
