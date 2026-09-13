export function dispatchOrder(aPriority: number, bPriority: number, cPriority: number): number {
  if (aPriority <= bPriority && aPriority <= cPriority) {
    return bPriority <= cPriority ? 123 : 132;
  }
  if (bPriority <= aPriority && bPriority <= cPriority) {
    return aPriority <= cPriority ? 213 : 231;
  }
  return aPriority <= bPriority ? 312 : 321;
}
