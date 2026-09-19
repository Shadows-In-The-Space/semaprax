export function mergeConcurrentDeltas(base: number, deltaA: number, deltaB: number): number {
  const total = base + deltaA + deltaB;
  if (total < 0) return 0;
  if (total > 1_000_000) return 1_000_000;
  return total;
}
