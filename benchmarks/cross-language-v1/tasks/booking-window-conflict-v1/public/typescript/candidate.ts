export function conflicts(aStart: number, aEnd: number, bStart: number, bEnd: number): number {
  return aStart < bEnd && bStart < aEnd ? 1 : 0;
}
