// A telemetry combiner register must saturate at the 32-bit signed boundary
// rather than wrap or trap: two independent delta readings are summed into
// one running total, and a reading that would carry the total past
// `I32_MAX`/`I32_MIN` must clamp there instead of silently doing whatever
// the underlying arithmetic happens to do at that magnitude.
const I32_MAX = 2147483647;
const I32_MIN = -2147483648;

export function combineTelemetry(deltaA: number, deltaB: number): number {
  if (deltaB > 0 && deltaA > I32_MAX - deltaB) return I32_MAX;
  if (deltaB < 0 && deltaA < I32_MIN - deltaB) return I32_MIN;
  return deltaA + deltaB;
}
