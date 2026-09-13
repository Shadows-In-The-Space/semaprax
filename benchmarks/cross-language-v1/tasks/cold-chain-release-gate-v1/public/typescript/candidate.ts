export function releaseAllowed(coreTemperature: number, sealPressure: number): number {
  return coreTemperature >= 2 && coreTemperature <= 8 && sealPressure >= 95 && sealPressure <= 105
    ? 1
    : 0;
}
