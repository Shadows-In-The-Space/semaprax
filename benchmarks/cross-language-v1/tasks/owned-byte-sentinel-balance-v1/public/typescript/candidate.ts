export function sentinelChecksum(input: Uint8Array): number {
  const transformed = new Uint8Array(input);
  for (let index = 0; index < transformed.length; index += 1) {
    const byte = transformed[index];
    if (byte === 0xff) {
      transformed[index] = 0x00;
    } else if (byte === 0x00) {
      transformed[index] = 0xff;
    } else {
      transformed[index] = 0x01;
    }
  }
  let checksum = 0;
  for (let index = 0; index < transformed.length; index += 1) {
    checksum += (index + 1) * transformed[index];
  }
  return checksum;
}
