import { sentinelChecksum } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(sentinelChecksum(new Uint8Array([0x00, 0xff, 0x00, 0x09])), 1024, "zero and ff");
assertEqual(sentinelChecksum(new Uint8Array([0x09, 0x00, 0xff, 0x00, 0x09])), 1536, "two zeroes");
