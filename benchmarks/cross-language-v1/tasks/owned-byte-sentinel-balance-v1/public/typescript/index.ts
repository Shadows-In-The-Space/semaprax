import { sentinelChecksum } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(sentinelChecksum(new Uint8Array([0xff])), 0, "one ff");
assertEqual(sentinelChecksum(new Uint8Array([0xff, 0x07, 0xff])), 2, "two ff");
assertEqual(sentinelChecksum(new Uint8Array([0x01, 0x02, 0x7f])), 6, "other bytes");
