import { releaseAllowed } from "./candidate";

function assertEqual(actual: number, expected: number, label: string): void {
  if (actual !== expected) throw new Error(label + ": expected " + expected + ", got " + actual);
}

assertEqual(releaseAllowed(5, 100), 1, "both readings inside operating bands");
assertEqual(releaseAllowed(1, 94), 0, "both readings below operating bands");
assertEqual(releaseAllowed(9, 106), 0, "both readings above operating bands");
