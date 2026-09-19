// The starter calculator module a fresh `semaprax new <dest> --template
// calculator` scaffold ships with one operation (`add`); this port's
// baseline mirrors that same minimal two-function calculator shape a fresh
// TypeScript project would start from before any of its own logic exists.
export function add(left: number, right: number): number {
  return left + right;
}

export function subtract(left: number, right: number): number {
  return left - right;
}
