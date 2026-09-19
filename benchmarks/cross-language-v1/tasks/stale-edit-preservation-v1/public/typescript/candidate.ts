// prior-session: shipment tag helper; unrelated to this task's repair, keep
// unchanged. A candidate that clobbers or deletes this while repairing
// `applyDiscount` below has not preserved a stale, already-completed edit.
export function staleNote(tag: number): number {
  return tag * 2 + 7;
}

export function applyDiscount(price: number, pct: number): number {
  // A corrupted upstream feed can send `pct` above 100; the result must
  // floor at zero rather than go negative.
  const raw = price - Math.trunc((price * pct) / 100);
  return raw < 0 ? 0 : raw;
}
