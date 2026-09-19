// prior-session: shipment tag helper; unrelated to this task's repair, keep
// unchanged. A candidate that clobbers or deletes this while repairing
// `apply_discount` below has not preserved a stale, already-completed edit.
pub fn stale_note(tag: i64) -> i64 {
    tag * 2 + 7
}

pub fn apply_discount(price: i64, pct: i64) -> i64 {
    // A corrupted upstream feed can send `pct` above 100; the result must
    // floor at zero rather than go negative.
    let raw = price - (price * pct) / 100;
    if raw < 0 {
        0
    } else {
        raw
    }
}
