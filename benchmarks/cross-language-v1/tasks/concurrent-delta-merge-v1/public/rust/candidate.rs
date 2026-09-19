pub fn merge_concurrent_deltas(base: i64, delta_a: i64, delta_b: i64) -> i64 {
    let total = base + delta_a + delta_b;
    if total < 0 {
        0
    } else if total > 1_000_000 {
        1_000_000
    } else {
        total
    }
}
