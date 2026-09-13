pub fn conflicts(a_start: i64, a_end: i64, b_start: i64, b_end: i64) -> i64 {
    if a_start < b_end && b_start < a_end {
        1
    } else {
        0
    }
}
