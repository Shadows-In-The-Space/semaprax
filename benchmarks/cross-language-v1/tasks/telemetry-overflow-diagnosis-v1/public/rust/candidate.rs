// A telemetry combiner register must saturate at the 32-bit signed boundary
// rather than wrap or trap: two independent delta readings are summed into
// one running total, and a reading that would carry the total past
// `i32::MAX`/`i32::MIN` must clamp there instead of silently doing
// whatever the underlying arithmetic happens to do at that magnitude.
//
// `i32::saturating_add`/`checked_add` would perform exactly the computation
// this task measures, so the guarded form below (not a standard-library
// helper) is the required implementation; see EQUIVALENCE.md.
pub fn combine_telemetry(delta_a: i32, delta_b: i32) -> i32 {
    if delta_b > 0 && delta_a > i32::MAX - delta_b {
        i32::MAX
    } else if delta_b < 0 && delta_a < i32::MIN - delta_b {
        i32::MIN
    } else {
        delta_a + delta_b
    }
}
