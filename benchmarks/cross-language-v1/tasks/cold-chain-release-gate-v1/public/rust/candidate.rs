pub fn release_allowed(core_temperature: i64, seal_pressure: i64) -> i64 {
    if core_temperature >= 2
        && core_temperature <= 8
        && seal_pressure >= 95
        && seal_pressure <= 105
    {
        1
    } else {
        0
    }
}
