// The starter calculator module a fresh `semaprax new <dest> --template
// calculator` scaffold ships with one operation (`add`); this port's
// baseline mirrors that same minimal two-function calculator shape a fresh
// Rust project would start from before any of its own logic exists.
pub fn add(left: i64, right: i64) -> i64 {
    left + right
}

pub fn subtract(left: i64, right: i64) -> i64 {
    left - right
}
