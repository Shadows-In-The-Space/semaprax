pub fn tax_for_subtotal(subtotal: i64, tax_rate: i64) -> i64 {
    subtotal * tax_rate / 100
}
