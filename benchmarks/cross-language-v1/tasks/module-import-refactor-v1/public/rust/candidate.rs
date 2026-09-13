use crate::helper::tax_for_subtotal;

pub fn invoice_total(price: i64, quantity: i64, tax_rate: i64, shipping: i64) -> i64 {
    let subtotal = price * quantity;
    subtotal + tax_for_subtotal(subtotal, tax_rate) + shipping
}
