mod candidate;
mod helper;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::invoice_total;

    #[test]
    fn whole_subtotal_tax_precedes_shipping_and_rounds_once() {
        assert_eq!(invoice_total(19, 3, 8, 10), 71);
        assert_eq!(invoice_total(7, 5, 13, 9), 48);
        assert_eq!(invoice_total(1, 64, 17, 3), 77);
    }
}

fn main() {}
