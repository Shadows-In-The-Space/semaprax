mod candidate;
mod helper;

#[cfg(test)]
mod public_tests {
    use super::candidate::invoice_total;

    #[test]
    fn exact_tax_and_zero_shipping_cases() {
        assert_eq!(invoice_total(10, 2, 10, 5), 27);
        assert_eq!(invoice_total(40, 2, 25, 0), 100);
        assert_eq!(invoice_total(25, 4, 20, 10), 130);
    }
}

fn main() {}
