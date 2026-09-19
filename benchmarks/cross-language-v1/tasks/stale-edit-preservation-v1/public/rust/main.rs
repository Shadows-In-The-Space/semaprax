mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::apply_discount;

    #[test]
    fn ordinary_discounts_reduce_price() {
        assert_eq!(apply_discount(100, 10), 90);
        assert_eq!(apply_discount(200, 25), 150);
    }
}

fn main() {}
