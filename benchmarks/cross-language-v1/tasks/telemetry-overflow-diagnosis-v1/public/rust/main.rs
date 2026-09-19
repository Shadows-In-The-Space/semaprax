mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::combine_telemetry;

    #[test]
    fn ordinary_deltas_combine_by_plain_addition() {
        assert_eq!(combine_telemetry(10, 20), 30);
        assert_eq!(combine_telemetry(-5, 5), 0);
    }
}

fn main() {}
