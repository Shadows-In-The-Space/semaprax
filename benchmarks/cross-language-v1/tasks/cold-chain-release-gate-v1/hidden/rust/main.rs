mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::release_allowed;

    #[test]
    fn rejects_a_good_temperature_with_bad_pressure() {
        assert_eq!(release_allowed(5, 106), 0);
    }

    #[test]
    fn rejects_a_good_pressure_with_bad_temperature() {
        assert_eq!(release_allowed(1, 100), 0);
    }

    #[test]
    fn accepts_inclusive_band_edges() {
        assert_eq!(release_allowed(2, 95), 1);
        assert_eq!(release_allowed(8, 105), 1);
    }
}

fn main() {}
