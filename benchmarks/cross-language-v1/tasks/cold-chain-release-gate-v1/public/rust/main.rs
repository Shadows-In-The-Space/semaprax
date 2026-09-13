mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::release_allowed;

    #[test]
    fn accepts_readings_inside_both_operating_bands() {
        assert_eq!(release_allowed(5, 100), 1);
    }

    #[test]
    fn rejects_when_both_readings_are_outside_their_bands() {
        assert_eq!(release_allowed(1, 94), 0);
        assert_eq!(release_allowed(9, 106), 0);
    }
}

fn main() {}
