mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::conflicts;

    #[test]
    fn overlapping_and_contained_bookings_conflict() {
        assert_eq!(conflicts(10, 20, 15, 25), 1);
        assert_eq!(conflicts(10, 30, 12, 18), 1);
    }

    #[test]
    fn a_real_gap_does_not_conflict() {
        assert_eq!(conflicts(10, 20, 25, 30), 0);
    }
}

fn main() {}
