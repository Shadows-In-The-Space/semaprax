mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::merge_concurrent_deltas;

    #[test]
    fn merges_two_deltas_well_inside_the_shared_bound() {
        assert_eq!(merge_concurrent_deltas(100, 50, -30), 120);
        assert_eq!(merge_concurrent_deltas(500_000, 100, 100), 500_200);
    }

    #[test]
    fn merges_negative_deltas_that_never_approach_the_floor() {
        assert_eq!(merge_concurrent_deltas(10, -5, -3), 2);
        assert_eq!(merge_concurrent_deltas(0, 0, 0), 0);
    }
}

fn main() {}
