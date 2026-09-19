mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::merge_concurrent_deltas;

    #[test]
    fn repeats_the_public_vectors_against_the_copied_candidate() {
        assert_eq!(merge_concurrent_deltas(100, 50, -30), 120);
        assert_eq!(merge_concurrent_deltas(500_000, 100, 100), 500_200);
        assert_eq!(merge_concurrent_deltas(10, -5, -3), 2);
        assert_eq!(merge_concurrent_deltas(0, 0, 0), 0);
    }

    #[test]
    fn a_ceiling_side_delta_must_not_clamp_before_the_other_concurrent_delta_lands() {
        // Applying `delta_a` first and clamping there, then adding
        // `delta_b`, is the sequential-application bug this task is built
        // to catch: `clamp(999_990 + 20) = 1_000_000`, then
        // `1_000_000 - 50 = 999_950`. Treating both deltas as arriving
        // concurrently against the same `base` gives `999_990 + 20 - 50 =
        // 999_960` instead, which never needed to touch the ceiling at all.
        assert_eq!(merge_concurrent_deltas(999_990, 20, -50), 999_960);
    }

    #[test]
    fn a_floor_side_delta_must_not_clamp_before_the_other_concurrent_delta_lands() {
        // Symmetric floor case: `clamp(10 - 20) = 0`, then `0 + 15 = 15`
        // under sequential application; the correct concurrent merge is
        // `10 - 20 + 15 = 5`.
        assert_eq!(merge_concurrent_deltas(10, -20, 15), 5);
    }
}

fn main() {}
