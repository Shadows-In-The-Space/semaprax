mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::combine_telemetry;

    #[test]
    fn a_delta_that_would_carry_the_total_past_the_boundary_saturates_instead_of_wrapping_or_trapping(
    ) {
        assert_eq!(combine_telemetry(i32::MAX, 1), i32::MAX);
        assert_eq!(combine_telemetry(i32::MIN, -1), i32::MIN);
    }
}

fn main() {}
