mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::dispatch_order;

    #[test]
    fn preserves_arrival_order_for_asymmetric_ties() {
        assert_eq!(dispatch_order(1, 1, 2), 123);
        assert_eq!(dispatch_order(1, 2, 1), 132);
        assert_eq!(dispatch_order(2, 1, 1), 231);
    }

    #[test]
    fn preserves_every_arrival_position_when_all_priorities_tie() {
        assert_eq!(dispatch_order(7, 7, 7), 123);
    }
}

fn main() {}
