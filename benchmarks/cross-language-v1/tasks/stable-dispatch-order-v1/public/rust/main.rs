mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::dispatch_order;

    #[test]
    fn orders_distinct_priorities_from_each_initial_position() {
        assert_eq!(dispatch_order(1, 2, 3), 123);
        assert_eq!(dispatch_order(3, 1, 2), 231);
        assert_eq!(dispatch_order(2, 3, 1), 312);
    }
}

fn main() {}
