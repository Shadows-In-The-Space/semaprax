mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::{add, subtract};

    #[test]
    fn subtraction_may_produce_a_negative_result_unlike_a_bounded_counter() {
        assert_eq!(subtract(8, 50), -42);
        assert_eq!(subtract(-5, -5), 0);
        assert_eq!(add(19, 23), 42);
    }
}

fn main() {}
