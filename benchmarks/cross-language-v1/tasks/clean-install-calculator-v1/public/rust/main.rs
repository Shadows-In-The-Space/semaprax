mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::{add, subtract};

    #[test]
    fn the_starter_operation_and_its_new_sibling_compute_correctly() {
        assert_eq!(add(19, 23), 42);
        assert_eq!(subtract(50, 8), 42);
    }
}

fn main() {}
