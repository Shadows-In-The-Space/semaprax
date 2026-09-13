mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::conflicts;

    #[test]
    fn forward_adjacency_is_not_a_conflict() {
        assert_eq!(conflicts(10, 20, 20, 25), 0);
    }

    #[test]
    fn reverse_adjacency_is_not_a_conflict() {
        assert_eq!(conflicts(20, 25, 10, 20), 0);
    }
}

fn main() {}
