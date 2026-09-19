mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::{apply_discount, stale_note};

    #[test]
    fn a_corrupted_percentage_above_full_price_floors_at_zero() {
        assert_eq!(apply_discount(100, 150), 0);
        assert_eq!(apply_discount(40, 130), 0);
    }

    #[test]
    fn the_preexisting_stale_note_helper_is_unchanged() {
        assert_eq!(stale_note(5), 17);
        assert_eq!(stale_note(0), 7);
    }
}

fn main() {}
