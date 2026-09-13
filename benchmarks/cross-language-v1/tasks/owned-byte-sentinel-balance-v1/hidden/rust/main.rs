mod candidate;

#[cfg(test)]
mod hidden_tests {
    use super::candidate::sentinel_checksum;

    #[test]
    fn hidden_zero_and_ff_vectors() {
        assert_eq!(sentinel_checksum(&[0x00, 0xff, 0x00, 0x09]), 1024);
        assert_eq!(sentinel_checksum(&[0x09, 0x00, 0xff, 0x00, 0x09]), 1536);
    }
}

fn main() {}
