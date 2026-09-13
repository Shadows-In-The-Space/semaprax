mod candidate;

#[cfg(test)]
mod public_tests {
    use super::candidate::sentinel_checksum;

    #[test]
    fn public_sentinel_vectors() {
        assert_eq!(sentinel_checksum(&[0xff]), 0);
        assert_eq!(sentinel_checksum(&[0xff, 0x07, 0xff]), 2);
        assert_eq!(sentinel_checksum(&[0x01, 0x02, 0x7f]), 6);
    }
}

fn main() {}
