pub fn sentinel_checksum(input: &[u8]) -> usize {
    let mut transformed = input.to_vec();
    for byte in &mut transformed {
        if *byte == 0xff {
            *byte = 0x00;
        } else if *byte == 0x00 {
            *byte = 0xff;
        } else {
            *byte = 0x01;
        }
    }
    transformed
        .iter()
        .enumerate()
        .map(|(index, byte)| (index + 1) * usize::from(*byte))
        .sum()
}
