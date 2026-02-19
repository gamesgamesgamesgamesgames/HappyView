use std::time::{SystemTime, UNIX_EPOCH};

/// Base32-sortstring alphabet used by AT Protocol TIDs.
const BASE32_SORT: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// Generate a TID (timestamp identifier) compatible with the AT Protocol spec.
///
/// Layout: 64-bit value = `(microsecond_timestamp << 10) | random_10bit_clock_id`
/// Encoded as a 13-character base32-sortstring.
pub fn generate_tid() -> String {
    let us = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_micros() as u64;

    // 10-bit random clock ID from UUID v4 bytes
    let rand_bytes = uuid::Uuid::new_v4();
    let clock_id = u16::from_le_bytes([rand_bytes.as_bytes()[0], rand_bytes.as_bytes()[1]]) & 0x3FF;

    let val = (us << 10) | clock_id as u64;
    encode_base32_sort(val)
}

/// Encode a u64 into a 13-character base32-sortstring.
fn encode_base32_sort(mut val: u64) -> String {
    let mut buf = [0u8; 13];
    for i in (0..13).rev() {
        buf[i] = BASE32_SORT[(val & 0x1F) as usize];
        val >>= 5;
    }
    // SAFETY: all bytes come from BASE32_SORT which is ASCII
    String::from_utf8(buf.to_vec()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tid_is_13_chars() {
        let tid = generate_tid();
        assert_eq!(tid.len(), 13, "TID should be 13 characters, got: {tid}");
    }

    #[test]
    fn tid_uses_valid_charset() {
        let tid = generate_tid();
        let valid = "234567abcdefghijklmnopqrstuvwxyz";
        for ch in tid.chars() {
            assert!(valid.contains(ch), "invalid character '{ch}' in TID {tid}");
        }
    }

    #[test]
    fn tids_are_unique() {
        let a = generate_tid();
        let b = generate_tid();
        assert_ne!(a, b, "two TIDs should differ");
    }

    #[test]
    fn tids_are_sortable() {
        // TIDs generated later should sort after earlier ones
        let a = generate_tid();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = generate_tid();
        assert!(b > a, "later TID '{b}' should sort after earlier TID '{a}'");
    }

    #[test]
    fn encode_base32_sort_known_value() {
        // Zero should encode to all '2's (the first character in the alphabet)
        let result = encode_base32_sort(0);
        assert_eq!(result, "2222222222222");
    }
}
