use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, TimeZone, Utc};

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

/// Decode a 13-character base32-sortstring back to a u64.
fn decode_base32_sort(tid: &str) -> Option<u64> {
    if tid.len() != 13 {
        return None;
    }
    let mut val: u64 = 0;
    for byte in tid.bytes() {
        let idx = BASE32_SORT.iter().position(|&b| b == byte)?;
        val = (val << 5) | idx as u64;
    }
    Some(val)
}

/// Extract the microsecond timestamp from a TID and return it as an ISO 8601
/// string. The 10-bit clock ID is discarded (lossy).
pub fn tid_to_iso8601(tid: &str) -> Option<String> {
    let val = decode_base32_sort(tid)?;
    let us = (val >> 10) as i64;
    let dt: DateTime<Utc> = Utc.timestamp_micros(us).single()?;
    Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

/// Create a TID from an ISO 8601 timestamp string. Uses a zero clock ID, so
/// the result won't match any specific generated TID but will sort correctly
/// relative to TIDs from the same moment.
pub fn tid_from_iso8601(iso: &str) -> Option<String> {
    let dt = iso.parse::<DateTime<Utc>>().ok()?;
    let us = dt.timestamp_micros() as u64;
    Some(encode_base32_sort(us << 10))
}

/// Extract the microsecond timestamp from a TID (lossy — drops clock ID).
pub fn tid_to_unix_microseconds(tid: &str) -> Option<i64> {
    let val = decode_base32_sort(tid)?;
    Some((val >> 10) as i64)
}

/// Create a TID from a microsecond timestamp. Uses a zero clock ID.
pub fn tid_from_unix_microseconds(us: i64) -> String {
    encode_base32_sort((us as u64) << 10)
}

/// Lossless: decode a TID to its full u64 representation (timestamp + clock ID).
pub fn tid_to_number(tid: &str) -> Option<u64> {
    decode_base32_sort(tid)
}

/// Lossless: encode a u64 back into a TID.
pub fn tid_from_number(val: u64) -> String {
    encode_base32_sort(val)
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

    #[test]
    fn decode_inverts_encode() {
        let val: u64 = 0x123456789ABCDEF;
        let encoded = encode_base32_sort(val);
        assert_eq!(decode_base32_sort(&encoded), Some(val));
    }

    #[test]
    fn decode_rejects_invalid() {
        assert_eq!(decode_base32_sort("short"), None);
        assert_eq!(decode_base32_sort("AAAAAAAAAAAAA"), None);
    }

    #[test]
    fn tid_to_iso8601_roundtrip() {
        let tid = generate_tid();
        let iso = tid_to_iso8601(&tid).expect("valid TID");
        assert!(iso.ends_with('Z'), "should be UTC: {iso}");
        // fromISO8601 won't match exactly (clock ID is lost) but the
        // timestamp portion should produce a TID that converts back to
        // the same ISO string.
        let tid2 = tid_from_iso8601(&iso).expect("valid ISO");
        let iso2 = tid_to_iso8601(&tid2).expect("valid TID");
        assert_eq!(iso, iso2);
    }

    #[test]
    fn tid_from_iso8601_known_value() {
        let tid = tid_from_iso8601("2024-01-01T00:00:00Z").expect("valid ISO");
        assert_eq!(tid.len(), 13);
        let iso = tid_to_iso8601(&tid).expect("valid TID");
        assert_eq!(iso, "2024-01-01T00:00:00.000000Z");
    }

    #[test]
    fn tid_from_iso8601_rejects_garbage() {
        assert!(tid_from_iso8601("not a date").is_none());
    }

    #[test]
    fn tid_from_iso8601_with_offset() {
        let tid = tid_from_iso8601("2024-01-01T05:00:00+05:00").expect("valid ISO with offset");
        let iso = tid_to_iso8601(&tid).expect("valid TID");
        assert_eq!(iso, "2024-01-01T00:00:00.000000Z");
    }

    #[test]
    fn tid_from_iso8601_with_fractional_seconds() {
        let tid = tid_from_iso8601("2024-06-15T12:30:45.123456Z").expect("valid ISO");
        let iso = tid_to_iso8601(&tid).expect("valid TID");
        assert_eq!(iso, "2024-06-15T12:30:45.123456Z");
    }

    #[test]
    fn tid_to_unix_microseconds_known_value() {
        let tid = tid_from_iso8601("2024-01-01T00:00:00Z").expect("valid ISO");
        let us = tid_to_unix_microseconds(&tid).expect("valid TID");
        assert_eq!(us, 1_704_067_200_000_000);
    }

    #[test]
    fn tid_microseconds_roundtrip() {
        let tid = generate_tid();
        let us = tid_to_unix_microseconds(&tid).expect("valid TID");
        let tid2 = tid_from_unix_microseconds(us);
        let us2 = tid_to_unix_microseconds(&tid2).expect("valid TID");
        assert_eq!(us, us2);
    }

    #[test]
    fn tid_to_unix_microseconds_rejects_invalid() {
        assert!(tid_to_unix_microseconds("garbage").is_none());
    }

    #[test]
    fn tid_number_lossless_roundtrip() {
        let tid = generate_tid();
        let val = tid_to_number(&tid).expect("valid TID");
        let tid2 = tid_from_number(val);
        assert_eq!(tid, tid2);
    }

    #[test]
    fn tid_to_number_rejects_invalid() {
        assert!(tid_to_number("garbage").is_none());
    }

    #[test]
    fn tid_to_iso8601_rejects_invalid() {
        assert!(tid_to_iso8601("garbage").is_none());
        assert!(tid_to_iso8601("AAAAAAAAAAAAA").is_none());
    }
}
