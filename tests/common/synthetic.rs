// Shared helpers for integration tests. Not compiled into the library.

use bxmap::extract_strings;

/// Build a small, deterministic "memory dump" in memory for tests.
///
/// Layout (all offsets are byte positions in the returned vector):
///   0..4096   : pseudo-random bytes (seeded, reproducible)
///   then      : ASCII string "HELLO_ASCII_MARKER" at a known offset
///   then      : UTF-16LE string "WIDE_MARKER" (null terminated)
///   then      : a few IOC-like tokens (IP, URL, fake AWS key)
///   then      : zeros to pad to ~64 KiB
pub fn synthetic_dump() -> Vec<u8> {
    let mut data = Vec::with_capacity(64 * 1024);
    // Seeded pseudo-random background (LCG, deterministic).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..4096 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        data.push((state >> 32) as u8);
    }
    data.push(0);
    let marker_off = data.len();
    data.extend_from_slice(b"HELLO_ASCII_MARKER\x00");
    // UTF-16LE "WIDE_MARKER\0"
    for unit in "WIDE_MARKER\0".encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    // IOC-like tokens
    data.extend_from_slice(b" 192.168.1.42 http://example.com/x AKIAIOSFODNN7EXAMPLE ");
    // Pad to 64 KiB with zeros.
    data.resize(64 * 1024, 0);
    let _ = marker_off;
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_dump_extracts_known_strings() {
        let data = synthetic_dump();
        let out = extract_strings(&data, 4, 100_000);
        assert!(out.iter().any(|s| s.text == "HELLO_ASCII_MARKER"));
        assert!(out.iter().any(|s| s.text == "WIDE_MARKER"));
    }
}
