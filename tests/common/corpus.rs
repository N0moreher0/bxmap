// A small, fully synthetic corpus for the regression tests.
//
// Nothing here comes from a real memory dump: every byte is generated, so the
// fixture can live in the repository without leaking evidence. The layout is
// fixed, which lets the tests assert exact offsets and exact output sets.

/// A string the corpus contains, with the offset it must be reported at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub offset: u64,
    pub encoding: &'static str,
    pub text: &'static str,
}

/// The corpus: raw bytes plus the strings they must produce.
pub struct Corpus {
    pub data: Vec<u8>,
    pub expected: Vec<Expected>,
}

/// Deterministic background that cannot form a printable run in ASCII and
/// does not create a valid UTF-16 or Shift-JIS pair: a high byte is always
/// followed by a plain control byte, which is not a valid trail byte.
fn push_noise(data: &mut Vec<u8>, bytes: usize) {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    while data.len() < bytes {
        for _ in 0..2 {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let r = (state >> 33) as u8;
            if data.len() % 2 == 0 {
                // C1 control range: not printable in ASCII or Latin-1.
                data.push(0x80 | (r & 0x1f));
            } else {
                // Plain control byte: not printable in ASCII, and not a valid
                // Shift-JIS trail byte either.
                data.push(1 + (r % 8));
            }
        }
    }
}

fn push_utf16(data: &mut Vec<u8>, text: &str, big_endian: bool) {
    for unit in text.encode_utf16() {
        let [lo, hi] = unit.to_le_bytes();
        if big_endian {
            data.extend_from_slice(&[hi, lo]);
        } else {
            data.extend_from_slice(&[lo, hi]);
        }
    }
    data.extend_from_slice(&[0, 0]);
}

/// Build the corpus and the list of strings it must produce.
pub fn synthetic_corpus() -> Corpus {
    let mut data: Vec<u8> = Vec::new();
    let mut expected: Vec<Expected> = Vec::new();

    // Background noise.
    push_noise(&mut data, 8 * 1024);

    // Plain ASCII marker.
    let offset = data.len();
    data.extend_from_slice(b"HELLO_ASCII_MARKER\0");
    expected.push(Expected {
        offset: offset as u64,
        encoding: "ascii",
        text: "HELLO_ASCII_MARKER",
    });

    // UTF-16LE marker.
    let offset = data.len();
    push_utf16(&mut data, "WIDE_LE_MARKER", false);
    expected.push(Expected {
        offset: offset as u64,
        encoding: "utf16le",
        text: "WIDE_LE_MARKER",
    });

    // UTF-16BE marker.
    let offset = data.len();
    push_utf16(&mut data, "WIDE_BE_MARKER", true);
    expected.push(Expected {
        offset: offset as u64,
        encoding: "utf16be",
        text: "WIDE_BE_MARKER",
    });

    // UTF-8 with multi-byte characters. The ASCII fragments around them stay
    // below the minimum length, so the ASCII view stays exact.
    let offset = data.len();
    data.extend_from_slice("\u{4e2d}caf\u{e9}abc".as_bytes());
    data.push(0);
    expected.push(Expected {
        offset: offset as u64,
        encoding: "utf8",
        text: "\u{4e2d}caf\u{e9}abc",
    });

    // IOC-ish tokens, one ASCII run.
    let offset = data.len();
    data.extend_from_slice(b"192.168.1.42 https://example.org/login analyst@example.com\0");
    expected.push(Expected {
        offset: offset as u64,
        encoding: "ascii",
        text: "192.168.1.42 https://example.org/login analyst@example.com",
    });

    // A Windows path.
    let offset = data.len();
    data.extend_from_slice(b"C:\\Users\\analyst\\Desktop\\notes.txt\0");
    expected.push(Expected {
        offset: offset as u64,
        encoding: "ascii",
        text: "C:\\Users\\analyst\\Desktop\\notes.txt",
    });

    // An environment block in UTF-16LE -- the classic place to find a
    // password in a memory dump.
    let offset = data.len();
    push_utf16(&mut data, "PASSWORD=hunter2hunter2", false);
    expected.push(Expected {
        offset: offset as u64,
        encoding: "utf16le",
        text: "PASSWORD=hunter2hunter2",
    });

    // A cloud key and a card number next to each other.
    let offset = data.len();
    data.extend_from_slice(b"AKIAIOSFODNN7EXAMPLE 4532015112830366\0");
    expected.push(Expected {
        offset: offset as u64,
        encoding: "ascii",
        text: "AKIAIOSFODNN7EXAMPLE 4532015112830366",
    });

    // Trailing noise, so the last string is not at the end of the buffer.
    push_noise(&mut data, 4 * 1024);

    Corpus { data, expected }
}
