//! Magic-byte signature scanning.
//!
//! `--magic-bytes` and (later) the `--carve` validators need the same table:
//! what bytes start which format. Keeping it here means one source of truth
//! and one fast matcher instead of a hand-rolled scan per feature.

use crate::chunk::{self, CHUNK_SIZE};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use std::sync::OnceLock;

/// One magic-byte signature.
#[derive(Debug, Clone, Copy)]
pub struct Signature {
    /// Bytes that identify the format.
    pub bytes: &'static [u8],
    /// Human-readable label used in output.
    pub kind: &'static str,
}

/// Signatures reported by `--magic-bytes`.
///
/// Adding an entry here is enough for both the CLI report and the future
/// carver to pick it up.
pub const SIGNATURES: &[Signature] = &[
    Signature {
        bytes: b"MZ",
        kind: "PE/DOS executable",
    },
    Signature {
        bytes: b"\x7fELF",
        kind: "ELF executable",
    },
    Signature {
        bytes: b"PK\x03\x04",
        kind: "ZIP/Office archive",
    },
    Signature {
        bytes: b"%PDF-",
        kind: "PDF document",
    },
    Signature {
        bytes: b"\x89PNG\r\n\x1a\n",
        kind: "PNG image",
    },
];

/// A signature hit at a byte offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicMatch {
    pub offset: u64,
    /// Index into [`SIGNATURES`].
    pub signature: usize,
}

impl MagicMatch {
    /// Label of the matched signature.
    pub fn kind(self) -> &'static str {
        SIGNATURES[self.signature].kind
    }
}

struct Matcher {
    aho: AhoCorasick,
    /// Pattern id -> index into [`SIGNATURES`].
    patterns: Vec<usize>,
}

fn matcher() -> &'static Matcher {
    static MATCHER: OnceLock<Matcher> = OnceLock::new();
    MATCHER.get_or_init(|| {
        let mut patterns = Vec::with_capacity(SIGNATURES.len());
        let mut needles = Vec::with_capacity(SIGNATURES.len());
        for (index, signature) in SIGNATURES.iter().enumerate() {
            patterns.push(index);
            needles.push(signature.bytes);
        }
        let aho = AhoCorasickBuilder::new()
            .build(needles)
            .expect("magic-byte signatures are valid patterns");
        Matcher { aho, patterns }
    })
}

/// Longest signature, used as the chunk overlap so a header that straddles an
/// I/O boundary is still matched.
fn max_signature_len() -> usize {
    SIGNATURES
        .iter()
        .map(|signature| signature.bytes.len())
        .max()
        .unwrap_or(1)
}

/// Scan `path` for every [`SIGNATURES`] hit, sorted by offset.
///
/// `max_matches` caps the result (`0` = unlimited); the scan stops as soon as
/// the cap is reached so a dump full of `MZ` bytes cannot blow up memory.
pub fn scan_file(path: &str, max_matches: usize) -> std::io::Result<Vec<MagicMatch>> {
    let limit = if max_matches == 0 {
        usize::MAX
    } else {
        max_matches
    };
    let overlap = max_signature_len().saturating_sub(1);
    let mut matches = Vec::new();
    chunk::for_each_chunk(path, CHUNK_SIZE, overlap, |window| {
        for found in matcher().aho.find_iter(window.data) {
            if !window.spans_new_bytes(found.end()) {
                continue;
            }
            matches.push(MagicMatch {
                offset: window.offset_of(found.start()),
                signature: matcher().patterns[found.pattern().as_usize()],
            });
            if matches.len() >= limit {
                return false;
            }
        }
        true
    })?;
    matches.sort_by_key(|found| found.offset);
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("bxmap-magic-{}-{}.bin", name, std::process::id()));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn finds_signatures_and_reports_offsets() {
        let mut data = vec![b'.'; 100];
        data.extend_from_slice(b"%PDF-1.7");
        let path = write_temp("pdf", &data);
        let matches = scan_file(path.to_str().unwrap(), 0).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(matches.len(), 1, "{matches:?}");
        assert_eq!(matches[0].offset, 100);
        assert_eq!(matches[0].kind(), "PDF document");
    }

    #[test]
    fn matches_signatures_that_straddle_a_chunk_boundary() {
        let mut data = vec![b'x'; CHUNK_SIZE - 1];
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(&vec![b'y'; CHUNK_SIZE]);
        data.extend_from_slice(b"%PDF-");
        let path = write_temp("boundary", &data);
        let matches = scan_file(path.to_str().unwrap(), 0).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(matches.len(), 2, "{matches:?}");
        assert_eq!(matches[0].offset, (CHUNK_SIZE - 1) as u64);
        assert_eq!(matches[0].kind(), "PE/DOS executable");
        assert_eq!(matches[1].kind(), "PDF document");
    }

    #[test]
    fn reports_each_hit_once() {
        let mut data = vec![b'.'; 10];
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(&vec![b'.'; CHUNK_SIZE]);
        data.extend_from_slice(b"MZ");
        let path = write_temp("once", &data);
        let matches = scan_file(path.to_str().unwrap(), 0).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(matches.len(), 2, "{matches:?}");
        assert!(matches[0].offset < matches[1].offset);
    }

    #[test]
    fn respects_the_match_cap() {
        let mut data = vec![b'M'; 10];
        for _ in 0..50 {
            data.extend_from_slice(b"MZ");
        }
        let path = write_temp("cap", &data);
        let matches = scan_file(path.to_str().unwrap(), 5).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(matches.len(), 5);
    }

    #[test]
    fn missing_file_is_an_error() {
        let missing = std::env::temp_dir().join("bxmap-magic-does-not-exist.bin");
        assert!(scan_file(missing.to_str().unwrap(), 0).is_err());
    }
}
