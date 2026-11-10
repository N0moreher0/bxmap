//! `bxmap` -- a standalone crate (open source, dual-licensed under MIT OR Apache-2.0;
//! the `bxmap-cli` frontend is licensed separately under AGPL-3.0-only).
//! Depends on `serde` (so `ExtractedString` can be
//! serialized -- the caller decides how to wrap it in JSON/its own protocol
//! if needed, this crate only returns a plain `Vec<ExtractedString>`) and
//! `rayon`, used only by the opt-in parallel scanning path
//! (`extract_strings_from_file_parallel`) -- the default sequential/
//! streaming path does not touch it.
//!
//! Pulls printable ASCII / UTF-16LE strings out of a raw `.dmp` memory-dump
//! file (or any other binary file). Pure post-processing over an
//! already-existing file on disk (no WinAPI / process-permission
//! involved) -- scans the buffer sequentially, grouping contiguous runs of
//! printable bytes (ASCII) and UTF-16LE runs (printable low byte, high byte
//! == 0x00), the same principle as the Unix `strings` command. It does NOT
//! parse the MDMP file format's internal structure -- scanning the whole
//! payload is the only approach that doesn't depend on the Windows/DbgHelp
//! version that produced the dump.
//!
//! Two things keep this fast and memory-safe on multi-gigabyte files:
//! - Chunked streaming (`CHUNK_SIZE` = 32MB per read) via `Read`, carrying
//!   exactly 1 trailing byte over to the next chunk so a UTF-16LE pair
//!   straddling an I/O boundary is always tested correctly -- the whole
//!   file (which can be several GB) is NEVER loaded into RAM at once.
//! - ASCII and UTF-16LE are detected SIMULTANEOUSLY in a single pass
//!   (`StringRunScanner::feed`) instead of two independent loops -- fewer
//!   passes over the buffer.
//!
//! SPEED OPTIMIZATIONS (results unchanged, speed only): (1) a precomputed
//! 256-entry `PRINTABLE_TABLE` lookup table built at compile time instead
//! of a range-match per byte; (2) each byte is looked up in the printable
//! table EXACTLY ONCE (the ascii branch and the utf16 branch, when that
//! byte acts as the "lo" byte, share the same lookup); (3) fast-skip jumps
//! straight over an entire run of consecutive non-printable bytes when no
//! run is currently open (skipping the lookahead/aligned computation and
//! the no-op flush() calls for each junk byte entirely) -- non-printable
//! binary regions typically make up the bulk of a real RAM dump, so this
//! is the hottest path.
//!
//! Noise filtering (higher filter accuracy than a naive `strings`-style
//! scan, same ASCII/UTF-16LE run-grouping logic): a naive scan accepts ANY
//! run meeting `min_len` as a valid "string", including a run of a single
//! repeated character (`AAAAAAAA...`) or two characters alternating
//! (`ABABABAB...`) -- an extremely common kind of noise in real RAM dumps
//! (byte-fill/heap-fill patterns on alloc/free, alignment padding, repeated
//! memset), which almost never carries useful information and needlessly
//! bloats the result. `is_low_information_repeat()` filters exactly those
//! two simple repeat shapes (period 1 and period 2, only triggered from a
//! long-enough threshold so it doesn't accidentally drop short real
//! strings like "0000"/"====" which can still be real data) -- it does NOT
//! filter more broadly (no entropy/complex statistics) to avoid false
//! negatives (missing real strings), staying true to the "only filter
//! what's certainly noise" spirit.
pub mod artifacts;
pub mod carve;
pub mod chunk;
pub mod classifier;
pub use classifier::{
    classify, detect_bitlocker_header, detect_encryption_shell, detect_luks_header,
    detect_openssl_encrypted, detect_pgp_container, detect_secrets, detect_secrets_detailed,
    detect_veracrypt_header, entropy_of, extract_pems, validate_base58check, validate_bech32,
    validate_credit_card, validate_finding, validate_jwt, validate_luhn, EncryptedContainer,
    ValidationResult,
};
pub mod keys;
pub mod magic;
pub mod minidump;
pub mod vmware;
pub use keys::KeyCandidate;

use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

/// One pattern hit contributing to a [`YaraMatch`].
#[derive(Debug, Clone)]
pub struct YaraMatchHit {
    pub pattern: String,
    pub offset: u64,
    pub length: usize,
}

pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    /// Offset of the first pattern match in this window (0 if none reported).
    pub offset: u64,
    /// Every pattern match found in this window. May be empty when yara-x
    /// reports a rule match without an individual pattern range.
    pub matches: Vec<YaraMatchHit>,
}

/// Compiles YARA source and scans a reader in bounded chunks (windowed mode).
///
/// A small overlap is retained between chunks so literals and regular
/// expressions crossing an I/O boundary are still visible to YARA. Pattern
/// hits lying entirely inside the overlap were already reported by the previous
/// window and are skipped. A rule is reported for every window with new hits; `offset`
/// is the real offset of the first pattern hit in that window (not the window
/// start), and `matches` lists every hit with its pattern id and range.
///
/// Limits of windowed mode: rules whose semantics depend on the whole input
/// (`filesize`, `#a >= 2` across distant windows, `for all`, `at`, ...) are
/// evaluated per window and may differ from a single full-file scan. Use
/// [`scan_yara_from_file_streaming`] for files; for whole-file semantics on a
/// path, prefer yara-x's `Scanner::scan_file` directly.
#[cfg(feature = "yara")]
pub fn scan_yara_from_reader_streaming<R: Read, F: FnMut(YaraMatch)>(
    reader: R,
    rules_source: &str,
    on_match: F,
) -> std::io::Result<usize> {
    scan_yara_windowed(
        reader,
        rules_source,
        CHUNK_SIZE,
        YARA_OVERLAP_SIZE,
        on_match,
    )
}

/// Lõi quét YARA theo cửa sổ. Tách `chunk_size`/`overlap_size` thành tham số
/// để test dùng cửa sổ nhỏ; hàm công khai truyền hằng số mặc định.
#[cfg(feature = "yara")]
fn scan_yara_windowed<R: Read, F: FnMut(YaraMatch)>(
    mut reader: R,
    rules_source: &str,
    chunk_size: usize,
    overlap_size: usize,
    mut on_match: F,
) -> std::io::Result<usize> {
    let chunk_size = chunk_size.max(1);
    let rules = yara_x::compile(rules_source).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    let mut scanner = yara_x::Scanner::new(&rules);
    let mut buffer = vec![0u8; chunk_size];
    let mut carry = Vec::new();
    let mut global_offset = 0u64;
    let mut count = 0usize;

    loop {
        // Lấp đầy buffer: pipe/stdin/reader tuỳ biến có thể trả ngắn, nếu chỉ
        // `read` một lần thì mỗi cửa sổ rất nhỏ và vùng overlap bị quét lặp.
        let mut read = 0usize;
        while read < chunk_size {
            match reader.read(&mut buffer[read..]) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if read == 0 {
            break;
        }
        let carried = carry.len();
        let mut window = Vec::with_capacity(carried + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..read]);
        let window_offset = global_offset.saturating_sub(carried as u64);
        let results = scanner.scan(&window).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        for rule in results.matching_rules() {
            // Gom mọi hit với offset thật; bỏ hit nằm trọn trong phần carry vì
            // cửa sổ trước đã nhìn thấy và báo rồi (tránh báo trùng).
            let mut hits = Vec::new();
            let mut first_offset = window_offset;
            let mut have_first = false;
            let mut skipped_old = false;
            for pattern in rule.patterns() {
                for m in pattern.matches() {
                    let range = m.range();
                    if range.end <= carried {
                        skipped_old = true;
                        continue;
                    }
                    let off = window_offset + range.start as u64;
                    if !have_first {
                        first_offset = off;
                        have_first = true;
                    }
                    hits.push(YaraMatchHit {
                        pattern: pattern.identifier().to_string(),
                        offset: off,
                        length: range.len(),
                    });
                }
            }
            // Rule chỉ khớp lại đúng dữ liệu cũ trong overlap: đã báo trước đó.
            if hits.is_empty() && skipped_old {
                continue;
            }
            on_match(YaraMatch {
                rule: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                offset: first_offset,
                matches: hits,
            });
            count += 1;
        }
        carry.clear();
        let overlap = window.len().min(overlap_size);
        carry.extend_from_slice(&window[window.len() - overlap..]);
        global_offset += read as u64;
    }
    Ok(count)
}
/// Stub used by lite builds (`--no-default-features`): YARA is not compiled in.
#[cfg(not(feature = "yara"))]
pub fn scan_yara_from_reader_streaming<R: Read, F: FnMut(YaraMatch)>(
    _reader: R,
    _rules_source: &str,
    _on_match: F,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "YARA support is not compiled into this lite build; use the full build",
    ))
}

/// File-based convenience wrapper for [`scan_yara_from_reader_streaming`].
pub fn scan_yara_from_file_streaming<F: FnMut(YaraMatch)>(
    dump_path: &str,
    rules_path: &str,
    on_match: F,
) -> std::io::Result<usize> {
    let rules_source = std::fs::read_to_string(rules_path)?;
    let file = File::open(dump_path)?;
    scan_yara_from_reader_streaming(
        BufReader::with_capacity(1 << 16, file),
        &rules_source,
        on_match,
    )
}

/// Default `min_len` when the caller doesn't pass one -- a reasonable
/// baseline for the `extract_strings*` functions below when the caller
/// wants a sensible default instead of picking their own.
pub const MIN_STRING_LEN: usize = 4;
/// Default `max_strings` (see MIN_STRING_LEN above).
pub const MAX_STRINGS: usize = 200_000;

// Default minimum length for a "single repeated character" run (period 1,
// e.g. "aaaaaa") to be treated as byte-fill/padding noise rather than real
// data. Set a bit higher than the default MIN_STRING_LEN (4) because short
// strings like "0000"/"1111" can still be real numbers (a PIN, a repeated
// year...). Overridable at runtime via `NoiseConfig` / `--noise-threshold`.
const NOISE_REPEAT1_MIN_LEN: usize = 6;

// Default minimum length for a "strictly alternating 2-character" run
// (period 2, e.g. "ababab"/"\xCD\xAB\xCD\xAB...") to be treated as noise --
// higher than the period-1 threshold because a 2-character pattern has a
// slightly higher chance of coincidentally matching a real string (e.g. a
// short letter pair repeated), so more length evidence is required to be
// confident it's a fill pattern. Overridable at runtime, see `NoiseConfig`.
const NOISE_REPEAT2_MIN_LEN: usize = 8;

/// Runtime-configurable noise-filter thresholds (see `is_low_information_repeat`).
/// Previously these were the hardcoded constants `NOISE_REPEAT1_MIN_LEN` /
/// `NOISE_REPEAT2_MIN_LEN` -- now callers (including the CLI's
/// `--noise-threshold <N>`) can tune or fully disable the filter.
#[derive(Debug, Clone, Copy)]
pub struct NoiseConfig {
    /// Minimum run length for a period-1 repeat (e.g. "aaaaaa") to count as noise.
    pub repeat1_min_len: usize,
    /// Minimum run length for a period-2 repeat (e.g. "abab") to count as noise.
    pub repeat2_min_len: usize,
}

impl Default for NoiseConfig {
    fn default() -> Self {
        Self {
            repeat1_min_len: NOISE_REPEAT1_MIN_LEN,
            repeat2_min_len: NOISE_REPEAT2_MIN_LEN,
        }
    }
}

impl NoiseConfig {
    /// Turns the noise filter off entirely (every run is kept, however repetitive).
    pub fn disabled() -> Self {
        Self {
            repeat1_min_len: usize::MAX,
            repeat2_min_len: usize::MAX,
        }
    }

    /// Builds a config from a single `--noise-threshold <N>`-style value:
    /// `N` becomes the period-1 threshold, and the period-2 threshold is
    /// `N + 2` (preserving the original gap between the two, since a
    /// 2-character pattern needs a bit more length evidence to be confident
    /// it's a fill pattern rather than a coincidental short real string).
    /// `0` disables the filter entirely.
    pub fn from_threshold(threshold: usize) -> Self {
        if threshold == 0 {
            Self::disabled()
        } else {
            Self {
                repeat1_min_len: threshold,
                repeat2_min_len: threshold + 2,
            }
        }
    }
}

/// Size of the buffer the sequential scanner reads into (32 MiB).
///
/// File chunk size per read -- large enough for efficient I/O, small enough to
/// not accumulate too much RAM for the buffer.
pub const SEQUENTIAL_BUFFER_SIZE: usize = 32 * 1024 * 1024;
const CHUNK_SIZE: usize = SEQUENTIAL_BUFFER_SIZE;
// Keeps ordinary YARA literals and bounded regexes visible across chunk
// boundaries without turning the streaming scan into a whole-file read.
#[cfg(feature = "yara")]
const YARA_OVERLAP_SIZE: usize = 64 * 1024;
/// Fixed window used by the entropy pass. Keeping this separate from the
/// string-scan chunk makes entropy results comparable across files.
pub const ENTROPY_BLOCK_SIZE: usize = 64 * 1024;

// Upper bound on the length of a currently-open "run" before it's forced
// to flush into the results -- guards against an unusually long run of
// contiguous printable bytes growing the buffer without limit. 1MB of text
// for a single "string" is already more than enough to spot an IOC.
const MAX_RUN_CHARS: usize = 1_000_000;

const AVG_BYTES_PER_STRING: u64 = 48; // pure heuristic, only used to hint the initial capacity
const MIN_CAPACITY_HINT: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: &'static str,
    pub text: String,
}

/// A fixed file region whose byte distribution has high Shannon entropy.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct EntropyRegion {
    pub offset: u64,
    pub length: usize,
    pub entropy: f64,
}

/// Computes Shannon entropy in bits per byte for a byte slice.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

/// Streams high-entropy fixed-size regions from a file.
///
/// This is a heuristic signal for compressed, encrypted, or packed data. It
/// does not identify which of those cases applies and does not decrypt data.
pub fn scan_entropy_from_file_streaming<F: FnMut(EntropyRegion)>(
    dump_path: &str,
    threshold: f64,
    mut on_region: F,
) -> std::io::Result<usize> {
    scan_entropy_from_file_streaming_with_data(dump_path, threshold, |region, _data| {
        on_region(region);
    })
}

/// Like [`scan_entropy_from_file_streaming`], but also provides each matching
/// block's bytes to the callback before the scan buffer is reused.
pub fn scan_entropy_from_file_streaming_with_data<F: FnMut(EntropyRegion, &[u8])>(
    dump_path: &str,
    threshold: f64,
    mut on_region: F,
) -> std::io::Result<usize> {
    scan_entropy_from_file_with_options(
        dump_path,
        EntropyScanOptions {
            threshold,
            ..EntropyScanOptions::default()
        },
        |region, data, _truncated| on_region(region, data),
    )
}

/// Configurable entropy pass.
#[derive(Debug, Clone, Copy)]
pub struct EntropyScanOptions {
    /// Bytes per entropy window. `0` falls back to [`ENTROPY_BLOCK_SIZE`].
    pub window: usize,
    /// Minimum Shannon entropy (bits per byte) for a window to be reported.
    pub threshold: f64,
    /// Merge contiguous high-entropy windows into one region. The merged
    /// region reports the exact entropy of the whole run.
    pub merge: bool,
    /// Keep at most this many payload bytes per region. `0` keeps no payload;
    /// [`usize::MAX`] keeps everything (which can grow large when `merge` is
    /// enabled).
    pub max_data: usize,
}

impl Default for EntropyScanOptions {
    fn default() -> Self {
        Self {
            window: ENTROPY_BLOCK_SIZE,
            threshold: ENTROPY_DEFAULT_THRESHOLD,
            merge: false,
            max_data: usize::MAX,
        }
    }
}

/// Default entropy threshold used by the CLI and the simple scan helpers.
pub const ENTROPY_DEFAULT_THRESHOLD: f64 = 7.2;

/// Pending merged region: keeps the exact byte histogram (so the merged
/// entropy is exact) plus a capped copy of the payload.
struct PendingEntropyRegion {
    offset: u64,
    length: usize,
    counts: [u64; 256],
    data: Vec<u8>,
    data_truncated: bool,
}

impl PendingEntropyRegion {
    fn new(offset: u64, max_data: usize) -> Self {
        Self {
            offset,
            length: 0,
            counts: [0u64; 256],
            data: Vec::with_capacity(max_data.min(ENTROPY_BLOCK_SIZE)),
            data_truncated: false,
        }
    }

    fn extend(&mut self, block: &[u8], max_data: usize) {
        self.length += block.len();
        for &byte in block {
            self.counts[byte as usize] += 1;
        }
        let keep = max_data.saturating_sub(self.data.len()).min(block.len());
        self.data.extend_from_slice(&block[..keep]);
        if keep < block.len() {
            self.data_truncated = true;
        }
    }

    fn region(&self) -> EntropyRegion {
        EntropyRegion {
            offset: self.offset,
            length: self.length,
            entropy: entropy_from_counts(&self.counts, self.length),
        }
    }
}

fn entropy_from_counts(counts: &[u64; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / len;
            -probability * probability.log2()
        })
        .sum()
}

/// Configurable streaming entropy scan.
///
/// The callback receives each region, a payload slice capped at
/// `options.max_data` (`usize::MAX` keeps the whole region) and a flag telling
/// whether the payload was truncated. When `options.merge` is set, contiguous
/// windows above the threshold are reported as a single region whose entropy
/// is computed exactly from the full byte histogram.
pub fn scan_entropy_from_file_with_options<F: FnMut(EntropyRegion, &[u8], bool)>(
    dump_path: &str,
    options: EntropyScanOptions,
    mut on_region: F,
) -> std::io::Result<usize> {
    let window = if options.window == 0 {
        ENTROPY_BLOCK_SIZE
    } else {
        options.window
    };
    let max_data = options.max_data;
    let mut file = File::open(dump_path)?;
    let mut buffer = vec![0u8; window];
    let mut offset = 0u64;
    let mut emitted = 0usize;
    let mut pending: Option<PendingEntropyRegion> = None;

    loop {
        let mut filled = 0usize;
        while filled < buffer.len() {
            let read = file.read(&mut buffer[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            break;
        }
        let block = &buffer[..filled];
        if shannon_entropy(block) >= options.threshold {
            let contiguous = pending
                .as_ref()
                .is_some_and(|region| region.offset + region.length as u64 == offset);
            if options.merge && contiguous {
                if let Some(region) = pending.as_mut() {
                    region.extend(block, max_data);
                }
            } else {
                if let Some(region) = pending.take() {
                    let current = region.region();
                    on_region(current, &region.data, region.data_truncated);
                    emitted += 1;
                }
                let mut region = PendingEntropyRegion::new(offset, max_data);
                region.extend(block, max_data);
                pending = Some(region);
            }
        } else if let Some(region) = pending.take() {
            let current = region.region();
            on_region(current, &region.data, region.data_truncated);
            emitted += 1;
        }
        offset += filled as u64;
        if filled < buffer.len() {
            break;
        }
    }
    if let Some(region) = pending.take() {
        let current = region.region();
        on_region(current, &region.data, region.data_truncated);
        emitted += 1;
    }
    Ok(emitted)
}

/// The printable-character set: printable ASCII + common whitespace,
/// minus `\v` (0x0b) and `\f` (0x0c).
///
/// OPTIMIZATION (character set unchanged): a 256-entry lookup table is
/// computed at compile time instead of matching several range branches per
/// byte -- looking up `PRINTABLE_TABLE[b as usize]` is a branchless O(1)
/// array read, much cheaper than a chain of range comparisons when running
/// over tens/hundreds of millions of bytes in a real dump file.
const fn build_printable_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = match b {
            b'0'..=b'9' => true,
            b'A'..=b'Z' => true,
            b'a'..=b'z' => true,
            b' ' | b'\t' | b'\n' | b'\r' => true,
            // !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
            0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => true,
            _ => false,
        };
        i += 1;
    }
    table
}

/// Latin1 (ISO-8859-1) printable set: ASCII printable + 0xA0-0xFF (except control chars)
const fn build_latin1_printable_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = match b {
            // ASCII printable
            b'0'..=b'9' => true,
            b'A'..=b'Z' => true,
            b'a'..=b'z' => true,
            b' ' | b'\t' | b'\n' | b'\r' => true,
            0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => true,
            // Latin1 extended: 0xA0-0xFF (excluding control chars 0x80-0x9F)
            0xA0..=0xFF => true,
            _ => false,
        };
        i += 1;
    }
    table
}

/// CP1252 (Windows-1252) printable set: ASCII printable + 0x80-0xFF (with specific mappings)
/// 0x80-0x9F have printable chars in CP1252 (€, ', ƒ, ", …, †, ‡, ˆ, ‰, Š, ‹, Œ, Ž, ', ', ", •, –, —, ˜, ™, š, ›, œ, ž, Ÿ)
const fn build_cp1252_printable_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        table[i] = match b {
            // ASCII printable
            b'0'..=b'9' => true,
            b'A'..=b'Z' => true,
            b'a'..=b'z' => true,
            b' ' | b'\t' | b'\n' | b'\r' => true,
            0x21..=0x2F | 0x3A..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E => true,
            // CP1252 specific: 0x80-0x9F are printable (unlike Latin1), except the
            // five bytes Windows leaves undefined (0x81, 0x8D, 0x8F, 0x90, 0x9D):
            // they decode to C1 control characters, which no one can read.
            0x81 | 0x8D | 0x8F | 0x90 | 0x9D => false,
            0x80..=0x9F => true,
            // Latin1 extended: 0xA0-0xFF
            0xA0..=0xFF => true,
            _ => false,
        };
        i += 1;
    }
    table
}

static PRINTABLE_TABLE: [bool; 256] = build_printable_table();
static LATIN1_PRINTABLE_TABLE: [bool; 256] = build_latin1_printable_table();
static CP1252_PRINTABLE_TABLE: [bool; 256] = build_cp1252_printable_table();

#[inline(always)]
fn is_printable(b: u8) -> bool {
    PRINTABLE_TABLE[b as usize]
}

#[inline(always)]
fn is_latin1_printable(b: u8) -> bool {
    LATIN1_PRINTABLE_TABLE[b as usize]
}

#[inline(always)]
fn is_cp1252_printable(b: u8) -> bool {
    CP1252_PRINTABLE_TABLE[b as usize]
}

/// Returns the expected length of a UTF-8 sequence based on the first byte.
/// Returns 1 for ASCII, 2-4 for multi-byte sequences, or 0 for invalid.
fn utf8_expected_len(first: u8) -> usize {
    if first < 0x80 {
        1 // ASCII
    } else if first < 0xC0 {
        0 // Continuation byte (0x80-0xBF) - invalid as start
    } else if first < 0xE0 {
        2 // 2-byte sequence
    } else if first < 0xF0 {
        3 // 3-byte sequence
    } else if first < 0xF8 {
        4 // 4-byte sequence
    } else {
        0 // Invalid
    }
}

/// Validates a UTF-8 byte sequence.
fn utf8_validate_seq(seq: &[u8]) -> bool {
    utf8_validate_structure(seq)
        && std::str::from_utf8(seq)
            .ok()
            .and_then(|s| s.chars().next())
            .is_some_and(is_readable_char)
}

/// Structural UTF-8 check only (lead/continuation bytes, overlong, surrogates).
fn utf8_validate_structure(seq: &[u8]) -> bool {
    if seq.is_empty() {
        return false;
    }
    let expected = utf8_expected_len(seq[0]);
    if expected == 0 || seq.len() != expected {
        return false;
    }
    for (_, &byte) in seq.iter().enumerate().skip(1) {
        if !(0x80..=0xBF).contains(&byte) {
            return false;
        }
    }
    // Check for overlong encoding
    match expected {
        2 => seq[0] >= 0xC2, // No overlong 2-byte
        3 => {
            // No overlong 3-byte, no surrogates
            !(seq[0] == 0xE0 && seq[1] < 0xA0) && !(seq[0] == 0xED && seq[1] >= 0xA0)
        }
        4 => {
            // No overlong 4-byte, max U+10FFFF
            !(seq[0] == 0xF0 && seq[1] < 0x90) && !(seq[0] == 0xF4 && seq[1] >= 0x90)
        }
        _ => true,
    }
}

/// Checks if a byte is a valid Shift-JIS lead byte.
fn shift_jis_is_lead_byte(b: u8) -> bool {
    (0x81..=0x9F).contains(&b) || (0xE0..=0xFC).contains(&b)
}

/// Checks if a byte is a valid Shift-JIS trail byte.
fn shift_jis_is_trail_byte(b: u8) -> bool {
    (0x40..=0x7E).contains(&b) || (0x80..=0xFC).contains(&b)
}

/// True for characters a reader can actually see. Rejects U+FFFD, control
/// characters (C0/C1), private-use areas and noncharacters. Random binary data
/// that merely *looks* like a multi-byte encoding decodes to these, and they show
/// up as "?" / "<?>" in most terminals.
fn is_readable_char(c: char) -> bool {
    let cp = c as u32;
    !(c == '\u{FFFD}'
        || c.is_control()
        || (0xE000..=0xF8FF).contains(&cp)
        // Planes 15-16 are entirely private use.
        || (0xF0000..=0x10FFFF).contains(&cp)
        || (0xFDD0..=0xFDEF).contains(&cp)
        // U+xFFFE / U+xFFFF of every plane are noncharacters.
        || (cp & 0xFFFE) == 0xFFFE)
}

/// True when `(lead, trail)` is a Shift-JIS pair that decodes to exactly one
/// readable character. Checking only the byte ranges also accepts unassigned
/// pairs (decoded as U+FFFD) and the user-defined area (decoded as private use).
fn shift_jis_pair_valid(lead: u8, trail: u8) -> bool {
    static TABLE: std::sync::OnceLock<Vec<bool>> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = vec![false; 256 * 256];
        for l in 0u8..=255 {
            if !shift_jis_is_lead_byte(l) {
                continue;
            }
            for r in 0u8..=255 {
                if !shift_jis_is_trail_byte(r) {
                    continue;
                }
                let s = shift_jis_to_utf8(&[l, r]);
                let mut chars = s.chars();
                if let (Some(c), None) = (chars.next(), chars.next()) {
                    t[l as usize * 256 + r as usize] = is_readable_char(c);
                }
            }
        }
        t
    });
    table[lead as usize * 256 + trail as usize]
}

/// Converts a CP1252 byte to a Unicode character.
fn cp1252_to_char(b: u8) -> char {
    match b {
        0x80 => '€',
        0x81 => '\u{0081}', // undefined
        0x82 => '‚',
        0x83 => 'ƒ',
        0x84 => '„',
        0x85 => '…',
        0x86 => '†',
        0x87 => '‡',
        0x88 => 'ˆ',
        0x89 => '‰',
        0x8A => 'Š',
        0x8B => '‹',
        0x8C => 'Œ',
        0x8D => '\u{008D}', // undefined
        0x8E => 'Ž',
        0x8F => '\u{008F}', // undefined
        0x90 => '\u{0090}', // undefined
        0x91 => '\u{2018}', // Left single quotation mark
        0x92 => '\u{2019}', // Right single quotation mark
        0x93 => '"',
        0x94 => '"',
        0x95 => '•',
        0x96 => '–',
        0x97 => '—',
        0x98 => '˜',
        0x99 => '™',
        0x9A => 'š',
        0x9B => '›',
        0x9C => 'œ',
        0x9D => '\u{009D}', // undefined
        0x9E => 'ž',
        0x9F => 'Ÿ',
        0xA0..=0xFF => char::from(b), // Latin1 range
        _ => char::from(b),           // ASCII
    }
}

/// Converts Shift-JIS byte sequence to UTF-8 string.
#[cfg(feature = "shift-jis")]
fn shift_jis_to_utf8(bytes: &[u8]) -> String {
    // encoding_rs provides a comprehensive Shift-JIS decoder (JIS X 0208 with
    // the usual extension axes), replacing the partial hand-rolled table that
    // previously dropped most non-Hiragana/Katakana pairs. Invalid sequences
    // become U+FFFD; valid input never emits one.
    encoding_rs::SHIFT_JIS
        .decode_without_bom_handling(bytes)
        .0
        .into_owned()
}

/// Converts Shift-JIS byte sequence to UTF-8 string using the legacy
/// hand-rolled table. Kept for `--no-default-features` builds.
#[cfg(not(feature = "shift-jis"))]
fn shift_jis_to_utf8(bytes: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if shift_jis_is_lead_byte(b) && i + 1 < bytes.len() {
            let b2 = bytes[i + 1];
            if shift_jis_is_trail_byte(b2) {
                // Try to decode as Shift-JIS
                if let Some(ch) = shift_jis_decode_pair(b, b2) {
                    result.push(ch);
                } else {
                    // Fallback: use replacement character
                    result.push('\u{FFFD}');
                }
                i += 2;
                continue;
            }
        }
        // Single byte (ASCII or half-width katakana)
        if b < 0x80 || (0xA1..=0xDF).contains(&b) {
            // Half-width katakana (0xA1-0xDF) - map to Unicode
            if (0xA1..=0xDF).contains(&b) {
                // Half-width katakana: 0xA1-0xDF maps to U+FF61-U+FF9F
                result.push(char::from_u32(0xFF61 + (b - 0xA1) as u32).unwrap_or('\u{FFFD}'));
            } else {
                result.push(char::from(b));
            }
        } else {
            result.push('\u{FFFD}');
        }
        i += 1;
    }
    result
}

/// Decodes a Shift-JIS lead/trail byte pair to a Unicode character.
#[cfg(not(feature = "shift-jis"))]
fn shift_jis_decode_pair(lead: u8, trail: u8) -> Option<char> {
    // JIS X 0208 mapping (simplified for common ranges)
    let ku = if lead <= 0x9F {
        (lead - 0x81) as u32 * 2 + 1
    } else {
        (lead - 0xE0) as u32 * 2 + 1 + (0x9F - 0x81 + 1) * 2
    };
    let ten = if trail <= 0x7E {
        trail as u32 - 0x40
    } else {
        trail as u32 - 0x80 + 0x3F
    };
    let _jis_code = ku * 100 + ten; // Not standard, but for lookup

    // For a proper implementation, we'd need a full JIS X 0208 -> Unicode table
    // This is a simplified version handling common cases
    match (lead, trail) {
        // Common ASCII punctuation in Shift-JIS
        (0x81, 0x40) => Some('　'), // Ideographic space
        // Hiragana range
        (0x82, 0x9F..=0xF1) => char::from_u32(0x3040 + (trail - 0x9F) as u32),
        // Katakana range
        (0x83, 0x40..=0x96) => char::from_u32(0x30A0 + (trail - 0x40) as u32),
        // Greek letters
        (0x83, 0x9F..=0xB6) => char::from_u32(0x0390 + (trail - 0x9F) as u32),
        // Cyrillic
        (0x83, 0xB7..=0xD0) => char::from_u32(0x0410 + (trail - 0xB7) as u32),
        // Box drawing
        (0x81, 0x7C..=0x9B) => char::from_u32(0x2500 + (trail - 0x7C) as u32),
        // Common punctuation
        (0x81, 0x41..=0x5F) => char::from_u32(0xFF00 + (trail - 0x41) as u32), // Full-width ASCII
        _ => None,
    }
}

/// Stateful scanner that groups ASCII + UTF-16LE runs SIMULTANEOUSLY in a
/// single pass over the buffer, and carries its state (a still-open run)
/// ACROSS successive calls to `feed()` on different chunks of data read
/// from the file -- so a string straddling two I/O chunk boundaries is
/// still grouped in full, never truncated or lost.
///
/// The UTF-16LE testing rule is kept EXACTLY as in the original: every byte
/// position could be the START of a new string (every offset is tried),
/// but while a run is ALREADY open, the next test only happens at the
/// correct "next low byte" position (2 bytes ahead).
/// Selects which encodings the scanner will actually look for. Restricting
/// this (e.g. to ASCII only) lets the core loop skip the work for the other
/// encodings entirely, instead of scanning everything and filtering later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingFilter {
    pub ascii: bool,
    pub utf16le: bool,
    pub utf16be: bool,
    pub utf32le: bool,
    pub utf32be: bool,
    pub latin1: bool,
    pub cp1252: bool,
    pub utf8: bool,
    pub shift_jis: bool,
}

impl EncodingFilter {
    pub const fn all() -> Self {
        Self {
            ascii: true,
            utf16le: true,
            utf16be: true,
            utf32le: true,
            utf32be: true,
            latin1: true,
            cp1252: true,
            utf8: true,
            shift_jis: true,
        }
    }
    pub const fn ascii() -> Self {
        Self {
            ascii: true,
            utf16le: false,
            utf16be: false,
            utf32le: false,
            utf32be: false,
            latin1: false,
            cp1252: false,
            utf8: false,
            shift_jis: false,
        }
    }
    pub const fn utf16() -> Self {
        Self {
            ascii: false,
            utf16le: true,
            utf16be: true,
            utf32le: false,
            utf32be: false,
            latin1: false,
            cp1252: false,
            utf8: false,
            shift_jis: false,
        }
    }
    pub const fn utf32() -> Self {
        Self {
            ascii: false,
            utf16le: false,
            utf16be: false,
            utf32le: true,
            utf32be: true,
            latin1: false,
            cp1252: false,
            utf8: false,
            shift_jis: false,
        }
    }
    pub const fn legacy() -> Self {
        Self {
            ascii: true,
            utf16le: true,
            utf16be: true,
            utf32le: true,
            utf32be: true,
            latin1: true,
            cp1252: true,
            utf8: false,
            shift_jis: false,
        }
    }
    pub const fn extended() -> Self {
        Self {
            ascii: true,
            utf16le: true,
            utf16be: true,
            utf32le: true,
            utf32be: true,
            latin1: true,
            cp1252: true,
            utf8: true,
            shift_jis: true,
        }
    }
}

struct StringRunScanner<'a> {
    min_len: usize,
    noise_cfg: NoiseConfig,
    on_found: &'a mut dyn FnMut(ExtractedString),

    ascii_start: i64,
    ascii_buf: Vec<u8>,

    u16_start: i64,
    u16_next_pos: i64,
    u16_buf: Vec<u16>,

    u16be_start: i64,
    u16be_next_pos: i64,
    u16be_buf: Vec<u16>,

    u32le_start: i64,
    u32le_next_pos: i64,
    u32le_buf: Vec<u32>,

    u32be_start: i64,
    u32be_next_pos: i64,
    u32be_buf: Vec<u32>,

    // New single-byte encodings (Latin1, CP1252)
    latin1_start: i64,
    latin1_buf: Vec<u8>,

    cp1252_start: i64,
    cp1252_buf: Vec<u8>,

    // New multi-byte encodings (UTF-8, Shift-JIS)
    utf8_start: i64,
    utf8_next_pos: i64,
    utf8_buf: Vec<u8>,

    shift_jis_start: i64,
    shift_jis_next_pos: i64,
    shift_jis_buf: Vec<u8>,

    encodings: EncodingFilter,
    candidate_start: [bool; 256],

    /// Reused ASCII staging buffer for the repeat-noise check and text creation.
    scratch: Vec<u8>,

    /// Last emitted UTF-16LE run (bytes + start offset) used to suppress the
    /// redundant UTF-16BE mirror that appears one byte later for ASCII text.
    last_u16le_bytes: Vec<u8>,
    last_u16le_offset: i64,
    /// Same for UTF-32LE / UTF-32BE.
    last_u32le_bytes: Vec<u8>,
    last_u32le_offset: i64,
    /// Buffered results waiting to be emitted in offset order.
    /// Emitted when we know no earlier results can appear (current_pos > offset + MAX_RUN_CHARS).
    pending: Vec<ExtractedString>,
}

impl<'a> StringRunScanner<'a> {
    fn new(
        min_len: usize,
        noise_cfg: NoiseConfig,
        on_found: &'a mut dyn FnMut(ExtractedString),
        encodings: EncodingFilter,
    ) -> Self {
        // Precompute a per-byte "could this byte be the START of some enabled
        // run?" table. Used by the fast-skip path. Conservative: a may-be-start
        // byte is never skipped, even if the subsequent conditions end up not
        // opening a run (correctness only suffers speed, never results).
        let mut candidate_start = [false; 256];
        let le_enabled = encodings.ascii
            || encodings.utf16le
            || encodings.utf32le
            || encodings.utf8
            || encodings.shift_jis
            || encodings.latin1
            || encodings.cp1252;
        let be_enabled = encodings.utf16be || encodings.utf32be;
        for (i, slot) in candidate_start.iter_mut().enumerate() {
            let b = i as u8;
            let latin1_cp1252_enabled = encodings.latin1 || encodings.cp1252;
            *slot = (le_enabled && is_printable(b))
                || (be_enabled && (b == 0 || is_printable(b)))
                || (latin1_cp1252_enabled && (is_latin1_printable(b) || is_cp1252_printable(b)))
                || (encodings.utf8 && (0xC2..=0xF4).contains(&b))
                || (encodings.shift_jis && shift_jis_is_lead_byte(b));
        }
        Self {
            min_len,
            noise_cfg,
            on_found,
            ascii_start: -1,
            ascii_buf: Vec::with_capacity(64),
            u16_start: -1,
            u16_next_pos: -1,
            u16_buf: Vec::with_capacity(64),

            u16be_start: -1,
            u16be_next_pos: -1,
            u16be_buf: Vec::with_capacity(64),

            u32le_start: -1,
            u32le_next_pos: -1,
            u32le_buf: Vec::with_capacity(64),

            u32be_start: -1,
            u32be_next_pos: -1,
            u32be_buf: Vec::with_capacity(64),

            latin1_start: -1,
            latin1_buf: Vec::with_capacity(64),

            cp1252_start: -1,
            cp1252_buf: Vec::with_capacity(64),

            utf8_start: -1,
            utf8_next_pos: -1,
            utf8_buf: Vec::with_capacity(64),

            shift_jis_start: -1,
            shift_jis_next_pos: -1,
            shift_jis_buf: Vec::with_capacity(64),

            encodings,
            candidate_start,
            scratch: Vec::with_capacity(64),
            last_u16le_bytes: Vec::with_capacity(64),
            last_u16le_offset: -100,
            last_u32le_bytes: Vec::with_capacity(64),
            last_u32le_offset: -100,
            pending: Vec::new(),
        }
    }

    /// Emit any pending results whose offset is far enough behind the current
    /// processing position that no earlier results can appear.
    /// A run can be at most MAX_RUN_CHARS long (force-flushed), so if we're at
    /// position `current_pos`, any result with offset < current_pos - MAX_RUN_CHARS
    /// is safe to emit.
    fn emit_pending(&mut self, current_pos: u64) {
        if self.pending.is_empty() {
            return;
        }
        let threshold = current_pos.saturating_sub(MAX_RUN_CHARS as u64 + 1);
        // Sort by offset (pending is small, typically < 10 items)
        self.pending.sort_by_key(|s| s.offset);
        // Emit all results with offset < threshold
        let mut i = 0;
        while i < self.pending.len() && self.pending[i].offset < threshold {
            let result = self.pending[i].clone();
            (self.on_found)(result);
            i += 1;
        }
        if i > 0 {
            self.pending.drain(0..i);
        }
    }

    /// Flush all pending results (used at end of stream).
    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        self.pending.sort_by_key(|s| s.offset);
        for result in self.pending.drain(..) {
            (self.on_found)(result);
        }
    }

    /// Processes `process_count` bytes starting at `buffer[offset]`,
    /// corresponding to absolute offset `global_base` in the original
    /// overall data. `buffer_valid_len` is the total number of bytes
    /// ACTUALLY available in the buffer from `offset` onward (can be
    /// LARGER than process_count) -- used to safely test 1-byte lookahead
    /// (buffer[i+1]) without processing that byte right away, letting the
    /// caller "hold back" the last byte of a chunk as carry into the next
    /// `feed()` call.
    fn feed(
        &mut self,
        buffer: &[u8],
        offset: usize,
        process_count: usize,
        buffer_valid_len: usize,
        global_base: u64,
    ) {
        let mut k = 0usize;
        while k < process_count {
            // -- Fast-skip: when NO run is currently open, the current
            // position can only be the START of a
            // new run, never a CONTINUATION point -- and both run kinds
            // require the current byte (ascii) / "lo" byte (utf16) to be
            // printable, so a non-printable byte can't open any run at all
            // (it could only be the "hi" byte of a utf16 pair starting at
            // the PREVIOUS position -- and that position already did its
            // own lookahead check on this byte, no need to re-check).
            // So jump straight over the whole run of consecutive
            // non-printable bytes without computing has_next/aligned or
            // calling the no-op flush() for every junk byte -- the
            // non-printable binary region is usually the bulk of a real
            // RAM dump's payload, so this is the hottest path.
            if self.ascii_start < 0
                && self.u16_start < 0
                && self.u16be_start < 0
                && self.u32le_start < 0
                && self.u32be_start < 0
                && self.utf8_start < 0
                && self.shift_jis_start < 0
            {
                let valid_end = offset + buffer_valid_len;
                while k < process_count {
                    let i = offset + k;
                    let b = buffer[i];
                    // Fast path: bytes that cannot possibly open ANY enabled
                    // run (non-printable AND, for BE-only scan, non-zero) are
                    // skipped; 8 at a time when a whole word has no candidate.
                    if !self.candidate_start[b as usize] {
                        if k + 8 <= process_count && i + 8 <= valid_end {
                            let mut all_noncandidate = true;
                            for t in 1..8usize {
                                if self.candidate_start[buffer[i + t] as usize] {
                                    all_noncandidate = false;
                                    break;
                                }
                            }
                            if all_noncandidate {
                                k += 8;
                                continue;
                            }
                        }
                        k += 1;
                        continue;
                    }
                    if b == 0x00 {
                        // zero handling only relevant for BE runs.
                        if !(self.encodings.utf16be || self.encodings.utf32be) {
                            // zero can't open anything else: treat as
                            // non-candidate. (candidate_start would already be
                            // false in this configuration, so we shouldn't
                            // reach here -- guard for safety.)
                            k += 1;
                            continue;
                        }
                        // 8 zero bytes ahead => positions k..k+4 cannot start anything.
                        if k + 4 <= process_count
                            && i + 8 <= valid_end
                            && u64::from_ne_bytes(buffer[i..i + 8].try_into().unwrap()) == 0
                        {
                            k += 4;
                            continue;
                        }
                        let can_u16be = self.encodings.utf16be
                            && i + 1 < valid_end
                            && is_printable(buffer[i + 1]);
                        let can_u32be = self.encodings.utf32be
                            && i + 3 < valid_end
                            && buffer[i + 1] == 0
                            && buffer[i + 2] == 0
                            && is_printable(buffer[i + 3]);
                        if can_u16be || can_u32be {
                            break;
                        }
                        k += 1;
                        continue;
                    }
                    // a printable candidate byte
                    break;
                }
                if k >= process_count {
                    break;
                }
            }

            let i = offset + k;
            let g = global_base + k as u64;
            let b = buffer[i];
            let printable_b = is_printable(b); // shared by both branches below, avoids looking up the table twice for the same byte

            // -- ASCII: only needs the current byte itself, no lookahead --
            if self.encodings.ascii {
                if printable_b {
                    if self.ascii_start < 0 {
                        self.ascii_start = g as i64;
                    }
                    self.ascii_buf.push(b);
                    if self.ascii_buf.len() >= MAX_RUN_CHARS {
                        self.flush_ascii();
                    }
                } else {
                    self.flush_ascii();
                }
            } else if self.ascii_start >= 0 {
                self.ascii_start = -1;
                self.ascii_buf.clear();
            }

            if self.encodings.utf16le {
                // -- UTF-16LE: needs a lookahead at buffer[i+1] --
                let has_next = (i + 1) < (offset + buffer_valid_len);
                if has_next {
                    let aligned = self.u16_start < 0 || g as i64 == self.u16_next_pos;
                    if aligned {
                        let hi = buffer[i + 1];
                        if hi == 0x00 && printable_b {
                            if self.u16_start < 0 {
                                self.u16_start = g as i64;
                                self.u16_buf.clear();
                            }
                            self.u16_buf.push(b as u16);
                            self.u16_next_pos = g as i64 + 2;
                            if self.u16_buf.len() >= MAX_RUN_CHARS {
                                self.flush_u16();
                            }
                        } else {
                            self.flush_u16();
                        }
                    }
                }
            } else if self.u16_start >= 0 {
                self.u16_start = -1;
                self.u16_next_pos = -1;
                self.u16_buf.clear();
            }

            if self.encodings.utf16be {
                if i + 1 < (offset + buffer_valid_len) {
                    let aligned = self.u16be_start < 0 || g as i64 == self.u16be_next_pos;
                    if aligned {
                        let lo = buffer[i + 1];
                        if buffer[i] == 0x00 && is_printable(lo) {
                            if self.u16be_start < 0 {
                                self.u16be_start = g as i64;
                                self.u16be_buf.clear();
                            }
                            self.u16be_buf.push(lo as u16);
                            self.u16be_next_pos = g as i64 + 2;
                            if self.u16be_buf.len() >= MAX_RUN_CHARS {
                                self.flush_u16be();
                            }
                        } else {
                            // only flush if we were at an aligned boundary position
                            if self.u16be_start >= 0 && g as i64 == self.u16be_next_pos - 2 {
                                // fall through to flush below
                            }
                        }
                    }
                }
                // flush u16be if not aligned continuation
                if !(i + 1 < (offset + buffer_valid_len)) {
                    self.flush_u16be();
                } else {
                    let aligned = self.u16be_start < 0 || g as i64 == self.u16be_next_pos;
                    if aligned {
                        let lo = buffer[i + 1];
                        let cond = buffer[i] == 0x00 && is_printable(lo);
                        if !cond {
                            self.flush_u16be();
                        }
                    }
                }
            } else if self.u16be_start >= 0 {
                self.u16be_start = -1;
                self.u16be_next_pos = -1;
                self.u16be_buf.clear();
            }

            if self.encodings.utf32le {
                if i + 3 < (offset + buffer_valid_len) {
                    let aligned = self.u32le_start < 0 || g as i64 == self.u32le_next_pos;
                    if aligned {
                        let b1 = buffer[i + 1];
                        let b2 = buffer[i + 2];
                        let b3 = buffer[i + 3];
                        if printable_b && b1 == 0 && b2 == 0 && b3 == 0 {
                            if self.u32le_start < 0 {
                                self.u32le_start = g as i64;
                                self.u32le_buf.clear();
                            }
                            self.u32le_buf.push(b as u32);
                            self.u32le_next_pos = g as i64 + 4;
                            if self.u32le_buf.len() >= MAX_RUN_CHARS {
                                self.flush_u32le();
                            }
                        } else {
                            // flush if currently open and aligned
                            if self.u32le_start >= 0 {
                                self.flush_u32le();
                            }
                        }
                    }
                }
            } else if self.u32le_start >= 0 {
                self.u32le_start = -1;
                self.u32le_next_pos = -1;
                self.u32le_buf.clear();
            }

            if self.encodings.utf32be {
                if i + 3 < (offset + buffer_valid_len) {
                    let aligned = self.u32be_start < 0 || g as i64 == self.u32be_next_pos;
                    if aligned {
                        let b1 = buffer[i + 1];
                        let b2 = buffer[i + 2];
                        let b3 = buffer[i + 3];
                        if b == 0 && b1 == 0 && b2 == 0 && is_printable(b3) {
                            if self.u32be_start < 0 {
                                self.u32be_start = g as i64;
                                self.u32be_buf.clear();
                            }
                            self.u32be_buf.push(b3 as u32);
                            self.u32be_next_pos = g as i64 + 4;
                            if self.u32be_buf.len() >= MAX_RUN_CHARS {
                                self.flush_u32be();
                            }
                        } else {
                            if self.u32be_start >= 0 {
                                self.flush_u32be();
                            }
                        }
                    }
                }
            } else if self.u32be_start >= 0 {
                self.u32be_start = -1;
                self.u32be_next_pos = -1;
                self.u32be_buf.clear();
            }

            // -- Latin1 (ISO-8859-1): single byte, extends ASCII with 0xA0-0xFF --
            if self.encodings.latin1 {
                let latin1_printable_b = is_latin1_printable(b);
                if latin1_printable_b {
                    if self.latin1_start < 0 {
                        self.latin1_start = g as i64;
                    }
                    self.latin1_buf.push(b);
                    if self.latin1_buf.len() >= MAX_RUN_CHARS {
                        self.flush_latin1();
                    }
                } else {
                    self.flush_latin1();
                }
            } else if self.latin1_start >= 0 {
                self.latin1_start = -1;
                self.latin1_buf.clear();
            }

            // -- CP1252 (Windows-1252): single byte, like Latin1 but 0x80-0x9F are printable --
            if self.encodings.cp1252 {
                let cp1252_printable_b = is_cp1252_printable(b);
                if cp1252_printable_b {
                    if self.cp1252_start < 0 {
                        self.cp1252_start = g as i64;
                    }
                    self.cp1252_buf.push(b);
                    if self.cp1252_buf.len() >= MAX_RUN_CHARS {
                        self.flush_cp1252();
                    }
                } else {
                    self.flush_cp1252();
                }
            } else if self.cp1252_start >= 0 {
                self.cp1252_start = -1;
                self.cp1252_buf.clear();
            }

            // -- UTF-8: variable-length encoding --
            if self.encodings.utf8 {
                let has_next = (i + 1) < (offset + buffer_valid_len);
                let aligned = self.utf8_start < 0 || g as i64 == self.utf8_next_pos;
                if aligned && has_next {
                    let expected_len = utf8_expected_len(b);
                    let can_start =
                        expected_len > 1 && i + expected_len <= offset + buffer_valid_len;
                    if can_start {
                        let valid = utf8_validate_seq(&buffer[i..i + expected_len]);
                        if valid {
                            if self.utf8_start < 0 {
                                self.utf8_start = g as i64;
                                self.utf8_buf.clear();
                            }
                            self.utf8_buf
                                .extend_from_slice(&buffer[i..i + expected_len]);
                            self.utf8_next_pos = g as i64 + expected_len as i64;
                            if self.utf8_buf.len() >= MAX_RUN_CHARS {
                                self.flush_utf8();
                            }
                            // Skip the continuation bytes since we consumed them
                            k += expected_len - 1;
                        } else {
                            self.flush_utf8();
                        }
                    } else if expected_len == 1 && is_printable(b) {
                        // ASCII byte in UTF-8 mode - treat as single-byte UTF-8 (ASCII subset)
                        if self.utf8_start < 0 {
                            self.utf8_start = g as i64;
                            self.utf8_buf.clear();
                        }
                        self.utf8_buf.push(b);
                        self.utf8_next_pos = g as i64 + 1;
                        if self.utf8_buf.len() >= MAX_RUN_CHARS {
                            self.flush_utf8();
                        }
                    } else {
                        self.flush_utf8();
                    }
                } else if !aligned {
                    self.flush_utf8();
                }
            } else if self.utf8_start >= 0 {
                self.utf8_start = -1;
                self.utf8_next_pos = -1;
                self.utf8_buf.clear();
            }

            // -- Shift-JIS: Japanese multi-byte encoding --
            if self.encodings.shift_jis {
                let has_next = (i + 1) < (offset + buffer_valid_len);
                let aligned = self.shift_jis_start < 0 || g as i64 == self.shift_jis_next_pos;
                if aligned && has_next {
                    let b2 = buffer[i + 1];
                    if shift_jis_is_lead_byte(b)
                        && shift_jis_is_trail_byte(b2)
                        && shift_jis_pair_valid(b, b2)
                    {
                        if self.shift_jis_start < 0 {
                            self.shift_jis_start = g as i64;
                            self.shift_jis_buf.clear();
                        }
                        self.shift_jis_buf.push(b);
                        self.shift_jis_buf.push(b2);
                        self.shift_jis_next_pos = g as i64 + 2;
                        if self.shift_jis_buf.len() >= MAX_RUN_CHARS {
                            self.flush_shift_jis();
                        }
                        k += 1; // Skip trail byte
                    } else if is_printable(b) {
                        // Single-byte ASCII-compatible
                        if self.shift_jis_start < 0 {
                            self.shift_jis_start = g as i64;
                            self.shift_jis_buf.clear();
                        }
                        self.shift_jis_buf.push(b);
                        self.shift_jis_next_pos = g as i64 + 1;
                        if self.shift_jis_buf.len() >= MAX_RUN_CHARS {
                            self.flush_shift_jis();
                        }
                    } else {
                        self.flush_shift_jis();
                    }
                } else if !aligned {
                    self.flush_shift_jis();
                }
            } else if self.shift_jis_start >= 0 {
                self.shift_jis_start = -1;
                self.shift_jis_next_pos = -1;
                self.shift_jis_buf.clear();
            }

            k += 1;
        }
        // Emit any pending results that are now far enough behind the current position.
        let current_pos = global_base + process_count as u64;
        self.emit_pending(current_pos);
    }

    /// Call ONCE after `feed()` has processed all the data (end of
    /// file/array) so the still-open run at the very end isn't lost.
    fn flush_all(&mut self) {
        self.flush_ascii();
        self.flush_u16();
        self.flush_u16be();
        self.flush_u32le();
        self.flush_u32be();
        self.flush_latin1();
        self.flush_cp1252();
        self.flush_utf8();
        self.flush_shift_jis();
        self.flush_pending();
    }

    fn flush_ascii(&mut self) {
        if !self.encodings.ascii {
            self.ascii_start = -1;
            self.ascii_buf.clear();
            return;
        }
        if self.ascii_start >= 0
            && self.ascii_buf.len() >= self.min_len
            && !is_low_information_repeat(&self.ascii_buf, &self.noise_cfg)
        {
            let text = String::from_utf8_lossy(&self.ascii_buf).into_owned();
            self.pending.push(ExtractedString {
                offset: self.ascii_start as u64,
                encoding: "ascii",
                text,
            });
        }
        self.ascii_start = -1;
        self.ascii_buf.clear();
    }

    fn flush_u16(&mut self) {
        if !self.encodings.utf16le {
            self.u16_start = -1;
            self.u16_next_pos = -1;
            self.u16_buf.clear();
            return;
        }
        if self.u16_start >= 0 && self.u16_buf.len() >= self.min_len {
            // u16_buf always holds values in 0..=0x7F (gated by is_printable
            // before pushing) -- the `as u8` cast is safe, no bits lost.
            self.scratch.clear();
            self.scratch.extend(self.u16_buf.iter().map(|&c| c as u8));
            if !is_low_information_repeat(&self.scratch, &self.noise_cfg) {
                let text = String::from_utf8_lossy(&self.scratch).into_owned();
                self.pending.push(ExtractedString {
                    offset: self.u16_start as u64,
                    encoding: "utf16le",
                    text,
                });
                self.last_u16le_offset = self.u16_start;
                self.last_u16le_bytes.clear();
                self.last_u16le_bytes.extend_from_slice(&self.scratch);
            }
        }
        self.u16_start = -1;
        self.u16_next_pos = -1;
        self.u16_buf.clear();
    }

    fn flush_u16be(&mut self) {
        if !self.encodings.utf16be {
            self.u16be_start = -1;
            self.u16be_next_pos = -1;
            self.u16be_buf.clear();
            return;
        }
        if self.u16be_start >= 0 && self.u16be_buf.len() >= self.min_len {
            self.scratch.clear();
            self.scratch.extend(self.u16be_buf.iter().map(|&c| c as u8));
            // Suppress the redundant UTF-16BE mirror of an ASCII UTF-16LE run
            // that starts exactly one byte earlier (common for LE-stored text).
            let duplicate = self.last_u16le_offset + 1 == self.u16be_start
                && self.last_u16le_bytes == self.scratch;
            if !is_low_information_repeat(&self.scratch, &self.noise_cfg) && !duplicate {
                let text = String::from_utf8_lossy(&self.scratch).into_owned();
                self.pending.push(ExtractedString {
                    offset: self.u16be_start as u64,
                    encoding: "utf16be",
                    text,
                });
            }
        }
        self.u16be_start = -1;
        self.u16be_next_pos = -1;
        self.u16be_buf.clear();
    }

    fn flush_u32le(&mut self) {
        if !self.encodings.utf32le {
            self.u32le_start = -1;
            self.u32le_next_pos = -1;
            self.u32le_buf.clear();
            return;
        }
        if self.u32le_start >= 0 && self.u32le_buf.len() >= self.min_len {
            self.scratch.clear();
            self.scratch.extend(self.u32le_buf.iter().map(|&c| c as u8));
            if !is_low_information_repeat(&self.scratch, &self.noise_cfg) {
                let text = String::from_utf8_lossy(&self.scratch).into_owned();
                self.pending.push(ExtractedString {
                    offset: self.u32le_start as u64,
                    encoding: "utf32le",
                    text,
                });
                self.last_u32le_offset = self.u32le_start;
                self.last_u32le_bytes.clear();
                self.last_u32le_bytes.extend_from_slice(&self.scratch);
            }
        }
        self.u32le_start = -1;
        self.u32le_next_pos = -1;
        self.u32le_buf.clear();
    }

    fn flush_u32be(&mut self) {
        if !self.encodings.utf32be {
            self.u32be_start = -1;
            self.u32be_next_pos = -1;
            self.u32be_buf.clear();
            return;
        }
        if self.u32be_start >= 0 && self.u32be_buf.len() >= self.min_len {
            self.scratch.clear();
            self.scratch.extend(self.u32be_buf.iter().map(|&c| c as u8));
            let duplicate = self.last_u32le_offset + 1 == self.u32be_start
                && self.last_u32le_bytes == self.scratch;
            if !is_low_information_repeat(&self.scratch, &self.noise_cfg) && !duplicate {
                let text = String::from_utf8_lossy(&self.scratch).into_owned();
                self.pending.push(ExtractedString {
                    offset: self.u32be_start as u64,
                    encoding: "utf32be",
                    text,
                });
            }
        }
        self.u32be_start = -1;
        self.u32be_next_pos = -1;
        self.u32be_buf.clear();
    }

    fn flush_latin1(&mut self) {
        if !self.encodings.latin1 {
            self.latin1_start = -1;
            self.latin1_buf.clear();
            return;
        }
        if self.latin1_start >= 0
            && self.latin1_buf.len() >= self.min_len
            // With ASCII also enabled, an all-ASCII run already has an "ascii"
            // record at this offset; re-emitting it as latin1 only creates a
            // duplicate. Runs with any non-ASCII byte are kept.
            && (!self.encodings.ascii || self.latin1_buf.iter().any(|&b| b >= 0x80))
            && !is_low_information_repeat(&self.latin1_buf, &self.noise_cfg)
            && !has_acpi_field_noise(&self.latin1_buf)
            && !single_byte_high_entropy_noise(&self.latin1_buf, &self.noise_cfg)
        {
            // Decode Latin1 bytes to UTF-8 string
            let text = self
                .latin1_buf
                .iter()
                .map(|&b| char::from(b))
                .collect::<String>();
            self.pending.push(ExtractedString {
                offset: self.latin1_start as u64,
                encoding: "latin1",
                text,
            });
        }
        self.latin1_start = -1;
        self.latin1_buf.clear();
    }

    fn flush_cp1252(&mut self) {
        if !self.encodings.cp1252 {
            self.cp1252_start = -1;
            self.cp1252_buf.clear();
            return;
        }
        if self.cp1252_start >= 0
            && self.cp1252_buf.len() >= self.min_len
            // Same duplicate suppression as latin1: all-ASCII runs are already
            // covered by the "ascii" record when that family is scanned.
            && (!self.encodings.ascii || self.cp1252_buf.iter().any(|&b| b >= 0x80))
            && !is_low_information_repeat(&self.cp1252_buf, &self.noise_cfg)
            && !has_acpi_field_noise(&self.cp1252_buf)
            && !single_byte_high_entropy_noise(&self.cp1252_buf, &self.noise_cfg)
        {
            // Decode CP1252 bytes to UTF-8 string
            let text = self
                .cp1252_buf
                .iter()
                .map(|&b| cp1252_to_char(b))
                .collect::<String>();
            self.pending.push(ExtractedString {
                offset: self.cp1252_start as u64,
                encoding: "cp1252",
                text,
            });
        }
        self.cp1252_start = -1;
        self.cp1252_buf.clear();
    }

    fn flush_utf8(&mut self) {
        if !self.encodings.utf8 {
            self.utf8_start = -1;
            self.utf8_next_pos = -1;
            self.utf8_buf.clear();
            return;
        }
        if self.utf8_start >= 0
            && self.utf8_buf.len() >= self.min_len
            // All-ASCII UTF-8 belongs to the ASCII family; keep only runs that
            // contain a multi-byte (>= 0x80) sequence.
            && self.utf8_buf.iter().any(|&b| b >= 0x80)
            && !is_low_information_repeat(&self.utf8_buf, &self.noise_cfg)
        {
            // Validate and decode UTF-8
            let text = String::from_utf8_lossy(&self.utf8_buf).into_owned();
            if !decoded_text_noise(&text, &self.noise_cfg) {
                self.pending.push(ExtractedString {
                    offset: self.utf8_start as u64,
                    encoding: "utf8",
                    text,
                });
            }
        }
        self.utf8_start = -1;
        self.utf8_next_pos = -1;
        self.utf8_buf.clear();
    }

    fn flush_shift_jis(&mut self) {
        if !self.encodings.shift_jis {
            self.shift_jis_start = -1;
            self.shift_jis_next_pos = -1;
            self.shift_jis_buf.clear();
            return;
        }
        if self.shift_jis_start >= 0
            && self.shift_jis_buf.len() >= self.min_len
            // ASCII-only runs belong to the ASCII family; keep only Shift-JIS
            // runs containing a lead byte or half-width katakana.
            && self.shift_jis_buf.iter().any(|&b| b >= 0x80)
            && !is_low_information_repeat(&self.shift_jis_buf, &self.noise_cfg)
        {
            // Decode Shift-JIS to UTF-8
            let text = shift_jis_to_utf8(&self.shift_jis_buf);
            if !decoded_text_noise(&text, &self.noise_cfg) {
                self.pending.push(ExtractedString {
                    offset: self.shift_jis_start as u64,
                    encoding: "shift_jis",
                    text,
                });
            }
        }
        self.shift_jis_start = -1;
        self.shift_jis_next_pos = -1;
        self.shift_jis_buf.clear();
    }
}

/// Detects two shapes of "simple repeat noise" (byte-fill/heap-fill/
/// padding) -- period 1 (a single repeated character) or period 2
/// (strictly alternating 2 characters) covering the ENTIRE run, with no
/// other characters mixed in. Only triggers past the corresponding length
/// threshold (see the constants above) so it doesn't accidentally drop
/// short real strings. Takes a `&[u8]` shared by both ASCII (`ascii_buf`)
/// and UTF-16LE lowered to its low bytes (`u16_buf` is always within
/// 0..=0x7F since it's gated by `is_printable` before being pushed into
/// the buffer, so the `as u8` cast loses no information).
fn is_low_information_repeat(buf: &[u8], cfg: &NoiseConfig) -> bool {
    let n = buf.len();
    if n == 0 {
        return false;
    }

    // Period 1: every byte is identical to the first byte.
    if n >= cfg.repeat1_min_len && buf.iter().all(|&b| b == buf[0]) {
        return true;
    }

    // Period 2: strictly alternates between 2 values (different from each
    // other -- if they were the same it would already have been caught by
    // the period-1 branch) across the whole run length.
    if n >= cfg.repeat2_min_len {
        let (p0, p1) = (buf[0], buf[1]);
        if p0 != p1
            && buf
                .iter()
                .enumerate()
                .all(|(i, &b)| b == if i % 2 == 0 { p0 } else { p1 })
        {
            return true;
        }
    }

    false
}

fn estimate_capacity(input_len: u64, max_strings: usize) -> usize {
    let guess = if input_len > 0 {
        std::cmp::max(MIN_CAPACITY_HINT as u64, input_len / AVG_BYTES_PER_STRING)
    } else {
        MIN_CAPACITY_HINT as u64
    };
    std::cmp::min(max_strings as u64, guess) as usize
}

/// Returns true if the buffer contains at least 4 consecutive bytes spelling a
/// known ACPI field/table name that is a frequent false-positive source in
/// memory dumps when decoded as Latin1/CP1252. Only triggered when a
/// high byte (>=0x80) is also present (real ACPI ACPI structure noise).
pub fn has_acpi_field_noise(buf: &[u8]) -> bool {
    const ACPI_FIELDS: &[(u8, u8, u8, u8)] = &[
        (0x46, 0x41, 0x43, 0x50),
        (0x44, 0x53, 0x44, 0x54),
        (0x53, 0x53, 0x44, 0x54),
        (0x41, 0x50, 0x49, 0x43),
        (0x56, 0x42, 0x4F, 0x58),
        (0x44, 0x42, 0x47, 0x30),
        (0x44, 0x42, 0x47, 0x5F),
        (0x48, 0x45, 0x58, 0x5F),
        (0x53, 0x4C, 0x45, 0x4E),
        (0x53, 0x43, 0x4D, 0x50),
        (0x44, 0x43, 0x48, 0x52),
        (0x42, 0x55, 0x46, 0x46),
        (0x4D, 0x49, 0x4E, 0x5F),
        (0x4D, 0x54, 0x43, 0x48),
        (0x4D, 0x53, 0x57, 0x56),
        (0x4D, 0x53, 0x57, 0x4E),
        (0x5F, 0x4F, 0x53, 0x49),
        (0x50, 0x49, 0x43, 0x4D),
        (0x5F, 0x50, 0x49, 0x43),
        (0x53, 0x59, 0x53, 0x49),
        (0x50, 0x52, 0x30, 0x30),
        (0x4C, 0x4E, 0x4B, 0x42),
        (0x4C, 0x4E, 0x4B, 0x43),
        (0x4C, 0x4E, 0x4B, 0x44),
        (0x4C, 0x4E, 0x4B, 0x41),
        (0x49, 0x4E, 0x54, 0x4C),
        (0x5F, 0x52, 0x45, 0x56),
        (0x5F, 0x4F, 0x53, 0x5F),
        (0x5F, 0x49, 0x4E, 0x49),
        (0x4D, 0x45, 0x4D, 0x4C),
    ];
    let n = buf.len();
    if n < 4 {
        return false;
    }
    for i in 0..=n.saturating_sub(4) {
        let w = (buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
        for &sig in ACPI_FIELDS {
            if w == sig {
                return true;
            }
        }
    }
    false
}

/// Filters single-byte Latin1/CP1252 strings whose byte distribution looks
/// like mostly-binary noise rather than real text: either too few printable
/// ASCII chars or too many distinct byte values per unit length (high entropy).
fn single_byte_high_entropy_noise(buf: &[u8], cfg: &NoiseConfig) -> bool {
    let n = buf.len();
    if n < 8 {
        return false;
    }
    if cfg.repeat1_min_len == usize::MAX {
        return false;
    }
    let printable_ascii = buf.iter().filter(|&&b| (0x20..=0x7E).contains(&b)).count();
    let ratio = printable_ascii as f64 / n as f64;
    if ratio < 0.40 {
        return true;
    }
    if n < 16 {
        return false;
    }
    let mut seen = [false; 256];
    let mut distinct = 0usize;
    for &b in buf {
        if !seen[b as usize] {
            seen[b as usize] = true;
            distinct += 1;
        }
    }
    if distinct > 30 && (distinct as f64 / n as f64) > 0.20 {
        return true;
    }
    false
}

/// Strings shorter than this (in decoded chars) are judged only on hard
/// evidence (U+FFFD / control / private-use chars), never on a ratio, so short
/// real artifacts are not lost to a statistical heuristic.
const DECODED_NOISE_MIN_CHARS: usize = 8;

/// Characters that essentially never occur in genuine text but are common in
/// binary data decoded as text: the replacement character, control chars
/// (C0/C1, except tab/LF/CR), Private Use areas and Unicode noncharacters.
fn is_decoded_bad_char(c: char) -> bool {
    match c {
        '\t' | '\n' | '\r' => false,
        '\u{FFFD}' => true,
        '\u{E000}'..='\u{F8FF}' => true,
        '\u{FDD0}'..='\u{FDEF}' | '\u{FFFE}' | '\u{FFFF}' => true,
        '\u{F0000}'..='\u{10FFFF}' => true,
        c => c.is_control(),
    }
}

/// Characters that look like part of readable text: letters/digits (incl.
/// CJK, kana), whitespace, ASCII punctuation, and the common Latin-1,
/// general-punctuation, currency, CJK-punctuation and full/half-width blocks.
fn is_decoded_readable_char(c: char) -> bool {
    c.is_alphanumeric()
        || c.is_whitespace()
        || c.is_ascii_punctuation()
        || matches!(
            c,
            '\u{00A0}'..='\u{00BF}'
                | '\u{2000}'..='\u{206F}'
                | '\u{20A0}'..='\u{20CF}'
                | '\u{3000}'..='\u{303F}'
                | '\u{FF00}'..='\u{FFEF}'
        )
}

/// Post-decode noise check for the multi-byte encodings (UTF-8, Shift-JIS),
/// whose byte-level filters cannot tell real text from binary that merely
/// happens to decode. Drops a string when it
///  * is short (< `DECODED_NOISE_MIN_CHARS`) and contains any "bad" char, or
///  * is longer and more than 10% of its chars are "bad", or fewer than 60%
///    of its chars look readable.
///
/// Disabled together with the rest of the noise filter
/// (`NoiseConfig::disabled()` / `--noise-threshold 0`).
fn decoded_text_noise(text: &str, cfg: &NoiseConfig) -> bool {
    if cfg.repeat1_min_len == usize::MAX {
        return false;
    }
    let mut total = 0usize;
    let mut bad = 0usize;
    let mut readable = 0usize;
    for c in text.chars() {
        total += 1;
        if is_decoded_bad_char(c) {
            bad += 1;
        } else if is_decoded_readable_char(c) {
            readable += 1;
        }
    }
    if total == 0 {
        return false;
    }
    if total < DECODED_NOISE_MIN_CHARS {
        return bad > 0;
    }
    bad * 10 > total || readable * 10 < total * 6
}

/// Returns a list of `ExtractedString`, sorted by ascending offset, from a
/// byte slice ALREADY in RAM. `max_strings` is an upper bound to avoid
/// unbounded growth of memory / the JSON returned to the UI.
pub fn extract_strings(data: &[u8], min_len: usize, max_strings: usize) -> Vec<ExtractedString> {
    extract_strings_with_noise_config(data, min_len, max_strings, NoiseConfig::default())
}

/// Same as `extract_strings`, but with a configurable noise filter (see
/// `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_with_noise_config(
    data: &[u8],
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> Vec<ExtractedString> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(data.len() as u64, max_strings));
    {
        let mut on_found = |s: ExtractedString| {
            if results.len() < max_strings {
                results.push(s);
            }
        };
        let mut scanner =
            StringRunScanner::new(min_len, noise_cfg, &mut on_found, EncodingFilter::all());
        scanner.feed(data, 0, data.len(), data.len(), 0);
        scanner.flush_all();
    }
    results.sort_by_key(|s| s.offset);
    results
}

/// Same as [`extract_strings_with_noise_config`], but only scans the encodings
/// selected by `encodings` (see [`EncodingFilter`]).
pub fn extract_strings_with_noise_config_and_encodings(
    data: &[u8],
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
) -> Vec<ExtractedString> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(data.len() as u64, max_strings));
    {
        let mut on_found = |s: ExtractedString| {
            if results.len() < max_strings {
                results.push(s);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found, encodings);
        scanner.feed(data, 0, data.len(), data.len(), 0);
        scanner.flush_all();
    }
    results.sort_by_key(|s| s.offset);
    results
}

/// Convenience wrapper combining [`NoiseConfig::default`] with an encoding
/// selection (see [`EncodingFilter`]).
pub fn extract_strings_with_encodings(
    data: &[u8],
    min_len: usize,
    max_strings: usize,
    encodings: EncodingFilter,
) -> Vec<ExtractedString> {
    extract_strings_with_noise_config_and_encodings(
        data,
        min_len,
        max_strings,
        NoiseConfig::default(),
        encodings,
    )
}

// Borrow-checker note: in `extract_strings_from_reader` below, the outer
// loop needs to check "have we hit max_strings yet" while the `on_found`
// closure holds a mutable borrow of `results` for the whole block -- using
// `results.len()` directly in the `while` condition would conflict with
// that borrow (the closure is still alive). A separate `Cell<usize>` is
// used for the counter instead: `Cell::get()` only needs `&self` (an
// immutable borrow), so it can be read alongside the closure's mutable
// borrow of `results` without upsetting the borrow checker.

/// Extracts strings directly from a `Read`, in chunks -- NEVER
/// loads more than `CHUNK_SIZE` bytes into RAM at once, suitable for
/// multi-GB dump files. Carries exactly 1 trailing byte from each chunk
/// into the next so a UTF-16LE pair straddling an I/O boundary is always
/// tested correctly.
pub fn extract_strings_from_reader<R: Read>(
    reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_reader_with_noise_config(
        reader,
        min_len,
        max_strings,
        estimated_len,
        NoiseConfig::default(),
    )
}

/// Same as `extract_strings_from_reader`, but with a configurable noise
/// filter (see `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_from_reader_with_noise_config<R: Read>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(estimated_len, max_strings));
    let count = std::cell::Cell::new(0usize); // see the borrow-checker note in extract_strings()
    {
        let mut on_found = |s: ExtractedString| {
            if count.get() < max_strings {
                results.push(s);
                count.set(count.get() + 1);
            }
        };
        let mut scanner =
            StringRunScanner::new(min_len, noise_cfg, &mut on_found, EncodingFilter::all());

        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut global_base: u64 = 0;
        let mut carry_len: usize = 0; // 0 or 1

        while count.get() < max_strings {
            let to_read_into = buffer.len() - carry_len;
            let mut read_total = 0usize;
            while read_total < to_read_into {
                let n =
                    reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }

            let len = carry_len + read_total;
            if len == 0 {
                break;
            }

            let is_last_chunk = read_total < to_read_into;

            if is_last_chunk {
                scanner.feed(&buffer, 0, len, len, global_base);
                scanner.flush_all();
                break;
            } else {
                scanner.feed(&buffer, 0, len - 1, len, global_base);
                buffer[0] = buffer[len - 1];
                carry_len = 1;
                global_base += (len - 1) as u64;
            }
        }
    }

    results.sort_by_key(|s| s.offset);
    Ok(results)
}

/// Same as [`extract_strings_from_reader_with_noise_config`], but only scans the
/// encodings selected by `encodings` (see [`EncodingFilter`]).
pub fn extract_strings_from_reader_with_noise_config_and_encodings<R: Read>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    let mut results: Vec<ExtractedString> =
        Vec::with_capacity(estimate_capacity(estimated_len, max_strings));
    let count = std::cell::Cell::new(0usize);
    {
        let mut on_found = |s: ExtractedString| {
            if count.get() < max_strings {
                results.push(s);
                count.set(count.get() + 1);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found, encodings);

        let mut buffer = vec![0u8; CHUNK_SIZE];
        let mut global_base: u64 = 0;
        let mut carry_len: usize = 0; // 0 or 1

        while count.get() < max_strings {
            let to_read_into = buffer.len() - carry_len;
            let mut read_total = 0usize;
            while read_total < to_read_into {
                let n =
                    reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
                if n == 0 {
                    break;
                }
                read_total += n;
            }

            let len = carry_len + read_total;
            if len == 0 {
                break;
            }

            let is_last_chunk = read_total < to_read_into;

            if is_last_chunk {
                scanner.feed(&buffer, 0, len, len, global_base);
                scanner.flush_all();
                break;
            } else {
                scanner.feed(&buffer, 0, len - 1, len, global_base);
                buffer[0] = buffer[len - 1];
                carry_len = 1;
                global_base += (len - 1) as u64;
            }
        }
    }

    results.sort_by_key(|s| s.offset);
    Ok(results)
}

/// Convenience wrapper of [`extract_strings_from_reader_with_noise_config_and_encodings`]
/// with the default noise config.
pub fn extract_strings_from_reader_with_encodings<R: Read>(
    reader: R,
    min_len: usize,
    max_strings: usize,
    estimated_len: u64,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_reader_with_noise_config_and_encodings(
        reader,
        min_len,
        max_strings,
        estimated_len,
        NoiseConfig::default(),
        encodings,
    )
}

/// Streams extracted strings to `on_found` while scanning a reader.
///
/// The input is still read in fixed-size chunks, but results are delivered
/// immediately instead of being accumulated in a `Vec`. This keeps memory
/// bounded by the scan buffer and the caller's callback state.
pub fn extract_strings_from_reader_streaming<R: Read, F: FnMut(ExtractedString)>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    mut on_found: F,
) -> std::io::Result<usize> {
    let emitted = std::cell::Cell::new(0usize);
    let mut scanner_callback = |s: ExtractedString| {
        if emitted.get() < max_strings {
            emitted.set(emitted.get() + 1);
            on_found(s);
        }
    };
    let mut scanner = StringRunScanner::new(
        min_len,
        noise_cfg,
        &mut scanner_callback,
        EncodingFilter::all(),
    );
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut global_base = 0u64;
    let mut carry_len = 0usize;

    while emitted.get() < max_strings {
        let to_read_into = buffer.len() - carry_len;
        let mut read_total = 0usize;
        while read_total < to_read_into {
            let n = reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
            if n == 0 {
                break;
            }
            read_total += n;
        }

        let len = carry_len + read_total;
        if len == 0 {
            break;
        }
        let is_last_chunk = read_total < to_read_into;
        if is_last_chunk {
            scanner.feed(&buffer, 0, len, len, global_base);
            scanner.flush_all();
            break;
        }

        scanner.feed(&buffer, 0, len - 1, len, global_base);
        buffer[0] = buffer[len - 1];
        carry_len = 1;
        global_base += (len - 1) as u64;
    }

    Ok(emitted.get())
}

/// Streaming variant, but only scans the encodings selected by `encodings`.
pub fn extract_strings_from_reader_streaming_with_encodings<R: Read, F: FnMut(ExtractedString)>(
    mut reader: R,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    mut on_found: F,
) -> std::io::Result<usize> {
    let emitted = std::cell::Cell::new(0usize);
    let mut scanner_callback = |s: ExtractedString| {
        if emitted.get() < max_strings {
            emitted.set(emitted.get() + 1);
            on_found(s);
        }
    };
    let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut scanner_callback, encodings);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut global_base = 0u64;
    let mut carry_len = 0usize;

    while emitted.get() < max_strings {
        let to_read_into = buffer.len() - carry_len;
        let mut read_total = 0usize;
        while read_total < to_read_into {
            let n = reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
            if n == 0 {
                break;
            }
            read_total += n;
        }

        let len = carry_len + read_total;
        if len == 0 {
            break;
        }
        let is_last_chunk = read_total < to_read_into;
        if is_last_chunk {
            scanner.feed(&buffer, 0, len, len, global_base);
            scanner.flush_all();
            break;
        }

        scanner.feed(&buffer, 0, len - 1, len, global_base);
        buffer[0] = buffer[len - 1];
        carry_len = 1;
        global_base += (len - 1) as u64;
    }

    Ok(emitted.get())
}

/// File-based streaming variant of the encoding-aware streaming scanner.
pub fn extract_strings_from_file_streaming_with_encodings<F: FnMut(ExtractedString)>(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    on_found: F,
) -> std::io::Result<usize> {
    let file = File::open(dump_path)?;
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_streaming_with_encodings(
        reader,
        min_len,
        max_strings,
        noise_cfg,
        encodings,
        on_found,
    )
}

/// Scan only `[start, end)` of a file, streaming results to `on_found`.
///
/// The scanner reads up to [`MAX_RUN_CHARS`] bytes before `start` and after
/// `end` so strings crossing the requested boundaries are still complete, but
/// only strings whose start offset is inside `[start, end)` are emitted. This
/// is the building block for splitting a large dump across processes.
#[allow(clippy::too_many_arguments)]
pub fn extract_strings_from_file_streaming_range_with_encodings<F: FnMut(ExtractedString)>(
    dump_path: &str,
    start: u64,
    end: u64,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    on_found: F,
) -> std::io::Result<usize> {
    extract_strings_from_file_streaming_range_with_encodings_progress(
        dump_path,
        start,
        end,
        min_len,
        max_strings,
        noise_cfg,
        encodings,
        on_found,
        |_| {},
    )
}

/// Same as [`extract_strings_from_file_streaming_range_with_encodings`], but
/// also calls `on_progress(absolute_offset)` after every chunk so callers can
/// render a progress bar. The callback runs on the scanning thread; keep it
/// cheap or throttle it.
#[allow(clippy::too_many_arguments)]
pub fn extract_strings_from_file_streaming_range_with_encodings_progress<
    F: FnMut(ExtractedString),
    P: FnMut(u64),
>(
    dump_path: &str,
    start: u64,
    end: u64,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    mut on_found: F,
    mut on_progress: P,
) -> std::io::Result<usize> {
    let file_len = std::fs::metadata(dump_path)?.len();
    let start = start.min(file_len);
    let end = end.min(file_len).max(start);
    if start >= end {
        on_progress(end);
        return Ok(0);
    }
    let overlap = MAX_RUN_CHARS as u64;
    let scan_start = start.saturating_sub(overlap);
    let scan_end = std::cmp::min(end.saturating_add(overlap), file_len);
    let scan_len = scan_end - scan_start;

    let mut file = File::open(dump_path)?;
    file.seek(SeekFrom::Start(scan_start))?;
    let mut reader = BufReader::with_capacity(1 << 16, file.take(scan_len));

    let emitted = std::cell::Cell::new(0usize);
    let mut scanner_callback = |s: ExtractedString| {
        if s.offset >= start && s.offset < end && emitted.get() < max_strings {
            emitted.set(emitted.get() + 1);
            on_found(s);
        }
    };
    let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut scanner_callback, encodings);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut global_base = scan_start;
    let mut carry_len = 0usize;

    while emitted.get() < max_strings {
        let to_read_into = buffer.len() - carry_len;
        let mut read_total = 0usize;
        while read_total < to_read_into {
            let n = reader.read(&mut buffer[carry_len + read_total..carry_len + to_read_into])?;
            if n == 0 {
                break;
            }
            read_total += n;
        }

        let len = carry_len + read_total;
        if len == 0 {
            break;
        }
        let is_last_chunk = read_total < to_read_into;
        if is_last_chunk {
            scanner.feed(&buffer, 0, len, len, global_base);
            scanner.flush_all();
            on_progress(global_base + len as u64);
            break;
        }

        scanner.feed(&buffer, 0, len - 1, len, global_base);
        buffer[0] = buffer[len - 1];
        carry_len = 1;
        global_base += (len - 1) as u64;
        on_progress(global_base);
    }

    Ok(emitted.get())
}

/// File-based streaming variant of [`extract_strings_from_reader_streaming`].
pub fn extract_strings_from_file_streaming<F: FnMut(ExtractedString)>(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    on_found: F,
) -> std::io::Result<usize> {
    let file = File::open(dump_path)?;
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_streaming(reader, min_len, max_strings, noise_cfg, on_found)
}

/// Extracts strings from a `.dmp` file, in chunks -- does NOT
/// read the whole file into RAM.
pub fn extract_strings_from_file(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_file_with_noise_config(
        dump_path,
        min_len,
        max_strings,
        NoiseConfig::default(),
    )
}

/// Same as `extract_strings_from_file`, but with a configurable noise
/// filter (see `NoiseConfig`) instead of the hardcoded defaults.
pub fn extract_strings_from_file_with_noise_config(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    let file = File::open(dump_path)?;
    let estimated_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    // 64KB BufReader -- a good balance between syscall overhead and memory
    // use for sequential reads; the OS read-ahead heuristics naturally
    // match this access pattern too.
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_with_noise_config(
        reader,
        min_len,
        max_strings,
        estimated_len,
        noise_cfg,
    )
}

/// Same as [`extract_strings_from_file_with_noise_config`], but only scans the
/// encodings selected by `encodings` (see [`EncodingFilter`]).
pub fn extract_strings_from_file_with_noise_config_and_encodings(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    let file = File::open(dump_path)?;
    let estimated_len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = BufReader::with_capacity(1 << 16, file);
    extract_strings_from_reader_with_noise_config_and_encodings(
        reader,
        min_len,
        max_strings,
        estimated_len,
        noise_cfg,
        encodings,
    )
}

/// Convenience wrapper of the above with the default noise config.
pub fn extract_strings_from_file_with_encodings(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_file_with_noise_config_and_encodings(
        dump_path,
        min_len,
        max_strings,
        NoiseConfig::default(),
        encodings,
    )
}

// --- Parallel scanning (rayon work-stealing) --------------------------------
//
// The single-threaded path above is I/O-bound-friendly (streams CHUNK_SIZE
// at a time, constant peak memory) but only uses one core for the actual
// scanning. On a multi-core box scanning an already-fast SSD/NVMe (or a
// dump cached by the OS page cache), the CPU-bound scan itself becomes the
// bottleneck -- this is where splitting the work across threads helps.
//
// Design: split the file into fixed-size `PARALLEL_CHUNK_SIZE` regions and
// hand each region to rayon's work-stealing pool (`par_iter`). Each worker
// re-opens the file and seeks to its region independently (cheap: just an
// fd + seek, no shared state/locking needed between threads). Each region
// is read with an extra `MAX_RUN_CHARS` bytes of "overlap" past its
// boundary -- exactly the same limit the single-threaded scanner already
// force-flushes a run at -- so a run starting near the end of a region is
// never truncated by the region split. A region only *keeps* strings whose
// start offset falls inside its own `[start, logical_end)` -- the next
// region picks up the continuation on its own, so nothing is duplicated or
// lost at the boundary. Results are concatenated and re-sorted by offset
// (each region's own results are already offset-sorted, but merge order
// across regions/threads isn't guaranteed).
/// Size of the region one parallel worker reads (16 MiB).
///
/// Public so callers can reason about the memory a scan will use before
/// starting it; see [`scan_working_set_bytes`].
pub const PARALLEL_REGION_SIZE: u64 = 16 * 1024 * 1024;
#[cfg(not(test))]
const PARALLEL_CHUNK_SIZE: u64 = PARALLEL_REGION_SIZE;
#[cfg(test)]
const PARALLEL_CHUNK_SIZE: u64 = 4 * 1024; // small regions so boundary tests stay fast

/// Approximate RAM the scanner needs for its own buffers when `threads`
/// workers are used, in bytes.
///
/// This counts the read buffers (and the small overlap each worker keeps) but
/// not the extracted results, which are streamed out, nor the OS page cache.
/// It is what a `--max-memory` budget has to be compared against.
pub fn scan_working_set_bytes(threads: usize) -> u64 {
    if threads > 1 {
        threads as u64 * (PARALLEL_REGION_SIZE + MAX_RUN_CHARS as u64)
    } else {
        SEQUENTIAL_BUFFER_SIZE as u64 + MAX_RUN_CHARS as u64
    }
}

/// Scan one `PARALLEL_CHUNK_SIZE` region of `dump_path` and return the
/// strings that *start* inside it, in ascending offset order.
///
/// The region reads `MAX_RUN_CHARS` bytes past its own boundary so a string
/// crossing the boundary is still complete, but it only keeps strings whose
/// start offset belongs to this region -- the next region owns the rest, so
/// nothing is duplicated or lost at the boundary.
fn scan_parallel_chunk(
    dump_path: &str,
    idx: usize,
    file_len: u64,
    min_len: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    let start = idx as u64 * PARALLEL_CHUNK_SIZE;
    let logical_end = std::cmp::min(start + PARALLEL_CHUNK_SIZE, file_len);
    // Left overlap: read MAX_RUN_CHARS bytes before `start` so a run that
    // began in the previous region is seen in full and its offset stays below
    // `start`, where it is discarded instead of being re-emitted as a tail
    // fragment. Region 0 has no predecessor.
    let overlap = if idx == 0 { 0u64 } else { MAX_RUN_CHARS as u64 };
    let read_start = start.saturating_sub(overlap);
    let read_end = std::cmp::min(logical_end + MAX_RUN_CHARS as u64, file_len);
    let read_len = (read_end - read_start) as usize;

    let mut file = File::open(dump_path)?;
    file.seek(SeekFrom::Start(read_start))?;
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;

    let _region_offset_in_buf = (start - read_start) as usize;
    let mut local: Vec<ExtractedString> = Vec::new();
    {
        let mut on_found = |s: ExtractedString| {
            if s.offset >= start && s.offset < logical_end {
                local.push(s);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found, encodings);
        scanner.feed(&buf, 0, buf.len(), buf.len(), read_start);
        scanner.flush_all();
    }
    Ok(local)
}

fn parallel_chunk_count(file_len: u64) -> usize {
    file_len.div_ceil(PARALLEL_CHUNK_SIZE) as usize
}

/// Same as `extract_strings_from_file`, but scans the file in parallel
/// across multiple OS threads via `rayon`'s work-stealing thread pool
/// instead of a single sequential pass. Best on multi-core machines with
/// fast storage / a warm page cache, where the CPU-bound scan (not disk
/// I/O) is the bottleneck. Peak memory is bounded by
/// `num_active_threads * (PARALLEL_CHUNK_SIZE + MAX_RUN_CHARS)`, not by the
/// file size -- but the *results* are collected into one `Vec`, so prefer
/// [`extract_strings_from_file_parallel_streaming_with_encodings`] for very
/// large result sets. Use `rayon::ThreadPoolBuilder::num_threads` (or the
/// `RAYON_NUM_THREADS` env var) to control the degree of parallelism; by
/// default rayon uses one thread per logical CPU.
pub fn extract_strings_from_file_parallel(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
) -> std::io::Result<Vec<ExtractedString>> {
    extract_strings_from_file_parallel_with_encodings(
        dump_path,
        min_len,
        max_strings,
        noise_cfg,
        EncodingFilter::all(),
    )
}

/// Same as [`extract_strings_from_file_parallel`], but only scans the encodings
/// selected by `encodings` (see [`EncodingFilter`]).
pub fn extract_strings_from_file_parallel_with_encodings(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
) -> std::io::Result<Vec<ExtractedString>> {
    use rayon::prelude::*;

    let file_len = std::fs::metadata(dump_path)?.len();
    if file_len == 0 {
        return Ok(Vec::new());
    }
    let n_chunks = parallel_chunk_count(file_len);

    let chunk_results: Vec<std::io::Result<Vec<ExtractedString>>> = (0..n_chunks)
        .into_par_iter()
        .map(|idx| scan_parallel_chunk(dump_path, idx, file_len, min_len, noise_cfg, encodings))
        .collect();

    let mut results = Vec::new();
    for r in chunk_results {
        results.extend(r?);
    }
    results.sort_by_key(|s| s.offset);
    if results.len() > max_strings {
        results.truncate(max_strings);
    }
    Ok(results)
}

/// Streaming variant of [`extract_strings_from_file_parallel_with_encodings`]:
/// scans a bounded window of regions in parallel, emits their results in
/// ascending offset order, then drops them and moves on.
///
/// Peak memory is bounded by `threads * (PARALLEL_CHUNK_SIZE + MAX_RUN_CHARS)`
/// for the scan buffers plus the results of at most `threads` regions -- it
/// does **not** grow with the number of matches in the file, unlike the
/// buffered parallel API. `threads` is the worker count (`0`/`1` means "no
/// private pool"; `1` still scans region-by-region on the current thread).
/// Scanning stops as soon as `max_strings` results have been emitted, so a
/// small cap keeps a huge dump cheap. Returns the number of emitted strings.
#[allow(clippy::too_many_arguments)]
pub fn extract_strings_from_file_parallel_streaming_with_encodings<F: FnMut(ExtractedString)>(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    threads: usize,
    on_found: F,
) -> std::io::Result<usize> {
    extract_strings_from_file_parallel_streaming_with_encodings_progress(
        dump_path,
        min_len,
        max_strings,
        noise_cfg,
        encodings,
        threads,
        on_found,
        |_| {},
    )
}

/// Same as [`extract_strings_from_file_parallel_streaming_with_encodings`],
/// but also reports the absolute offset reached after every completed window
/// so callers can render a progress bar.
#[allow(clippy::too_many_arguments)]
pub fn extract_strings_from_file_parallel_streaming_with_encodings_progress<
    F: FnMut(ExtractedString),
    P: FnMut(u64),
>(
    dump_path: &str,
    min_len: usize,
    max_strings: usize,
    noise_cfg: NoiseConfig,
    encodings: EncodingFilter,
    threads: usize,
    mut on_found: F,
    mut on_progress: P,
) -> std::io::Result<usize> {
    use rayon::prelude::*;

    let file_len = std::fs::metadata(dump_path)?.len();
    if file_len == 0 {
        on_progress(0);
        return Ok(0);
    }
    let n_chunks = parallel_chunk_count(file_len);

    let pool = if threads > 1 {
        Some(
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .map_err(std::io::Error::other)?,
        )
    } else {
        None
    };
    // One region per worker: enough to keep every core busy without letting
    // the scan buffers (and their result vectors) pile up.
    let window = threads.max(1);

    let mut emitted = 0usize;
    let mut idx = 0usize;
    while idx < n_chunks && emitted < max_strings {
        let end_idx = std::cmp::min(idx + window, n_chunks);
        let scan = || -> Vec<std::io::Result<Vec<ExtractedString>>> {
            (idx..end_idx)
                .into_par_iter()
                .map(|i| scan_parallel_chunk(dump_path, i, file_len, min_len, noise_cfg, encodings))
                .collect()
        };
        let batch = match pool.as_ref() {
            Some(pool) => pool.install(scan),
            None => scan(),
        };
        for chunk in batch {
            for s in chunk? {
                if emitted >= max_strings {
                    return Ok(emitted);
                }
                emitted += 1;
                on_found(s);
            }
        }
        idx = end_idx;
        on_progress(std::cmp::min(
            end_idx as u64 * PARALLEL_CHUNK_SIZE,
            file_len,
        ));
    }
    Ok(emitted)
}

/// Canonical encoding labels produced by the scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Encoding {
    Ascii,
    Latin1,
    Cp1252,
    Utf8,
    ShiftJis,
    Utf16Le,
    Utf16Be,
    Utf32Le,
    Utf32Be,
}

impl Encoding {
    pub fn as_str(&self) -> &'static str {
        match self {
            Encoding::Ascii => "ascii",
            Encoding::Latin1 => "latin1",
            Encoding::Cp1252 => "cp1252",
            Encoding::Utf8 => "utf8",
            Encoding::ShiftJis => "shift_jis",
            Encoding::Utf16Le => "utf16le",
            Encoding::Utf16Be => "utf16be",
            Encoding::Utf32Le => "utf32le",
            Encoding::Utf32Be => "utf32be",
        }
    }

    pub fn from_label(label: &str) -> Option<Self> {
        Some(match label {
            "ascii" => Encoding::Ascii,
            "latin1" => Encoding::Latin1,
            "cp1252" => Encoding::Cp1252,
            "utf8" => Encoding::Utf8,
            "shift_jis" => Encoding::ShiftJis,
            "utf16le" => Encoding::Utf16Le,
            "utf16be" => Encoding::Utf16Be,
            "utf32le" => Encoding::Utf32Le,
            "utf32be" => Encoding::Utf32Be,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Encoding {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Encoding::from_label(s).ok_or(())
    }
}

impl ExtractedString {
    /// Typed view of the `encoding` field. Unknown labels map to `None`.
    pub fn encoding_kind(&self) -> Option<Encoding> {
        Encoding::from_label(self.encoding)
    }
}

/// Options for a scan, used by the new builder-style entry points.
#[derive(Clone)]
#[non_exhaustive]
pub struct ScanOptions {
    pub min_len: usize,
    pub max_strings: usize,
    pub noise: NoiseConfig,
    pub encodings: EncodingFilter,
    pub range: Option<(u64, u64)>,
    pub threads: usize,
    pub max_str_len: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            min_len: MIN_STRING_LEN,
            max_strings: MAX_STRINGS,
            noise: NoiseConfig::default(),
            encodings: EncodingFilter::all(),
            range: None,
            threads: 1,
            max_str_len: 0,
        }
    }
}

impl ScanOptions {
    /// # Example
    /// ```no_run
    /// use bxmap::{ScanOptions, EncodingFilter};
    /// let opts = ScanOptions::new().min_len(6).encodings(EncodingFilter::ascii());
    /// let _ = opts.scan_file("dump.bin");
    /// ```
    pub fn new() -> Self {
        Self::default()
    }
    pub fn min_len(mut self, n: usize) -> Self {
        self.min_len = n;
        self
    }
    pub fn max_strings(mut self, n: usize) -> Self {
        self.max_strings = n;
        self
    }
    pub fn noise(mut self, cfg: NoiseConfig) -> Self {
        self.noise = cfg;
        self
    }
    pub fn encodings(mut self, f: EncodingFilter) -> Self {
        self.encodings = f;
        self
    }
    pub fn range(mut self, start: u64, end: u64) -> Self {
        self.range = Some((start, end));
        self
    }
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n;
        self
    }
    pub fn max_str_len(mut self, n: usize) -> Self {
        self.max_str_len = n;
        self
    }

    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<Vec<ExtractedString>> {
        let path = path.as_ref();
        let path_str = path.to_str().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not valid UTF-8")
        })?;
        let file_len = std::fs::metadata(path)?.len();
        let (rs, re) = self.range.unwrap_or((0, file_len));
        let rs = rs.min(file_len);
        let re = re.min(file_len);
        let cap = self.max_strings.saturating_add(1);
        let mut results = Vec::new();
        let max_str_len = self.max_str_len;
        let mut on_found = |s: ExtractedString| {
            let mut s = s;
            if max_str_len > 0 && s.text.chars().count() > max_str_len {
                s.text = s.text.chars().take(max_str_len).collect();
            }
            results.push(s);
        };
        if self.threads > 1 && self.range.is_none() {
            extract_strings_from_file_parallel_streaming_with_encodings_progress(
                path_str,
                self.min_len,
                cap,
                self.noise,
                self.encodings,
                self.threads,
                &mut on_found,
                &mut |_| {},
            )?;
        } else {
            extract_strings_from_file_streaming_range_with_encodings_progress(
                path_str,
                rs,
                re,
                self.min_len,
                cap,
                self.noise,
                self.encodings,
                &mut on_found,
                &mut |_| {},
            )?;
        }
        if results.len() > self.max_strings {
            results.truncate(self.max_strings);
        }
        Ok(results)
    }

    pub fn scan_reader<R: Read>(
        &self,
        reader: R,
        estimated_len: u64,
    ) -> std::io::Result<Vec<ExtractedString>> {
        let mut results = extract_strings_from_reader_with_noise_config_and_encodings(
            reader,
            self.min_len,
            self.max_strings.saturating_add(1),
            estimated_len,
            self.noise,
            self.encodings,
        )?;
        if self.max_str_len > 0 {
            for s in &mut results {
                if s.text.chars().count() > self.max_str_len {
                    s.text = s.text.chars().take(self.max_str_len).collect();
                }
            }
        }
        if results.len() > self.max_strings {
            results.truncate(self.max_strings);
        }
        Ok(results)
    }
}

/// Version of the `bxmap` library crate, taken from `Cargo.toml` at build
/// time so it can never drift from the published package.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_package_metadata() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[cfg(test)]
    mod prop_tests {
        use super::*;
        use proptest::collection;
        use proptest::prelude::*;
        use std::io::Cursor;

        proptest! {
            #[test]
            fn reader_matches_in_memory_for_various_chunk_sizes(
                data in collection::vec(any::<u8>(), 0..2048),
                min_len in 1usize..9,
            ) {
                let in_mem = extract_strings(&data, min_len, 100_000);
                for &_ in &[1usize, 3, 7, 64, 4096] {
                    let reader = Cursor::new(&data);
                    let from_reader = extract_strings_from_reader(reader, min_len, 100_000, data.len() as u64).unwrap();
                    prop_assert_eq!(in_mem.len(), from_reader.len());
                    for (a, b) in in_mem.iter().zip(from_reader.iter()) {
                        prop_assert_eq!(a.offset, b.offset);
                        prop_assert_eq!(&a.encoding, &b.encoding);
                        prop_assert_eq!(&a.text, &b.text);
                    }
                }
            }

            #[test]
            fn parallel_matches_sequential_prop(
                data in collection::vec(any::<u8>(), 0..4096),
            ) {
                // Write to temp file.
                let path = std::env::temp_dir().join("bxmap-prop-par.bin");
                std::fs::write(&path, &data).unwrap();
                let p = path.to_str().unwrap();
                let seq = extract_strings_from_file_with_noise_config(p, 4, 100_000, NoiseConfig::default()).unwrap();
                let par = extract_strings_from_file_parallel_with_encodings(p, 4, 100_000, NoiseConfig::default(), EncodingFilter::all()).unwrap();
                prop_assert_eq!(seq.len(), par.len());
                for (a, b) in seq.iter().zip(par.iter()) {
                    prop_assert_eq!(a.offset, b.offset);
                    prop_assert_eq!(&a.encoding, &b.encoding);
                    prop_assert_eq!(&a.text, &b.text);
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    #[test]
    fn parallel_matches_sequential_across_region_boundaries() {
        // Put long strings straddling region boundaries (and a few bytes on
        // either side) and require the parallel scanner to agree with the
        // sequential one byte-for-byte.
        use std::io::Write;
        let path = std::env::temp_dir().join("bxmap-par-equiv.bin");
        let mut f = std::fs::File::create(&path).unwrap();
        // Region size under test is 4 KiB.
        let region = PARALLEL_CHUNK_SIZE as usize;
        let mut data = vec![0u8; region * 3];
        // ASCII run crossing the first boundary at region..region+64.
        for i in 0..80usize {
            data[region - 10 + i] = b'A';
        }
        // UTF-16LE run crossing the second boundary.
        let s = b"HELLO";
        let mut pos = region * 2 - 3;
        for &c in s {
            data[pos] = c;
            data[pos + 1] = 0;
            pos += 2;
        }
        // A short tail string entirely inside region 1.
        for (k, &c) in b"tailstr".iter().enumerate() {
            data[100 + k] = c;
        }
        f.write_all(&data).unwrap();
        f.flush().unwrap();
        let p = path.to_str().unwrap();

        let seq =
            extract_strings_from_file_with_noise_config(p, 4, 100_000, NoiseConfig::default())
                .unwrap();
        let par = extract_strings_from_file_parallel_with_encodings(
            p,
            4,
            100_000,
            NoiseConfig::default(),
            EncodingFilter::all(),
        )
        .unwrap();
        assert_eq!(
            seq.len(),
            par.len(),
            "count mismatch: seq={} par={}",
            seq.len(),
            par.len()
        );
        for (a, b) in seq.iter().zip(par.iter()) {
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.encoding, b.encoding);
            assert_eq!(a.text, b.text);
        }
        let _ = std::fs::remove_file(&path);
    }
    #[test]
    fn all_encoding_drops_all_ascii_duplicates_of_latin1_utf8_shift_jis() {
        // When the ascii family is scanned too, an all-ASCII run is already
        // covered by the "ascii" record; re-emitting it as latin1 / cp1252 /
        // utf8 / shift_jis only duplicates it at the same offset.
        let data = b"hello world de ad be ef\x00";
        let out = extract_strings_with_encodings(data, 4, 1000, EncodingFilter::all());

        assert!(out
            .iter()
            .any(|s| s.encoding == "ascii" && s.text == "hello world de ad be ef"));
        for family in ["latin1", "cp1252", "utf8", "shift_jis"] {
            assert!(
                !out.iter()
                    .any(|s| s.encoding == family && s.text == "hello world de ad be ef"),
                "{family} should not duplicate the all-ASCII run: {out:?}"
            );
        }
    }

    #[cfg(feature = "shift-jis")]
    #[test]
    fn shift_jis_decodes_japanese_and_ascii_mixture() {
        let raw = [0x93u8, 0xFA, 0x96, 0x7B, 0x8C, 0xEA];
        assert_eq!(shift_jis_to_utf8(&raw), "日本語");
        assert!(!shift_jis_to_utf8(&raw).contains('\u{FFFD}'));
        let mut mixed = vec![b'a', b'b'];
        mixed.extend_from_slice(&raw);
        mixed.push(b'c');
        assert_eq!(shift_jis_to_utf8(&mixed), "ab日本語c");
        assert!(!shift_jis_to_utf8(&mixed).contains('\u{FFFD}'));
    }

    #[test]
    fn text_family_only_filter_still_emits_everything() {
        // --encoding latin1 keeps ascii off in the scanner, so the suppression
        // above must NOT apply: even an all-ASCII run is emitted as latin1.
        let filter = EncodingFilter {
            ascii: false,
            latin1: true,
            ..EncodingFilter::ascii()
        };
        let data = b"plain ascii\x00";
        let out = extract_strings_with_encodings(data, 4, 1000, filter);
        assert!(out
            .iter()
            .any(|s| s.encoding == "latin1" && s.text == "plain ascii"));
    }
    #[test]
    fn utf8_filter_skips_ascii_only_runs() {
        let filter = EncodingFilter {
            ascii: false,
            utf8: true,
            ..EncodingFilter::ascii()
        };
        let data = b"plain ascii\x00caf\xc3\xa9\x00";
        let out = extract_strings_with_encodings(data, 4, 1000, filter);

        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf8" && s.text == "plain ascii"));
        assert!(
            out.iter()
                .any(|s| s.encoding == "utf8" && s.text == "caf\u{00e9}"),
            "{out:?}"
        );
    }

    #[cfg(feature = "shift-jis")]
    #[test]
    fn shift_jis_filter_skips_ascii_only_runs() {
        let filter = EncodingFilter {
            ascii: false,
            shift_jis: true,
            ..EncodingFilter::ascii()
        };
        let mut data = b"plain ascii\x00".to_vec();
        data.extend_from_slice(&[0x93, 0xFA, 0x96, 0x7B, 0x8C, 0xEA, 0x00]);
        let out = extract_strings_with_encodings(&data, 4, 1000, filter);

        assert!(!out
            .iter()
            .any(|s| s.encoding == "shift_jis" && s.text == "plain ascii"));
        assert!(
            out.iter()
                .any(|s| s.encoding == "shift_jis" && s.text.contains("日本語")),
            "{out:?}"
        );
    }

    #[test]
    fn ascii_and_utf16_basic() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00\x01hello world\x00");
        // "hi" UTF-16LE
        data.extend_from_slice(&[b'h', 0x00, b'i', 0x00, 0x00, 0x00]);
        let out = extract_strings(&data, 4, 200_000);
        assert!(out
            .iter()
            .any(|s| s.encoding == "ascii" && s.text == "hello world"));
    }

    #[test]
    fn entropy_distinguishes_uniform_and_mixed_data() {
        let uniform = vec![0u8; 1024];
        assert_eq!(shannon_entropy(&uniform), 0.0);

        let mixed: Vec<u8> = (0..=255).cycle().take(4096).collect();
        assert!((shannon_entropy(&mixed) - 8.0).abs() < f64::EPSILON);
    }

    #[cfg(feature = "yara")]
    #[test]
    fn yara_reader_scan_reports_matching_rule() {
        let rules = r#"
            rule marker {
                strings:
                    $s = "password123"
                condition:
                    $s
            }
        "#;
        let mut matches = Vec::new();
        let count = scan_yara_from_reader_streaming(
            std::io::Cursor::new(b"prefix password123 suffix"),
            rules,
            |matched| matches.push(matched),
        )
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(matches[0].rule, "marker");
        assert_eq!(matches[0].namespace, "default");
    }

    #[test]
    fn be_strings_after_zero_pages_are_still_found() {
        // zero-run fast skip must never hide a BE run that begins inside/after zeros
        let mut u16be = vec![0u8; 100];
        for c in b"abcd" {
            u16be.extend_from_slice(&[0, *c]);
        }
        let found = extract_strings(&u16be, 4, 1000);
        assert!(found
            .iter()
            .any(|r| r.encoding == "utf16be" && r.text == "abcd" && r.offset == 100));

        let mut u32be = vec![0u8; 64];
        for c in b"abcd" {
            u32be.extend_from_slice(&[0, 0, 0, *c]);
        }
        let found = extract_strings(&u32be, 4, 1000);
        assert!(found
            .iter()
            .any(|r| r.encoding == "utf32be" && r.text == "abcd" && r.offset == 64));

        // run that ends exactly at the end of the buffer, after a long zero page
        let mut tail = vec![0u8; 4096];
        tail.extend_from_slice(b"\0h\0e\0l\0l\0o");
        let found = extract_strings(&tail, 4, 1000);
        assert!(found
            .iter()
            .any(|r| r.encoding == "utf16be" && r.text == "hello" && r.offset == 4096));
    }

    #[test]
    fn min_len_filters_short_runs() {
        let data = b"ab\x00cdef\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "ab"));
        assert!(out.iter().any(|s| s.text == "cdef"));
    }

    #[test]
    fn chunk_boundary_carries_utf16_pair() {
        // Simulate a small CHUNK_SIZE by feeding manually across 2
        // consecutive feed() calls, carrying exactly 1 trailing byte --
        // this mirrors exactly what extract_strings_from_reader does at a
        // real chunk boundary.
        let full = {
            let mut v = Vec::new();
            v.extend_from_slice(&[b'a', 0x00, b'b', 0x00, b'c', 0x00, b'd', 0x00]);
            v
        };
        let mut results = Vec::new();
        {
            let mut on_found = |s: ExtractedString| results.push(s);
            let mut scanner = StringRunScanner::new(
                4,
                NoiseConfig::default(),
                &mut on_found,
                EncodingFilter::all(),
            );
            // Chunk 1: bytes 0..=5 (feed 5, valid_len 6) -- carry byte 6 (index 5)
            scanner.feed(&full[0..6], 0, 5, 6, 0);
            // Chunk 2 starts with the carry (full[5]) then the rest full[6..]
            let mut block2 = vec![full[5]];
            block2.extend_from_slice(&full[6..]);
            scanner.feed(&block2, 0, block2.len(), block2.len(), 5);
            scanner.flush_all();
        }
        assert!(results
            .iter()
            .any(|s| s.encoding == "utf16le" && s.text == "abcd"));
    }

    #[test]
    fn round_trip_via_reader_matches_in_memory() {
        let mut data = Vec::new();
        for i in 0..5000u32 {
            data.extend_from_slice(format!("token_{i:04}_", i = i).as_bytes());
        }
        let expected = extract_strings(&data, 4, 200_000);
        let via_reader =
            extract_strings_from_reader(std::io::Cursor::new(&data), 4, 200_000, data.len() as u64)
                .unwrap();
        assert_eq!(expected.len(), via_reader.len());
        assert_eq!(expected[0].text, via_reader[0].text);
    }

    #[test]
    fn noise_period1_ascii_is_filtered() {
        // "aaaaaaaa" (8 characters, >= NOISE_REPEAT1_MIN_LEN) is a
        // textbook byte-fill run -- must be filtered out of the results.
        let data = b"\x00aaaaaaaa\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "aaaaaaaa"));
    }

    #[test]
    fn noise_period2_ascii_is_filtered() {
        // "ABABABAB" (8 characters, exactly the NOISE_REPEAT2_MIN_LEN
        // threshold) -- alternating 2-character repeat, must be filtered.
        let data = b"\x00ABABABAB\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out.iter().any(|s| s.text == "ABABABAB"));
    }

    #[test]
    fn short_repeat_below_threshold_is_kept() {
        // "0000" (4 characters, below NOISE_REPEAT1_MIN_LEN=6) can still
        // be a real number (a PIN/year) -- must NOT be filtered out.
        let data = b"\x000000\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(out.iter().any(|s| s.text == "0000"));
    }

    #[test]
    fn custom_noise_threshold_from_cli_style_value() {
        // With threshold=16, an 8-char repeat like "aaaaaaaa" is now BELOW
        // the (raised) noise threshold, so it must be kept.
        let cfg = NoiseConfig::from_threshold(16);
        let data = b"\x00aaaaaaaa\x00".to_vec();
        let out = extract_strings_with_noise_config(&data, 4, 200_000, cfg);
        assert!(out.iter().any(|s| s.text == "aaaaaaaa"));
    }

    #[test]
    fn noise_threshold_zero_disables_filter_entirely() {
        let cfg = NoiseConfig::from_threshold(0);
        let data = b"\x00aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x00".to_vec();
        let out = extract_strings_with_noise_config(&data, 4, 200_000, cfg);
        assert!(out.iter().any(|s| s.text.starts_with("aaaa")));
    }

    #[test]
    fn decoded_noise_keeps_normal_text() {
        let cfg = NoiseConfig::default();
        assert!(!decoded_text_noise("Hello, world! 2026", &cfg));
        assert!(!decoded_text_noise("caf\u{e9} au lait", &cfg));
        assert!(!decoded_text_noise("日本語のテキストです", &cfg));
        assert!(!decoded_text_noise("\u{20ac}100", &cfg));
        // Tab/LF/CR are legitimate whitespace, not "bad" chars.
        assert!(!decoded_text_noise("line one\r\nline two\tend", &cfg));
    }

    #[test]
    fn decoded_noise_short_strings_judged_on_hard_evidence_only() {
        let cfg = NoiseConfig::default();
        assert!(decoded_text_noise("ab\u{fffd}d", &cfg));
        assert!(decoded_text_noise("ab\u{1}d", &cfg));
        assert!(decoded_text_noise("ab\u{e000}d", &cfg));
        // Short symbol-only text is kept (no ratio test below the minimum).
        assert!(!decoded_text_noise("\u{2605}\u{2605}\u{2605}", &cfg));
    }

    #[test]
    fn decoded_noise_long_strings_use_ratios() {
        let cfg = NoiseConfig::default();
        // 2 U+FFFD in 14 chars (> 10%) -> noise.
        assert!(decoded_text_noise("hello\u{fffd}wor\u{fffd}ld ok", &cfg));
        // 1 U+FFFD in 40+ chars (< 10%) -> kept (e.g. a truncated multibyte tail).
        assert!(!decoded_text_noise(
            "this is a long readable sentence with one \u{fffd}",
            &cfg
        ));
        // Long run of unreadable symbols -> noise.
        assert!(decoded_text_noise(
            "\u{2605}\u{2606}\u{2605}\u{2606}\u{2605}\u{2606}\u{2605}\u{2606}\u{2605}\u{2606}",
            &cfg
        ));
    }

    #[test]
    fn decoded_noise_disabled_with_noise_threshold_zero() {
        let cfg = NoiseConfig::from_threshold(0);
        assert!(!decoded_text_noise(
            "\u{fffd}\u{fffd}\u{fffd}\u{fffd}",
            &cfg
        ));
    }

    #[test]
    fn utf8_run_with_replacement_chars_is_filtered_end_to_end() {
        // A valid UTF-8 string is kept ...
        let good = b"\x00caf\xc3\xa9 au lait\x00".to_vec();
        let out = extract_strings(&good, 4, 200_000);
        assert!(out
            .iter()
            .any(|s| s.encoding == "utf8" && s.text.contains("caf\u{e9}")));
        // ... but no utf8 record may ever carry U+FFFD / control chars by default.
        let mut junk = b"\x00".to_vec();
        junk.extend_from_slice(b"ab\xc3\xa9\xff\xfe\xc3\xa9cd");
        junk.push(0);
        let out = extract_strings(&junk, 4, 200_000);
        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf8" && s.text.contains('\u{fffd}')));
    }

    /// Results as `(offset, encoding, text)`, sorted so equal-offset ties
    /// (e.g. ascii and utf8 starting on the same byte) compare deterministically.
    fn parity_key(results: Vec<ExtractedString>) -> Vec<(u64, &'static str, String)> {
        let mut v: Vec<_> = results
            .into_iter()
            .map(|s| (s.offset, s.encoding, s.text))
            .collect();
        v.sort();
        v
    }

    /// Binary filler that never forms a printable ASCII run, so the only
    /// strings the scanner can find are the ones planted by the caller.
    fn fill_binary_noise(data: &mut [u8]) {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for b in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let r = (state >> 24) as u8;
            *b = if r & 1 == 0 { r | 0x80 } else { (r % 31) + 1 };
        }
    }

    /// Copy `bytes` at `offset` and zero `pad` bytes on both sides so the
    /// planted run cannot merge into the surrounding noise.
    fn plant(data: &mut [u8], offset: usize, bytes: &[u8], pad: usize) {
        let end = offset + bytes.len();
        assert!(
            end + pad <= data.len(),
            "planted string must fit in the dump"
        );
        let before = offset.saturating_sub(pad);
        data[before..offset].fill(0);
        data[offset..end].copy_from_slice(bytes);
        let after = std::cmp::min(end + pad, data.len());
        data[end..after].fill(0);
    }

    fn plant_utf16(data: &mut [u8], offset: usize, s: &str, big_endian: bool) {
        let mut bytes = Vec::with_capacity(s.len() * 2);
        for unit in s.encode_utf16() {
            let [lo, hi] = unit.to_le_bytes();
            let pair = if big_endian { [hi, lo] } else { [lo, hi] };
            bytes.extend_from_slice(&pair);
        }
        plant(data, offset, &bytes, 2);
    }

    /// Dump spanning several `PARALLEL_CHUNK_SIZE` regions with strings that
    /// straddle, end on, and start on region boundaries in ascii, UTF-16LE
    /// and UTF-16BE.
    fn build_multi_region_dump(regions: usize) -> Vec<u8> {
        let region = PARALLEL_CHUNK_SIZE as usize;
        let mut data = vec![0u8; region * regions];
        fill_binary_noise(&mut data);

        for k in 0..regions {
            // Well inside a region: never affected by the region split.
            plant(
                &mut data,
                k * region + region / 2,
                b"inside_region_marker",
                1,
            );
        }
        // One behaviour per interior boundary, each far enough apart that the
        // planted runs cannot overwrite each other.
        for k in 1..regions {
            let b = k * region;
            match k {
                1 => plant(&mut data, b - 4, b"ascii_straddles_boundary_run", 1),
                2 => plant_utf16(&mut data, b - 6, "utf16le_straddles_border", false),
                3 => plant_utf16(&mut data, b - 6, "utf16be_straddles_border", true),
                4 => plant(&mut data, b - 24, b"ends_exactly_on_border", 1),
                5 => plant(&mut data, b, b"starts_exactly_on_border", 1),
                6 => plant_utf16(&mut data, b - 32, "utf16le_ends_on_border", false),
                7 => plant_utf16(&mut data, b, "utf16be_starts_on_border", true),
                _ => {}
            }
        }
        data
    }

    #[test]
    fn parallel_matches_sequential_on_multi_region_data() {
        // Same set, same ascending offset order from every code path: the
        // in-memory scanner, the buffered parallel scan and the streaming
        // parallel scan (with and without a private rayon pool).
        let data = build_multi_region_dump(8);
        assert!(
            data.len() as u64 > 3 * PARALLEL_CHUNK_SIZE,
            "test data must span more than one parallel region"
        );
        let tmp =
            std::env::temp_dir().join(format!("bxmap_parallel_parity_{}.bin", std::process::id()));
        std::fs::write(&tmp, &data).unwrap();
        let path = tmp.to_str().unwrap();

        let sequential = parity_key(extract_strings(&data, 4, 200_000));
        assert!(
            sequential.len() >= 16,
            "expected planted strings, got {}",
            sequential.len()
        );
        // Every encoding's records must be offset-ascending on their own too.
        assert!(sequential.windows(2).all(|w| w[0].0 <= w[1].0));

        let buffered = parity_key(
            extract_strings_from_file_parallel(path, 4, 200_000, NoiseConfig::default()).unwrap(),
        );
        assert_eq!(sequential, buffered, "buffered parallel diverged");

        for threads in [1usize, 2, 4] {
            let mut streamed = Vec::new();
            extract_strings_from_file_parallel_streaming_with_encodings(
                path,
                4,
                200_000,
                NoiseConfig::default(),
                EncodingFilter::all(),
                threads,
                |s| streamed.push(s),
            )
            .unwrap();
            assert_eq!(
                sequential,
                parity_key(streamed),
                "streaming parallel diverged with threads={threads}"
            );
        }

        // Encoding filters must apply identically on both paths.
        let seq_utf16 = parity_key(extract_strings_with_encodings(
            &data,
            4,
            200_000,
            EncodingFilter::utf16(),
        ));
        assert!(!seq_utf16.is_empty());
        let mut par_utf16 = Vec::new();
        extract_strings_from_file_parallel_streaming_with_encodings(
            path,
            4,
            200_000,
            NoiseConfig::default(),
            EncodingFilter::utf16(),
            2,
            |s| par_utf16.push(s),
        )
        .unwrap();
        assert_eq!(seq_utf16, parity_key(par_utf16), "utf16 filter diverged");

        // A cap must cut at the same place (first N by offset) on both paths.
        let cap = 5;
        let mut capped = Vec::new();
        let emitted = extract_strings_from_file_parallel_streaming_with_encodings(
            path,
            4,
            cap,
            NoiseConfig::default(),
            EncodingFilter::all(),
            4,
            |s| capped.push(s),
        )
        .unwrap();
        assert_eq!(emitted, cap.min(sequential.len()));
        assert_eq!(
            sequential[..emitted],
            parity_key(capped)[..],
            "max_strings cut diverged"
        );

        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn real_looking_string_not_filtered() {
        let data = b"\x00password123\x00".to_vec();
        let out = extract_strings(&data, 4, 200_000);
        assert!(out.iter().any(|s| s.text == "password123"));
    }

    #[test]
    fn noise_period1_utf16_is_filtered() {
        // "aaaaaaaa" as UTF-16LE (8 characters) -- the same filtering
        // logic must apply to the utf16le branch, not just ascii.
        let mut data = vec![0x00, 0x00];
        for _ in 0..8 {
            data.push(b'a');
            data.push(0x00);
        }
        data.extend_from_slice(&[0x00, 0x00]);
        let out = extract_strings(&data, 4, 200_000);
        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf16le" && s.text == "aaaaaaaa"));
    }

    #[test]
    fn chunk_boundary_ascii() {
        let full = b"abcdef".to_vec();
        let mut results = Vec::new();
        {
            let mut on_found = |s: ExtractedString| results.push(s);
            let mut scanner = StringRunScanner::new(
                4,
                NoiseConfig::default(),
                &mut on_found,
                EncodingFilter::all(),
            );
            scanner.feed(&full[0..6], 0, 5, 6, 0);
            let mut block2 = vec![full[5]];
            block2.extend_from_slice(&full[6..]);
            scanner.feed(&block2, 0, block2.len(), block2.len(), 5);
            scanner.flush_all();
        }
        assert!(results
            .iter()
            .any(|s| s.encoding == "ascii" && s.text == "abcdef"));
    }

    #[test]
    fn chunk_boundary_utf16be() {
        let mut full = Vec::new();
        for c in b"abcd" {
            full.extend_from_slice(&[0, *c]);
        }
        let mut results = Vec::new();
        {
            let mut on_found = |s: ExtractedString| results.push(s);
            let mut scanner = StringRunScanner::new(
                4,
                NoiseConfig::default(),
                &mut on_found,
                EncodingFilter::all(),
            );
            scanner.feed(&full[0..6], 0, 5, 6, 0);
            let mut block2 = vec![full[5]];
            block2.extend_from_slice(&full[6..]);
            scanner.feed(&block2, 0, block2.len(), block2.len(), 5);
            scanner.flush_all();
        }
        assert!(results
            .iter()
            .any(|s| s.encoding == "utf16be" && s.text == "abcd"));
    }

    #[test]
    fn utf16_ascii_le_does_not_emit_duplicate_be() {
        // "hello" stored as UTF-16LE must not also be reported as UTF-16BE
        // starting one byte later.
        let mut data = Vec::new();
        for c in b"hello" {
            data.push(*c);
            data.push(0);
        }
        let out = extract_strings(&data, 4, 1000);
        assert!(out
            .iter()
            .any(|s| s.encoding == "utf16le" && s.text == "hello"));
        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf16be" && s.text == "hello"));
    }

    #[test]
    fn utf32_ascii_le_does_not_emit_duplicate_be() {
        let mut data = Vec::new();
        for c in b"hello" {
            data.push(*c);
            data.extend_from_slice(&[0, 0, 0]);
        }
        let out = extract_strings(&data, 4, 1000);
        assert!(out
            .iter()
            .any(|s| s.encoding == "utf32le" && s.text == "hello"));
        assert!(!out
            .iter()
            .any(|s| s.encoding == "utf32be" && s.text == "hello"));
    }

    #[test]
    fn streaming_results_are_sorted_by_offset() {
        // Test that streaming API emits results in ascending offset order.
        // Uses a pattern that exercises UTF-16LE/BE runs across chunk boundaries.
        // Use the in-memory function as reference (it sorts)
        let mut data = Vec::new();
        // ASCII string
        data.extend_from_slice(b"ASCII_TEST_STRING\x00");
        // UTF-16LE "HELLO" - this creates LE at even offsets, BE at odd offsets
        for c in b"HELLO" {
            data.push(*c);
            data.push(0);
        }
        data.extend_from_slice(&[0, 0]); // terminator
                                         // Another ASCII string
        data.extend_from_slice(b"ANOTHER_ASCII_STRING\x00");

        let reference = extract_strings(&data, 4, 1000);

        // Now use streaming with a small buffer to force multiple feeds
        // We simulate by using the scanner directly with multiple feed calls
        let mut streaming_results = Vec::new();
        let mut on_found = |s: ExtractedString| streaming_results.push(s);
        let mut scanner = StringRunScanner::new(
            4,
            NoiseConfig::default(),
            &mut on_found,
            EncodingFilter::all(),
        );
        // Feed in small chunks to simulate streaming
        let chunk_size = 32;
        let mut offset = 0;
        while offset < data.len() {
            let end = std::cmp::min(offset + chunk_size, data.len());
            let is_last = end == data.len();
            let valid_len = if is_last {
                end - offset
            } else {
                end - offset + 1
            }; // +1 for lookahead
            let actual_valid = std::cmp::min(valid_len, data.len() - offset);
            scanner.feed(
                &data[offset..],
                0,
                end - offset,
                actual_valid,
                offset as u64,
            );
            if is_last {
                scanner.flush_all();
            }
            offset = end;
        }

        // Check that both produce same results in same order
        eprintln!("Reference ({}):", reference.len());
        for (i, r) in reference.iter().enumerate() {
            eprintln!(
                "  [{}] offset={} encoding={} text={}",
                i, r.offset, r.encoding, r.text
            );
        }
        eprintln!("Streaming ({}):", streaming_results.len());
        for (i, s) in streaming_results.iter().enumerate() {
            eprintln!(
                "  [{}] offset={} encoding={} text={}",
                i, s.offset, s.encoding, s.text
            );
        }

        assert_eq!(
            streaming_results.len(),
            reference.len(),
            "streaming count {} vs reference {}",
            streaming_results.len(),
            reference.len()
        );

        for (i, (stream, ref_s)) in streaming_results.iter().zip(reference.iter()).enumerate() {
            assert_eq!(
                stream.offset, ref_s.offset,
                "offset mismatch at index {}: streaming {} vs reference {}",
                i, stream.offset, ref_s.offset
            );
            assert_eq!(stream.text, ref_s.text, "text mismatch at index {}", i);
            assert_eq!(
                stream.encoding, ref_s.encoding,
                "encoding mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn parallel_streaming_matches_sequential_and_stays_sorted() {
        let mut data = Vec::new();
        for index in 0..500 {
            data.extend_from_slice(b"\x00\x01\x02binary-junk\xff\xfe");
            data.extend_from_slice(format!("C:\\Users\\victim\\file{index}.txt").as_bytes());
            data.extend_from_slice(&[0, 0, 0]);
            let utf16: Vec<u8> = format!("RAR password=secret{index}")
                .encode_utf16()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            data.extend_from_slice(&utf16);
            data.extend_from_slice(&[0, 0, 0, 0]);
        }
        let path = temp_bin("parallel-stream", &data);
        let path_str = path.to_string_lossy().to_string();

        let sequential = extract_strings_from_file_with_encodings(
            &path_str,
            4,
            usize::MAX,
            EncodingFilter::all(),
        )
        .unwrap();
        let mut streamed = Vec::new();
        let emitted = extract_strings_from_file_parallel_streaming_with_encodings(
            &path_str,
            4,
            usize::MAX,
            NoiseConfig::default(),
            EncodingFilter::all(),
            4,
            |item| streamed.push(item),
        )
        .unwrap();

        assert_eq!(emitted, streamed.len());
        assert_eq!(streamed.len(), sequential.len());
        assert!(streamed
            .windows(2)
            .all(|pair| pair[0].offset <= pair[1].offset));
        for (left, right) in streamed.iter().zip(sequential.iter()) {
            assert_eq!(
                (left.offset, &left.encoding, &left.text),
                (right.offset, &right.encoding, &right.text)
            );
        }

        // The cap must stop the scan early and report exactly that many.
        let mut capped = 0usize;
        let emitted = extract_strings_from_file_parallel_streaming_with_encodings(
            &path_str,
            4,
            10,
            NoiseConfig::default(),
            EncodingFilter::all(),
            4,
            |_| capped += 1,
        )
        .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(emitted, 10);
        assert_eq!(capped, 10);
    }

    fn temp_bin(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bxmap-{name}-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn streaming_range_emits_only_strings_starting_inside_the_window() {
        // Offsets: AAAA@0, BBBB@5, CCCC@10, DDDD@15, EEEE@20.
        let path = temp_bin("range-window", b"AAAA\x00BBBB\x00CCCC\x00DDDD\x00EEEE\x00");
        let mut found = Vec::new();
        let count = extract_strings_from_file_streaming_range_with_encodings(
            path.to_str().unwrap(),
            5,
            15,
            4,
            1000,
            NoiseConfig::default(),
            EncodingFilter::ascii(),
            |s| found.push(s),
        )
        .unwrap();
        let _ = std::fs::remove_file(&path);

        let texts: Vec<&str> = found.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(count, 2);
        assert_eq!(texts, vec!["BBBB", "CCCC"]);
        assert_eq!(found[0].offset, 5);
        assert_eq!(found[1].offset, 10);
    }

    #[test]
    fn streaming_range_keeps_strings_that_cross_the_end_boundary() {
        // The run starts inside [5, 10) but extends past it; it must be emitted
        // whole because the scanner reads MAX_RUN_CHARS past the boundary.
        let path = temp_bin("range-cross", b"xxxx\x00ABCDEFGHIJ\x00tail");
        let mut found = Vec::new();
        extract_strings_from_file_streaming_range_with_encodings(
            path.to_str().unwrap(),
            5,
            10,
            4,
            1000,
            NoiseConfig::default(),
            EncodingFilter::ascii(),
            |s| found.push(s),
        )
        .unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].text, "ABCDEFGHIJ");
        assert_eq!(found[0].offset, 5);
    }

    #[test]
    fn streaming_range_honours_max_strings() {
        let path = temp_bin("range-limit", b"AAAA\x00BBBB\x00CCCC\x00");
        let mut found = Vec::new();
        let count = extract_strings_from_file_streaming_range_with_encodings(
            path.to_str().unwrap(),
            0,
            15,
            4,
            1,
            NoiseConfig::default(),
            EncodingFilter::ascii(),
            |s| found.push(s),
        )
        .unwrap();
        let _ = std::fs::remove_file(&path);

        assert_eq!(count, 1);
        assert_eq!(found.len(), 1);
    }

    /// Deterministic pseudo-random bytes for entropy tests.
    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x9e37_79b9;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_options_merge_adjacent_windows() {
        let data = pseudo_random_bytes(8 * 1024);
        let path = temp_bin("entropy-merge", &data);

        let mut regions = Vec::new();
        scan_entropy_from_file_with_options(
            path.to_str().unwrap(),
            EntropyScanOptions {
                window: 1024,
                threshold: 7.0,
                merge: false,
                max_data: usize::MAX,
            },
            |region, payload, truncated| {
                assert_eq!(payload.len(), region.length);
                assert!(!truncated);
                regions.push(region);
            },
        )
        .unwrap();
        assert_eq!(regions.len(), 8);
        assert!(regions.iter().all(|r| r.length == 1024));

        let mut merged = Vec::new();
        let mut payload_len = 0usize;
        scan_entropy_from_file_with_options(
            path.to_str().unwrap(),
            EntropyScanOptions {
                window: 1024,
                threshold: 7.0,
                merge: true,
                max_data: usize::MAX,
            },
            |region, payload, truncated| {
                payload_len += payload.len();
                assert!(!truncated);
                merged.push(region);
            },
        )
        .unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].offset, 0);
        assert_eq!(merged[0].length, data.len());
        assert_eq!(payload_len, data.len());
        // The merged entropy is exact, so it must match the whole-file value.
        assert!((merged[0].entropy - shannon_entropy(&data)).abs() < 1e-12);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entropy_options_cap_payload() {
        let data = pseudo_random_bytes(4 * 1024);
        let path = temp_bin("entropy-cap", &data);

        let mut seen = 0usize;
        scan_entropy_from_file_with_options(
            path.to_str().unwrap(),
            EntropyScanOptions {
                window: 1024,
                threshold: 7.0,
                merge: true,
                max_data: 16,
            },
            |region, payload, truncated| {
                seen += 1;
                assert_eq!(region.length, data.len());
                assert_eq!(payload.len(), 16);
                assert!(truncated);
                assert_eq!(payload, &data[..16]);
            },
        )
        .unwrap();
        assert_eq!(seen, 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn entropy_options_threshold_filters_low_entropy() {
        let path = temp_bin("entropy-threshold", &vec![0u8; 4096]);

        let mut seen = 0usize;
        scan_entropy_from_file_with_options(
            path.to_str().unwrap(),
            EntropyScanOptions {
                window: 1024,
                threshold: 0.5,
                merge: false,
                max_data: usize::MAX,
            },
            |_region, _payload, _truncated| seen += 1,
        )
        .unwrap();
        assert_eq!(seen, 0);

        let _ = std::fs::remove_file(&path);
    }
}

/// Test hồi quy cho quét YARA theo cửa sổ (lỗi review 2026-11-09, ROADMAP 2.6.1).
#[cfg(all(test, feature = "yara"))]
mod yara_window_tests {
    use super::*;

    /// Reader giả lập pipe/stdin: mỗi lần `read` chỉ trả tối đa `max` byte.
    struct Dribble<'a> {
        data: &'a [u8],
        pos: usize,
        max: usize,
    }

    impl Read for Dribble<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.max.min(buf.len()).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    const RULE: &str = r#"rule r { strings: $a = "NEEDLE" condition: $a }"#;

    /// Chạy quét và trả về offset của mọi hit đã được báo.
    fn hit_offsets<R: Read>(reader: R, chunk: usize, overlap: usize) -> Vec<u64> {
        let mut out = Vec::new();
        scan_yara_windowed(reader, RULE, chunk, overlap, |m| {
            out.extend(m.matches.iter().map(|h| h.offset));
        })
        .unwrap();
        out
    }

    fn data_with_needles(len: usize, at: &[usize]) -> Vec<u8> {
        let mut data = vec![b'.'; len];
        for &pos in at {
            data[pos..pos + 6].copy_from_slice(b"NEEDLE");
        }
        data
    }

    #[test]
    fn short_reads_do_not_duplicate_hits() {
        // Trước khi sửa: reader trả 10 KB/lần làm hit bị báo 7 lần.
        let data = data_with_needles(300_000, &[1000]);
        let reader = Dribble {
            data: &data,
            pos: 0,
            max: 10_000,
        };
        assert_eq!(hit_offsets(reader, 64 * 1024, 64 * 1024), vec![1000]);
    }

    #[test]
    fn short_reads_match_full_reads() {
        let data = data_with_needles(5000, &[10, 126, 700, 4990]);
        let full = hit_offsets(std::io::Cursor::new(&data), 128, 16);
        let short = hit_offsets(
            Dribble {
                data: &data,
                pos: 0,
                max: 7,
            },
            128,
            16,
        );
        assert_eq!(full, short);
        assert_eq!(full, vec![10, 126, 700, 4990]);
    }

    #[test]
    fn hit_inside_overlap_is_reported_once() {
        // Cửa sổ 100 byte, overlap 32: hit ở 90..96 nằm trọn trong phần carry
        // của cửa sổ thứ hai; hit ở 98..104 vắt ngang ranh giới.
        let data = data_with_needles(1000, &[90, 98, 500]);
        let hits = hit_offsets(std::io::Cursor::new(&data), 100, 32);
        assert_eq!(hits, vec![90, 98, 500]);
    }

    #[test]
    fn every_needle_found_exactly_once_across_windows() {
        let positions: Vec<usize> = (0..10).map(|i| 126 + i * 200).collect();
        let data = data_with_needles(2200, &positions);
        let mut hits = hit_offsets(std::io::Cursor::new(&data), 128, 16);
        hits.sort_unstable();
        let expected: Vec<u64> = positions.iter().map(|&p| p as u64).collect();
        assert_eq!(hits, expected);
    }
}

/// Regression tests: no encoding may emit strings made of characters nobody can
/// read (U+FFFD, C1 controls, private use). Seen as "?" / "<?>" in terminals.
#[cfg(test)]
mod unreadable_text_tests {
    use super::*;

    fn texts(data: &[u8], encoding: &str) -> Vec<String> {
        extract_strings_with_encodings(data, 4, 100_000, EncodingFilter::all())
            .into_iter()
            .filter(|s| s.encoding == encoding)
            .map(|s| s.text)
            .collect()
    }

    fn is_bad(c: char) -> bool {
        !is_readable_char(c) && !matches!(c, '\n' | '\r' | '\t')
    }

    #[test]
    fn cp1252_undefined_bytes_are_not_emitted() {
        let data = b"\x00caf\xe9 \x81\x8d\x8f\x90\x9d na\xefve text\x00";
        for t in texts(data, "cp1252") {
            assert!(!t.chars().any(is_bad), "unreadable char in {t:?}");
        }
        // Defined 0x80-0x9F bytes (euro sign, curly quotes) must still work.
        let ok = texts(b"\x00price \x80 99 \x93quoted\x94 ok\x00", "cp1252");
        assert!(ok.iter().any(|t| t.contains('€')), "{ok:?}");
    }

    #[test]
    fn utf8_rejects_replacement_c1_and_private_use() {
        // U+FFFD, U+0085 (C1), U+E000 (private use), U+10FFFF (noncharacter).
        let data = b"\x00abcd\xef\xbf\xbdefgh\xc2\x85ijkl\xee\x80\x80mnop\xf4\x8f\xbf\xbfqrst\x00";
        for t in texts(data, "utf8") {
            assert!(!t.chars().any(is_bad), "unreadable char in {t:?}");
        }
        let ok = texts("\0h\u{e9}llo w\u{f6}rld\0".as_bytes(), "utf8");
        assert!(ok.iter().any(|t| t.contains("h\u{e9}llo")), "{ok:?}");
    }

    #[test]
    fn shift_jis_rejects_unassigned_and_user_defined_pairs() {
        // 0x8540 is unassigned (decodes to U+FFFD); 0xF040.. is the user-defined area.
        let bad = b"\x00\x85\x40\x85\x40\x85\x40\xf0\x40\xf0\x41\xf0\x42\x00";
        assert!(texts(bad, "shift_jis").is_empty());
        assert!(!shift_jis_pair_valid(0x85, 0x40));
        assert!(!shift_jis_pair_valid(0xF0, 0x40));
        // Real text still decodes (full Shift-JIS table only; the lite fallback
        // has no kanji).
        #[cfg(feature = "shift-jis")]
        {
            let jp = [0x00, 0x93, 0xFA, 0x96, 0x7B, 0x8C, 0xEA, 0x00];
            assert!(texts(&jp, "shift_jis").iter().any(|t| t.contains("日本語")));
        }
    }

    #[test]
    fn pseudo_random_data_never_yields_unreadable_strings() {
        // Deterministic xorshift noise: lots of byte pairs that merely look like
        // multi-byte text.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let data: Vec<u8> = (0..512 * 1024)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect();
        for s in extract_strings_with_encodings(&data, 4, 1_000_000, EncodingFilter::all()) {
            assert!(
                !s.text.chars().any(is_bad),
                "{} @0x{:x} has an unreadable char: {:?}",
                s.encoding,
                s.offset,
                s.text
            );
        }
    }
}
