//! `bxmap` -- a standalone crate (open source, licensed under AGPLv3).
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
pub mod magic;
pub mod minidump;
pub mod vmware;

use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

/// A YARA rule that matched while a dump was being streamed.
#[derive(Debug, Clone, Serialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub offset: u64,
}

/// Compiles YARA source and scans a reader in bounded chunks.
///
/// A small overlap is retained between chunks so literals and regular
/// expressions crossing an I/O boundary are still visible to YARA. Rules are
/// reported once, at the first chunk in which they match.
#[cfg(feature = "yara")]
pub fn scan_yara_from_reader_streaming<R: Read, F: FnMut(YaraMatch)>(
    mut reader: R,
    rules_source: &str,
    mut on_match: F,
) -> std::io::Result<usize> {
    let rules = yara_x::compile(rules_source).map_err(|error| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    })?;
    let mut scanner = yara_x::Scanner::new(&rules);
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut carry = Vec::new();
    let mut global_offset = 0u64;
    let mut reported = std::collections::HashSet::new();
    let mut count = 0usize;

    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + read);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..read]);
        let window_offset = global_offset.saturating_sub(carry.len() as u64);
        let results = scanner.scan(&window).map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
        })?;
        for rule in results.matching_rules() {
            let key = format!("{}:{}", rule.namespace(), rule.identifier());
            if reported.insert(key) {
                on_match(YaraMatch {
                    rule: rule.identifier().to_string(),
                    namespace: rule.namespace().to_string(),
                    offset: window_offset,
                });
                count += 1;
            }
        }
        carry.clear();
        let overlap = window.len().min(YARA_OVERLAP_SIZE);
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

// File chunk size per read -- large enough for efficient I/O,
// small enough to not accumulate too much RAM for the buffer.
const CHUNK_SIZE: usize = 32 * 1024 * 1024;
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

static PRINTABLE_TABLE: [bool; 256] = build_printable_table();

#[inline(always)]
fn is_printable(b: u8) -> bool {
    PRINTABLE_TABLE[b as usize]
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
}

impl EncodingFilter {
    pub const fn all() -> Self {
        Self {
            ascii: true,
            utf16le: true,
            utf16be: true,
            utf32le: true,
            utf32be: true,
        }
    }
    pub const fn ascii() -> Self {
        Self {
            ascii: true,
            utf16le: false,
            utf16be: false,
            utf32le: false,
            utf32be: false,
        }
    }
    pub const fn utf16() -> Self {
        Self {
            ascii: false,
            utf16le: true,
            utf16be: true,
            utf32le: false,
            utf32be: false,
        }
    }
    pub const fn utf32() -> Self {
        Self {
            ascii: false,
            utf16le: false,
            utf16be: false,
            utf32le: true,
            utf32be: true,
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
        let le_enabled = encodings.ascii || encodings.utf16le || encodings.utf32le;
        let be_enabled = encodings.utf16be || encodings.utf32be;
        for (i, slot) in candidate_start.iter_mut().enumerate() {
            let b = i as u8;
            *slot = (le_enabled && is_printable(b)) || (be_enabled && (b == 0 || is_printable(b)));
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
            // -- Fast-skip: when NO run is currently open (neither ascii
            // nor utf16), the current position can only be the START of a
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
const PARALLEL_CHUNK_SIZE: u64 = 16 * 1024 * 1024; // 16MB per region

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
    let read_end = std::cmp::min(logical_end + MAX_RUN_CHARS as u64, file_len);
    let read_len = (read_end - start) as usize;

    let mut file = File::open(dump_path)?;
    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; read_len];
    file.read_exact(&mut buf)?;

    let mut local: Vec<ExtractedString> = Vec::new();
    {
        let mut on_found = |s: ExtractedString| {
            if s.offset < logical_end {
                local.push(s);
            }
        };
        let mut scanner = StringRunScanner::new(min_len, noise_cfg, &mut on_found, encodings);
        scanner.feed(&buf, 0, buf.len(), buf.len(), start);
        scanner.flush_all();
    }
    Ok(local)
}

fn parallel_chunk_count(file_len: u64) -> usize {
    ((file_len + PARALLEL_CHUNK_SIZE - 1) / PARALLEL_CHUNK_SIZE) as usize
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
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
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

pub const VERSION: &str = "1.0.4";
#[cfg(test)]
mod tests {
    use super::*;

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
    fn parallel_matches_sequential_on_multi_region_data() {
        // Build data spanning several PARALLEL_CHUNK_SIZE-sized regions so
        // the parallel path actually exercises >1 chunk / boundary
        // handling, and check it agrees with the sequential scanner.
        let mut data = Vec::new();
        for i in 0..3000u32 {
            data.extend_from_slice(format!("marker_{i:05}_value_", i = i).as_bytes());
        }
        let tmp = std::env::temp_dir().join(format!("bxmap_test_{}.bin", std::process::id()));
        std::fs::write(&tmp, &data).unwrap();

        let sequential = extract_strings(&data, 4, 200_000);
        let parallel = extract_strings_from_file_parallel(
            tmp.to_str().unwrap(),
            4,
            200_000,
            NoiseConfig::default(),
        )
        .unwrap();

        std::fs::remove_file(&tmp).ok();

        assert_eq!(sequential.len(), parallel.len());
        for (a, b) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(a.offset, b.offset);
            assert_eq!(a.text, b.text);
        }
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
