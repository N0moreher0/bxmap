//! Signature-based file carving.
//!
//! `--carve` walks a dump once, finds format headers, and then *validates* the
//! structure behind each header before writing anything. A header alone is a
//! guess: `PK\x03\x04` also occurs inside compressed data, and a single `BM`
//! matches almost every page. Every validator therefore walks the format's own
//! length fields, refuses to trust a size that does not fit the remaining dump,
//! and reports whether the recovered file is complete or truncated.
//!
//! Scope is deliberately narrow (see `ROADMAP.md`): carve structured files,
//! never decrypt, never crack a password, never execute what was carved. Output
//! files get the neutral `.carved` extension so nothing auto-opens them.
//!
//! Signatures live in [`crate::magic::SIGNATURES`] so `--magic-bytes` and
//! `--carve` cannot drift apart; the only carve-only entry is BMP, whose
//! two-byte `BM` header is too weak to report as a magic hit.

use crate::chunk;
use crate::magic::{Signature, SIGNATURES};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Smallest file worth writing; shorter matches are almost always noise.
pub const DEFAULT_MIN_SIZE: u64 = 64;
/// Per-file ceiling. Header-declared sizes are clamped to this.
pub const DEFAULT_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// Total bytes written before the carver stops (`0` = unlimited).
pub const DEFAULT_MAX_TOTAL: u64 = 512 * 1024 * 1024;
/// Files written before the carver stops.
pub const DEFAULT_MAX_FILES: usize = 1000;

const READ_BUF: usize = 1 << 16;

/// A format the carver understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CarveKind {
    Jpeg,
    Png,
    Zip,
    Rar4,
    Rar5,
    SevenZip,
    Pdf,
    Gzip,
    Bmp,
    Sqlite,
}

impl CarveKind {
    /// Short id used in `--carve`, file names and the index.
    pub fn as_str(self) -> &'static str {
        match self {
            CarveKind::Jpeg => "jpeg",
            CarveKind::Png => "png",
            CarveKind::Zip => "zip",
            CarveKind::Rar4 => "rar4",
            CarveKind::Rar5 => "rar5",
            CarveKind::SevenZip => "7z",
            CarveKind::Pdf => "pdf",
            CarveKind::Gzip => "gzip",
            CarveKind::Bmp => "bmp",
            CarveKind::Sqlite => "sqlite",
        }
    }

    /// Every kind, in the order `--carve all` enables them.
    pub const ALL: [CarveKind; 10] = [
        CarveKind::Jpeg,
        CarveKind::Png,
        CarveKind::Zip,
        CarveKind::Rar4,
        CarveKind::Rar5,
        CarveKind::SevenZip,
        CarveKind::Pdf,
        CarveKind::Gzip,
        CarveKind::Bmp,
        CarveKind::Sqlite,
    ];

    fn from_id(id: &str) -> Option<Self> {
        match id {
            "jpeg" => Some(CarveKind::Jpeg),
            "png" => Some(CarveKind::Png),
            "zip" => Some(CarveKind::Zip),
            "rar4" => Some(CarveKind::Rar4),
            "rar5" => Some(CarveKind::Rar5),
            "7z" => Some(CarveKind::SevenZip),
            "pdf" => Some(CarveKind::Pdf),
            "gzip" => Some(CarveKind::Gzip),
            "bmp" => Some(CarveKind::Bmp),
            "sqlite" => Some(CarveKind::Sqlite),
            _ => None,
        }
    }

    /// Parse a comma/space separated list such as `jpeg,png,zip`.
    ///
    /// `all` expands to every kind; `rar` means both RAR4 and RAR5; `jpg` and
    /// `7zip` are accepted as aliases.
    pub fn from_list(list: &str) -> Result<Vec<CarveKind>, String> {
        let mut kinds: Vec<CarveKind> = Vec::new();
        for raw in list.split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace()) {
            let name = raw.trim().to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            let expanded: Vec<CarveKind> = match name.as_str() {
                "all" => CarveKind::ALL.to_vec(),
                "rar" => vec![CarveKind::Rar4, CarveKind::Rar5],
                "jpg" | "jpeg" => vec![CarveKind::Jpeg],
                "7zip" | "7z" => vec![CarveKind::SevenZip],
                other => vec![CarveKind::from_id(other).ok_or_else(|| {
                    format!(
                        "unknown carve type '{other}' (known: {})",
                        CarveKind::ALL
                            .iter()
                            .map(|kind| kind.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?],
            };
            for kind in expanded {
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
        }
        if kinds.is_empty() {
            return Err("empty carve type list".to_string());
        }
        kinds.sort();
        Ok(kinds)
    }
}

impl fmt::Display for CarveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Carving policy.
#[derive(Debug, Clone)]
pub struct CarveOptions {
    /// Formats to look for.
    pub kinds: Vec<CarveKind>,
    /// Files smaller than this are dropped (`0` keeps everything).
    pub min_size: u64,
    /// Per-file ceiling; header-declared sizes are clamped to it.
    pub max_size: u64,
    /// Stop after writing this many bytes (`0` = unlimited).
    pub max_total: u64,
    /// Stop after writing this many files.
    pub max_files: usize,
}

impl Default for CarveOptions {
    fn default() -> Self {
        Self {
            kinds: CarveKind::ALL.to_vec(),
            min_size: DEFAULT_MIN_SIZE,
            max_size: DEFAULT_MAX_SIZE,
            max_total: DEFAULT_MAX_TOTAL,
            max_files: DEFAULT_MAX_FILES,
        }
    }
}

/// One recovered file.
#[derive(Debug, Clone)]
pub struct CarvedFile {
    /// Absolute offset of the header in the dump.
    pub offset: u64,
    pub kind: CarveKind,
    /// Bytes covered by the file (validated length, not a header guess).
    pub size: u64,
    /// False when the terminator was missing, the dump ended first, or a
    /// size field exceeded `max_size`.
    pub complete: bool,
    pub sha256: String,
    /// Shannon entropy over the carved bytes (bits per byte).
    pub entropy: f64,
    /// Why the file is incomplete, or a note about how it was found.
    pub notes: String,
    /// Where the bytes were written, if the carver was asked to write.
    pub path: Option<PathBuf>,
    /// Later offsets with byte-identical content (deduped by SHA-256).
    pub duplicates: Vec<u64>,
}

/// Result of one carving pass.
#[derive(Debug, Default)]
pub struct CarveReport {
    pub files: Vec<CarvedFile>,
    /// Bytes written to disk (deduplicated copies are not written).
    pub bytes_written: u64,
    /// Bytes of duplicates that were recognised but not written.
    pub duplicate_bytes: u64,
    /// True when `max_total` or `max_files` stopped the scan early.
    pub truncated: bool,
    /// Signatures that passed the header check.
    pub candidates: usize,
    /// Signatures rejected by the structural validator.
    pub rejected: usize,
    /// First few rejection reasons (`offset kind: reason`), for debugging why
    /// a header was not carved.
    pub rejected_details: Vec<String>,
    /// Signatures inside an already carved file (nested images, etc.).
    pub nested: usize,
    /// Duplicates collapsed into an existing file.
    pub duplicates: usize,
}

impl CarveReport {
    /// Files whose structure validated all the way to a terminator.
    pub fn complete_count(&self) -> usize {
        self.files.iter().filter(|file| file.complete).count()
    }

    /// One-line summary for `--report summary`.
    pub fn summary_line(&self) -> String {
        let kinds = {
            let mut counts: Vec<(CarveKind, usize)> = Vec::new();
            for file in &self.files {
                match counts.iter_mut().find(|(kind, _)| *kind == file.kind) {
                    Some((_, count)) => *count += 1,
                    None => counts.push((file.kind, 1)),
                }
            }
            counts.sort_by_key(|(kind, _)| *kind);
            counts
                .iter()
                .map(|(kind, count)| format!("{kind}={count}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut line = format!(
            "{} file(s) ({} complete), {} bytes written",
            self.files.len(),
            self.complete_count(),
            self.bytes_written
        );
        if !kinds.is_empty() {
            line.push_str(&format!(" [{kinds}]"));
        }
        if self.duplicates > 0 {
            line.push_str(&format!(
                ", {} duplicate(s) skipped ({} bytes)",
                self.duplicates, self.duplicate_bytes
            ));
        }
        if self.rejected > 0 {
            line.push_str(&format!(", {} header(s) rejected", self.rejected));
        }
        line
    }
}

/// Structural verdict from a format validator.
enum Verdict {
    /// Header and terminator both checked out.
    Valid,
    /// Looks like the format but the dump ended (or a cap cut it) first.
    Truncated(String),
    /// Fails a structural check, so it is not this format at all.
    Invalid(String),
}

/// A carving pass over one dump.
#[derive(Debug, Clone)]
pub struct Carver {
    options: CarveOptions,
}

impl Carver {
    pub fn new(options: CarveOptions) -> Self {
        Self { options }
    }

    /// Find and validate files without writing them.
    pub fn scan(&self, dump_path: &str) -> io::Result<CarveReport> {
        self.run(dump_path, None)
    }

    /// Find, validate and write files under `out_dir`, deduplicated by SHA-256.
    ///
    /// Existing files are never overwritten: a name collision is an error so a
    /// previous carve cannot be silently replaced.
    pub fn carve_to_dir(&self, dump_path: &str, out_dir: &Path) -> io::Result<CarveReport> {
        std::fs::create_dir_all(out_dir)?;
        self.run(dump_path, Some(out_dir))
    }

    /// Find and validate files from any `Read` source without writing them.
    /// Writes the input to a temporary file first (suitable for fuzzing/small inputs).
    pub fn scan_from_reader<R>(&self, mut reader: R) -> io::Result<CarveReport>
    where
        R: Read,
    {
        use std::io::Write;
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!(
            "bxmap-fuzz-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut temp_file = File::create(&temp_path)?;
        std::io::copy(&mut reader, &mut temp_file)?;
        temp_file.flush()?;
        drop(temp_file);
        let result = self.scan(temp_path.to_str().unwrap());
        let _ = std::fs::remove_file(&temp_path);
        result
    }

    fn run(&self, dump_path: &str, out_dir: Option<&Path>) -> io::Result<CarveReport> {
        let file_len = std::fs::metadata(dump_path)?.len();
        let mut source = File::open(dump_path)?;
        let mut report = CarveReport::default();
        let mut by_hash: HashMap<String, usize> = HashMap::new();
        let mut covered_end = 0u64;
        let mut failure: Option<io::Error> = None;
        let mut stop = false;

        let overlap = max_signature_len().saturating_sub(1);
        chunk::for_each_chunk(dump_path, chunk::CHUNK_SIZE, overlap, |window| {
            for found in matcher().aho.find_iter(window.data) {
                if !window.spans_new_bytes(found.end()) {
                    continue;
                }
                let kind = matcher().kinds[found.pattern().as_usize()];
                if !self.options.kinds.contains(&kind) {
                    continue;
                }
                let offset = window.offset_of(found.start());
                report.candidates += 1;
                // A file already carved from an earlier offset owns these
                // bytes; an embedded thumbnail must not become a second hit.
                if offset < covered_end {
                    report.nested += 1;
                    continue;
                }
                let end = offset
                    .saturating_add(self.options.max_size.max(1))
                    .min(file_len);
                let outcome = match validate(kind, &mut source, offset, end) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                let (verdict, size) = outcome;
                let notes = match verdict {
                    Verdict::Invalid(reason) => {
                        report.rejected += 1;
                        if report.rejected_details.len() < 16 {
                            report
                                .rejected_details
                                .push(format!("{offset:#x} {kind}: {reason}"));
                        }
                        continue;
                    }
                    Verdict::Valid => String::new(),
                    Verdict::Truncated(reason) => reason,
                };
                if size < self.options.min_size {
                    report.rejected += 1;
                    continue;
                }
                let digest = match digest_region(&mut source, offset, size) {
                    Ok(digest) => digest,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                let (sha256, entropy) = digest;
                if let Some(&index) = by_hash.get(&sha256) {
                    report.duplicates += 1;
                    report.duplicate_bytes += size;
                    report.files[index].duplicates.push(offset);
                    covered_end = covered_end.max(offset + size);
                    continue;
                }
                let path = match out_dir {
                    Some(dir) => {
                        let name = format!(
                            "{offset:08x}-{}-{}.carved",
                            kind.as_str(),
                            &sha256[..8.min(sha256.len())]
                        );
                        let path = dir.join(name);
                        if path.exists() {
                            failure = Some(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                format!(
                                    "refusing to overwrite '{}'; use a fresh --carve-out",
                                    path.display()
                                ),
                            ));
                            return false;
                        }
                        if let Err(error) = write_region(&mut source, offset, size, &path) {
                            failure = Some(error);
                            return false;
                        }
                        Some(path)
                    }
                    None => None,
                };
                by_hash.insert(sha256.clone(), report.files.len());
                report.bytes_written += size;
                report.files.push(CarvedFile {
                    offset,
                    kind,
                    size,
                    complete: notes.is_empty(),
                    sha256,
                    entropy,
                    notes,
                    path,
                    duplicates: Vec::new(),
                });
                covered_end = offset + size;

                if self.options.max_files != 0 && report.files.len() >= self.options.max_files {
                    report.truncated = true;
                    stop = true;
                    return false;
                }
                if self.options.max_total != 0 && report.bytes_written >= self.options.max_total {
                    report.truncated = true;
                    stop = true;
                    return false;
                }
            }
            !stop
        })?;

        if let Some(error) = failure {
            return Err(error);
        }
        Ok(report)
    }
}

// --- signature matcher -------------------------------------------------------

struct Matcher {
    aho: AhoCorasick,
    kinds: Vec<CarveKind>,
}

/// Carve-only signatures. `BM` is deliberately absent from
/// [`crate::magic::SIGNATURES`]: two bytes are far too common to report as a
/// magic hit, but the BMP validator's extra header checks make it usable here.
const EXTRA_SIGNATURES: &[Signature] = &[Signature {
    bytes: b"BM",
    kind: "BMP image",
    carve: Some("bmp"),
}];

fn all_signatures() -> impl Iterator<Item = &'static Signature> {
    SIGNATURES.iter().chain(EXTRA_SIGNATURES.iter())
}

fn matcher() -> &'static Matcher {
    static MATCHER: OnceLock<Matcher> = OnceLock::new();
    MATCHER.get_or_init(|| {
        let mut kinds = Vec::new();
        let mut needles = Vec::new();
        for signature in all_signatures() {
            let Some(id) = signature.carve else {
                continue;
            };
            let Some(kind) = CarveKind::from_id(id) else {
                continue;
            };
            kinds.push(kind);
            needles.push(signature.bytes);
        }
        let aho = AhoCorasickBuilder::new()
            .build(needles)
            .expect("carve signatures are valid patterns");
        Matcher { aho, kinds }
    })
}

fn max_signature_len() -> usize {
    all_signatures()
        .map(|signature| signature.bytes.len())
        .max()
        .unwrap_or(1)
}

// --- validation --------------------------------------------------------------

fn validate(kind: CarveKind, file: &mut File, offset: u64, end: u64) -> io::Result<(Verdict, u64)> {
    let mut source = Source::new(file, offset, end);
    let verdict = match kind {
        CarveKind::Jpeg => carve_jpeg(&mut source)?,
        CarveKind::Png => carve_png(&mut source)?,
        CarveKind::Zip => carve_zip(&mut source)?,
        CarveKind::Rar4 => carve_rar4(&mut source)?,
        CarveKind::Rar5 => carve_rar5(&mut source)?,
        CarveKind::SevenZip => carve_7z(&mut source)?,
        CarveKind::Pdf => carve_pdf(&mut source)?,
        CarveKind::Gzip => carve_gzip(&mut source)?,
        CarveKind::Bmp => carve_bmp(&mut source)?,
        CarveKind::Sqlite => carve_sqlite(&mut source)?,
    };
    Ok((verdict, source.produced()))
}

/// Sequential reader over `[origin, end)` with a small lookahead window.
struct Source<'a> {
    file: &'a mut File,
    origin: u64,
    /// Absolute offset of `buf[0]`.
    base: u64,
    buf: Vec<u8>,
    len: usize,
    at: usize,
    end: u64,
}

impl<'a> Source<'a> {
    fn new(file: &'a mut File, origin: u64, end: u64) -> Self {
        Self {
            file,
            origin,
            base: origin,
            buf: vec![0u8; READ_BUF],
            len: 0,
            at: 0,
            end,
        }
    }

    fn abs(&self) -> u64 {
        self.base + self.at as u64
    }

    /// Bytes consumed since `origin`.
    fn produced(&self) -> u64 {
        self.abs() - self.origin
    }

    fn fill(&mut self, want: usize) -> io::Result<()> {
        if self.len - self.at >= want {
            return Ok(());
        }
        if self.at > 0 {
            self.buf.copy_within(self.at..self.len, 0);
            self.base += self.at as u64;
            self.len -= self.at;
            self.at = 0;
        }
        while self.len < want {
            let room = self.buf.len() - self.len;
            if room == 0 {
                break;
            }
            let pos = self.base + self.len as u64;
            if pos >= self.end {
                break;
            }
            let take = room.min((self.end - pos) as usize);
            self.file.seek(SeekFrom::Start(pos))?;
            let read = self.file.read(&mut self.buf[self.len..self.len + take])?;
            if read == 0 {
                break;
            }
            self.len += read;
        }
        Ok(())
    }

    fn peek(&mut self, want: usize) -> io::Result<&[u8]> {
        self.fill(want)?;
        let end = (self.at + want).min(self.len);
        Ok(&self.buf[self.at..end])
    }

    /// Move forward without reading the skipped bytes.
    fn skip(&mut self, amount: u64) -> io::Result<u64> {
        let target = self.abs().saturating_add(amount).min(self.end);
        let moved = target - self.abs();
        if moved <= (self.len - self.at) as u64 {
            self.at += moved as usize;
        } else {
            self.base = target;
            self.len = 0;
            self.at = 0;
        }
        Ok(moved)
    }
}

fn peek_array<const N: usize>(source: &mut Source<'_>) -> io::Result<Option<[u8; N]>> {
    let bytes = source.peek(N)?;
    if bytes.len() < N {
        return Ok(None);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(Some(out))
}

fn peek_u8(source: &mut Source<'_>) -> io::Result<Option<u8>> {
    Ok(source.peek(1)?.first().copied())
}

/// Find `needle` at or after the current position. Leaves the position at the
/// start of the match.
fn find_bytes(source: &mut Source<'_>, needle: &[u8]) -> io::Result<Option<u64>> {
    if needle.is_empty() {
        return Ok(Some(source.abs()));
    }
    loop {
        source.fill(needle.len())?;
        let available = source.len - source.at;
        if available < needle.len() {
            return Ok(None);
        }
        let found = {
            let hay = &source.buf[source.at..source.len];
            hay.windows(needle.len())
                .position(|window| window == needle)
        };
        if let Some(index) = found {
            source.skip(index as u64)?;
            return Ok(Some(source.abs()));
        }
        // Keep `needle.len() - 1` bytes so a match straddling the next read is
        // still found.
        let step = (available - (needle.len() - 1)) as u64;
        source.skip(step)?;
    }
}

fn find_byte(source: &mut Source<'_>, byte: u8) -> io::Result<Option<u64>> {
    let found = find_bytes(source, &[byte])?;
    if found.is_some() {
        source.skip(1)?;
    }
    Ok(found)
}

fn take_bytes(source: &mut Source<'_>, amount: usize) -> io::Result<Option<Vec<u8>>> {
    source.fill(amount)?;
    if source.len - source.at < amount {
        return Ok(None);
    }
    let bytes = source.buf[source.at..source.at + amount].to_vec();
    source.skip(amount as u64)?;
    Ok(Some(bytes))
}

/// Read a RAR5-style variable-length integer (7 bits per byte, high bit = more).
fn read_vint(source: &mut Source<'_>) -> io::Result<Option<u64>> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let Some(byte) = peek_u8(source)? else {
            return Ok(None);
        };
        source.skip(1)?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(Some(value));
        }
        shift += 7;
    }
    Ok(None)
}

fn vint_at(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let byte = *bytes.get(*cursor)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
    }
    None
}

fn carve_jpeg(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<3>(source)? != Some([0xFF, 0xD8, 0xFF]) {
        return Ok(Verdict::Invalid("missing JPEG SOI".to_string()));
    }
    // Skip only SOI (2 bytes): the third 0xFF starts the next marker.
    source.skip(2)?;
    let mut markers = 0usize;
    loop {
        let Some(first) = peek_u8(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the JPEG EOI marker".to_string(),
            ));
        };
        // Every marker starts with 0xFF. Anything else means the previous
        // segment's length field lied, so this is not a usable JPEG.
        if first != 0xFF {
            return Ok(Verdict::Invalid(format!(
                "expected a JPEG marker at {:#x}, found {first:#04x}",
                source.abs()
            )));
        }
        let Some([0xFF, marker]) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a JPEG marker".to_string(),
            ));
        };
        match marker {
            // Fill byte: a marker may be preceded by any number of 0xFF.
            0xFF => {
                source.skip(1)?;
                continue;
            }
            // Standalone markers carry no length field.
            0xD8 | 0x01 | 0xD0..=0xD7 => {
                source.skip(2)?;
                continue;
            }
            0xD9 => {
                source.skip(2)?;
                return Ok(Verdict::Valid);
            }
            _ => {}
        }
        let Some(header) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a JPEG marker header".to_string(),
            ));
        };
        let length = u64::from(u16::from_be_bytes([header[2], header[3]]));
        if length < 2 {
            // Corrupt length: resynchronise on the next marker instead of
            // trusting it.
            source.skip(2)?;
            continue;
        }
        if marker == 0xDA {
            // Start of scan: the entropy-coded data follows and is not
            // length-prefixed, so scan for the next real marker.
            if source.skip(2 + length)? != 2 + length {
                return Ok(Verdict::Truncated(
                    "dump ended inside the JPEG SOS header".to_string(),
                ));
            }
            // Scan data is not length-prefixed, so look for the next 0xFF and
            // decide whether it starts a real marker: FF00 is byte stuffing,
            // FFD0..FFD7 are restart markers and FFFF is padding, none of
            // which ends the scan.
            loop {
                if find_bytes(source, &[0xFF])?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside JPEG scan data".to_string(),
                    ));
                }
                let Some([0xFF, next]) = peek_array::<2>(source)? else {
                    return Ok(Verdict::Truncated(
                        "dump ended inside JPEG scan data".to_string(),
                    ));
                };
                if next == 0x00 || next == 0xFF || (0xD0..=0xD7).contains(&next) {
                    source.skip(1)?;
                    continue;
                }
                break;
            }
            markers += 1;
            continue;
        }
        if source.skip(2 + length)? != 2 + length {
            return Ok(Verdict::Truncated(format!(
                "dump ended inside JPEG segment 0xFF{marker:02X}"
            )));
        }
        markers += 1;
        if markers > 65_536 {
            return Ok(Verdict::Invalid(
                "JPEG has an implausible number of segments".to_string(),
            ));
        }
    }
}

fn carve_png(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(signature) = peek_array::<8>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the PNG signature".to_string(),
        ));
    };
    if signature != *b"\x89PNG\r\n\x1a\n" {
        return Ok(Verdict::Invalid("bad PNG signature".to_string()));
    }
    source.skip(8)?;
    let mut chunks = 0usize;
    loop {
        let Some(header) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the PNG IEND chunk".to_string(),
            ));
        };
        let length = u64::from(u32::from_be_bytes([
            header[0], header[1], header[2], header[3],
        ]));
        let kind = [header[4], header[5], header[6], header[7]];
        if length > 0x7fff_ffff {
            return Ok(Verdict::Invalid(format!(
                "implausible PNG chunk length {length}"
            )));
        }
        source.skip(8)?;
        let mut crc = crc32(0xffff_ffff, &kind);
        let mut left = length;
        while left > 0 {
            let take = left.min(READ_BUF as u64) as usize;
            let bytes = source.peek(take)?;
            if bytes.len() < take {
                return Ok(Verdict::Truncated(format!(
                    "dump ended inside the PNG {} chunk",
                    chunk_name(&kind)
                )));
            }
            crc = crc32(crc, bytes);
            source.skip(take as u64)?;
            left -= take as u64;
        }
        let Some(crc_bytes) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(format!(
                "dump ended before the PNG {} CRC",
                chunk_name(&kind)
            )));
        };
        let expected = u32::from_be_bytes(crc_bytes);
        let actual = crc ^ 0xffff_ffff;
        if actual != expected {
            return Ok(Verdict::Invalid(format!(
                "PNG {} chunk CRC mismatch",
                chunk_name(&kind)
            )));
        }
        source.skip(4)?;
        chunks += 1;
        if kind == *b"IEND" {
            return Ok(Verdict::Valid);
        }
        if chunks > 100_000 {
            return Ok(Verdict::Invalid(
                "PNG has an implausible number of chunks".to_string(),
            ));
        }
    }
}

fn chunk_name(kind: &[u8; 4]) -> String {
    kind.iter()
        .map(|byte| {
            if byte.is_ascii_graphic() {
                *byte as char
            } else {
                '?'
            }
        })
        .collect()
}

fn carve_zip(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"PK\x03\x04") {
        return Ok(Verdict::Invalid("missing ZIP local header".to_string()));
    }
    let mut entries = 0usize;
    loop {
        let Some(signature) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the ZIP end-of-central-directory".to_string(),
            ));
        };
        match &signature {
            b"PK\x03\x04" => {
                let Some(header) = peek_array::<30>(source)? else {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a ZIP local header".to_string(),
                    ));
                };
                let flags = u16::from_le_bytes([header[6], header[7]]);
                let packed = u64::from(u32::from_le_bytes([
                    header[18], header[19], header[20], header[21],
                ]));
                let name = u64::from(u16::from_le_bytes([header[26], header[27]]));
                let extra = u64::from(u16::from_le_bytes([header[28], header[29]]));
                source.skip(30)?;
                if source.skip(name + extra)? != name + extra {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a ZIP file name".to_string(),
                    ));
                }
                if flags & 0x0008 != 0 {
                    // Sizes live in a trailing data descriptor, so the local
                    // headers cannot be walked. Fall back to the EOCD scan.
                    break;
                }
                if source.skip(packed)? != packed {
                    return Ok(Verdict::Truncated(
                        "dump ended inside ZIP entry data".to_string(),
                    ));
                }
                entries += 1;
                if entries > 200_000 {
                    return Ok(Verdict::Invalid(
                        "ZIP has an implausible number of entries".to_string(),
                    ));
                }
            }
            b"PK\x01\x02" | b"PK\x05\x06" => break,
            _ => break,
        }
    }

    // The EOCD record ends the archive. Its comment length gives the exact
    // size, which is more reliable than any header-declared offset.
    let Some(eocd) = find_bytes(source, b"PK\x05\x06")? else {
        return Ok(Verdict::Truncated(
            "no ZIP end-of-central-directory record found".to_string(),
        ));
    };
    let distance = eocd - source.abs();
    source.skip(distance)?;
    let Some(record) = peek_array::<22>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the ZIP end-of-central-directory".to_string(),
        ));
    };
    let disk = u16::from_le_bytes([record[4], record[5]]);
    let comment = u64::from(u16::from_le_bytes([record[20], record[21]]));
    if disk != 0 {
        return Ok(Verdict::Invalid(
            "ZIP claims to continue on another disk".to_string(),
        ));
    }
    if source.skip(22 + comment)? != 22 + comment {
        return Ok(Verdict::Truncated(
            "dump ended inside the ZIP archive comment".to_string(),
        ));
    }
    Ok(Verdict::Valid)
}

fn carve_rar4(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(signature) = peek_array::<7>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the RAR4 signature".to_string(),
        ));
    };
    if signature != *b"Rar!\x1a\x07\x00" {
        return Ok(Verdict::Invalid("bad RAR4 signature".to_string()));
    }
    source.skip(7)?;
    let mut blocks = 0usize;
    loop {
        let Some(header) = peek_array::<7>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the RAR4 end-of-archive block".to_string(),
            ));
        };
        let kind = header[2];
        let flags = u16::from_le_bytes([header[3], header[4]]);
        let head_size = u64::from(u16::from_le_bytes([header[5], header[6]]));
        if head_size < 7 {
            return Ok(Verdict::Invalid(format!(
                "implausible RAR4 block size {head_size}"
            )));
        }
        // 0x7B is the end-of-archive block.
        if kind == 0x7B {
            if source.skip(head_size)? != head_size {
                return Ok(Verdict::Truncated(
                    "dump ended inside the RAR4 end block".to_string(),
                ));
            }
            return Ok(Verdict::Valid);
        }
        let mut data = 0u64;
        // ADD_SIZE is present on sub-blocks; file blocks carry PACK_SIZE in the
        // same position. Both describe the data area that follows the header.
        if flags & 0x8000 != 0 || kind == 0x73 {
            let Some(extended) = peek_array::<11>(source)? else {
                return Ok(Verdict::Truncated(
                    "dump ended inside a RAR4 block header".to_string(),
                ));
            };
            data = u64::from(u32::from_le_bytes([
                extended[7],
                extended[8],
                extended[9],
                extended[10],
            ]));
        }
        if source.skip(head_size)? != head_size {
            return Ok(Verdict::Truncated(
                "dump ended inside a RAR4 block header".to_string(),
            ));
        }
        if source.skip(data)? != data {
            return Ok(Verdict::Truncated(
                "dump ended inside RAR4 block data".to_string(),
            ));
        }
        blocks += 1;
        if blocks > 200_000 {
            return Ok(Verdict::Invalid(
                "RAR4 has an implausible number of blocks".to_string(),
            ));
        }
    }
}

fn carve_rar5(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(signature) = peek_array::<8>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the RAR5 signature".to_string(),
        ));
    };
    if signature != *b"Rar!\x1a\x07\x01\x00" {
        return Ok(Verdict::Invalid("bad RAR5 signature".to_string()));
    }
    source.skip(8)?;
    let mut blocks = 0usize;
    loop {
        // HEAD_CRC (4 bytes) then the variable-length HEAD_SIZE.
        let Some(_crc) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the RAR5 end-of-archive block".to_string(),
            ));
        };
        source.skip(4)?;
        let Some(head_size) = read_vint(source)? else {
            return Ok(Verdict::Invalid("malformed RAR5 header size".to_string()));
        };
        if !(2..=(1 << 20)).contains(&head_size) {
            return Ok(Verdict::Invalid(format!(
                "implausible RAR5 header size {head_size}"
            )));
        }
        let Some(header) = take_bytes(source, head_size as usize)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a RAR5 header".to_string(),
            ));
        };
        let mut cursor = 0usize;
        let Some(kind) = vint_at(&header, &mut cursor) else {
            return Ok(Verdict::Invalid("malformed RAR5 block type".to_string()));
        };
        let Some(flags) = vint_at(&header, &mut cursor) else {
            return Ok(Verdict::Invalid("malformed RAR5 block flags".to_string()));
        };
        let mut data_size = 0u64;
        if flags & 0x0001 != 0 {
            // Extra area: length is part of the header and already skipped.
            if vint_at(&header, &mut cursor).is_none() {
                return Ok(Verdict::Invalid("malformed RAR5 extra size".to_string()));
            }
        }
        if flags & 0x0002 != 0 {
            match vint_at(&header, &mut cursor) {
                Some(size) => data_size = size,
                None => {
                    return Ok(Verdict::Invalid("malformed RAR5 data size".to_string()));
                }
            }
        }
        // Block type 5 is the end of the archive.
        if kind == 5 {
            return Ok(Verdict::Valid);
        }
        if source.skip(data_size)? != data_size {
            return Ok(Verdict::Truncated(
                "dump ended inside RAR5 block data".to_string(),
            ));
        }
        blocks += 1;
        if blocks > 200_000 {
            return Ok(Verdict::Invalid(
                "RAR5 has an implausible number of blocks".to_string(),
            ));
        }
    }
}

fn carve_7z(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<32>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the 7-Zip signature header".to_string(),
        ));
    };
    if &header[0..6] != b"7z\xbc\xaf\x27\x1c" {
        return Ok(Verdict::Invalid("bad 7-Zip signature".to_string()));
    }
    let next_offset = u64::from_le_bytes(header[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(header[20..28].try_into().unwrap());
    let total = match 32u64
        .checked_add(next_offset)
        .and_then(|value| value.checked_add(next_size))
    {
        Some(total) => total,
        None => return Ok(Verdict::Invalid("7-Zip header sizes overflow".to_string())),
    };
    if total > source.end - source.origin {
        return Ok(Verdict::Truncated(format!(
            "7-Zip next header extends {total} bytes past the available data"
        )));
    }
    source.skip(total)?;
    Ok(Verdict::Valid)
}

fn carve_pdf(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<5>(source)? != Some(*b"%PDF-") {
        return Ok(Verdict::Invalid("missing %PDF- header".to_string()));
    }
    source.skip(5)?;
    match find_bytes(source, b"%%EOF")? {
        Some(offset) => {
            source.skip(offset - source.abs())?;
            if source.skip(5)? != 5 {
                return Ok(Verdict::Truncated(
                    "dump ended inside the PDF EOF marker".to_string(),
                ));
            }
            // A trailing EOL belongs to the file when present.
            let eol = matches!(peek_array::<1>(source)?, Some([b'\r']) | Some([b'\n']));
            if eol {
                source.skip(1)?;
                if matches!(peek_array::<2>(source)?, Some([b'\r', b'\n'])) {
                    source.skip(2)?;
                }
            }
            Ok(Verdict::Valid)
        }
        None => Ok(Verdict::Truncated(
            "no %%EOF marker found before the size limit".to_string(),
        )),
    }
}

fn carve_gzip(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<10>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the GZIP header".to_string(),
        ));
    };
    if &header[0..3] != b"\x1f\x8b\x08" {
        return Ok(Verdict::Invalid("bad GZIP header".to_string()));
    }
    let flags = header[3];
    source.skip(10)?;
    if flags & 0x04 != 0 {
        let Some(length) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside the GZIP extra field".to_string(),
            ));
        };
        let extra = u64::from(u16::from_le_bytes(length));
        source.skip(2)?;
        if source.skip(extra)? != extra {
            return Ok(Verdict::Truncated(
                "dump ended inside the GZIP extra field".to_string(),
            ));
        }
    }
    if flags & 0x08 != 0 && find_byte(source, 0)?.is_none() {
        return Ok(Verdict::Truncated(
            "unterminated GZIP file name".to_string(),
        ));
    }
    if flags & 0x10 != 0 && find_byte(source, 0)?.is_none() {
        return Ok(Verdict::Truncated("unterminated GZIP comment".to_string()));
    }
    if flags & 0x02 != 0 {
        source.skip(2)?;
    }

    // Walk the deflate stream so the exact end of the compressed data is known.
    let mut decoder = flate2::Decompress::new(false);
    let mut scratch = vec![0u8; READ_BUF];
    loop {
        let before = decoder.total_in();
        let status = {
            source.fill(READ_BUF)?;
            let input = &source.buf[source.at..source.len];
            if input.is_empty() {
                return Ok(Verdict::Truncated(
                    "deflate stream ended before its final block".to_string(),
                ));
            }
            decoder
                .decompress(input, &mut scratch, flate2::FlushDecompress::None)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        };
        let consumed = decoder.total_in() - before;
        source.skip(consumed)?;
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if consumed == 0 {
                    return Ok(Verdict::Truncated(
                        "deflate stream stalled before its final block".to_string(),
                    ));
                }
            }
        }
    }
    // CRC32 + ISIZE trailer.
    if source.skip(8)? != 8 {
        return Ok(Verdict::Truncated(
            "dump ended before the GZIP trailer".to_string(),
        ));
    }
    Ok(Verdict::Valid)
}

fn carve_bmp(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<26>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the BMP file header".to_string(),
        ));
    };
    if &header[0..2] != b"BM" {
        return Ok(Verdict::Invalid("missing BMP signature".to_string()));
    }
    let size = u64::from(u32::from_le_bytes([
        header[2], header[3], header[4], header[5],
    ]));
    let reserved = u32::from_le_bytes([header[6], header[7], header[8], header[9]]);
    let data_offset = u64::from(u32::from_le_bytes([
        header[10], header[11], header[12], header[13],
    ]));
    let dib = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
    if reserved != 0 {
        return Ok(Verdict::Invalid(
            "BMP reserved fields are not zero".to_string(),
        ));
    }
    if ![12, 40, 52, 56, 64, 108, 124].contains(&dib) {
        return Ok(Verdict::Invalid(format!(
            "implausible BMP DIB header size {dib}"
        )));
    }
    if size < 14 + u64::from(dib) || data_offset < 14 + u64::from(dib) || data_offset >= size {
        return Ok(Verdict::Invalid(
            "BMP header sizes are inconsistent".to_string(),
        ));
    }
    if size > source.end - source.origin {
        return Ok(Verdict::Truncated(format!(
            "BMP declares {size} bytes but the dump has less"
        )));
    }
    source.skip(size)?;
    Ok(Verdict::Valid)
}

fn carve_sqlite(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<32>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the SQLite header".to_string(),
        ));
    };
    if &header[0..16] != b"SQLite format 3\x00" {
        return Ok(Verdict::Invalid("bad SQLite signature".to_string()));
    }
    let raw_page = u16::from_be_bytes([header[16], header[17]]);
    // A page size of 1 is the encoding for 65536 bytes.
    let page = if raw_page == 1 {
        65_536u64
    } else {
        u64::from(raw_page)
    };
    if page < 512 || !page.is_power_of_two() {
        return Ok(Verdict::Invalid(format!(
            "implausible SQLite page size {page}"
        )));
    }
    let pages = u64::from(u32::from_be_bytes([
        header[28], header[29], header[30], header[31],
    ]));
    if pages == 0 {
        return Ok(Verdict::Truncated(
            "SQLite page count is 0 (database not checkpointed)".to_string(),
        ));
    }
    let total = page * pages;
    if total > source.end - source.origin {
        return Ok(Verdict::Truncated(format!(
            "SQLite declares {total} bytes but the dump has less"
        )));
    }
    source.skip(total)?;
    Ok(Verdict::Valid)
}

// --- hashing / writing -------------------------------------------------------

fn stream_region<F>(file: &mut File, offset: u64, size: u64, mut sink: F) -> io::Result<()>
where
    F: FnMut(&[u8]) -> io::Result<()>,
{
    file.seek(SeekFrom::Start(offset))?;
    let mut left = size;
    let mut buffer = vec![0u8; READ_BUF];
    while left > 0 {
        let take = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..take])?;
        sink(&buffer[..take])?;
        left -= take as u64;
    }
    Ok(())
}

fn digest_region(file: &mut File, offset: u64, size: u64) -> io::Result<(String, f64)> {
    let mut hasher = Sha256::new();
    let mut counts = [0u64; 256];
    stream_region(file, offset, size, |chunk| {
        hasher.update(chunk);
        for &byte in chunk {
            counts[byte as usize] += 1;
        }
        Ok(())
    })?;
    Ok((hex(&hasher.finalize()), entropy(&counts, size)))
}

fn write_region(file: &mut File, offset: u64, size: u64, path: &Path) -> io::Result<()> {
    let mut out = BufWriter::new(File::create(path)?);
    stream_region(file, offset, size, |chunk| out.write_all(chunk))?;
    out.flush()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn entropy(counts: &[u64; 256], size: u64) -> f64 {
    if size == 0 {
        return 0.0;
    }
    let length = size as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

/// CRC-32 (IEEE, as used by PNG and gzip).
fn crc32(state: u32, data: &[u8]) -> u32 {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    0xedb8_8320 ^ (value >> 1)
                } else {
                    value >> 1
                };
            }
            *slot = value;
        }
        table
    });
    let mut crc = state;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "bxmap-carve-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn png_bytes(pixels: &[u8]) -> Vec<u8> {
        let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(kind);
            out.extend_from_slice(data);
            let mut crc = crc32(0xffff_ffff, kind);
            crc = crc32(crc, data) ^ 0xffff_ffff;
            out.extend_from_slice(&crc.to_be_bytes());
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes()); // width
        ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, no interlace
        chunk(b"IHDR", &ihdr);
        chunk(b"IDAT", pixels);
        chunk(b"IEND", &[]);
        out
    }

    fn jpeg_bytes(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        // APP0 segment: length includes its own two bytes, so 16 = 2 + the
        // 14-byte JFIF payload.
        out.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        out.extend_from_slice(b"JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00");
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 1, 1, 0, 0, 0x3f, 0]);
        out.extend_from_slice(payload);
        out.extend_from_slice(&[0xFF, 0xD9]);
        out
    }

    fn write_dump(name: &str, data: &[u8]) -> PathBuf {
        let dir = temp_dir(name);
        let path = dir.join("dump.bin");
        std::fs::write(&path, data).unwrap();
        path
    }

    /// A minimal but structurally valid ZIP: one stored entry, a central
    /// directory record and an end-of-central-directory record.
    fn zip_bytes(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let name_bytes = name.as_bytes();
        let crc = crc32(0xffff_ffff, payload) ^ 0xffff_ffff;
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(payload);

        let central_offset = out.len() as u32;
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes()); // made by
        out.extend_from_slice(&20u16.to_le_bytes()); // needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&[0u8; 4]); // time + date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        out.extend_from_slice(name_bytes);

        let central_size = out.len() as u32 - central_offset;
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]); // this disk + central disk
        out.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        out.extend_from_slice(&1u16.to_le_bytes()); // entries total
        out.extend_from_slice(&central_size.to_le_bytes());
        out.extend_from_slice(&central_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment length
        out
    }

    #[test]
    fn carves_zip_and_gzip() {
        let zip = zip_bytes("notes.txt", b"hello from a carved archive");
        let mut gzip = Vec::new();
        {
            use flate2::write::GzEncoder;
            let mut encoder = GzEncoder::new(&mut gzip, flate2::Compression::fast());
            encoder
                .write_all(b"gzip payload that should be recovered")
                .unwrap();
            encoder.finish().unwrap();
        }

        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&[0u8; 96]);
        dump.extend_from_slice(&gzip);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("zip-gzip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 2, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Zip);
        assert_eq!(report.files[0].size, zip.len() as u64);
        assert!(report.files[0].complete);
        assert_eq!(report.files[1].kind, CarveKind::Gzip);
        assert_eq!(report.files[1].size, gzip.len() as u64);
        assert!(report.files[1].complete);
    }

    #[test]
    fn carves_rar4_with_an_end_of_archive_block() {
        let mut rar = b"Rar!\x1a\x07\x00".to_vec();
        // End-of-archive block: CRC(2), type 0x7B, flags(2), header size(2).
        rar.extend_from_slice(&[0x00, 0x00, 0x7B, 0x00, 0x00, 0x07, 0x00]);
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&rar);

        let path = write_dump("rar4", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Rar4);
        assert!(report.files[0].complete);
        assert_eq!(report.files[0].size, rar.len() as u64);
    }

    #[test]
    fn carves_jpeg_and_png_with_offsets() {
        let mut dump = vec![0u8; 300];
        let png = png_bytes(b"not-really-deflate-but-the-chunks-are-valid");
        let png_offset = dump.len() as u64;
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 128]);
        let jpeg = jpeg_bytes(&[0x5au8; 200]);
        let jpeg_offset = dump.len() as u64;
        dump.extend_from_slice(&jpeg);
        dump.extend_from_slice(&vec![0u8; 512]);

        let path = write_dump("two", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 2, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Png);
        assert_eq!(report.files[0].offset, png_offset);
        assert_eq!(report.files[0].size, png.len() as u64);
        assert!(report.files[0].complete);
        assert_eq!(report.files[1].kind, CarveKind::Jpeg);
        assert_eq!(report.files[1].offset, jpeg_offset);
        assert_eq!(report.files[1].size, jpeg.len() as u64);
        assert!(report.files[1].complete);
        assert_eq!(report.complete_count(), 2);
    }

    #[test]
    fn writes_files_and_dedupes_identical_copies() {
        let png = png_bytes(b"same-bytes");
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 64]);
        dump.extend_from_slice(&png);

        let path = write_dump("write", &dump);
        let out = temp_dir("write-out");
        let report = Carver::new(CarveOptions::default())
            .carve_to_dir(path.to_str().unwrap(), &out)
            .unwrap();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].duplicates.len(), 1);
        assert_eq!(report.duplicates, 1);
        assert!(report.files[0].path.as_ref().unwrap().exists());
        let written = std::fs::read(report.files[0].path.as_ref().unwrap()).unwrap();
        assert_eq!(written, png);
        assert_eq!(report.files[0].sha256.len(), 64);

        // A second run must refuse to overwrite instead of clobbering.
        let again = Carver::new(CarveOptions::default()).carve_to_dir(path.to_str().unwrap(), &out);
        assert!(again.is_err());

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn truncated_png_is_kept_but_marked_incomplete() {
        let mut png = png_bytes(b"payload");
        png.truncate(png.len() - 6); // cut inside IEND
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&png);
        let path = write_dump("truncated", &dump);

        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(!report.files[0].complete);
        assert!(report.files[0].notes.contains("dump ended"));
        assert_eq!(report.complete_count(), 0);
    }

    #[test]
    fn png_with_bad_crc_is_rejected() {
        let mut png = png_bytes(b"payload");
        // Corrupt one byte of the IDAT data without touching the CRC.
        let position = png.len() - 20;
        png[position] ^= 0xFF;
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&png);
        let path = write_dump("bad-crc", &dump);

        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
        assert_eq!(report.rejected, 1);
    }

    #[test]
    fn bmp_requires_a_consistent_header() {
        // A real 2x2 24-bit BMP.
        let mut bmp = Vec::new();
        let pixel_bytes = 2 * 2 * 3 + 8; // two rows padded to 4 bytes
        let size = 14 + 40 + pixel_bytes;
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&(size as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&54u32.to_le_bytes());
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&2i32.to_le_bytes());
        bmp.extend_from_slice(&2i32.to_le_bytes());
        bmp.extend_from_slice(&[1, 0]);
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&[0u8; 24]);
        bmp.extend_from_slice(&vec![0x7fu8; pixel_bytes]);

        let mut dump = vec![0u8; 40];
        dump.extend_from_slice(&bmp);
        let path = write_dump("bmp", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Bmp);
        assert!(report.files[0].complete);

        // A stray "BM" with junk behind it must not be carved.
        let mut junk = vec![0u8; 40];
        junk.extend_from_slice(b"BM");
        junk.extend_from_slice(&[0xAA; 64]);
        let path = write_dump("bmp-junk", &junk);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn respects_kind_filter_and_size_limits() {
        let png = png_bytes(b"payload");
        let mut dump = vec![0u8; 16];
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 16]);
        dump.extend_from_slice(&jpeg_bytes(b"scan"));
        let path = write_dump("filter", &dump);

        let options = CarveOptions {
            kinds: vec![CarveKind::Png],
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].kind, CarveKind::Png);

        let options = CarveOptions {
            min_size: 10_000,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        assert!(report.files.is_empty());

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn max_total_stops_the_scan_and_reports_truncation() {
        let png = png_bytes(b"payload");
        let mut dump = vec![0u8; 16];
        for _ in 0..3 {
            dump.extend_from_slice(&png);
            dump.extend_from_slice(&[0u8; 16]);
        }
        let path = write_dump("max-total", &dump);

        let options = CarveOptions {
            max_total: png.len() as u64,
            max_files: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(report.truncated);
    }

    #[test]
    fn kind_list_parsing_accepts_aliases_and_rejects_unknown() {
        assert_eq!(
            CarveKind::from_list("jpg,rar,7zip").unwrap(),
            vec![
                CarveKind::Jpeg,
                CarveKind::Rar4,
                CarveKind::Rar5,
                CarveKind::SevenZip
            ]
        );
        assert_eq!(
            CarveKind::from_list("all").unwrap().len(),
            CarveKind::ALL.len()
        );
        assert!(CarveKind::from_list("exe").is_err());
        assert!(CarveKind::from_list("").is_err());
    }
}
