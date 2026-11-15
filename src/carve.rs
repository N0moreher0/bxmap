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
//! files get the neutral `.carved` extension (after the format's own one, e.g.
//! `.docx.carved`) so nothing auto-opens them.
//!
//! Signatures live in [`crate::magic::SIGNATURES`] so `--signature magic` and
//! `--carve` cannot drift apart; BMP and OLE are carve-only entries whose
//! two-byte headers (`BM`, `D0 CF`) are too weak to report as magic hits.

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

/// Maximum JPEG segment length (64 MiB) - prevents OOM from bogus length fields.
const MAX_JPEG_SEGMENT: u64 = 64 * 1024 * 1024;
/// Maximum PNG chunk length (2 GiB, per spec) - already checked against 0x7fff_ffff.
const MAX_PNG_CHUNK: u64 = 0x7fff_ffff;
/// Maximum ZIP entry packed size (64 MiB).
const MAX_ZIP_PACKED: u64 = 64 * 1024 * 1024;
/// Maximum RAR4 block data size (64 MiB).
const MAX_RAR4_DATA: u64 = 64 * 1024 * 1024;
/// Maximum RAR5 block data size (64 MiB).
const MAX_RAR5_DATA: u64 = 64 * 1024 * 1024;
/// Maximum GZIP extra field size (1 MiB).
const MAX_GZIP_EXTRA: u64 = 1024 * 1024;
/// Maximum GZIP name/comment search length (1 MiB).
const MAX_GZIP_NAME_COMMENT: u64 = 1024 * 1024;
/// Maximum PDF search window for %%EOF (64 MiB).
const MAX_PDF_SEARCH: u64 = 64 * 1024 * 1024;

const READ_BUF: usize = 1 << 16;

/// Window used to look for the structured -> random boundary inside an
/// incomplete file (see [`entropy_rise`]).
const SPIKE_WINDOW: usize = 4096;
/// A window at or above this entropy (bits/byte) looks encrypted or compressed.
const SPIKE_HIGH: f64 = 7.8;
/// A window below this entropy is clearly structured data (text, headers, tables).
const SPIKE_LOW: f64 = 7.0;
/// Block the text pass scores. Block-granular detection (plus a byte-level
/// refine at the edges) keeps a stray non-text byte from splitting a long
/// plaintext run.
const TEXT_BLOCK: usize = 4096;
/// Share of a block that must decode as text for the block itself to count.
/// Random data scores ~30-38%, so 0.97 separates cleanly.
const TEXT_BLOCK_RATIO: f64 = 0.97;
/// A non-text block this long *inside* a run is bridged, not a boundary
/// (one 4 KiB glitch should not split a 350 KB note).
const TEXT_BRIDGE_BLOCKS: u64 = 1;
/// Smallest region the text pass emits. Below this it is noise, not evidence.
const TEXT_MIN_REGION: u64 = 2048;

/// Which piece of a file a carved output holds. It decides the file-name
/// suffix so a name never promises more than the bytes deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarveRole {
    /// Bytes starting at the file's own header.
    Whole,
    /// Footer-first salvage: the tail of a file whose head is gone, so it will
    /// not open directly.
    Tail,
    /// Fragments stitched together by `reassemble_fragments`.
    Reassembled,
}

/// Builds the one canonical output name: `{offset:08x}-{kind}-{sha8}.{ext}.carved`.
///
/// `.carved` is always the last extension so nothing auto-opens or runs the
/// file; `ext` comes only from the static [`CarveKind::default_ext`] table,
/// never from file contents, so the name cannot carry path separators or
/// other surprises. A salvaged tail gets `.tail` (`...png.tail.carved`) and a
/// reassembled file replaces the hash with `reassembled`.
pub fn carved_file_name(offset: u64, kind: CarveKind, role: CarveRole, sha256: &str) -> String {
    let ext = kind.default_ext();
    let kind_id = kind.as_str();
    match role {
        CarveRole::Whole => {
            format!("{offset:08x}-{kind_id}-{}.{ext}.carved", short_hash(sha256))
        }
        CarveRole::Tail => {
            format!("{offset:08x}-{kind_id}-{}.{ext}.tail.carved", short_hash(sha256))
        }
        CarveRole::Reassembled => {
            format!("{offset:08x}-{kind_id}-reassembled.{ext}.carved")
        }
    }
}

fn short_hash(sha256: &str) -> &str {
    &sha256[..8.min(sha256.len())]
}

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
    Ole,
    Mp4,
    Pe,
    Elf,
    Gif,
    Ico,
    Tar,
    Pcap,
    Pcapng,
    Lnk,
    Wasm,
    Dex,
    Kdbx,
    Pem,
    Avi,
    Wav,
    Webp,
    Mkv,
    Webm,
    Ogg,
    Opus,
    Flac,
    Mp3,
    Tiff,
    Vdi,
    Vmdk,
    Bz2,
    Xz,
    Class,
    Rtf,
    Evtx,
    /// Plaintext (txt, md, logs, source, ...). It has no magic number, so the
    /// text pass finds it by content and it is **not** part of
    /// [`CarveKind::ALL`]: ask for it with `--carve text` (or `all,text`).
    Text,
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
            CarveKind::Ole => "ole",
            CarveKind::Mp4 => "mp4",
            CarveKind::Pe => "pe",
            CarveKind::Elf => "elf",
            CarveKind::Gif => "gif",
            CarveKind::Ico => "ico",
            CarveKind::Tar => "tar",
            CarveKind::Pcap => "pcap",
            CarveKind::Pcapng => "pcapng",
            CarveKind::Lnk => "lnk",
            CarveKind::Wasm => "wasm",
            CarveKind::Dex => "dex",
            CarveKind::Kdbx => "kdbx",
            CarveKind::Pem => "pem",
            CarveKind::Avi => "avi",
            CarveKind::Wav => "wav",
            CarveKind::Webp => "webp",
            CarveKind::Mkv => "mkv",
            CarveKind::Webm => "webm",
            CarveKind::Ogg => "ogg",
            CarveKind::Opus => "opus",
            CarveKind::Flac => "flac",
            CarveKind::Mp3 => "mp3",
            CarveKind::Tiff => "tif",
            CarveKind::Vdi => "vdi",
            CarveKind::Vmdk => "vmdk",
            CarveKind::Bz2 => "bz2",
            CarveKind::Xz => "xz",
            CarveKind::Class => "class",
            CarveKind::Rtf => "rtf",
            CarveKind::Evtx => "evtx",
            CarveKind::Text => "text",
        }
    }

    /// Extension a carved file of this kind carries before `.carved`.
    ///
    /// Static whitelist (`[a-z0-9]{1,8}`): it is the format's usual name, not
    /// something read from the carved bytes. `Pe` defaults to `exe`; telling
    /// `dll`/`sys` apart needs the content sniff planned in ROADMAP 8.10.3.
    /// Plaintext is always `txt`: its real kind is only a hint in the index.
    pub fn default_ext(self) -> &'static str {
        match self {
            CarveKind::Jpeg => "jpg",
            CarveKind::Png => "png",
            CarveKind::Zip => "zip",
            CarveKind::Rar4 | CarveKind::Rar5 => "rar",
            CarveKind::SevenZip => "7z",
            CarveKind::Pdf => "pdf",
            CarveKind::Gzip => "gz",
            CarveKind::Bmp => "bmp",
            CarveKind::Sqlite => "sqlite",
            CarveKind::Ole => "ole",
            CarveKind::Mp4 => "mp4",
            CarveKind::Pe => "exe",
            CarveKind::Elf => "elf",
            CarveKind::Gif => "gif",
            CarveKind::Ico => "ico",
            CarveKind::Tar => "tar",
            CarveKind::Pcap => "pcap",
            CarveKind::Pcapng => "pcapng",
            CarveKind::Lnk => "lnk",
            CarveKind::Wasm => "wasm",
            CarveKind::Dex => "dex",
            CarveKind::Kdbx => "kdbx",
            CarveKind::Pem => "pem",
            CarveKind::Avi => "avi",
            CarveKind::Wav => "wav",
            CarveKind::Webp => "webp",
            CarveKind::Mkv => "mkv",
            CarveKind::Webm => "webm",
            CarveKind::Ogg => "ogg",
            CarveKind::Opus => "opus",
            CarveKind::Flac => "flac",
            CarveKind::Mp3 => "mp3",
            CarveKind::Tiff => "tif",
            CarveKind::Vdi => "vdi",
            CarveKind::Vmdk => "vmdk",
            CarveKind::Bz2 => "bz2",
            CarveKind::Xz => "xz",
            CarveKind::Class => "class",
            CarveKind::Rtf => "rtf",
            CarveKind::Evtx => "evtx",
            CarveKind::Text => "txt",
        }
    }

    /// Every kind, in the order `--carve all` enables them.
    pub const ALL: [CarveKind; 41] = [
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
        CarveKind::Ole,
        CarveKind::Mp4,
        CarveKind::Pe,
        CarveKind::Elf,
        CarveKind::Gif,
        CarveKind::Ico,
        CarveKind::Tar,
        CarveKind::Pcap,
        CarveKind::Pcapng,
        CarveKind::Lnk,
        CarveKind::Wasm,
        CarveKind::Dex,
        CarveKind::Kdbx,
        CarveKind::Pem,
        CarveKind::Avi,
        CarveKind::Wav,
        CarveKind::Webp,
        CarveKind::Mkv,
        CarveKind::Webm,
        CarveKind::Ogg,
        CarveKind::Opus,
        CarveKind::Flac,
        CarveKind::Mp3,
        CarveKind::Tiff,
        CarveKind::Vdi,
        CarveKind::Vmdk,
        CarveKind::Bz2,
        CarveKind::Xz,
        CarveKind::Class,
        CarveKind::Rtf,
        CarveKind::Evtx,
    ];

    fn from_id(id: &str) -> Option<Self> {
        match id {
            "jpeg" | "jpg" => Some(CarveKind::Jpeg),
            "png" => Some(CarveKind::Png),
            "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "jar" | "apk" => {
                Some(CarveKind::Zip)
            }
            "rar4" => Some(CarveKind::Rar4),
            "rar5" => Some(CarveKind::Rar5),
            "7z" => Some(CarveKind::SevenZip),
            "pdf" => Some(CarveKind::Pdf),
            "gzip" => Some(CarveKind::Gzip),
            "bmp" => Some(CarveKind::Bmp),
            "sqlite" | "sqlite3" | "db" => Some(CarveKind::Sqlite),
            "ole" | "msi" | "msg" | "doc" | "xls" | "ppt" => Some(CarveKind::Ole),
            "mp4" | "mov" | "m4a" => Some(CarveKind::Mp4),
            "pe" | "dll" | "sys" => Some(CarveKind::Pe),
            "elf" | "so" => Some(CarveKind::Elf),
            "gif" => Some(CarveKind::Gif),
            "ico" => Some(CarveKind::Ico),
            "tar" => Some(CarveKind::Tar),
            "pcap" => Some(CarveKind::Pcap),
            "pcapng" => Some(CarveKind::Pcapng),
            "lnk" => Some(CarveKind::Lnk),
            "wasm" => Some(CarveKind::Wasm),
            "dex" => Some(CarveKind::Dex),
            "kdbx" => Some(CarveKind::Kdbx),
            "pem" => Some(CarveKind::Pem),
            "avi" => Some(CarveKind::Avi),
            "wav" => Some(CarveKind::Wav),
            "webp" => Some(CarveKind::Webp),
            "mkv" => Some(CarveKind::Mkv),
            "webm" => Some(CarveKind::Webm),
            "ogg" => Some(CarveKind::Ogg),
            "opus" => Some(CarveKind::Opus),
            "flac" => Some(CarveKind::Flac),
            "mp3" => Some(CarveKind::Mp3),
            "tif" | "tiff" => Some(CarveKind::Tiff),
            "vdi" => Some(CarveKind::Vdi),
            "vmdk" => Some(CarveKind::Vmdk),
            "bz2" => Some(CarveKind::Bz2),
            "xz" => Some(CarveKind::Xz),
            "class" => Some(CarveKind::Class),
            "rtf" => Some(CarveKind::Rtf),
            "evtx" => Some(CarveKind::Evtx),
            "text" | "txt" => Some(CarveKind::Text),
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
                "office" | "ms-office" | "ole" => vec![CarveKind::Ole],
                "mp4" => vec![CarveKind::Mp4],
                "pe" | "exe" | "executable" => vec![CarveKind::Pe],
                "elf" => vec![CarveKind::Elf],
                other => vec![CarveKind::from_id(other).ok_or_else(|| {
                    format!(
                        "unknown carve type '{other}' (known: {}, text)",
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
    /// Absolute offset of the header in the dump. For a `salvage:tail` file
    /// this is where the surviving tail starts: the header itself is missing.
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
    /// Absolute offset where structural validation stopped (the end of the
    /// bytes the validator could walk). `None` for complete files.
    pub corrupted_offset: Option<u64>,
    /// Absolute start of the first 4 KiB window whose entropy jumps to
    /// >= 7.8 bits/byte after structured (< 7.0) data: a hint of where an
    /// encrypted region begins. Heuristic only (compressed data looks the
    /// same). `None` for complete files or when no such jump exists.
    pub entropy_spike_at: Option<u64>,
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
    incomplete_dir: bool,
    salvage: bool,
}

impl Carver {
    pub fn new(options: CarveOptions) -> Self {
        Self {
            options,
            incomplete_dir: false,
            salvage: false,
        }
    }

    /// Write incomplete files (`complete == false`) into a `partial/`
    /// subdirectory of the output directory instead of beside the complete
    /// ones, so an analyst can feed that folder to repair tools (Untrunc,
    /// 7-Zip recovery, manual header splicing) in one go. Off by default,
    /// which keeps the flat layout.
    pub fn with_incomplete_dir(mut self, enabled: bool) -> Self {
        self.incomplete_dir = enabled;
        self
    }

    /// Footer-first salvage (`--carve-salvage`): after the normal header-first
    /// pass, look for healthy *tails* (ZIP central directory + end record,
    /// PDF `startxref` + `%%EOF`) that no carved file already covers, and walk
    /// backwards from each one to where the data turns into high-entropy
    /// bytes (the edge of an encrypted region), a carved neighbour, or
    /// `max_size`. Each tail is reported as an incomplete file whose notes
    /// start with `salvage:tail`, and is written under `partial/`. Nothing is
    /// decrypted or repaired; the tail is only cut out and labelled.
    pub fn with_salvage(mut self, enabled: bool) -> Self {
        self.salvage = enabled;
        self
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
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut temp_file = File::create(&temp_path)?;
        std::io::copy(&mut reader, &mut temp_file)?;
        temp_file.flush()?;
        drop(temp_file);
        let temp_str = temp_path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "temp path is not valid UTF-8")
        })?;
        let result = self.scan(temp_str);
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
            for found in matcher().aho.find_overlapping_iter(window.data) {
                if !window.spans_new_bytes(found.end()) {
                    continue;
                }
                let kind = matcher().kinds[found.pattern().as_usize()];
                if !self.options.kinds.contains(&kind) {
                    continue;
                }
                let Some(offset) = candidate_offset(kind, window.offset_of(found.start())) else {
                    continue;
                };
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
                let incomplete = !notes.is_empty();
                let corrupted_offset = incomplete.then_some(offset + size);
                let entropy_spike_at = if incomplete {
                    match entropy_rise(&mut source, offset, size) {
                        Ok(spike) => spike,
                        Err(error) => {
                            failure = Some(error);
                            return false;
                        }
                    }
                } else {
                    None
                };
                let path = match out_dir {
                    Some(dir) => {
                        let name = carved_file_name(offset, kind, CarveRole::Whole, &sha256);
                        let target_dir = if incomplete && self.incomplete_dir {
                            let partial = dir.join("partial");
                            if let Err(error) = std::fs::create_dir_all(&partial) {
                                failure = Some(error);
                                return false;
                            }
                            partial
                        } else {
                            dir.to_path_buf()
                        };
                        let path = target_dir.join(name);
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
                    corrupted_offset,
                    entropy_spike_at,
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
        if self.salvage {
            self.salvage_pass(dump_path, out_dir, file_len, &mut report)?;
        }
        if self.options.kinds.contains(&CarveKind::Text) {
            self.text_pass(dump_path, out_dir, file_len, &mut report)?;
        }
        Ok(report)
    }

    /// Second pass behind [`Carver::with_salvage`]: find footers that no
    /// header-first file covers and recover the tail behind each one.
    fn salvage_pass(
        &self,
        dump_path: &str,
        out_dir: Option<&Path>,
        file_len: u64,
        report: &mut CarveReport,
    ) -> io::Result<()> {
        // A header pass that already hit a cap must not be extended.
        if report.truncated || !self.options.kinds.iter().any(|kind| has_footer(*kind)) {
            return Ok(());
        }
        let mut source = File::open(dump_path)?;
        let mut by_hash: HashMap<String, usize> = HashMap::new();
        let mut covered: Vec<(u64, u64)> = Vec::new();
        for (index, file) in report.files.iter().enumerate() {
            by_hash.insert(file.sha256.clone(), index);
            covered.push((file.offset, file.offset + file.size));
            for &duplicate in &file.duplicates {
                covered.push((duplicate, duplicate + file.size));
            }
        }
        let mut failure: Option<io::Error> = None;
        let mut stop = false;

        chunk::for_each_chunk(dump_path, chunk::CHUNK_SIZE, FOOTER_OVERLAP, |window| {
            for found in footer_matcher().aho.find_iter(window.data) {
                if !window.spans_new_bytes(found.end()) {
                    continue;
                }
                let kind = footer_matcher().kinds[found.pattern().as_usize()];
                if !self.options.kinds.contains(&kind) {
                    continue;
                }
                let position = window.offset_of(found.start());
                let tail = match salvage_tail(
                    kind,
                    &mut source,
                    position,
                    file_len,
                    self.options.max_size,
                    &covered,
                ) {
                    Ok(Some(tail)) => tail,
                    Ok(None) => continue,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                let size = tail.end - tail.start;
                if size < self.options.min_size {
                    report.rejected += 1;
                    continue;
                }
                let (sha256, entropy) = match digest_region(&mut source, tail.start, size) {
                    Ok(digest) => digest,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                covered.push((tail.start, tail.end));
                if let Some(&index) = by_hash.get(&sha256) {
                    report.duplicates += 1;
                    report.duplicate_bytes += size;
                    report.files[index].duplicates.push(tail.start);
                    continue;
                }
                let path = match out_dir {
                    Some(dir) => {
                        // A salvaged tail is incomplete by definition, so it
                        // always goes beside the other partial files.
                        let partial = dir.join("partial");
                        if let Err(error) = std::fs::create_dir_all(&partial) {
                            failure = Some(error);
                            return false;
                        }
                        let name = carved_file_name(tail.start, kind, CarveRole::Tail, &sha256);
                        let path = partial.join(name);
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
                        if let Err(error) = write_region(&mut source, tail.start, size, &path) {
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
                    offset: tail.start,
                    kind,
                    size,
                    complete: false,
                    sha256,
                    entropy,
                    notes: tail.note,
                    path,
                    duplicates: Vec::new(),
                    corrupted_offset: Some(tail.start),
                    entropy_spike_at: tail.spike,
                });

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

        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Third pass behind `--carve text` (it runs only when [`CarveKind::Text`]
    /// is in the wanted kinds): find long runs of printable text that carry
    /// no magic — notes, logs, Markdown, source dumps — and cut them out.
    ///
    /// The boundary is a heuristic, so every file is labelled `complete:
    /// false` with a `text:region` note and lands in `partial/`. Offset,
    /// size and a content sniff (`json`/`xml`/`html`/`csv`/`text`) are
    /// recorded; dedupe and the `max_files`/`max_total` caps match the other
    /// passes. Nothing is decrypted or repaired.
    fn text_pass(
        &self,
        dump_path: &str,
        out_dir: Option<&Path>,
        file_len: u64,
        report: &mut CarveReport,
    ) -> io::Result<()> {
        // A header pass that already hit a cap must not be extended.
        if report.truncated {
            return Ok(());
        }
        let mut by_hash: HashMap<String, usize> = HashMap::new();
        let mut covered: Vec<(u64, u64)> = Vec::new();
        for (index, file) in report.files.iter().enumerate() {
            by_hash.insert(file.sha256.clone(), index);
            covered.push((file.offset, file.offset + file.size));
            for &duplicate in &file.duplicates {
                covered.push((duplicate, duplicate + file.size));
            }
        }
        let mut source = File::open(dump_path)?;
        let mut failure: Option<io::Error> = None;

        for (start, end) in text_regions(&mut source, file_len, &covered)? {
            let size = end - start;
            if size < self.options.min_size.max(1).max(TEXT_MIN_REGION) {
                continue;
            }
            let (sha256, entropy) = match digest_region(&mut source, start, size) {
                Ok(digest) => digest,
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            };
            if let Some(&index) = by_hash.get(&sha256) {
                report.duplicates += 1;
                report.duplicate_bytes += size;
                report.files[index].duplicates.push(start);
                continue;
            }
            let path = match out_dir {
                Some(dir) => {
                    // Text boundaries are heuristic, so a text region always
                    // goes beside the other partial files.
                    let partial = dir.join("partial");
                    if let Err(error) = std::fs::create_dir_all(&partial) {
                        failure = Some(error);
                        break;
                    }
                    let name =
                        carved_file_name(start, CarveKind::Text, CarveRole::Whole, &sha256);
                    let path = partial.join(name);
                    if path.exists() {
                        failure = Some(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            format!(
                                "refusing to overwrite '{}'; use a fresh --carve-out",
                                path.display()
                            ),
                        ));
                        break;
                    }
                    if let Err(error) = write_region(&mut source, start, size, &path) {
                        failure = Some(error);
                        break;
                    }
                    Some(path)
                }
                None => None,
            };
            let mut prefix = vec![0u8; size.min(512) as usize];
            source.seek(SeekFrom::Start(start))?;
            source.read_exact(&mut prefix)?;
            let sniff = text_sniff(&prefix);
            let notes = format!(
                "text:region 0x{start:x}-0x{end:x}; boundary cut to newline; looks like {sniff}"
            );
            by_hash.insert(sha256.clone(), report.files.len());
            report.bytes_written += size;
            report.files.push(CarvedFile {
                offset: start,
                kind: CarveKind::Text,
                size,
                complete: false,
                sha256,
                entropy,
                notes,
                path,
                duplicates: Vec::new(),
                corrupted_offset: None,
                entropy_spike_at: None,
            });

            if self.options.max_files != 0 && report.files.len() >= self.options.max_files {
                report.truncated = true;
                break;
            }
            if self.options.max_total != 0 && report.bytes_written >= self.options.max_total {
                report.truncated = true;
            }
        }

        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Collect carve fragments without writing them, optionally mapping each
    /// file offset to a virtual address via `minidump`. Used by `--reassemble`.
    pub fn collect_fragments(
        &self,
        dump_path: &str,
        minidump: Option<&crate::minidump::Minidump>,
    ) -> io::Result<Vec<CarveFragment>> {
        let file_len = std::fs::metadata(dump_path)?.len();
        let mut source = File::open(dump_path)?;
        let mut fragments: Vec<CarveFragment> = Vec::new();
        let mut covered_end = 0u64;
        let mut failure: Option<io::Error> = None;

        let overlap = max_signature_len().saturating_sub(1);
        chunk::for_each_chunk(dump_path, chunk::CHUNK_SIZE, overlap, |window| {
            for found in matcher().aho.find_overlapping_iter(window.data) {
                if !window.spans_new_bytes(found.end()) {
                    continue;
                }
                let kind = matcher().kinds[found.pattern().as_usize()];
                if !self.options.kinds.contains(&kind) {
                    continue;
                }
                let Some(offset) = candidate_offset(kind, window.offset_of(found.start())) else {
                    continue;
                };
                if offset < covered_end {
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
                if size < self.options.min_size {
                    continue;
                }
                if size > self.options.max_size {
                    continue;
                }
                let va = minidump.and_then(|md| md.offset_to_va(offset));
                fragments.push(CarveFragment {
                    offset,
                    va,
                    kind,
                    size,
                    complete: matches!(verdict, Verdict::Valid),
                });
                covered_end = offset + size;
            }
            failure.is_none()
        })?;

        if let Some(error) = failure {
            return Err(error);
        }
        Ok(fragments)
    }
}

/// One recovered fragment before page-order reassembly.
#[derive(Debug, Clone)]
pub struct CarveFragment {
    /// File offset of the fragment inside the dump.
    pub offset: u64,
    /// Virtual address (if a minidump was provided), otherwise `None`.
    pub va: Option<u64>,
    /// Detected format.
    pub kind: CarveKind,
    /// Fragment size in bytes.
    pub size: u64,
    /// Whether the fragment passed full structural validation.
    pub complete: bool,
}

/// One reassembled file written to `--carve-out`.
#[derive(Debug, Clone)]
pub struct ReassembledFile {
    /// Starting virtual address (or file offset when no VA is known).
    pub va_start: u64,
    /// File offset of the first fragment.
    pub file_offset: u64,
    /// Total size after merging fragments.
    pub size: u64,
    /// Detected format.
    pub kind: CarveKind,
    /// Whether every merged fragment was structurally complete.
    pub complete: bool,
    /// Path of the written reassembled file.
    pub path: Option<PathBuf>,
}

/// Report of a reassembly pass.
#[derive(Debug, Clone, Default)]
pub struct ReassemblyReport {
    pub files: Vec<ReassembledFile>,
    pub fragments: usize,
    pub merged_groups: usize,
}

/// Merge fragments into page-ordered files and write them to `out_dir`.
///
/// Fragments are grouped by kind, sorted by VA (or file offset when no VA is
/// known), and merged when their VA ranges are adjacent (within one 4 KiB
/// page to tolerate small capture gaps). Each merged group is written as one
/// `.carved` file named `{va:08x}-{kind}-reassembled.{ext}.carved`.
pub fn reassemble_fragments(
    fragments: &[CarveFragment],
    dump_path: &str,
    out_dir: &Path,
) -> io::Result<ReassemblyReport> {
    let mut by_kind: HashMap<CarveKind, Vec<&CarveFragment>> = HashMap::new();
    for f in fragments {
        by_kind.entry(f.kind).or_default().push(f);
    }

    let mut out_files = Vec::new();
    let mut total_fragments = 0usize;

    for (kind, mut frags) in by_kind {
        frags.sort_by(|a, b| {
            let va_a = a.va.unwrap_or(a.offset);
            let va_b = b.va.unwrap_or(b.offset);
            va_a.cmp(&va_b)
        });

        total_fragments += frags.len();
        let mut groups: Vec<Vec<&CarveFragment>> = Vec::new();
        let mut current: Vec<&CarveFragment> = Vec::new();

        for f in frags {
            if current.is_empty() {
                current.push(f);
            } else {
                let last = current.last().unwrap();
                let last_end_va = last
                    .va
                    .map(|v| v.saturating_add(last.size))
                    .unwrap_or(last.offset.saturating_add(last.size));
                let this_va = f.va.unwrap_or(f.offset);
                let contiguous = this_va == last_end_va
                    || (this_va > last_end_va && this_va - last_end_va <= 4096);
                if contiguous {
                    current.push(f);
                } else {
                    groups.push(std::mem::take(&mut current));
                    current.push(f);
                }
            }
        }
        if !current.is_empty() {
            groups.push(current);
        }

        for group in groups {
            let first_offset = group[0].offset;
            let va_start = group[0].va.unwrap_or(first_offset);
            let total_size: u64 = group.iter().map(|f| f.size).sum();
            let complete = group.iter().all(|f| f.complete);

            let name = carved_file_name(va_start, kind, CarveRole::Reassembled, "");
            let path = out_dir.join(name);
            if path.exists() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("refusing to overwrite '{}'", path.display()),
                ));
            }

            let mut out = BufWriter::new(File::create(&path)?);
            let mut file = File::open(dump_path)?;
            for f in &group {
                file.seek(SeekFrom::Start(f.offset))?;
                let mut left = f.size;
                let mut buf = vec![0u8; READ_BUF];
                while left > 0 {
                    let take = left.min(buf.len() as u64) as usize;
                    file.read_exact(&mut buf[..take])?;
                    out.write_all(&buf[..take])?;
                    left -= take as u64;
                }
            }
            out.flush()?;

            out_files.push(ReassembledFile {
                va_start,
                file_offset: first_offset,
                size: total_size,
                kind,
                complete,
                path: Some(path),
            });
        }
    }

    let merged_groups = out_files.len();
    Ok(ReassemblyReport {
        files: out_files,
        fragments: total_fragments,
        merged_groups,
    })
}

// --- signature matcher -------------------------------------------------------

struct Matcher {
    aho: AhoCorasick,
    kinds: Vec<CarveKind>,
}

/// Carve-only signatures. `BM` is deliberately absent from
/// [`crate::magic::SIGNATURES`]: two bytes are far too common to report as a
/// magic hit, but the BMP validator's extra header checks make it usable here.
const EXTRA_SIGNATURES: &[Signature] = &[
    Signature {
        bytes: b"BM",
        kind: "BMP image",
        carve: Some("bmp"),
    },
    Signature {
        bytes: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        kind: "OLE compound file",
        carve: Some("ole"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x20ftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"GIF87a",
        kind: "GIF image",
        carve: Some("gif"),
    },
    Signature {
        bytes: b"GIF89a",
        kind: "GIF image",
        carve: Some("gif"),
    },
    Signature {
        bytes: b"\x00\x00\x01\x00",
        kind: "ICO image",
        carve: Some("ico"),
    },
    // `ustar` only qualifies inside a 512-byte header at offset 257; the
    // validator enforces that, so a stray occurrence alone never carves.
    Signature {
        bytes: b"ustar",
        kind: "TAR archive",
        carve: Some("tar"),
    },
    Signature {
        bytes: b"\xd4\xc3\xb2\xa1",
        kind: "PCAP capture",
        carve: Some("pcap"),
    },
    Signature {
        bytes: b"\xa1\xb2\xc3\xd4",
        kind: "PCAP capture",
        carve: Some("pcap"),
    },
    Signature {
        bytes: b"\x0a\x0d\x0d\x0a",
        kind: "PCAPNG capture",
        carve: Some("pcapng"),
    },
    Signature {
        bytes: b"L\x00\x00\x00\x01\x14\x02\x00",
        kind: "Windows shortcut (LNK)",
        carve: Some("lnk"),
    },
    Signature {
        bytes: b"\x00asm",
        kind: "WebAssembly module",
        carve: Some("wasm"),
    },
    Signature {
        bytes: b"dex\n",
        kind: "Android DEX file",
        carve: Some("dex"),
    },
    Signature {
        bytes: b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5",
        kind: "KeePass KDBX database",
        carve: Some("kdbx"),
    },
    Signature {
        bytes: b"-----BEGIN ",
        kind: "PEM block",
        carve: Some("pem"),
    },
    Signature {
        bytes: b"RIFF",
        kind: "RIFF media (AVI)",
        carve: Some("avi"),
    },
    Signature {
        bytes: b"RIFF",
        kind: "RIFF media (WAV)",
        carve: Some("wav"),
    },
    Signature {
        bytes: b"RIFF",
        kind: "RIFF media (WEBP)",
        carve: Some("webp"),
    },
    Signature {
        bytes: b"\x1a\x45\xdf\xa3",
        kind: "EBML media (MKV)",
        carve: Some("mkv"),
    },
    Signature {
        bytes: b"\x1a\x45\xdf\xa3",
        kind: "EBML media (WebM)",
        carve: Some("webm"),
    },
    Signature {
        bytes: b"OggS",
        kind: "Ogg media",
        carve: Some("ogg"),
    },
    Signature {
        bytes: b"OggS",
        kind: "Opus media",
        carve: Some("opus"),
    },
    Signature {
        bytes: b"fLaC",
        kind: "FLAC audio",
        carve: Some("flac"),
    },
    Signature {
        bytes: b"ID3",
        kind: "MP3 audio (ID3)",
        carve: Some("mp3"),
    },
    Signature {
        bytes: b"\xff\xfb",
        kind: "MP3 audio (frame)",
        carve: Some("mp3"),
    },
    Signature {
        bytes: b"II*\x00",
        kind: "TIFF image",
        carve: Some("tif"),
    },
    Signature {
        bytes: b"MM\x00*",
        kind: "TIFF image",
        carve: Some("tif"),
    },
    Signature {
        bytes: b"<<< Oracle VM VirtualBox Disk Image >>>\n",
        kind: "VirtualBox disk image",
        carve: Some("vdi"),
    },
    Signature {
        bytes: b"KDMV",
        kind: "VMDK sparse extent",
        carve: Some("vmdk"),
    },
    Signature {
        bytes: b"BZh",
        kind: "BZIP2 stream",
        carve: Some("bz2"),
    },
    Signature {
        bytes: b"\xfd7zXZ\x00",
        kind: "XZ stream",
        carve: Some("xz"),
    },
    Signature {
        bytes: b"\xca\xfe\xba\xbe",
        kind: "Java class file",
        carve: Some("class"),
    },
    Signature {
        bytes: b"{\\rtf1",
        kind: "RTF document",
        carve: Some("rtf"),
    },
    Signature {
        bytes: b"ElfFile\x00",
        kind: "Windows event log",
        carve: Some("evtx"),
    },
];

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

// --- salvage (footer-first) --------------------------------------------------

/// ZIP end-of-central-directory signature. Not a header signature, so it
/// never collides with the header-first matcher.
const ZIP_EOCD: &[u8] = b"PK\x05\x06";
/// PDF end-of-file marker.
const PDF_EOF: &[u8] = b"%%EOF";
/// PNG IEND chunk: zero length, tag and its fixed CRC. 12 fixed bytes do not
/// turn up by chance, so unlike a bare `FF D9` this is a usable footer.
const PNG_IEND: &[u8] = b"\x00\x00\x00\x00IEND\xaeB`\x82";
/// How far back from an IEND the PNG tail salvage reads at most.
const PNG_SALVAGE_WINDOW: u64 = 64 * 1024 * 1024;
/// Longest footer minus one: chunk overlap so a footer split across two
/// chunks is still seen once.
const FOOTER_OVERLAP: usize = 11;

/// Footers the salvage pass understands. Only formats whose footer is long or
/// can be checked structurally are listed: a bare JPEG `FF D9` or an MP4
/// `moov` would flood the pass with false positives, and JPEG bodies are
/// compressed already, so an entropy boundary says nothing about them. PNG is
/// walked back chunk by chunk (CRC-verified) instead of by entropy.
fn has_footer(kind: CarveKind) -> bool {
    matches!(kind, CarveKind::Zip | CarveKind::Pdf | CarveKind::Png)
}

struct FooterMatcher {
    aho: AhoCorasick,
    kinds: [CarveKind; 3],
}

fn footer_matcher() -> &'static FooterMatcher {
    static MATCHER: OnceLock<FooterMatcher> = OnceLock::new();
    MATCHER.get_or_init(|| FooterMatcher {
        aho: AhoCorasickBuilder::new()
            .build([ZIP_EOCD, PDF_EOF, PNG_IEND])
            .expect("footer patterns are valid"),
        kinds: [CarveKind::Zip, CarveKind::Pdf, CarveKind::Png],
    })
}

/// A surviving tail found behind a footer.
struct SalvageTail {
    start: u64,
    end: u64,
    /// Start of the 4 KiB window just before the tail whose entropy is
    /// >= 7.8 bits/byte (where the encrypted region is suspected to end).
    spike: Option<u64>,
    note: String,
}

/// Read exactly `len` bytes at `offset`, or `None` when they do not fit in
/// the dump.
fn salvage_read(file: &mut File, offset: u64, len: usize, file_len: u64) -> io::Result<Option<Vec<u8>>> {
    match offset.checked_add(len as u64) {
        Some(end) if end <= file_len => {}
        _ => return Ok(None),
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)?;
    Ok(Some(buffer))
}

fn window_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    entropy(&counts, bytes.len() as u64)
}

/// Printable ASCII or common whitespace: what a trailer, xref table or
/// central-directory name looks like, and what ciphertext rarely strings
/// together for long.
fn is_text_byte(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b'\t') || (0x20..=0x7e).contains(&byte)
}

/// Printable ASCII plus form feed: the pure-ASCII subset the text pass uses
/// to walk backwards/forwards from a block boundary to a byte-exact edge.
fn is_ascii_text_byte(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b'\t' | 0x0c) || (0x20..=0x7e).contains(&byte)
}

/// Length in bytes of the text token starting at `bytes[i]`, or `0` when the
/// byte does not start one. A token is one printable ASCII byte, one of the
/// common whitespace bytes (`\n`, `\r`, `\t`, form feed) or a valid UTF-8
/// multibyte sequence (no overlongs, no surrogates, no noncharacters U+FFFE /
/// U+FFFF, no C1 controls U+0080-U+009F). Counting token bytes instead of
/// classifying per byte keeps the block ratio meaningful for Vietnamese and
/// other UTF-8 text mixed with ASCII.
fn text_token_len(bytes: &[u8], i: usize) -> usize {
    let byte = bytes[i];
    if is_ascii_text_byte(byte) {
        return 1;
    }
    let len = match byte {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return 0,
    };
    if i + len > bytes.len() {
        return 0;
    }
    let b1 = bytes[i + 1];
    let second = match byte {
        0xe0 => 0xa0..=0xbf,
        0xed => 0x80..=0x9f,
        0xf0 => 0x90..=0xbf,
        0xf4 => 0x80..=0x8f,
        _ => 0x80..=0xbf,
    };
    if !second.contains(&b1) {
        return 0;
    }
    if !bytes[i + 2..i + len].iter().all(|b| (0x80..=0xbf).contains(b)) {
        return 0;
    }
    // C1 controls arrive as C2 80..C2 9F; U+FFFE/U+FFFF as EF BF BE/BF.
    if byte == 0xc2 && (0x80..=0x9f).contains(&b1) {
        return 0;
    }
    if byte == 0xef && b1 == 0xbf && matches!(bytes[i + 2], 0xbe | 0xbf) {
        return 0;
    }
    len
}

/// Share of `block` that decodes as text tokens, `0.0..=1.0`. A block
/// dominated by one byte is never text, however printable that byte looks:
/// a run of `?` passes the ASCII test but is junk, not evidence.
fn text_block_ratio(block: &[u8]) -> f64 {
    let mut i = 0usize;
    let mut matched = 0u64;
    let mut counts = [0u64; 256];
    while i < block.len() {
        let len = text_token_len(block, i);
        for &byte in &block[i..i + len.max(1)] {
            counts[byte as usize] += 1;
        }
        if len > 0 {
            matched += len as u64;
            i += len;
        } else {
            i += 1;
        }
    }
    if block.is_empty() {
        return 0.0;
    }
    let max_freq = counts.iter().max().copied().unwrap_or(0);
    if max_freq as f64 / block.len() as f64 > 0.90 {
        return 0.0;
    }
    matched as f64 / block.len() as f64
}

/// Cheap content sniff for the note attached to a text region. Coarse on
/// purpose: the point is to help an analyst pick a viewer, not to classify.
fn text_sniff(prefix: &[u8]) -> &'static str {
    let start = prefix
        .iter()
        .position(|&byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(prefix.len());
    let trimmed = &prefix[start..];
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        return "json";
    }
    if trimmed.starts_with(b"<?xml") {
        return "xml";
    }
    if trimmed.starts_with(b"<!DOCTYPE") || trimmed.starts_with(b"<html") {
        return "html";
    }
    // CSV: the first non-empty line and the second share a comma count.
    let text = String::from_utf8_lossy(&prefix[..prefix.len().min(4096)]);
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    if let (Some(first), Some(second)) = (lines.next(), lines.next()) {
        let commas = |line: &str| line.matches(',').count();
        if commas(first) >= 2 && commas(first) == commas(second) {
            return "csv";
        }
    }
    "text"
}

/// Carve away every byte of `region` covered by an already carved file.
/// Returns the uncovered pieces, in offset order. A text region may end up
/// split in two by a binary island (a ZIP smaller than one block, bridged by
/// the block merger); each surviving piece stands alone.
fn subtract_covered(region: (u64, u64), covered: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut pieces = vec![region];
    for &(a, b) in covered {
        let mut next = Vec::with_capacity(pieces.len() + 1);
        for (s, e) in pieces {
            if b <= s || a >= e {
                next.push((s, e));
                continue;
            }
            if s < a {
                next.push((s, a));
            }
            if b < e {
                next.push((b, e));
            }
        }
        pieces = next;
    }
    pieces
}

/// Absolute offsets of the text runs in `file`: blocks of at least
/// [`TEXT_BLOCK_RATIO`] text tokens, merged with a one-block bridge over
/// non-text glitches, refined backwards/forwards to byte-exact edges, cut to
/// the first and last newline (the boundary lines are usually fragments) and
/// filtered to [`TEXT_MIN_REGION`]. Already-covered ranges are subtracted.
fn text_regions(
    file: &mut File,
    file_len: u64,
    covered: &[(u64, u64)],
) -> io::Result<Vec<(u64, u64)>> {
    // Pass 1: score every block without holding the file in memory.
    let mut blocks: Vec<(u64, bool)> = Vec::new();
    file.seek(SeekFrom::Start(0))?;
    let mut buffer = vec![0u8; 1 << 20];
    let mut abs = 0u64;
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
        for block in buffer[..filled].chunks(TEXT_BLOCK) {
            blocks.push((abs, text_block_ratio(block) >= TEXT_BLOCK_RATIO));
            abs += block.len() as u64;
        }
    }

    // Pass 2: merge consecutive text blocks with a one-block bridge.
    let block_len = |index: usize| -> u64 {
        if index + 1 < blocks.len() {
            blocks[index + 1].0 - blocks[index].0
        } else {
            file_len - blocks[index].0
        }
    };
    let mut merged: Vec<(u64, u64)> = Vec::new();
    let mut i = 0usize;
    while i < blocks.len() {
        if !blocks[i].1 {
            i += 1;
            continue;
        }
        let start = blocks[i].0;
        let mut end = blocks[i].0 + block_len(i);
        let mut gap = 0u64;
        let mut j = i + 1;
        while j < blocks.len() {
            if blocks[j].1 {
                gap = 0;
                end = blocks[j].0 + block_len(j);
            } else {
                gap += 1;
                if gap > TEXT_BRIDGE_BLOCKS {
                    break;
                }
            }
            j += 1;
        }
        merged.push((start, end));
        i = j;
    }

    // Pass 3: subtract covered ranges, refine edges, cut to newlines.
    let mut out = Vec::new();
    for region in merged {
        for piece in subtract_covered(region, covered) {
            out.extend(refine_text_piece(file, piece, file_len, covered)?);
        }
    }
    Ok(out)
}

/// Byte-level refine of one grid piece: walk to the true edges over ASCII
/// text, drop the fragments of the first and last line (the cut usually
/// lands mid-line) and apply [`TEXT_MIN_REGION`]. Covered ranges are
/// subtracted again after the walk, since it may creep into an already
/// carved file by a few printable bytes.
fn refine_text_piece(
    file: &mut File,
    (start, end): (u64, u64),
    file_len: u64,
    covered: &[(u64, u64)],
) -> io::Result<Vec<(u64, u64)>> {
    const WALK: u64 = TEXT_BLOCK as u64;

    // Walk backwards over ASCII text (catches a run the grid clipped).
    let back = start.min(WALK);
    let mut new_start = start;
    if back > 0 {
        let mut buf = vec![0u8; back as usize];
        file.seek(SeekFrom::Start(start - back))?;
        file.read_exact(&mut buf)?;
        for index in (0..buf.len()).rev() {
            if is_ascii_text_byte(buf[index]) {
                new_start = start - back + index as u64;
            } else {
                break;
            }
        }
    }

    // Walk forwards over ASCII text.
    let front = (file_len - end).min(WALK);
    let mut new_end = end;
    if front > 0 {
        let mut buf = vec![0u8; front as usize];
        file.seek(SeekFrom::Start(end))?;
        file.read_exact(&mut buf)?;
        for (index, &byte) in buf.iter().enumerate() {
            if is_ascii_text_byte(byte) {
                new_end = end + index as u64 + 1;
            } else {
                break;
            }
        }
    }

    // Cut the fragments of the boundary lines in one pass.
    let mut first_nl: Option<u64> = None;
    let mut last_nl: Option<u64> = None;
    let mut base = new_start;
    stream_region(file, new_start, new_end - new_start, |chunk| {
        for (index, &byte) in chunk.iter().enumerate() {
            if byte == b'\n' {
                let abs_nl = base + index as u64;
                if first_nl.is_none() {
                    first_nl = Some(abs_nl);
                }
                last_nl = Some(abs_nl);
            }
        }
        base += chunk.len() as u64;
        Ok(())
    })?;
    if let Some(nl) = first_nl {
        new_start = nl + 1;
    }
    if let Some(nl) = last_nl {
        new_end = nl + 1;
    }
    if new_end <= new_start {
        return Ok(Vec::new());
    }

    // The walk may have crept into a carved file: subtract again.
    Ok(subtract_covered((new_start, new_end), covered)
        .into_iter()
        .filter(|(s, e)| e - s >= TEXT_MIN_REGION)
        .collect())
}

/// Walk backwards from `end` in [`SPIKE_WINDOW`] steps while the data stays
/// below [`SPIKE_HIGH`]. At the first high-entropy window, trim back only over
/// the text bytes at its tail so the boundary is not 4 KiB-coarse. Returns
/// the tail start and the start of the window that stopped the walk.
fn salvage_boundary(
    file: &mut File,
    end: u64,
    lower: u64,
    file_len: u64,
) -> io::Result<(u64, Option<u64>)> {
    let mut cursor = end;
    while cursor > lower {
        if cursor - lower < SPIKE_WINDOW as u64 {
            // Too short for a trustworthy entropy estimate: keep it all.
            return Ok((lower, None));
        }
        let window_start = cursor - SPIKE_WINDOW as u64;
        let Some(bytes) = salvage_read(file, window_start, SPIKE_WINDOW, file_len)? else {
            return Ok((cursor, None));
        };
        if window_entropy(&bytes) >= SPIKE_HIGH {
            let text = bytes
                .iter()
                .rev()
                .take_while(|&&byte| is_text_byte(byte))
                .count() as u64;
            return Ok((cursor - text, Some(window_start)));
        }
        cursor = window_start;
    }
    Ok((lower, None))
}

/// Entropy hint for the window right before `start`, bounded by `lower`.
fn salvage_spike_before(
    file: &mut File,
    start: u64,
    lower: u64,
    file_len: u64,
) -> io::Result<Option<u64>> {
    if start.saturating_sub(lower) < SPIKE_WINDOW as u64 {
        return Ok(None);
    }
    let window_start = start - SPIKE_WINDOW as u64;
    Ok(salvage_read(file, window_start, SPIKE_WINDOW, file_len)?
        .filter(|bytes| window_entropy(bytes) >= SPIKE_HIGH)
        .map(|_| window_start))
}

/// Decide whether the footer at `position` is a real, uncovered tail and, if
/// so, where the tail starts.
fn salvage_tail(
    kind: CarveKind,
    file: &mut File,
    position: u64,
    file_len: u64,
    max_size: u64,
    covered: &[(u64, u64)],
) -> io::Result<Option<SalvageTail>> {
    // A footer inside a file the header pass already carved is not a tail.
    if covered
        .iter()
        .any(|&(start, end)| start <= position && position < end)
    {
        return Ok(None);
    }
    let prior_end = covered
        .iter()
        .filter(|&&(start, _)| start < position)
        .map(|&(_, end)| end)
        .max()
        .unwrap_or(0);
    match kind {
        CarveKind::Zip => salvage_zip_tail(file, position, file_len, max_size, prior_end),
        CarveKind::Pdf => salvage_pdf_tail(file, position, file_len, max_size, prior_end),
        CarveKind::Png => salvage_png_tail(file, position, file_len, max_size, prior_end),
        _ => Ok(None),
    }
}

/// ZIP: the end record gives the exact central-directory size, so the tail is
/// `[eocd - cd_size, eocd + 22 + comment)` and must start with `PK\x01\x02`.
fn salvage_zip_tail(
    file: &mut File,
    position: u64,
    file_len: u64,
    max_size: u64,
    prior_end: u64,
) -> io::Result<Option<SalvageTail>> {
    let Some(eocd) = salvage_read(file, position, 22, file_len)? else {
        return Ok(None);
    };
    let entries = u16::from_le_bytes([eocd[10], eocd[11]]);
    let cd_size = u64::from(u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]));
    let comment = u64::from(u16::from_le_bytes([eocd[20], eocd[21]]));
    let end = position + 22 + comment;
    // 46 bytes is the smallest central-directory record.
    if entries == 0 || cd_size < 46 || cd_size > position || end > file_len {
        return Ok(None);
    }
    let start = position - cd_size;
    if start < prior_end || end - start > max_size {
        return Ok(None);
    }
    match salvage_read(file, start, 4, file_len)? {
        Some(head) if &head[..] == b"PK\x01\x02" => {}
        _ => return Ok(None),
    }
    let spike = salvage_spike_before(file, start, prior_end, file_len)?;
    Ok(Some(SalvageTail {
        start,
        end,
        spike,
        note: format!(
            "salvage:tail: ZIP central directory ({entries} entries) + end record at {position:#x}; local headers and data are missing"
        ),
    }))
}

/// PDF: require `startxref <digits>` right before `%%EOF`, then walk back by
/// entropy. Window-granular, refined over trailing text bytes.
fn salvage_pdf_tail(
    file: &mut File,
    position: u64,
    file_len: u64,
    max_size: u64,
    prior_end: u64,
) -> io::Result<Option<SalvageTail>> {
    let lookback = position.min(64) as usize;
    let Some(before) = salvage_read(file, position - lookback as u64, lookback, file_len)? else {
        return Ok(None);
    };
    let Some(at) = before.windows(9).rposition(|chunk| chunk == b"startxref") else {
        return Ok(None);
    };
    let rest = &before[at + 9..];
    let digits_only = rest
        .iter()
        .all(|byte| byte.is_ascii_digit() || byte.is_ascii_whitespace());
    if !digits_only || !rest.iter().any(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let mut end = position + PDF_EOF.len() as u64;
    let extra = (file_len - end).min(2) as usize;
    if extra > 0 {
        if let Some(bytes) = salvage_read(file, end, extra, file_len)? {
            for &byte in &bytes {
                if byte == b'\r' || byte == b'\n' {
                    end += 1;
                } else {
                    break;
                }
            }
        }
    }
    let lower = prior_end.max(end.saturating_sub(max_size));
    let (start, spike) = salvage_boundary(file, end, lower, file_len)?;
    Ok(Some(SalvageTail {
        start,
        end,
        spike,
        note: format!(
            "salvage:tail: PDF trailer ending at {position:#x} (startxref + EOF); header and body are missing"
        ),
    }))
}

/// PNG: the head (signature + IHDR + first IDATs) is gone but the IEND chunk
/// survived. Walk back from it over IDAT chunks whose length and CRC check out
/// and keep that run. The result has no signature/IHDR, so it is evidence of
/// the compressed pixel data rather than a viewable image.
fn salvage_png_tail(
    file: &mut File,
    position: u64,
    file_len: u64,
    max_size: u64,
    prior_end: u64,
) -> io::Result<Option<SalvageTail>> {
    let end = position + PNG_IEND.len() as u64;
    if end > file_len {
        return Ok(None);
    }
    let lower = prior_end
        .max(end.saturating_sub(max_size))
        .max(end.saturating_sub(PNG_SALVAGE_WINDOW));
    if position <= lower {
        return Ok(None);
    }
    let Some(buffer) = salvage_read(file, lower, (position - lower) as usize, file_len)? else {
        return Ok(None);
    };
    let mut boundary = buffer.len();
    let mut chunks = 0usize;
    while let Some(start) = png_previous_idat(&buffer, boundary) {
        boundary = start;
        chunks += 1;
    }
    if chunks == 0 {
        return Ok(None);
    }
    let start = lower + boundary as u64;
    let spike = salvage_spike_before(file, start, prior_end, file_len)?;
    Ok(Some(SalvageTail {
        start,
        end,
        spike,
        note: format!(
            "salvage:tail: PNG IDAT run ({chunks} chunk(s)) + IEND at {position:#x}; signature and IHDR are missing"
        ),
    }))
}

/// The IDAT chunk that ends exactly at `boundary` in `buffer`, as the index
/// of its length field, when its length and CRC verify.
fn png_previous_idat(buffer: &[u8], boundary: usize) -> Option<usize> {
    // Smallest chunk: length(4) + tag(4) + crc(4); the tag then sits at
    // `boundary - 8`. A chunk needs 4 bytes before its tag for the length.
    let newest_tag = boundary.checked_sub(8)?;
    for tag in (4..=newest_tag).rev() {
        if &buffer[tag..tag + 4] != b"IDAT" {
            continue;
        }
        let length = u32::from_be_bytes([
            buffer[tag - 4],
            buffer[tag - 3],
            buffer[tag - 2],
            buffer[tag - 1],
        ]) as usize;
        if tag + 4 + length + 4 != boundary {
            continue;
        }
        let crc = crc32(0xffff_ffff, &buffer[tag..tag + 4 + length]) ^ 0xffff_ffff;
        let stored = u32::from_be_bytes([
            buffer[boundary - 4],
            buffer[boundary - 3],
            buffer[boundary - 2],
            buffer[boundary - 1],
        ]);
        if crc == stored {
            return Some(tag - 4);
        }
    }
    None
}

/// Adjust a raw needle match to the candidate's true start. TAR has no
/// head magic; the `ustar` needle sits at offset 257 of the file, so a match
/// there means the archive starts 257 bytes earlier.
fn candidate_offset(kind: CarveKind, needle_offset: u64) -> Option<u64> {
    match kind {
        // 257 == name(100) + mode(8) + uid(8) + gid(8) + size(12) + mtime(12) + chksum(8) + typeflag(1) + linkname(100).
        CarveKind::Tar => needle_offset.checked_sub(257),
        _ => Some(needle_offset),
    }
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
        CarveKind::Ole => carve_ole(&mut source)?,
        CarveKind::Mp4 => carve_mp4(&mut source)?,
        CarveKind::Pe => carve_pe(&mut source)?,
        CarveKind::Elf => carve_elf(&mut source)?,
        CarveKind::Gif => carve_gif(&mut source)?,
        CarveKind::Ico => carve_ico(&mut source)?,
        CarveKind::Tar => carve_tar(&mut source)?,
        CarveKind::Pcap => carve_pcap(&mut source)?,
        CarveKind::Pcapng => carve_pcapng(&mut source)?,
        CarveKind::Lnk => carve_lnk(&mut source)?,
        CarveKind::Wasm => carve_wasm(&mut source)?,
        CarveKind::Dex => carve_dex(&mut source)?,
        CarveKind::Kdbx => carve_kdbx(&mut source)?,
        CarveKind::Pem => carve_pem(&mut source)?,
        CarveKind::Avi => carve_riff(&mut source, b"AVI ")?,
        CarveKind::Wav => carve_riff(&mut source, b"WAVE")?,
        CarveKind::Webp => carve_riff(&mut source, b"WEBP")?,
        CarveKind::Mkv => carve_ebml(&mut source, b"matroska")?,
        CarveKind::Webm => carve_ebml(&mut source, b"webm")?,
        CarveKind::Ogg => carve_ogg(&mut source, false)?,
        CarveKind::Opus => carve_ogg(&mut source, true)?,
        CarveKind::Flac => carve_flac(&mut source)?,
        CarveKind::Mp3 => carve_mp3(&mut source)?,
        CarveKind::Tiff => carve_tiff(&mut source)?,
        CarveKind::Vdi => carve_vdi(&mut source)?,
        CarveKind::Vmdk => carve_vmdk(&mut source)?,
        CarveKind::Bz2 => carve_bz2(&mut source)?,
        CarveKind::Xz => carve_xz(&mut source)?,
        CarveKind::Class => carve_class(&mut source)?,
        CarveKind::Rtf => carve_rtf(&mut source)?,
        CarveKind::Evtx => carve_evtx(&mut source)?,
        CarveKind::Text => Verdict::Invalid("text has no header; it is found by the text pass".to_string()),
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

    /// Move back (or forward) to an absolute offset inside `[origin, end]`,
    /// dropping the lookahead window. Used to end a salvaged file at the last
    /// byte that validated.
    fn rewind_to(&mut self, abs: u64) {
        self.base = abs.clamp(self.origin, self.end);
        self.len = 0;
        self.at = 0;
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
        // Anti-OOM: segment length must not exceed max size or reasonable limit.
        let remaining = source.end - source.abs();
        if length > MAX_JPEG_SEGMENT || 2 + length > remaining {
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
            // Anti-OOM: limit scan data search to prevent infinite loops.
            let scan_start = source.abs();
            // Scan data is not length-prefixed, so look for the next 0xFF and
            // decide whether it starts a real marker: FF00 is byte stuffing,
            // FFD0..FFD7 are restart markers and FFFF is padding, none of
            // which ends the scan.
            loop {
                if source.abs() - scan_start > MAX_JPEG_SEGMENT {
                    return Ok(Verdict::Invalid(
                        "JPEG scan data exceeds maximum allowed size".to_string(),
                    ));
                }
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
        // Start of this chunk: where a salvaged file ends if the chunk is bad.
        let chunk_start = source.abs();
        let Some(header) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended before the PNG IEND chunk".to_string(),
            ));
        };
        let length = u64::from(u32::from_be_bytes([
            header[0], header[1], header[2], header[3],
        ]));
        let kind = [header[4], header[5], header[6], header[7]];
        if length > MAX_PNG_CHUNK {
            // After at least one good chunk (IHDR), a garbage length means the
            // rest was overwritten: keep the intact chunks instead of dropping all.
            if chunks > 0 {
                return Ok(Verdict::Truncated(format!(
                    "PNG damaged at {chunk_start:#x}: implausible chunk length {length}; kept {chunks} valid chunk(s)"
                )));
            }
            return Ok(Verdict::Invalid(format!(
                "implausible PNG chunk length {length}"
            )));
        }
        // Anti-OOM: chunk must fit in remaining data.
        let remaining = source.end - source.abs();
        if 8 + length + 4 > remaining {
            return Ok(Verdict::Truncated(
                "PNG chunk extends past available data".to_string(),
            ));
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
            // Partial encryption / overwrite: keep every chunk that verified
            // (header + earlier IDAT) and cut right before the damaged one.
            if chunks > 0 {
                source.rewind_to(chunk_start);
                return Ok(Verdict::Truncated(format!(
                    "PNG {} chunk CRC mismatch at {chunk_start:#x}; kept {chunks} valid chunk(s)",
                    chunk_name(&kind)
                )));
            }
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
                // Anti-OOM: packed size must not exceed max size or reasonable limit.
                let remaining = source.end - source.abs();
                if packed > MAX_ZIP_PACKED || 30 + name + extra + packed > remaining {
                    return Ok(Verdict::Invalid(format!(
                        "ZIP entry packed size {packed} exceeds limit or available data"
                    )));
                }
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
        // Anti-OOM: data size must not exceed max size or reasonable limit.
        let remaining = source.end - source.abs();
        if data > MAX_RAR4_DATA || head_size + data > remaining {
            return Ok(Verdict::Invalid(format!(
                "RAR4 block data size {data} exceeds limit or available data"
            )));
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
        // Anti-OOM: data size must not exceed max size or reasonable limit.
        let remaining = source.end - source.abs();
        if data_size > MAX_RAR5_DATA || data_size > remaining {
            return Ok(Verdict::Invalid(format!(
                "RAR5 block data size {data_size} exceeds limit or available data"
            )));
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
    // StartHeaderCRC covers the 20 bytes that follow it (NextHeaderOffset,
    // NextHeaderSize, NextHeaderCRC). Without it, random data that happens to
    // start with the 6-byte signature would be reported as a valid archive.
    let stored_crc = u32::from_le_bytes(header[8..12].try_into().unwrap());
    let computed_crc = crc32(0xffff_ffff, &header[12..32]) ^ 0xffff_ffff;
    if stored_crc != computed_crc {
        return Ok(Verdict::Invalid(format!(
            "7-Zip start header CRC mismatch (stored {stored_crc:08x}, computed {computed_crc:08x})"
        )));
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
    // Anti-OOM: limit search for %%EOF to prevent scanning entire dump.
    let search_end = (source.abs() + MAX_PDF_SEARCH).min(source.end);
    let original_end = source.end;
    source.end = search_end;
    match find_bytes(source, b"%%EOF")? {
        Some(offset) => {
            source.end = original_end;
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
        // Anti-OOM: extra field size must not exceed limit or available data.
        let remaining = source.end - source.abs();
        if extra > MAX_GZIP_EXTRA || 2 + extra > remaining {
            return Ok(Verdict::Invalid(format!(
                "GZIP extra field size {extra} exceeds limit or available data"
            )));
        }
        source.skip(2)?;
        if source.skip(extra)? != extra {
            return Ok(Verdict::Truncated(
                "dump ended inside the GZIP extra field".to_string(),
            ));
        }
    }
    if flags & 0x08 != 0 {
        // Anti-OOM: limit name search.
        let name_start = source.abs();
        let found = find_byte(source, 0)?;
        if found.is_none() || source.abs() - name_start > MAX_GZIP_NAME_COMMENT {
            return Ok(Verdict::Truncated(
                "unterminated GZIP file name or exceeds limit".to_string(),
            ));
        }
    }
    if flags & 0x10 != 0 {
        // Anti-OOM: limit comment search.
        let comment_start = source.abs();
        let found = find_byte(source, 0)?;
        if found.is_none() || source.abs() - comment_start > MAX_GZIP_NAME_COMMENT {
            return Ok(Verdict::Truncated(
                "unterminated GZIP comment or exceeds limit".to_string(),
            ));
        }
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
            match decoder.decompress(input, &mut scratch, flate2::FlushDecompress::None) {
                Ok(status) => status,
                // A candidate whose deflate stream is corrupt is a bad/false
                // positive, not a fatal scan error: reject it and keep going.
                Err(error) => {
                    return Ok(Verdict::Invalid(format!("corrupt deflate stream: {error}")));
                }
            }
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

/// Maximum MP4 boxes to walk before giving up (prevents hostile loops).
const MAX_MP4_BOXES: usize = 1000;

fn carve_ole(source: &mut Source<'_>) -> io::Result<Verdict> {
    // OLE Compound File Binary Format (.doc, .xls, .ppt pre-2007).
    // Signature: D0 CF 11 E0 A1 B1 1A E1.
    let Some(header) = peek_array::<30>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the OLE header".to_string(),
        ));
    };
    if &header[0..8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" {
        return Ok(Verdict::Invalid("missing OLE signature".to_string()));
    }
    // Sector size is stored as a power of two at offset 0x1C (2 bytes LE);
    // real values are 9 (512 bytes) or 12 (4096 bytes).
    let sector_pow = u16::from_le_bytes([header[28], header[29]]) as u64;
    if !(9..=12).contains(&(sector_pow as i32)) {
        return Ok(Verdict::Invalid(format!(
            "implausible OLE sector size 2^{sector_pow}"
        )));
    }
    // The full OLE file size cannot be derived reliably from the header alone,
    // so we validate the header shape and skip one sector; the carver clamps
    // to --carve-max-size / remaining dump.
    let sector_size = 1u64 << sector_pow;
    source.skip(sector_size.min(source.end.saturating_sub(source.abs())))?;
    Ok(Verdict::Valid)
}

fn carve_mp4(source: &mut Source<'_>) -> io::Result<Verdict> {
    // ISO Base Media File Format (.mp4, .mov, .m4v...): a sequence of boxes,
    // each a 4-byte size (big-endian) + 4-byte type. Walk a bounded number of
    // boxes so hostile input cannot loop forever.
    let mut boxes = 0usize;
    let mut found_payload = false;
    while boxes < MAX_MP4_BOXES {
        let Some(header) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside an MP4 box header".to_string(),
            ));
        };
        let mut size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let box_type = &header[4..8];
        if size == 1 {
            // 64-bit extended size follows the box type.
            let Some(ext) = peek_array::<8>(source)? else {
                return Ok(Verdict::Truncated(
                    "dump ended inside an MP4 extended box size".to_string(),
                ));
            };
            size = u64::from_be_bytes([
                ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
            ]);
            if size < 16 {
                return Ok(Verdict::Invalid(
                    "MP4 extended box size too small".to_string(),
                ));
            }
        } else if size == 0 {
            // Box runs to the end of the file.
            source.skip(source.end.saturating_sub(source.origin))?;
            return Ok(Verdict::Valid);
        } else if size < 8 {
            return Ok(Verdict::Invalid("MP4 box size too small".to_string()));
        }
        if size > source.end.saturating_sub(source.origin) {
            return Ok(Verdict::Truncated(
                "MP4 declares more data than the dump has".to_string(),
            ));
        }
        source.skip(size - 8)?;
        boxes += 1;
        // Stop after the first real payload box or the movie box; we don't
        // need to walk the entire file.
        if box_type == *b"mdat" || box_type == *b"moov" {
            found_payload = true;
            break;
        }
    }
    if !found_payload {
        source.skip(source.end.saturating_sub(source.abs()))?;
    }
    Ok(Verdict::Valid)
}

fn carve_pe(source: &mut Source<'_>) -> io::Result<Verdict> {
    // Windows PE / DOS executable: "MZ" followed by a PE\0\0 signature at
    // the offset stored in e_lfanew (0x3C, 4 bytes LE).
    let Some(header) = peek_array::<64>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the PE header".to_string(),
        ));
    };
    if &header[0..2] != b"MZ" {
        return Ok(Verdict::Invalid("missing PE MZ signature".to_string()));
    }
    let e_lfanew =
        u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as u64;
    if e_lfanew == 0 || e_lfanew > source.end.saturating_sub(source.origin).saturating_sub(4) {
        return Ok(Verdict::Invalid("implausible PE e_lfanew".to_string()));
    }
    source.skip(e_lfanew)?;
    let Some(sig) = peek_array::<4>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended at the PE signature".to_string(),
        ));
    };
    if sig != *b"PE\0\0" {
        return Ok(Verdict::Invalid("missing PE signature".to_string()));
    }
    // PE file size cannot be determined from the header alone; skip a
    // reasonable amount so the carver writes a non-trivial file.
    source.skip(4096u64.min(source.end.saturating_sub(source.abs())))?;
    Ok(Verdict::Valid)
}

fn carve_elf(source: &mut Source<'_>) -> io::Result<Verdict> {
    // ELF executable: "\x7fELF", class (1=32-bit, 2=64-bit), data encoding
    // (1=LE, 2=BE), version 1.
    let Some(header) = peek_array::<16>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the ELF header".to_string(),
        ));
    };
    if &header[0..4] != b"\x7fELF" {
        return Ok(Verdict::Invalid("missing ELF magic".to_string()));
    }
    match header[4] {
        1 | 2 => {}
        other => {
            return Ok(Verdict::Invalid(format!("implausible ELF class {other}")));
        }
    }
    if header[5] != 1 && header[5] != 2 {
        return Ok(Verdict::Invalid(format!(
            "implausible ELF data encoding {}",
            header[5]
        )));
    }
    if header[6] != 1 {
        return Ok(Verdict::Invalid("implausible ELF version".to_string()));
    }
    // ELF file size cannot be determined from the header alone; skip a
    // reasonable amount so the carver writes a non-trivial file.
    source.skip(4096u64.min(source.end.saturating_sub(source.abs())))?;
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

/// Find where a file turns from structured data into random-looking bytes.
///
/// Splits `[offset, offset + size)` into [`SPIKE_WINDOW`]-byte windows and
/// returns the absolute start of the first window at or above [`SPIKE_HIGH`]
/// that comes after at least one window below [`SPIKE_LOW`]. Data that is
/// random from the first byte (a stored ZIP payload, a JPEG scan) never has a
/// structured window before it, so it yields `None` instead of a false
/// boundary. A trailing partial window is ignored.
fn entropy_rise(file: &mut File, offset: u64, size: u64) -> io::Result<Option<u64>> {
    let mut counts = [0u64; 256];
    let mut filled = 0usize;
    let mut window_start = offset;
    let mut seen_structured = false;
    let mut found: Option<u64> = None;
    stream_region(file, offset, size, |chunk| {
        for &byte in chunk {
            if found.is_some() {
                return Ok(());
            }
            counts[byte as usize] += 1;
            filled += 1;
            if filled == SPIKE_WINDOW {
                let bits = entropy(&counts, SPIKE_WINDOW as u64);
                if bits < SPIKE_LOW {
                    seen_structured = true;
                } else if bits >= SPIKE_HIGH && seen_structured {
                    found = Some(window_start);
                }
                counts = [0u64; 256];
                filled = 0;
                window_start += SPIKE_WINDOW as u64;
            }
        }
        Ok(())
    })?;
    Ok(found)
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

// --- new format validators ---------------------------------------------------

const MAX_GIF_BLOCKS: u64 = 1_000_000;
const MAX_EBML_ELEMENTS: u64 = 4_000_000;


/// Element ID reader for EBML: like [`ebml_vint`] but keeps the length bits
/// as part of the value, as the EBML spec requires. IDs are at most 4 bytes.
fn ebml_element_id(source: &mut Source<'_>) -> io::Result<Option<(u64, usize)>> {
    let Some(first) = peek_u8(source)? else { return Ok(None) };
    let mut length = 1usize;
    let mut mask = 0x80u8;
    while mask != 0 && first & mask == 0 {
        length += 1;
        mask >>= 1;
    }
    if length > 4 {
        return Ok(None);
    }
    let Some(bytes) = take_bytes(source, length)? else { return Ok(None) };
    let mut value: u64 = 0;
    for &byte in &bytes {
        value = (value << 8) | u64::from(byte);
    }
    Ok(Some((value, length)))
}

fn carve_ebml(source: &mut Source<'_>, expected_doctype: &[u8]) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some([0x1a, 0x45, 0xdf, 0xa3]) {
        return Ok(Verdict::Invalid("missing EBML magic".to_string()));
    }
    let window = window_len(source);
    let mut end_stack: Vec<u64> = Vec::new();
    let mut doctype: Option<Vec<u8>> = None;
    for _ in 0..MAX_EBML_ELEMENTS {
        if source.abs() >= source.end {
            break;
        }
        let Some((id, _)) = ebml_element_id(source)? else {
            return Ok(Verdict::Truncated("EBML element id desyncs from the stream".to_string()));
        };
        let Some((size, slen)) = ebml_vint(source)? else {
            return Ok(Verdict::Truncated("EBML element size desyncs from the stream".to_string()));
        };
        let unknown_size = size == (1u64 << (7 * slen as u64)) - 1;
        let element_end = if unknown_size {
            source.end
        } else {
            match source.abs().checked_add(size) {
                Some(end) if end <= source.end => end,
                _ => return Ok(Verdict::Truncated("EBML element extends past the candidate".to_string())),
            }
        };
        if id == 0x42_82 {
            let bytes = match take_bytes(source, size as usize)? {
                Some(bytes) if (size as usize) <= 64 => bytes,
                _ => Vec::new(),
            };
            doctype = Some(bytes);
        } else {
            source.skip(element_end - source.abs())?;
        }
        end_stack.push(element_end);
        while let Some(&top) = end_stack.last() {
            if top == source.abs() {
                end_stack.pop();
            } else {
                break;
            }
        }
    }
    let _ = window;
    match doctype {
        Some(found) if found == expected_doctype => Ok(Verdict::Valid),
        Some(found) => Ok(Verdict::Invalid(format!(
            "EBML DocType '{}' does not match this kind",
            String::from_utf8_lossy(&found)
        ))),
        None => Ok(Verdict::Invalid("EBML DocType element not found".to_string())),
    }
}

fn carve_ogg(source: &mut Source<'_>, expect_opus: bool) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"OggS") {
        return Ok(Verdict::Invalid("missing OggS page header".to_string()));
    }
    let mut serials: Vec<u32> = Vec::new();
    let mut pages: u64 = 0;
    let mut first = true;
    let mut opus_head = false;
    while source.abs() < source.end {
        pages += 1;
        if pages > MAX_OGG_PAGES {
            return Ok(Verdict::Truncated("OGG page count exceeded the limit".to_string()));
        }
        // Dump padding (all zero bytes) follows the last page; treat it as
        // the end of the stream.
        if let Some(next) = peek_array::<4>(source)? {
            if next.iter().all(|&byte| byte == 0) {
                break;
            }
        }
        let Some(header) = peek_array::<27>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside an OGG page header".to_string()));
        };
        if &header[..4] != b"OggS" || header[4] != 0 {
            return Ok(Verdict::Invalid("OGG page magic/version mismatch".to_string()));
        }
        let flags = header[5];
        if flags & 0x80 != 0 {
            return Ok(Verdict::Invalid("OGG continuation flag is not supported".to_string()));
        }
        if first && flags & 0x02 == 0 {
            return Ok(Verdict::Invalid("OGG stream does not start with a BOS page".to_string()));
        }
        let serial = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
        if !serials.contains(&serial) {
            if serials.len() >= 64 {
                return Ok(Verdict::Invalid("OGG serial count exceeded the limit".to_string()));
            }
            serials.push(serial);
        }
        source.skip(27)?;
        let segment_count = usize::from(header[26]);
        let table = match take_bytes(source, segment_count)? {
            Some(table) => table,
            None => return Ok(Verdict::Truncated("dump ended inside an OGG segment table".to_string())),
        };
        let payload: u64 = table.iter().map(|&size| u64::from(size)).sum();
        if !room_left(source, payload) {
            return Ok(Verdict::Truncated("dump ended inside an OGG page payload".to_string()));
        }
        let page = take_bytes(source, payload as usize)?.unwrap_or_default();
        if first && page.windows(8).any(|w| w == b"OpusHead") {
            opus_head = true;
        }
        first = false;
    }
    if expect_opus && !opus_head {
        return Ok(Verdict::Invalid("OGG stream has no OpusHead packet on its first page".to_string()));
    }
    Ok(Verdict::Valid)
}

fn carve_flac(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"fLaC") {
        return Ok(Verdict::Invalid("missing fLaC signature".to_string()));
    }
    source.skip(4)?;
    let Some(streaminfo) = peek_array::<4>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside a FLAC STREAMINFO header".to_string()));
    };
    let streaminfo_type = streaminfo[0] & 0x7f;
    let streaminfo_last = streaminfo[0] & 0x80 != 0;
    let streaminfo_len = u32::from_be_bytes([0, streaminfo[1], streaminfo[2], streaminfo[3]]);
    if streaminfo_type != 0 || streaminfo_len != 34 {
        return Ok(Verdict::Invalid("FLAC STREAMINFO block is missing or mis-sized".to_string()));
    }
    source.skip(4 + 34)?;
    if streaminfo_last {
        return Ok(Verdict::Valid);
    }
    for _ in 0..4096u64 {
        let Some(block) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a FLAC metadata block".to_string()));
        };
        let last = block[0] & 0x80 != 0;
        let block_len = u32::from_be_bytes([0, block[1], block[2], block[3]]);
        if !room_left(source, 4 + u64::from(block_len)) {
            return Ok(Verdict::Truncated(format!(
                "dump ended inside a FLAC metadata block of {block_len} bytes"
            )));
        }
        source.skip(4 + u64::from(block_len))?;
        if last {
            return Ok(Verdict::Valid);
        }
    }
    Ok(Verdict::Truncated("FLAC metadata block count exceeded the limit".to_string()))
}

fn carve_riff(source: &mut Source<'_>, expected_form: &[u8; 4]) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"RIFF") {
        return Ok(Verdict::Invalid("missing RIFF signature".to_string()));
    }
    let Some(header) = peek_array::<12>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the RIFF header".to_string()));
    };
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if &header[8..12] != expected_form {
        return Ok(Verdict::Invalid("RIFF form type does not match this kind".to_string()));
    }
    let riff_end = source.origin + 8 + u64::from(size);
    if riff_end > source.end {
        return Ok(Verdict::Truncated(format!(
            "RIFF declares {size} bytes but the candidate window is smaller"
        )));
    }
    source.skip(12)?;
    for _ in 0..MAX_RIFF_CHUNKS {
        if source.abs() >= riff_end {
            break;
        }
        let Some(chunk) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a RIFF chunk header".to_string()));
        };
        let chunk_size = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let padded = u64::from(chunk_size) + (u64::from(chunk_size) & 1);
        source.skip(8)?;
        if source.abs().checked_add(padded).is_none_or(|end| end > riff_end) {
            return Ok(Verdict::Truncated(format!(
                "dump ended inside a RIFF chunk of {chunk_size} bytes"
            )));
        }
        source.skip(padded)?;
    }
    let marker: &[u8] = match expected_form {
        b"AVI " => b"movi",
        b"WAVE" => b"data",
        b"WEBP" => b"VP8",
        _ => b"",
    };
    let found = if marker.is_empty() {
        true
    } else {
        find_bytes(source, marker)?.is_some()
    };
    source.skip(riff_end - source.abs())?;
    if found {
        Ok(Verdict::Valid)
    } else {
        Ok(Verdict::Invalid(
            "RIFF is missing the expected data chunk for this kind".to_string(),
        ))
    }
}

const MAX_RIFF_CHUNKS: u64 = 1_000_000;

const MAX_TIFF_IFDS: u64 = 256;
const MAX_OGG_PAGES: u64 = 10_000_000;
const MAX_CLASS_POOL: u64 = 1_000_000;
const MAX_RTF_BYTES: u64 = 16 * 1024 * 1024;

/// Adler-32 (as used by zlib), used to verify DEX headers.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65_521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// Parse an octal (optionally NUL/space terminated) tar checksum/size field.
fn parse_octal(bytes: &[u8]) -> Option<u64> {
    let text: String = bytes
        .iter()
        .take_while(|&&b| b != 0 && b != b' ')
        .filter_map(|&b| char::from(b).is_ascii_digit().then_some(char::from(b)))
        .filter(|&b| ('0'..='7').contains(&b))
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(&text, 8).ok()
}

/// Read an EBML variable-length integer (the length is encoded in the leading
/// one-bits). Returns `(value, length)`.
fn ebml_vint(source: &mut Source<'_>) -> io::Result<Option<(u64, usize)>> {
    let Some(first) = peek_u8(source)? else {
        return Ok(None);
    };
    let mut length = 1usize;
    let mut mask = 0x80u8;
    while mask != 0 && first & mask == 0 {
        length += 1;
        mask >>= 1;
    }
    if length > 8 {
        return Ok(None);
    }
    let Some(bytes) = take_bytes(source, length)? else {
        return Ok(None);
    };
    let mut value: u64 = u64::from(bytes[0] & (0xff >> length));
    for &byte in &bytes[1..] {
        value = (value << 8) | u64::from(byte);
    }
    Ok(Some((value, length)))
}

/// Code-window length in bytes (`end - origin`).
fn window_len(source: &Source<'_>) -> u64 {
    source.end - source.origin
}

/// Check that `amount` more bytes fit in the candidate window.
fn room_left(source: &Source<'_>, amount: u64) -> bool {
    source.end - source.abs() >= amount
}

fn carve_gif(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<6>(source)? != Some(*b"GIF87a") && peek_array::<6>(source)? != Some(*b"GIF89a") {
        return Ok(Verdict::Invalid("missing GIF87a/GIF89a signature".to_string()));
    }
    source.skip(6)?;
    let Some(lsd) = peek_array::<7>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the GIF logical screen descriptor".to_string()));
    };
    let packed = lsd[4];
    source.skip(7)?;
    if packed & 0x80 != 0 {
        let gct = 3u64 << (u32::from(packed & 0x07));
        if !room_left(source, gct) {
            return Ok(Verdict::Truncated("dump ended inside the GIF global color table".to_string()));
        }
        source.skip(gct)?;
    }
    for _ in 0..MAX_GIF_BLOCKS {
        let Some(marker) = peek_u8(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a GIF block".to_string()));
        };
        match marker {
            0x3b => {
                source.skip(1)?;
                return Ok(Verdict::Valid);
            }
            0x21 => {
                source.skip(1)?;
                let Some(_label) = peek_u8(source)? else {
                    return Ok(Verdict::Truncated("dump ended inside a GIF extension block".to_string()));
                };
                source.skip(1)?;
                if let Some(v) = gif_subblocks(source)? {
                    return Ok(v);
                }
            }
            0x2c => {
                source.skip(1)?;
                let Some(desc) = peek_array::<9>(source)? else {
                    return Ok(Verdict::Truncated("dump ended inside a GIF image descriptor".to_string()));
                };
                let image_packed = desc[8];
                source.skip(9)?;
                if image_packed & 0x80 != 0 {
                    let lct = 3u64 << (u32::from(image_packed & 0x07));
                    if !room_left(source, lct) {
                        return Ok(Verdict::Truncated("dump ended inside a GIF local color table".to_string()));
                    }
                    source.skip(lct)?;
                }
                let Some(_) = peek_u8(source)? else {
                    return Ok(Verdict::Truncated("dump ended at the GIF LZW minimum code size".to_string()));
                };
                source.skip(1)?;
                if let Some(v) = gif_subblocks(source)? {
                    return Ok(v);
                }
            }
            _ => return Ok(Verdict::Invalid(format!("unexpected GIF block marker 0x{marker:02x}"))),
        }
    }
    Ok(Verdict::Truncated("GIF block count exceeded the limit".to_string()))
}

/// Walk GIF data sub-blocks up to the zero terminator.
fn gif_subblocks(source: &mut Source<'_>) -> io::Result<Option<Verdict>> {
    loop {
        let Some(size) = peek_u8(source)? else {
            return Ok(Some(Verdict::Truncated("dump ended inside a GIF data sub-block".to_string())));
        };
        if size == 0 {
            source.skip(1)?;
            return Ok(None);
        }
        if !room_left(source, 1 + u64::from(size)) {
            return Ok(Some(Verdict::Truncated("dump ended inside a GIF data sub-block".to_string())));
        }
        source.skip(1 + u64::from(size))?;
    }
}

fn carve_ico(source: &mut Source<'_>) -> io::Result<Verdict> {
    let window = window_len(source);
    let Some(header) = peek_array::<6>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the ICO header".to_string()));
    };
    let reserved = u16::from_le_bytes([header[0], header[1]]);
    let kind = u16::from_le_bytes([header[2], header[3]]);
    let count = u16::from_le_bytes([header[4], header[5]]);
    if reserved != 0 || !matches!(kind, 1 | 2) || count == 0 || count > 256 {
        return Ok(Verdict::Invalid("implausible ICO reserved/kind/count fields".to_string()));
    }
    source.skip(6)?;
    let mut data_end: u64 = 6 + u64::from(count) * 16;
    for _ in 0..count {
        let Some(entry) = peek_array::<16>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside an ICO directory entry".to_string()));
        };
        source.skip(16)?;
        let size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
        let offset = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
        let end = u64::from(offset) + u64::from(size);
        if size == 0 || u64::from(offset) < 6 + u64::from(count) * 16 || end > window {
            return Ok(Verdict::Invalid(
                "ICO directory entry points outside the file".to_string(),
            ));
        }
        data_end = data_end.max(end);
    }
    source.skip(data_end - source.produced())?;
    Ok(Verdict::Valid)
}

fn carve_tar(source: &mut Source<'_>) -> io::Result<Verdict> {
    const BLOCK: usize = 512;
    let first = match peek_array::<BLOCK>(source)? {
        Some(header) => header,
        None => return Ok(Verdict::Truncated("dump ended inside the TAR header block".to_string())),
    };
    if &first[257..262] != b"ustar" {
        return Ok(Verdict::Invalid("ustar marker is missing from the TAR header".to_string()));
    }
    let stored = parse_octal(&first[148..156]);
    let computed = {
        let mut sum: u64 = 0;
        for (index, &byte) in first.iter().enumerate() {
            let byte = if (148..156).contains(&index) { b' ' } else { byte };
            sum += u64::from(byte);
        }
        sum
    };
    match stored {
        Some(value) if value == computed => {}
        _ => {
            return Ok(Verdict::Invalid(
                "TAR header checksum does not match".to_string(),
            ))
        }
    }
    source.skip(BLOCK as u64)?;
    for _ in 0..1_000_000u64 {
        let Some(header) = peek_array::<BLOCK>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a TAR file".to_string()));
        };
        if header.iter().all(|&byte| byte == 0) {
            source.skip(BLOCK as u64)?;
            // A second zero block finishes the archive; keep it when present.
            if let Some(next) = peek_array::<BLOCK>(source)? {
                if next.iter().all(|&byte| byte == 0) {
                    source.skip(BLOCK as u64)?;
                }
            }
            return Ok(Verdict::Valid);
        }
        if &header[257..262] != b"ustar" {
            return Ok(Verdict::Invalid("TAR file boundary does not line up with a header block".to_string()));
        }
        let size_field = &header[124..136];
        let size: u64 = if size_field[0] & 0x80 != 0 {
            // GNU base-256 encoding for >8 GiB entries; read big endian.
            let mut value: u64 = u64::from(size_field[0] & 0x7f);
            for &byte in &size_field[1..] {
                value = (value << 8) | u64::from(byte);
            }
            value
        } else {
            match parse_octal(size_field) {
                Some(value) => value,
                None => {
                    return Ok(Verdict::Invalid(
                        "TAR entry size field is not octal".to_string(),
                    ))
                }
            }
        };
        let padded = (size + 511) & !511;
        if !room_left(source, BLOCK as u64 + padded) {
            return Ok(Verdict::Truncated(format!(
                "dump ended inside a TAR entry of {size} bytes"
            )));
        }
        source.skip(BLOCK as u64 + padded)?;
        if u64::from(header[156]) == u64::from(b'L') {
            // Long-name entry: the real name lives in the data blocks, the
            // next header is the real file entry; handled by this loop.
        }
    }
    Ok(Verdict::Truncated("TAR entry count exceeded the limit".to_string()))
}

fn carve_pcap(source: &mut Source<'_>) -> io::Result<Verdict> {
    if !room_left(source, 24) {
        return Ok(Verdict::Truncated("dump ended inside the PCAP global header".to_string()));
    }
    let magic = peek_array::<4>(source)?.unwrap();
    let little_endian = match &magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        _ => return Ok(Verdict::Invalid("missing PCAP magic number".to_string())),
    };
    let read16 = |bytes: &[u8]| -> u16 {
        if little_endian {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            u16::from_be_bytes([bytes[0], bytes[1]])
        }
    };
    let read32 = |bytes: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    };
    let header = peek_array::<24>(source)?.unwrap();
    let version_major = read16(&header[4..6]);
    let version_minor = read16(&header[6..8]);
    if version_major != 2 || version_minor > 99 {
        return Ok(Verdict::Invalid(format!(
            "implausible PCAP version {version_major}.{version_minor}"
        )));
    }
    let snaplen = read32(&header[16..20]);
    if !(64..=64 * 1024 * 1024).contains(&snaplen) {
        return Ok(Verdict::Invalid(format!("implausible PCAP snaplen {snaplen}")));
    }
    source.skip(24)?;
    for _ in 0..1_000_000u64 {
        if source.abs() >= source.end {
            break;
        }
        let Some(record) = peek_array::<16>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a PCAP packet record".to_string()));
        };
        let incl_len = read32(&record[8..12]);
        let orig_len = read32(&record[12..16]);
        if incl_len > snaplen || orig_len > snaplen.max(0x7fff_ffff) {
            return Ok(Verdict::Invalid(
                "PCAP packet record exceeds the snaplen".to_string(),
            ));
        }
        if !room_left(source, 16 + u64::from(incl_len)) {
            return Ok(Verdict::Truncated("dump ended inside a PCAP packet".to_string()));
        }
        source.skip(16 + u64::from(incl_len))?;
    }
    Ok(Verdict::Valid)
}

fn carve_pcapng(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some([0x0a, 0x0d, 0x0d, 0x0a]) {
        return Ok(Verdict::Invalid("missing PCAPNG section magic".to_string()));
    }
    let bom = match peek_array::<12>(source)? {
        Some(bom) => bom,
        None => {
            return Ok(Verdict::Truncated(
                "dump ended inside the PCAPNG section header".to_string(),
            ))
        }
    };
    let little_endian = match &bom[8..12] {
        [0x4d, 0x3c, 0x2b, 0x1a] => true,
        [0x1a, 0x2b, 0x3c, 0x4d] => false,
        _ => return Ok(Verdict::Invalid("PCAPNG byte-order magic is wrong".to_string())),
    };
    let read32 = |bytes: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    };
    let section_len = read32(&bom[4..8]);
    if section_len < 28 || u64::from(section_len) > window_len(source) {
        return Ok(Verdict::Invalid("PCAPNG section length is implausible".to_string()));
    }
    source.skip(u64::from(section_len))?;
    for _ in 0..1_000_000u64 {
        if source.abs() >= source.end {
            break;
        }
        let block = match peek_array::<8>(source)? {
            Some(block) => block,
            None => {
                return Ok(Verdict::Truncated(
                    "dump ended inside a PCAPNG block header".to_string(),
                ))
            }
        };
        // Dump padding (all zero bytes) marks the end of the capture, like
        // TAR's zero blocks.
        if block.iter().all(|&byte| byte == 0) {
            return Ok(Verdict::Valid);
        }
        let block_len = read32(&block[4..8]);
        if block_len < 12 || u64::from(block_len) > source.end - source.abs() {
            return Ok(Verdict::Truncated("PCAPNG block length is implausible".to_string()));
        }
        source.skip(u64::from(block_len) - 4)?;
        let trailing = match peek_array::<4>(source)? {
            Some(trailing) => trailing,
            None => {
                return Ok(Verdict::Truncated(
                    "dump ended inside a PCAPNG block trailer".to_string(),
                ))
            }
        };
        if read32(&trailing) != block_len {
            return Ok(Verdict::Invalid(
                "PCAPNG block trailer does not repeat its length".to_string(),
            ));
        }
        source.skip(4)?;
    }
    Ok(Verdict::Valid)
}

fn carve_wasm(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"\0asm") {
        return Ok(Verdict::Invalid("missing WebAssembly magic".to_string()));
    }
    source.skip(4)?;
    let Some(version) = peek_array::<4>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the WebAssembly version field".to_string(),
        ));
    };
    if version != 1u32.to_le_bytes() && version != 2u32.to_le_bytes() {
        return Ok(Verdict::Invalid("unsupported WebAssembly binary version".to_string()));
    }
    source.skip(4)?;
    for _ in 0..4096u64 {
        if source.abs() >= source.end {
            break;
        }
        let Some(id) = peek_u8(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a WebAssembly section".to_string(),
            ));
        };
        if id > 12 {
            return Ok(Verdict::Invalid(format!(
                "WebAssembly section id {id} is not defined"
            )));
        }
        source.skip(1)?;
        let Some(size) = read_vint(source)? else {
            return Ok(Verdict::Truncated(
                "WebAssembly section size desyncs".to_string(),
            ));
        };
        if !room_left(source, size) {
            return Ok(Verdict::Truncated(
                "dump ended inside a WebAssembly section".to_string(),
            ));
        }
        source.skip(size)?;
    }
    Ok(Verdict::Valid)
}

fn carve_lnk(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<0x4c>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the LNK header".to_string()));
    };
    let clsid = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x46,
    ];
    if &header[..4] != b"L\0\0\0"
        || header[4..20] != clsid
    {
        return Ok(Verdict::Invalid("implausible LNK header (magic/CLSID)".to_string()));
    }
    let flags = u32::from_le_bytes([header[0x14], header[0x15], header[0x16], header[0x17]]);
    let is_unicode = flags & 0x0000_0080 != 0;
    source.skip(0x4c)?;
    if flags & 0x0000_0001 != 0 {
        let Some(size) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated("LNK LinkTargetIDListSize is missing".to_string()));
        };
        let idlist = u16::from_le_bytes(size);
        source.skip(2)?;
        if !room_left(source, u64::from(idlist)) {
            return Ok(Verdict::Truncated(
                "dump ended inside the LNK LinkTargetIDList".to_string(),
            ));
        }
        source.skip(u64::from(idlist))?;
    }
    if flags & 0x0000_0002 != 0 {
        let Some(size) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated("LNK LinkInfoSize is missing".to_string()));
        };
        let link_info = u32::from_le_bytes(size);
        if !room_left(source, u64::from(link_info)) {
            return Ok(Verdict::Truncated(
                "dump ended inside the LNK LinkInfo block".to_string(),
            ));
        }
        source.skip(u64::from(link_info))?;
    }
    let string_flags = [
        0x0000_0004_u32,
        0x0000_0008,
        0x0000_0010,
        0x0000_0020,
        0x0000_0040,
        0x0000_0200,
        0x0000_0800,
        0x0000_1000,
        0x0000_4000,
        0x0100_0000,
    ];
    for &bit in &string_flags {
        if flags & bit == 0 {
            continue;
        }
        let count_bytes = if is_unicode { 2 } else { 1 };
        let prefix = match peek_array::<2>(source)? {
            Some(prefix) => prefix,
            None => {
                return Ok(Verdict::Truncated(
                    "dump ended inside an LNK StringData header".to_string(),
                ))
            }
        };
        let count = if is_unicode {
            usize::from(u16::from_le_bytes(prefix))
        } else {
            usize::from(prefix[0])
        };
        let take_len = count * if is_unicode { 2 } else { 1 };
        source.skip(count_bytes as u64)?;
        if !room_left(source, take_len as u64) {
            return Ok(Verdict::Truncated(
                "dump ended inside an LNK StringData section".to_string(),
            ));
        }
        source.skip(take_len as u64)?;
    }
    let handled = 0x0000_0001
        | 0x0000_0002
        | 0x0000_0004
        | 0x0000_0008
        | 0x0000_0010
        | 0x0000_0020
        | 0x0000_0040
        | 0x0000_0080
        | 0x0000_0200
        | 0x0000_0800
        | 0x0000_1000
        | 0x0000_4000
        | 0x0100_0000;
    let unknown = flags & !handled;
    if unknown != 0 {
        return Ok(Verdict::Truncated(format!(
            "LNK has string flags 0x{unknown:08x} this validator does not parse"
        )));
    }
    Ok(Verdict::Valid)
}

fn carve_pem(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<11>(source)? != Some(*b"-----BEGIN ") {
        return Ok(Verdict::Invalid("missing PEM BEGIN line".to_string()));
    }
    source.skip(11)?;
    let mut label: Vec<u8> = Vec::new();
    loop {
        let Some(byte) = peek_u8(source)? else {
            return Ok(Verdict::Truncated("dump ended inside the PEM label".to_string()));
        };
        if byte == b'-' {
            break;
        }
        if !(byte.is_ascii_alphanumeric() || byte == b' ') || label.len() >= 64 {
            return Ok(Verdict::Invalid(
                "PEM label contains unexpected bytes".to_string(),
            ));
        }
        label.push(byte);
        source.skip(1)?;
    }
    if label.is_empty() {
        return Ok(Verdict::Invalid("PEM label is empty".to_string()));
    }
    if peek_array::<5>(source)? != Some(*b"-----") {
        return Ok(Verdict::Invalid(
            "PEM BEGIN line does not end with -----".to_string(),
        ));
    }
    source.skip(5)?;
    if peek_u8(source)? == Some(b'\r') {
        source.skip(1)?;
    }
    if peek_u8(source)? == Some(b'\n') {
        source.skip(1)?;
    }
    let end_marker = [b"-----END ".as_slice(), label.as_slice(), b"-----"].concat();
    for _ in 0..20_000u64 {
        let line_start = source.abs();
        let line_end = match find_byte(source, b'\n')? {
            Some(end) => end,
            None => {
                return Ok(Verdict::Truncated(
                    "dump ended inside the PEM payload".to_string(),
                ))
            }
        };
        if line_start == line_end {
            continue;
        }
        let len = line_end - line_start;
        let Some(line) = take_bytes(source, len as usize)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside the PEM payload".to_string(),
            ));
        };
        if line.starts_with(b"-----END ") {
            if line != end_marker {
                return Ok(Verdict::Invalid(
                    "PEM END label does not match the BEGIN label".to_string(),
                ));
            }
            return Ok(Verdict::Valid);
        }
        let trimmed: Vec<u8> = line.iter().copied().filter(|&b| b != b'\r').collect();
        if trimmed.is_empty()
            || !trimmed
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        {
            return Ok(Verdict::Invalid(
                "PEM payload line is not base64".to_string(),
            ));
        }
    }
    Ok(Verdict::Truncated(
        "PEM block line count exceeded the limit".to_string(),
    ))
}

fn carve_kdbx(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(magic) = peek_array::<12>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the KDBX signature".to_string()));
    };
    if magic[..4] != [0x03, 0xd9, 0xa2, 0x9a]
        || !matches!(&magic[4..8], [0x67, 0xfb, 0x4b, 0xb5] | [0x66, 0xfb, 0x4b, 0xb5] | [0x65, 0xfb, 0x4b, 0xb5])
    {
        return Ok(Verdict::Invalid("implausible KDBX signature".to_string()));
    }
    let version = u32::from_le_bytes([magic[8], magic[9], magic[10], magic[11]]);
    let major = version >> 16;
    if !(3..=4).contains(&major) {
        return Ok(Verdict::Invalid(format!(
            "unsupported KDBX major version {major}"
        )));
    }
    source.skip(12)?;
    for _ in 0..512u64 {
        let Some(id) = peek_u8(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a KDBX header field".to_string()));
        };
        source.skip(1)?;
        if id == 0 {
            break;
        }
        let Some(size_bytes) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a KDBX header field size".to_string(),
            ));
        };
        let size = u32::from_le_bytes(size_bytes);
        if !room_left(source, 4 + u64::from(size)) {
            return Ok(Verdict::Truncated(
                "dump ended inside a KDBX header field".to_string(),
            ));
        }
        source.skip(4 + u64::from(size))?;
    }
    if !room_left(source, 64) {
        return Ok(Verdict::Truncated(
            "dump ended inside the KDBX header hashes".to_string(),
        ));
    }
    source.skip(64)?;
    for _ in 0..1_000_000u64 {
        let Some(block) = peek_array::<12>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a KDBX block header".to_string()));
        };
        let id = u64::from_le_bytes(block[..8].try_into().unwrap());
        let size = i32::from_le_bytes(block[8..12].try_into().unwrap());
        source.skip(12)?;
        if size < 0 {
            return Ok(Verdict::Invalid("KDBX block size is negative".to_string()));
        }
        if !room_left(source, 32 + u64::from(size as u32)) {
            return Ok(Verdict::Truncated(
                "dump ended inside a KDBX block payload".to_string(),
            ));
        }
        source.skip(32 + u64::from(size as u32))?;
        if id == 0 && size == 0 {
            return Ok(Verdict::Valid);
        }
    }
    Ok(Verdict::Truncated(
        "KDBX block count exceeded the limit".to_string(),
    ))
}

fn carve_dex(source: &mut Source<'_>) -> io::Result<Verdict> {
    let window = window_len(source);
    let Some(header) = peek_array::<0x70>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the DEX header".to_string()));
    };
    if &header[..4] != b"dex\n"
        || !matches!(
            &header[4..8],
            b"035\x00" | b"036\x00" | b"037\x00" | b"038\x00" | b"039\x00" | b"040\x00"
        )
    {
        return Ok(Verdict::Invalid("implausible DEX magic/version".to_string()));
    }
    let read_u32 = |bytes: &[u8]| -> u32 {
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    };
    let header_size = read_u32(&header[36..40]);
    let endian_tag = read_u32(&header[40..44]);
    let file_size = u64::from(read_u32(&header[32..36]));
    let map_off = u64::from(read_u32(&header[52..56]));
    let string_ids_size = u64::from(read_u32(&header[56..60]));
    let string_ids_off = u64::from(read_u32(&header[60..64]));
    let type_ids_size = u64::from(read_u32(&header[64..68]));
    let type_ids_off = u64::from(read_u32(&header[68..72]));
    if header_size != 0x70 || endian_tag != 0x1234_5678 {
        return Ok(Verdict::Invalid("DEX header size/endian tag mismatch".to_string()));
    }
    if file_size < 0x70 || file_size > window {
        return Ok(Verdict::Truncated(format!(
            "DEX declares {file_size} bytes but the candidate window is smaller"
        )));
    }
    if map_off >= file_size || string_ids_off >= file_size || type_ids_off >= file_size
        || string_ids_size * 4 > file_size
        || type_ids_size * 4 > file_size
    {
        return Ok(Verdict::Invalid("DEX offsets point outside the file".to_string()));
    }
    // Verify integrity: Adler-32 of everything past the checksum field.
    let checksum = read_u32(&header[8..12]);
    source.skip(12)?;
    let checksum_read = {
        let amount = (file_size - 12) as usize;
        let mut buffer = vec![0u8; amount];
        source.file.seek(std::io::SeekFrom::Start(source.origin + 12))?;
        std::io::Read::read_exact(&mut source.file, &mut buffer)?;
        adler32(&buffer)
    };
    if checksum_read != checksum {
        return Ok(Verdict::Invalid(
            "DEX Adler-32 checksum does not match".to_string(),
        ));
    }
    source.skip(file_size - source.produced())?;
    Ok(Verdict::Valid)
}

fn carve_tiff(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(magic) = peek_array::<4>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the TIFF magic".to_string()));
    };
    let little_endian = match &magic {
        [b'I', b'I', 0x2a, 0x00] => true,
        [b'M', b'M', 0x00, 0x2a] => false,
        _ => return Ok(Verdict::Invalid("missing TIFF magic".to_string())),
    };
    let read16 = |bytes: &[u8]| -> u16 {
        if little_endian {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            u16::from_be_bytes([bytes[0], bytes[1]])
        }
    };
    let read32 = |bytes: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }
    };
    source.skip(4)?;
    let ifd0 = match peek_array::<4>(source)? {
        Some(offset) => read32(&offset) as u64,
        None => return Ok(Verdict::Truncated("TIFF IFD0 offset is missing".to_string())),
    };
    let window = window_len(source);
    if ifd0 >= window {
        return Ok(Verdict::Invalid("TIFF IFD0 offset points outside the file".to_string()));
    }
    source.skip(4)?;
    let type_size: u64 = 8; // upper bound used only for inline-value decisions
    let _ = type_size;
    let mut ifd = ifd0;
    for _ in 0..MAX_TIFF_IFDS {
        if ifd >= window {
            return Ok(Verdict::Invalid("TIFF IFD offset points outside the file".to_string()));
        }
        source.skip(ifd - source.abs())?;
        let Some(count_bytes) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a TIFF IFD".to_string()));
        };
        let count = read16(&count_bytes);
        if count == 0 || count > 4096 {
            return Ok(Verdict::Invalid(format!("TIFF IFD entry count {count} is implausible")));
        }
        source.skip(2)?;
        for _ in 0..count {
            let Some(entry) = peek_array::<12>(source)? else {
                return Ok(Verdict::Truncated("dump ended inside a TIFF IFD entry".to_string()));
            };
            let tag = read16(&entry[0..2]);
            let entry_type = read16(&entry[2..4]);
            let _ = tag;
            let type_len: u64 = match entry_type {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 => 4,
                5 | 10 | 12 => 8,
                16 | 17 | 18 => 8,
                _ => {
                    return Ok(Verdict::Invalid(format!(
                        "TIFF field type {entry_type} is not defined"
                    )))
                }
            };
            let value_count = read32(&entry[4..8]) as u64;
            if value_count > 1_000_000_000 {
                return Ok(Verdict::Invalid("TIFF field count is implausible".to_string()));
            }
            let total = type_len * value_count;
            if total > 4 {
                let offset = read32(&entry[8..12]) as u64;
                if offset.checked_add(total).is_none_or(|end| end > window) {
                    return Ok(Verdict::Truncated(
                        "TIFF field data extends past the candidate".to_string(),
                    ));
                }
            }
            source.skip(12)?;
        }
        let Some(next) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside a TIFF IFD trailer".to_string()));
        };
        let next_ifd = read32(&next) as u64;
        source.skip(4)?;
        if next_ifd == 0 {
            return Ok(Verdict::Valid);
        }
        ifd = next_ifd;
    }
    Ok(Verdict::Truncated("TIFF IFD count exceeded the limit".to_string()))
}

fn carve_mp3(source: &mut Source<'_>) -> io::Result<Verdict> {
    let window = window_len(source);
    let mut frames_start = 0u64;
    if peek_array::<3>(source)? == Some(*b"ID3") {
        // ID3v2 header: "ID3", ver(2), flags(1), syncsafe size(4).
        let Some(header) = peek_array::<10>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside the ID3v2 header".to_string()));
        };
        let id3_len = ((u32::from(header[6]) & 0x7f) << 21)
            | ((u32::from(header[7]) & 0x7f) << 14)
            | ((u32::from(header[8]) & 0x7f) << 7)
            | (u32::from(header[9]) & 0x7f);
        if u64::from(id3_len) + 10 > window {
            return Ok(Verdict::Truncated(
                "dump ended inside the ID3v2 tag".to_string(),
            ));
        }
        source.skip(10 + u64::from(id3_len))?;
        frames_start = source.abs();
    }
    let mpeg_bitrate = |version: u8, index: usize| -> Option<u32> {
        // Layer III tables, kbps.
        const MPEG1: [u32; 16] = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0];
        const MPEG2: [u32; 16] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0];
        if index >= 16 {
            return None;
        }
        match version {
            3 => Some(MPEG1[index]),
            2 | 0 => Some(MPEG2[index]),
            _ => None, // reserved
        }
    };
    let mpeg_samplerate = |version: u8, index: usize| -> Option<u32> {
        const MPEG1: [u32; 4] = [44100, 48000, 32000, 0];
        const MPEG2: [u32; 4] = [22050, 24000, 16000, 0];
        const MPEG25: [u32; 4] = [11025, 12000, 8000, 0];
        if index >= 4 {
            return None;
        }
        match version {
            3 => Some(MPEG1[index]),
            2 => Some(MPEG2[index]),
            0 => Some(MPEG25[index]),
            _ => None,
        }
    };
    let mut frames = 0u64;
    loop {
        if source.abs() >= source.end {
            break;
        }
        let Some(header) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside an MP3 frame header".to_string()));
        };
        if header[0] != 0xff || header[1] & 0xe0 != 0xe0 {
            if frames == 0 {
                return Ok(Verdict::Invalid(
                    "MP3 stream does not start with an MPEG frame sync".to_string(),
                ));
            }
            break;
        }
        let version = (header[1] >> 3) & 0x03;
        let layer = (header[1] >> 1) & 0x03;
        let bitrate_index = ((header[2] >> 4) & 0x0f) as usize;
        let samplerate_index = ((header[2] >> 2) & 0x03) as usize;
        let padding = (header[2] >> 1) & 0x01;
        if version == 1 || layer != 1 {
            if frames == 0 {
                return Ok(Verdict::Invalid(
                    "MP3 frame is not MPEG Layer III or uses a reserved version".to_string(),
                ));
            }
            break;
        }
        let bitrate = match mpeg_bitrate(version, bitrate_index) {
            Some(value) if value > 0 => value,
            _ => {
                if frames == 0 {
                    return Ok(Verdict::Invalid("MP3 frame has an invalid bitrate index".to_string()));
                }
                break;
            }
        };
        let samplerate = match mpeg_samplerate(version, samplerate_index) {
            Some(value) if value > 0 => value,
            _ => {
                if frames == 0 {
                    return Ok(Verdict::Invalid("MP3 frame has an invalid sample rate index".to_string()));
                }
                break;
            }
        };
        let coefficient: u64 = if version == 3 { 144 } else { 72 };
        let frame_len = coefficient * u64::from(bitrate) * 1000 / u64::from(samplerate)
            + u64::from(padding);
        if frame_len < 4 || !room_left(source, frame_len) {
            return Ok(Verdict::Truncated(
                "dump ended inside an MP3 frame".to_string(),
            ));
        }
        source.skip(frame_len)?;
        frames += 1;
        if frames > 10_000_000 {
            return Ok(Verdict::Truncated("MP3 frame count exceeded the limit".to_string()));
        }
    }
    let _ = frames_start;
    if frames == 0 {
        return Ok(Verdict::Invalid("no MPEG audio frames found".to_string()));
    }
    Ok(Verdict::Valid)
}

fn carve_bz2(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<10>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the BZIP2 header".to_string()));
    };
    if &header[..3] != b"BZh" || !(b'1'..=b'9').contains(&header[3]) {
        return Ok(Verdict::Invalid("implausible BZIP2 magic/level".to_string()));
    }
    if &header[4..10] != b"1AY&SY" {
        return Ok(Verdict::Invalid(
            "BZIP2 block magic is missing after the stream header".to_string(),
        ));
    }
    // The body is a Huffman/arithmetic bit stream with no terminal marker we
    // can trust; carve to the end of the candidate window and label the
    // result incomplete.
    source.skip(window_len(source))?;
    Ok(Verdict::Truncated(
        "bz2 stream body not decoded; extent ends at the candidate window".to_string(),
    ))
}

fn carve_xz(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<12>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the XZ header".to_string()));
    };
    if &header[..6] != b"\xfd7zXZ\x00" {
        return Ok(Verdict::Invalid("missing XZ magic".to_string()));
    }
    if header[6] != 0x00 || header[7] > 0x3f {
        return Ok(Verdict::Invalid(
            "XZ stream flags are implausible".to_string(),
        ));
    }
    let expected_crc = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if crc32(0, &header[..8]) != expected_crc {
        return Ok(Verdict::Invalid("XZ header CRC-32 does not match".to_string()));
    }
    source.skip(window_len(source))?;
    Ok(Verdict::Truncated(
        "XZ stream body not decoded; extent ends at the candidate window".to_string(),
    ))
}

fn carve_class(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(magic) = peek_array::<8>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the CLASS magic".to_string()));
    };
    if &magic[..4] != b"\xca\xfe\xba\xbe" {
        return Ok(Verdict::Invalid("missing CLASS magic".to_string()));
    }
    let minor = u16::from_be_bytes([magic[4], magic[5]]);
    let major = u16::from_be_bytes([magic[6], magic[7]]);
    let _ = minor;
    if !(45..=70).contains(&major) {
        return Ok(Verdict::Invalid(format!("implausible CLASS major version {major}")));
    }
    source.skip(8)?;
    let Some(cp_count_bytes) = peek_array::<2>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the CLASS constant pool".to_string()));
    };
    let cp_count = u64::from(u16::from_be_bytes(cp_count_bytes));
    if cp_count == 0 || cp_count > MAX_CLASS_POOL {
        return Ok(Verdict::Invalid(format!("CLASS constant pool count {cp_count} is implausible")));
    }
    source.skip(2)?;
    let mut index = 1u64;
    while index < cp_count {
        let Some(tag) = peek_u8(source)? else {
            return Ok(Verdict::Truncated("dump ended inside the CLASS constant pool".to_string()));
        };
        source.skip(1)?;
        let read_cp_value = |source: &mut Source<'_>, amount: u64| -> io::Result<Option<()>> {
            if !room_left(source, amount) {
                return Ok(None);
            }
            source.skip(amount)?;
            Ok(Some(()))
        };
        match tag {
            1 => {
                let Some(len_bytes) = peek_array::<2>(source)? else {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS UTF-8 entry".to_string()));
                };
                let len = u64::from(u16::from_be_bytes(len_bytes));
                source.skip(2)?;
                if read_cp_value(source, len)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS UTF-8 entry".to_string()));
                }
            }
            3 | 4 => {
                if read_cp_value(source, 4)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS integer entry".to_string()));
                }
            }
            5 | 6 => {
                if read_cp_value(source, 8)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS long entry".to_string()));
                }
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                if read_cp_value(source, 2)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS reference entry".to_string()));
                }
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                if read_cp_value(source, 4)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS reference entry".to_string()));
                }
            }
            15 => {
                if read_cp_value(source, 3)?.is_none() {
                    return Ok(Verdict::Truncated("dump ended inside a CLASS method-handle entry".to_string()));
                }
            }
            _ => {
                return Ok(Verdict::Invalid(format!(
                    "CLASS constant pool tag {tag} is not defined"
                )))
            }
        }
        index += 1;
    }
    for _ in 0..2u64 {
        if !room_left(source, 2) {
            return Ok(Verdict::Truncated(
                "dump ended inside the CLASS this/super class".to_string(),
            ));
        }
        source.skip(2)?;
    }
    let Some(interface_count) = peek_array::<2>(source)? else {
        return Ok(Verdict::Truncated("CLASS interface count is missing".to_string()));
    };
    let interfaces = u64::from(u16::from_be_bytes(interface_count));
    source.skip(2)?;
    if !room_left(source, interfaces * 2) {
        return Ok(Verdict::Truncated("dump ended inside the CLASS interface list".to_string()));
    }
    source.skip(interfaces * 2)?;
    // Fields then methods, each { access_flags(2), name(2), descriptor(2),
    // attributes_count(2), attributes[{ name_index(2), length(4), bytes }] }.
    for section in ["field", "method"] {
        let Some(count_bytes) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(format!("CLASS {section} count is missing")));
        };
        let count = u64::from(u16::from_be_bytes(count_bytes));
        source.skip(2)?;
        for _ in 0..count {
            if !room_left(source, 8) {
                return Ok(Verdict::Truncated(format!("dump ended inside a CLASS {section} entry")));
            }
            source.skip(6)?;
            let Some(attr_count_bytes) = peek_array::<2>(source)? else {
                return Ok(Verdict::Truncated(format!("CLASS {section} attribute count is missing")));
            };
            let attr_count = u64::from(u16::from_be_bytes(attr_count_bytes));
            source.skip(2)?;
            for _ in 0..attr_count {
                let Some(attr_len_bytes) = peek_array::<6>(source)? else {
                    return Ok(Verdict::Truncated(format!("CLASS {section} attribute header is missing")));
                };
                let attr_len = u32::from_be_bytes([
                    attr_len_bytes[2], attr_len_bytes[3], attr_len_bytes[4], attr_len_bytes[5],
                ]) as u64;
                source.skip(6)?;
                if !room_left(source, attr_len) {
                    return Ok(Verdict::Truncated(format!("dump ended inside a CLASS {section} attribute")));
                }
                source.skip(attr_len)?;
            }
        }
    }
    // Class-level attributes.
    let Some(attr_count_bytes) = peek_array::<2>(source)? else {
        return Ok(Verdict::Truncated("CLASS attribute count is missing".to_string()));
    };
    let attr_count = u64::from(u16::from_be_bytes(attr_count_bytes));
    source.skip(2)?;
    for _ in 0..attr_count {
        let Some(attr_len_bytes) = peek_array::<6>(source)? else {
            return Ok(Verdict::Truncated("CLASS attribute header is missing".to_string()));
        };
        let attr_len = u32::from_be_bytes([
            attr_len_bytes[2], attr_len_bytes[3], attr_len_bytes[4], attr_len_bytes[5],
        ]) as u64;
        source.skip(6)?;
        if !room_left(source, attr_len) {
            return Ok(Verdict::Truncated("dump ended inside a CLASS attribute".to_string()));
        }
        source.skip(attr_len)?;
    }
    Ok(Verdict::Valid)
}

fn carve_rtf(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<6>(source)? != Some(*b"{\\rtf1") {
        return Ok(Verdict::Invalid("missing RTF magic".to_string()));
    }
    let mut depth = 0i64;
    let mut offset = 0u64;
    while source.abs() < source.end && offset < MAX_RTF_BYTES {
        let Some(byte) = peek_u8(source)? else {
            return Ok(Verdict::Truncated("dump ended inside the RTF document".to_string()));
        };
        match byte {
            0x00 => {
                return Ok(Verdict::Invalid("NUL byte inside the RTF document".to_string()))
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    source.skip(1)?;
                    return Ok(Verdict::Valid);
                }
            }
            _ => {}
        }
        source.skip(1)?;
        offset += 1;
    }
    if offset >= MAX_RTF_BYTES {
        return Ok(Verdict::Truncated(
            "RTF document exceeded the 16 MiB scan limit".to_string(),
        ));
    }
    Ok(Verdict::Truncated(
        "dump ended before the RTF root group closed".to_string(),
    ))
}

fn carve_evtx(source: &mut Source<'_>) -> io::Result<Verdict> {
    const CHUNK_SIZE: u64 = 65536;
    let Some(header) = peek_array::<128>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the EVTX file header".to_string()));
    };
    if &header[..8] != b"ElfFile\x00" {
        return Ok(Verdict::Invalid("missing EVTX magic".to_string()));
    }
    let header_size = u32::from_le_bytes([header[48], header[49], header[50], header[51]]);
    let version_minor = u16::from_le_bytes([header[64], header[65]]);
    let version_major = u16::from_le_bytes([header[66], header[67]]);
    let first_chunk = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    let last_chunk = u32::from_le_bytes([header[12], header[13], header[14], header[15]]);
    if header_size != 128 || version_major == 0 || version_minor > 3 {
        return Ok(Verdict::Invalid(
            "EVTX header size/version is implausible".to_string(),
        ));
    }
    if last_chunk < first_chunk {
        return Ok(Verdict::Invalid(
            "EVTX chunk range is reversed".to_string(),
        ));
    }
    source.skip(u64::from(header_size))?;
    let mut chunks: u64 = 0;
    loop {
        if source.abs() >= source.end {
            break;
        }
        let Some(chunk) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated("dump ended inside an EVTX chunk header".to_string()));
        };
        if &chunk != b"ElfChnk\x00" {
            if chunks == 0 {
                return Ok(Verdict::Invalid(
                    "EVTX first chunk is not an ElfChnk container".to_string(),
                ));
            }
            break;
        }
        chunks += 1;
        if !room_left(source, CHUNK_SIZE) {
            return Ok(Verdict::Truncated("dump ended inside an EVTX chunk".to_string()));
        }
        source.skip(CHUNK_SIZE)?;
        if source.abs() - source.origin >= window_len(source) {
            break;
        }
    }
    if chunks == 0 {
        return Ok(Verdict::Invalid("EVTX contains no chunks".to_string()));
    }
    Ok(Verdict::Valid)
}

fn carve_vdi(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<40>(source)? != Some(*b"<<< Oracle VM VirtualBox Disk Image >>>\n") {
        return Ok(Verdict::Invalid("missing VDI magic".to_string()));
    }
    let Some(rest) = peek_array::<58>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the VDI header".to_string()));
    };
    if !rest[..58]
        .iter()
        .all(|&byte| byte == 0x00 || (0x20..=0x7e).contains(&byte))
    {
        return Ok(Verdict::Invalid("VDI creator string is not printable".to_string()));
    }
    let carved = window_len(source).min(4096);
    source.skip(carved)?;
    Ok(Verdict::Truncated(
        "VDI body not parsed; only the 4 KiB header was carved".to_string(),
    ))
}

fn carve_vmdk(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<512>(source)? else {
        return Ok(Verdict::Truncated("dump ended inside the VMDK sparse header".to_string()));
    };
    if &header[..4] != b"KDMV" {
        return Ok(Verdict::Invalid("missing VMDK sparse magic".to_string()));
    }
    let version = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    let capacity = u64::from_le_bytes([
        header[12], header[13], header[14], header[15], header[16], header[17], header[18],
        header[19],
    ]);
    let grain_size = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    if !(1..=3).contains(&version) || capacity == 0 || capacity > 1u64 << 40 || grain_size == 0 {
        return Ok(Verdict::Invalid("implausible VMDK sparse header fields".to_string()));
    }
    let carved = window_len(source).min(65536);
    source.skip(carved)?;
    Ok(Verdict::Truncated(
        "VMDK extents not parsed; only the 64 KiB header was carved".to_string(),
    ))
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
                .map(|d| d.as_nanos())
                .unwrap_or(0)
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

    /// Deterministic high-entropy bytes standing in for ciphertext.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut state = seed | 1;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// A ZIP entry whose first 8 KiB is structured text and whose last 8 KiB
    /// is "encrypted", with no central directory: the shape partial
    /// encryption leaves behind. The encrypted part starts 39 + 8192 bytes in.
    fn half_encrypted_zip() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&[0u8; 4]); // time + date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
        out.extend_from_slice(&16384u32.to_le_bytes()); // packed size
        out.extend_from_slice(&16384u32.to_le_bytes()); // unpacked size
        out.extend_from_slice(&9u16.to_le_bytes()); // name length
        out.extend_from_slice(&0u16.to_le_bytes()); // extra length
        out.extend_from_slice(b"notes.txt");
        out.extend_from_slice(&vec![b'A'; 8192]);
        out.extend_from_slice(&pseudo_random(8192, 0x9e37_79b9_7f4a_7c15));
        out
    }

    #[test]
    fn incomplete_zip_reports_corruption_and_entropy_spike_offsets() {
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&half_encrypted_zip());
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("partial-zip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.kind, CarveKind::Zip);
        assert!(!file.complete, "{file:?}");
        assert_eq!(file.corrupted_offset, Some(file.offset + file.size));
        let spike = file
            .entropy_spike_at
            .expect("the structured -> random jump must be flagged");
        let encrypted_from = file.offset + 39 + 8192;
        assert!(
            spike <= encrypted_from && encrypted_from < spike + SPIKE_WINDOW as u64,
            "spike {spike:#x} does not cover the encrypted start {encrypted_from:#x}"
        );
    }

    #[test]
    fn complete_files_carry_no_corruption_metadata() {
        let zip = zip_bytes("a.txt", b"hello");
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&[0u8; 32]);

        let path = write_dump("complete-zip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(report.files[0].complete);
        assert_eq!(report.files[0].corrupted_offset, None);
        assert_eq!(report.files[0].entropy_spike_at, None);
    }

    #[test]
    fn random_from_the_first_byte_has_no_entropy_spike() {
        // Ciphertext with no structured prefix has no boundary to report.
        let mut zip = half_encrypted_zip();
        let header = 39;
        zip.splice(header..header + 8192, pseudo_random(8192, 7));
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("all-random", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(!report.files[0].complete);
        assert_eq!(report.files[0].entropy_spike_at, None);
    }

    /// A ZIP whose local headers and data are replaced by "ciphertext" but
    /// whose central directory and end record survive. Returns the dump and
    /// the absolute offset where the surviving tail starts.
    fn zip_with_ruined_head() -> (Vec<u8>, usize) {
        let zip = zip_bytes("a.txt", b"hello world, hello world");
        let eocd_at = zip
            .windows(4)
            .rposition(|chunk| chunk == b"PK\x05\x06")
            .unwrap();
        let cd_size =
            u32::from_le_bytes(zip[eocd_at + 12..eocd_at + 16].try_into().unwrap()) as usize;
        let cd_at = eocd_at - cd_size;
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&pseudo_random(cd_at, 0x1357_9bdf_2468_ace1));
        let tail_at = dump.len();
        dump.extend_from_slice(&zip[cd_at..]);
        dump.extend_from_slice(&[0u8; 64]);
        (dump, tail_at)
    }

    #[test]
    fn salvage_recovers_a_zip_central_directory_whose_head_is_gone() {
        let (dump, tail_at) = zip_with_ruined_head();
        let path = write_dump("salvage-zip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let plain = Carver::new(options.clone())
            .scan(path.to_str().unwrap())
            .unwrap();
        let salvaged = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(
            plain
                .files
                .iter()
                .all(|file| !file.notes.starts_with("salvage:tail")),
            "salvage must stay off by default: {plain:?}"
        );
        let tails: Vec<_> = salvaged
            .files
            .iter()
            .filter(|file| file.notes.starts_with("salvage:tail"))
            .collect();
        assert_eq!(tails.len(), 1, "{salvaged:?}");
        let tail = tails[0];
        assert_eq!(tail.kind, CarveKind::Zip);
        assert!(!tail.complete);
        assert_eq!(tail.offset, tail_at as u64);
        assert_eq!(tail.size, (dump.len() - 64 - tail_at) as u64);
        assert_eq!(tail.corrupted_offset, Some(tail.offset));
    }

    #[test]
    fn salvage_recovers_a_pdf_trailer_behind_a_ruined_body() {
        let trailer: &[u8] =
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 /Root 1 0 R >>\nstartxref\n9999\n%%EOF\n";
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&pseudo_random(8192, 0x2545_f491_4f6c_dd1d));
        let tail_at = dump.len() as u64;
        dump.extend_from_slice(trailer);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("salvage-pdf", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        let tails: Vec<_> = report
            .files
            .iter()
            .filter(|file| file.kind == CarveKind::Pdf && file.notes.starts_with("salvage:tail"))
            .collect();
        assert_eq!(tails.len(), 1, "{report:?}");
        let tail = tails[0];
        assert!(!tail.complete);
        // The boundary may overshoot by the few ciphertext bytes that happen
        // to look like text, but never undershoot the trailer.
        assert!(tail.offset <= tail_at, "{tail:?}");
        assert!(tail_at - tail.offset < 16, "{tail:?}");
        assert_eq!(tail.offset + tail.size, tail_at + trailer.len() as u64);
        assert!(tail.entropy_spike_at.is_some(), "{tail:?}");
    }

    #[test]
    fn salvage_skips_footers_inside_files_the_header_pass_carved() {
        let zip = zip_bytes("a.txt", b"hello");
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&[0u8; 32]);

        let path = write_dump("salvage-covered", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(report.files[0].complete);
        assert!(!report.files[0].notes.starts_with("salvage:tail"));
    }

    #[test]
    fn incomplete_files_go_to_partial_dir_only_when_asked() {
        let zip = zip_bytes("ok.txt", b"a complete archive payload");
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&[0u8; 128]);
        dump.extend_from_slice(&half_encrypted_zip());
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("partial-dir", &dump);
        let root = path.parent().unwrap().to_path_buf();
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };

        let out = root.join("split");
        let report = Carver::new(options.clone())
            .with_incomplete_dir(true)
            .carve_to_dir(path.to_str().unwrap(), &out)
            .unwrap();
        assert_eq!(report.files.len(), 2, "{report:?}");
        let complete = report.files.iter().find(|file| file.complete).unwrap();
        let partial = report.files.iter().find(|file| !file.complete).unwrap();
        assert_eq!(complete.path.as_ref().unwrap().parent(), Some(out.as_path()));
        assert_eq!(
            partial.path.as_ref().unwrap().parent(),
            Some(out.join("partial").as_path())
        );
        assert!(partial.path.as_ref().unwrap().is_file());

        // Default keeps the old flat layout.
        let flat = root.join("flat");
        let report = Carver::new(options)
            .carve_to_dir(path.to_str().unwrap(), &flat)
            .unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(report.files.len(), 2, "{report:?}");
        for file in &report.files {
            assert_eq!(file.path.as_ref().unwrap().parent(), Some(flat.as_path()));
        }
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
    fn corrupt_deflate_candidate_is_rejected_not_fatal() {
        // A gzip header followed by bytes that cannot form a valid deflate
        // stream is a hostile/false-positive candidate: the carver must record
        // a rejection and keep scanning, not abort the whole pass with an error.
        let mut dump = vec![0u8; 128];
        dump.extend_from_slice(b"\x1f\x8b\x08\x00");
        dump.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("bad-gzip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        let report = report.expect("corrupt gzip candidate must be rejected, not fatal");
        assert!(report.rejected >= 1, "{report:?}");
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

    /// A minimal structurally valid 7-Zip archive: the 32-byte signature
    /// header with a correct `StartHeaderCRC` and an empty next header.
    fn seven_zip_bytes() -> Vec<u8> {
        let next_header: &[u8] = &[];
        let mut start_header = Vec::new();
        start_header.extend_from_slice(&0u64.to_le_bytes()); // next header offset
        start_header.extend_from_slice(&(next_header.len() as u64).to_le_bytes());
        start_header
            .extend_from_slice(&(crc32(0xffff_ffff, next_header) ^ 0xffff_ffff).to_le_bytes());

        let mut out = b"7z\xbc\xaf\x27\x1c".to_vec();
        out.push(0); // major version
        out.push(4); // minor version
        out.extend_from_slice(&(crc32(0xffff_ffff, &start_header) ^ 0xffff_ffff).to_le_bytes());
        out.extend_from_slice(&start_header);
        out
    }

    #[test]
    fn carves_7z_with_a_valid_start_header_crc() {
        let archive = seven_zip_bytes();
        assert_eq!(archive.len(), 32);
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&archive);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("seven-zip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::SevenZip);
        assert!(report.files[0].complete);
        assert_eq!(report.files[0].size, archive.len() as u64);
    }

    #[test]
    fn rejects_7z_with_a_bad_start_header_crc() {
        // Same signature and sizes, but the CRC no longer matches the 20
        // bytes it covers: this must be rejected as a false positive instead
        // of being carved as a valid archive.
        let mut archive = seven_zip_bytes();
        archive[8] ^= 0xff; // corrupt the stored StartHeaderCRC
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&archive);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("bad-seven-zip", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
        assert!(report.rejected >= 1, "{report:?}");
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
    fn png_with_bad_ihdr_crc_is_rejected() {
        let mut png = png_bytes(b"payload");
        // Corrupt one byte of the IHDR data without touching the CRC: no chunk
        // verified yet, so there is nothing to salvage.
        let position = 8 + 8 + 2;
        png[position] ^= 0xFF;
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&png);
        let path = write_dump("bad-crc", &dump);

        let report = Carver::new(CarveOptions {
            kinds: vec![CarveKind::Png],
            ..Default::default()
        })
        .scan(path.to_str().unwrap())
        .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
        assert_eq!(report.rejected, 1);
    }

    #[test]
    fn png_with_bad_idat_crc_keeps_the_valid_chunks() {
        // IHDR + 3 IDAT chunks + IEND; the middle IDAT is overwritten (as partial
        // encryption would) without fixing its CRC.
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            png.extend_from_slice(&(data.len() as u32).to_be_bytes());
            png.extend_from_slice(kind);
            png.extend_from_slice(data);
            let mut crc = crc32(0xffff_ffff, kind);
            crc = crc32(crc, data) ^ 0xffff_ffff;
            png.extend_from_slice(&crc.to_be_bytes());
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        chunk(b"IDAT", &[1u8; 40]);
        chunk(b"IDAT", &[2u8; 40]);
        chunk(b"IDAT", &[3u8; 40]);
        chunk(b"IEND", &[]);
        // 8 signature + IHDR(25) + first IDAT(52) = start of the second IDAT.
        let good_len = 8 + 25 + 52;
        let damaged = good_len + 8 + 5;
        png[damaged] ^= 0xFF;
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&png);
        let path = write_dump("bad-idat-salvage", &dump);

        let report = Carver::new(CarveOptions {
            kinds: vec![CarveKind::Png],
            min_size: 1,
            ..Default::default()
        })
        .scan(path.to_str().unwrap())
        .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(!file.complete);
        assert_eq!(file.size, good_len as u64);
        assert_eq!(file.corrupted_offset, Some(32 + good_len as u64));
        assert!(file.notes.contains("CRC mismatch"), "{}", file.notes);
        assert_eq!(report.rejected, 0);
    }

    #[test]
    fn salvage_recovers_the_idat_run_of_a_png_whose_head_is_gone() {
        // IHDR + 4 IDAT + IEND; the signature, IHDR and first IDAT are overwritten
        // (head encryption), so header-first finds nothing. Footer-first walks
        // back from IEND over the 3 IDAT chunks whose CRC still verifies.
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        let mut chunk = |kind: &[u8; 4], data: &[u8]| {
            png.extend_from_slice(&(data.len() as u32).to_be_bytes());
            png.extend_from_slice(kind);
            png.extend_from_slice(data);
            let mut crc = crc32(0xffff_ffff, kind);
            crc = crc32(crc, data) ^ 0xffff_ffff;
            png.extend_from_slice(&crc.to_be_bytes());
        };
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&1u32.to_be_bytes());
        ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
        chunk(b"IHDR", &ihdr);
        for fill in 1..=4u8 {
            chunk(b"IDAT", &[fill; 40]);
        }
        chunk(b"IEND", &[]);
        let ruined = 8 + 25 + 52; // signature + IHDR + first IDAT
        for byte in &mut png[..ruined] {
            *byte = 0xAA;
        }
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump("salvage-png", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Png],
            min_size: 1,
            ..Default::default()
        };
        let plain = Carver::new(options.clone())
            .scan(path.to_str().unwrap())
            .unwrap();
        let salvaged = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(plain.files.is_empty(), "{plain:?}");
        assert_eq!(salvaged.files.len(), 1, "{salvaged:?}");
        let tail = &salvaged.files[0];
        assert_eq!(tail.kind, CarveKind::Png);
        assert!(!tail.complete);
        assert!(tail.notes.starts_with("salvage:tail"), "{}", tail.notes);
        assert!(tail.notes.contains("3 chunk(s)"), "{}", tail.notes);
        assert_eq!(tail.offset, 32 + ruined as u64);
        assert_eq!(tail.size, (png.len() - ruined) as u64);
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
    fn carves_ole_document() {
        // OLE Compound File Binary Format header: D0 CF 11 E0 A1 B1 1A E1.
        let mut ole = Vec::new();
        ole.extend_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
        // sector size power = 9 (512 bytes) at offset 0x1C (20 bytes after the 8-byte signature)
        ole.extend_from_slice(&[0u8; 20]);
        ole.extend_from_slice(&9u16.to_le_bytes());
        ole.extend_from_slice(&vec![0u8; 512]);

        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&ole);
        let path = write_dump("ole", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Ole);
        assert!(report.files[0].complete);

        // Junk bytes that look nothing like OLE must be rejected.
        let mut junk = vec![0u8; 64];
        junk.extend_from_slice(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1");
        junk.extend_from_slice(&[0xAA; 28]);
        junk.extend_from_slice(&13u16.to_le_bytes()); // implausible sector pow
        let path = write_dump("ole-junk", &junk);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn carves_mp4_file() {
        // MP4: ftyp box (size 32, type "ftyp") followed by mdat box.
        let mut mp4 = Vec::new();
        mp4.extend_from_slice(&32u32.to_be_bytes());
        mp4.extend_from_slice(b"ftyp");
        mp4.extend_from_slice(&[0u8; 24]); // ftyp payload
                                           // mdat box: size 16, type "mdat", then stop
        mp4.extend_from_slice(&16u32.to_be_bytes());
        mp4.extend_from_slice(b"mdat");
        mp4.extend_from_slice(&[0u8; 8]);

        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&mp4);
        let path = write_dump("mp4", &dump);
        let report = Carver::new(CarveOptions {
            min_size: 0,
            ..Default::default()
        })
        .scan(path.to_str().unwrap())
        .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Mp4);
        assert!(report.files[0].complete);

        // Truncated MP4 (box size exceeds remaining dump) is rejected.
        let mut bad = Vec::new();
        bad.extend_from_slice(&1000u32.to_be_bytes());
        bad.extend_from_slice(b"ftyp");
        let path = write_dump("mp4-bad", &bad);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn carves_pe_executable() {
        // Minimal PE: MZ + e_lfanew pointing to PE\0\0 signature.
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.extend_from_slice(&[0u8; 0x3a]); // bytes 2..0x3c
        pe.extend_from_slice(&0x40u32.to_le_bytes()); // e_lfanew = 0x40
        pe.extend_from_slice(&[0u8; (0x40 - 0x40) as usize]); // padding to 0x40
        pe.extend_from_slice(b"PE\0\0");
        pe.extend_from_slice(&[0u8; 64]);

        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&pe);
        let path = write_dump("pe", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Pe);
        assert!(report.files[0].complete);

        // MZ without PE signature is rejected.
        let mut bad = vec![0u8; 64];
        bad.extend_from_slice(b"MZ");
        bad.extend_from_slice(&[0xAA; 62]);
        let path = write_dump("pe-bad", &bad);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn carves_elf_executable() {
        // ELF: \x7fELF, class 2 (64-bit), data 1 (LE), version 1.
        let mut elf = Vec::new();
        elf.extend_from_slice(b"\x7fELF");
        elf.push(2); // 64-bit class
        elf.push(1); // little-endian
        elf.push(1); // version
        elf.extend_from_slice(&[0u8; 64]);

        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&elf);
        let path = write_dump("elf", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].kind, CarveKind::Elf);
        assert!(report.files[0].complete);

        // Bad ELF class is rejected.
        let mut bad = Vec::new();
        bad.extend_from_slice(b"\x7fELF");
        bad.push(9); // implausible class
        bad.extend_from_slice(&[0u8; 64]);
        let path = write_dump("elf-bad", &bad);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
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
        assert!(CarveKind::from_list("xyz").is_err());
        assert!(CarveKind::from_list("").is_err());
    }

    /// Block-aligned deterministic text fixture: `blocks` blocks of 64-byte
    /// lines, ending on a newline. The first line is exactly 64 bytes.
    fn md_text(blocks: usize) -> Vec<u8> {
        let line = format!("{:<63}\n", "Lorem ipsum dolor sit amet, consectetur adipiscing elit");
        assert_eq!(line.len(), 64, "fixture lines must be exactly 64 bytes");
        let mut out = Vec::with_capacity(blocks * TEXT_BLOCK);
        for _ in 0..blocks * (TEXT_BLOCK / 64) {
            out.extend_from_slice(line.as_bytes());
        }
        out
    }

    #[test]
    fn text_pass_recovers_the_readable_region_and_skips_random_data() {
        let text = md_text(2);
        let mut dump = pseudo_random(0x10000, 0x9e37_79b9_7f4a_7c15);
        dump.extend_from_slice(&text);
        dump.extend_from_slice(&pseudo_random(0x4000, 0x3f84_d5b5_b547_0917));
        let text_at = 0x10000u64;
        let path = write_dump("text-basic", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.kind, CarveKind::Text);
        assert!(!file.complete);
        assert!(file.notes.starts_with("text:region"), "{file:?}");
        // The ragged first line is cut at the newline.
        assert_eq!(file.offset, text_at + 64);
        assert_eq!(file.size, text.len() as u64 - 64);
        assert_eq!(file.entropy, file.entropy.min(6.0));
    }

    #[test]
    fn text_pass_rejects_constant_byte_runs() {
        // 0x3F ('?') is printable, so a run of it scores 100% "text" by any
        // printable-ratio rule; it is junk, not evidence, and must not be
        // carved.
        let mut dump = pseudo_random(0x10000, 0x0ca11_ab1e_0000_0001);
        dump.extend_from_slice(&vec![b'?'; 0x4000]);
        dump.extend_from_slice(&pseudo_random(0x4000, 0xfeed_face_1111_2222));

        let path = write_dump("text-degenerate", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn text_pass_bridges_one_bad_block_inside_a_run() {
        let head = md_text(1);
        let tail = md_text(2);
        let mut dump = pseudo_random(0x10000, 0xdead_beef_cafe_f00d);
        let base = dump.len() as u64;
        dump.extend_from_slice(&head);
        dump.extend_from_slice(&pseudo_random(0x1000, 0x1eaf_5eed_1234_5678));
        dump.extend_from_slice(&tail);
        dump.extend_from_slice(&pseudo_random(0x4000, 0x0bad_f00d_0bad_f00d));

        let path = write_dump("text-bridge", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        // One 4 KiB non-text block does not split the region.
        assert_eq!(file.offset, base + 64);
        assert_eq!(file.size, (0x4000 - 64) as u64);
    }

    #[test]
    fn text_pass_yields_nothing_on_pure_random_data() {
        let dump = pseudo_random(1 << 20, 0x1234_5678_9abc_def0);
        let path = write_dump("text-random", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn text_pass_is_opt_in_and_all_does_not_include_it() {
        // `all` must not change: text is an explicit opt-in.
        assert!(!CarveKind::ALL.contains(&CarveKind::Text));
        assert_eq!(
            CarveKind::from_list("all").unwrap(),
            CarveKind::ALL.to_vec()
        );
        assert!(CarveKind::from_list("text").unwrap().contains(&CarveKind::Text));
        assert!(CarveKind::from_list("txt").unwrap().contains(&CarveKind::Text));
        assert!(CarveKind::from_list("all,text").unwrap().contains(&CarveKind::Text));

        let text = md_text(2);
        let mut dump = pseudo_random(0x10000, 0xabcd_ef01_2345_6789);
        dump.extend_from_slice(&text);
        dump.extend_from_slice(&pseudo_random(0x4000, 0x0f0e_0d0c_0b0a_0908));
        let path = write_dump("text-optin", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(
            report.files.iter().all(|file| file.kind != CarveKind::Text),
            "{report:?}"
        );
    }

    #[test]
    fn text_pass_clips_regions_around_already_carved_files() {
        let text = md_text(2);
        let zip = zip_bytes("ok.txt", b"hello");
        let mut dump = pseudo_random(0x10000, 0x0ddc_0ffe_ee11_2233);
        let zip_at = dump.len() as u64;
        dump.extend_from_slice(&zip);
        dump.extend_from_slice(&text);
        dump.extend_from_slice(&pseudo_random(0x4000, 0x5544_3322_1100_ffee));

        let path = write_dump("text-clip", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Zip, CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        let zip_file = report
            .files
            .iter()
            .find(|file| file.kind == CarveKind::Zip)
            .expect("zip must be carved");
        assert_eq!(zip_file.offset, zip_at);
        let zip_end = zip_at + zip_file.size;
        let text_file = report
            .files
            .iter()
            .find(|file| file.kind == CarveKind::Text)
            .unwrap_or_else(|| panic!("text region must be recovered: {report:?}"));
        assert!(
            text_file.offset >= zip_end && text_file.offset + text_file.size <= zip_at + zip.len() as u64 + text.len() as u64 + 1,
            "text region must not enter the carved zip: {text_file:?}"
        );
    }

    #[test]
    fn text_pass_recovers_utf8_vietnamese_content() {
        let line = "Tiếng Việt có dấu, chữ Latin pha trộn.\n";
        assert!(line.len() > 16);
        let mut text = Vec::new();
        while text.len() < 0x10000 {
            text.extend_from_slice(line.as_bytes());
        }
        // End on a complete line so the fixture is deterministic.
        text.truncate(text.len() - (text.len() % line.len()));
        let text_at = 0x10000u64;
        let mut dump = pseudo_random(0x10000, 0x1234_abcd_5678_9abc);
        dump.extend_from_slice(&text);
        dump.extend_from_slice(&pseudo_random(0x4000, 0x9876_5432_10fe_dcba));

        let path = write_dump("text-utf8", &dump);
        let out_dir = path.parent().unwrap().join("out");
        let options = CarveOptions {
            kinds: vec![CarveKind::Text],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .carve_to_dir(path.to_str().unwrap(), &out_dir)
            .unwrap();
        let file = report
            .files
            .iter()
            .find(|file| file.kind == CarveKind::Text)
            .unwrap_or_else(|| panic!("utf-8 region must be recovered: {report:?}"));
        assert_eq!(file.offset, text_at + line.len() as u64);
        let written = std::fs::read(file.path.as_ref().unwrap()).unwrap();
        let recovered = String::from_utf8_lossy(&written);
        assert!(recovered.contains("Tiếng Việt có dấu"));
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}

#[cfg(test)]
mod new_formats {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("bxmap-new-fmt-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_dump(name: &str, data: &[u8]) -> PathBuf {
        let dir = temp_dir(name);
        let path = dir.join("dump.bin");
        std::fs::write(&path, data).unwrap();
        path
    }

    fn carve_one(name: &str, kind: CarveKind, payload: &[u8]) -> CarveReport {
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(payload);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump(name, &dump);
        let options = CarveOptions {
            kinds: vec![kind],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        report
    }

    fn minimal_class() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\xca\xfe\xba\xbe"); // magic
        out.extend_from_slice(&0u16.to_be_bytes()); // minor
        out.extend_from_slice(&61u16.to_be_bytes()); // major (Java 17)
        out.extend_from_slice(&1u16.to_be_bytes()); // cp_count (empty pool)
        out.extend_from_slice(&0u16.to_be_bytes()); // access_flags
        out.extend_from_slice(&0u16.to_be_bytes()); // this_class
        out.extend_from_slice(&0u16.to_be_bytes()); // super_class
        out.extend_from_slice(&0u16.to_be_bytes()); // interface_count
        out.extend_from_slice(&0u16.to_be_bytes()); // field_count
        out.extend_from_slice(&0u16.to_be_bytes()); // method_count
        out.extend_from_slice(&0u16.to_be_bytes()); // attributes_count
        out
    }

    fn minimal_dex() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"dex\n035\x00"); // magic + version
        out.extend_from_slice(&[0u8; 4]); // checksum (patched below)
        out.extend_from_slice(&[0u8; 20]); // signature
        out.extend_from_slice(&0x70u32.to_le_bytes()); // file_size (patched below)
        out.extend_from_slice(&0x70u32.to_le_bytes()); // header_size
        out.extend_from_slice(&0x12345678u32.to_le_bytes()); // endian_tag
        out.extend_from_slice(&0u32.to_le_bytes()); // link_size
        out.extend_from_slice(&0u32.to_le_bytes()); // link_off
        out.extend_from_slice(&0x00u32.to_le_bytes()); // map_off (offset 0 is never read; size is 0)
        out.extend_from_slice(&0u32.to_le_bytes()); // string_ids_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // string_ids_off
        out.extend_from_slice(&0u32.to_le_bytes()); // type_ids_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // type_ids_off
        out.extend_from_slice(&0u32.to_le_bytes()); // proto_ids_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // proto_ids_off
        out.extend_from_slice(&0u32.to_le_bytes()); // field_ids_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // field_ids_off
        out.extend_from_slice(&0u32.to_le_bytes()); // method_ids_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // method_ids_off
        out.extend_from_slice(&0u32.to_le_bytes()); // class_defs_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // class_defs_off
        out.extend_from_slice(&0u32.to_le_bytes()); // data_size
        out.extend_from_slice(&0x00u32.to_le_bytes()); // data_off
        let file_size = out.len() as u32;
        out[32..36].copy_from_slice(&file_size.to_le_bytes());
        let checksum = adler32(&out[12..]);
        out[8..12].copy_from_slice(&checksum.to_le_bytes());
        out
    }

    fn minimal_tar() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[b'A'; 100]); // name
        out.extend_from_slice(&[0u8; 8]); // mode
        out.extend_from_slice(&[0u8; 8]); // uid
        out.extend_from_slice(&[0u8; 8]); // gid
        out.extend_from_slice(b"00000000000\x00"); // size (octal 0, 12 bytes)
        out.extend_from_slice(b"00000000000\x00"); // mtime (12 bytes)
        out.extend_from_slice(&[b' '; 8]); // checksum (patched below)
        out.push(b'0'); // typeflag regular
        out.extend_from_slice(&[0u8; 100]); // linkname
        out.extend_from_slice(b"ustar\x00"); // magic
        out.extend_from_slice(b"00"); // version
        out.extend_from_slice(&[0u8; 64]); // uname + gname (32 + 32)
        out.extend_from_slice(&[0u8; 16]); // devmajor + devminor (8 + 8)
        out.extend_from_slice(&[0u8; 155]); // prefix
        out.extend_from_slice(&[0u8; 12]); // padding
        assert_eq!(out.len(), 512);
        let mut sum: u64 = 0;
        for (i, &byte) in out.iter().enumerate() {
            sum += u64::from(if (148..156).contains(&i) { b' ' } else { byte });
        }
        out[148..156].copy_from_slice(format!("{sum:07o}\x00").as_bytes());
        out.extend_from_slice(&[0u8; 1024]); // two zero blocks
        out
    }

    fn minimal_pcap() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xa1b2c3d4u32.to_be_bytes()); // BE magic
        out.extend_from_slice(&2u16.to_be_bytes()); // version major
        out.extend_from_slice(&4u16.to_be_bytes()); // version minor
        out.extend_from_slice(&0u32.to_be_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_be_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_be_bytes()); // snaplen
        out.extend_from_slice(&101u32.to_be_bytes()); // network = Ethernet
        out.extend_from_slice(&0u32.to_be_bytes()); // ts sec
        out.extend_from_slice(&0u32.to_be_bytes()); // ts usec
        out.extend_from_slice(&4u32.to_be_bytes()); // incl len
        out.extend_from_slice(&4u32.to_be_bytes()); // orig len
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // payload
        out
    }

    fn minimal_pcapng() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0a0d0d0au32.to_le_bytes()); // section magic
        out.extend_from_slice(&28u32.to_le_bytes()); // section length
        out.extend_from_slice(&0x1a2b3c4du32.to_le_bytes()); // BOM (LE)
        out.extend_from_slice(&1u16.to_le_bytes()); // major
        out.extend_from_slice(&0u16.to_le_bytes()); // minor
        out.extend_from_slice(&(-1i64).to_le_bytes()); // section length unknown
        out.extend_from_slice(&28u32.to_le_bytes()); // SHB trailing length
        out.extend_from_slice(&1u32.to_le_bytes()); // block type = IDB
        out.extend_from_slice(&20u32.to_le_bytes()); // block length
        out.extend_from_slice(&1u16.to_le_bytes()); // linktype Ethernet
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&20u32.to_le_bytes()); // trailing length
        out
    }

    fn minimal_evtx() -> Vec<u8> {
        let mut out = vec![0u8; 128];
        out[..8].copy_from_slice(b"ElfFile\x00");
        out[8..12].copy_from_slice(&0u32.to_le_bytes()); // first_chunk
        out[12..16].copy_from_slice(&0u32.to_le_bytes()); // last_chunk
        out[48..52].copy_from_slice(&128u32.to_le_bytes()); // header_size
        out[64..66].copy_from_slice(&1u16.to_le_bytes()); // minor
        out[66..68].copy_from_slice(&3u16.to_le_bytes()); // major
        out.extend_from_slice(b"ElfChnk\x00");
        out.extend_from_slice(&[0u8; 65536 - 8]);
        out
    }

    fn minimal_flac() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"fLaC");
        out.push(0x80); // last-metadata-block flag | STREAMINFO(0)
        out.extend_from_slice(&[0, 0, 34]); // length 34
        out.extend_from_slice(&[0u8; 34]);
        out
    }

    fn minimal_ogg(opus: bool) -> Vec<u8> {
        let marker: &[u8] = if opus { b"OpusHead" } else { b"vorbis" };
        let mut out = Vec::new();
        out.extend_from_slice(b"OggS");
        out.push(0); // version
        out.push(0x02); // BOS
        out.extend_from_slice(&0u64.to_le_bytes()); // granule position
        out.extend_from_slice(&42u32.to_le_bytes()); // serial
        out.extend_from_slice(&0u32.to_le_bytes()); // page number
        out.extend_from_slice(&0u32.to_le_bytes()); // CRC (not checked)
        out.push(1); // segment count
        out.push(marker.len() as u8); // segment 1 size
        out.extend_from_slice(marker);
        out
    }

    fn minimal_mp3_frame() -> Vec<u8> {
        // MPEG1 Layer III, 128 kbps, 44100 Hz. bitrate idx 9, sr idx 0.
        let mut out = vec![0xff, 0xfb, 0x90, 0x00];
        out.extend(std::iter::repeat(0u8).take(417));
        out
    }

    fn minimal_mp3_with_id3() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"ID3");
        out.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0]); // ver 3, syncsafe size 0
        out.extend_from_slice(&minimal_mp3_frame());
        out
    }

    fn minimal_gif() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GIF89a");
        out.extend_from_slice(&1u16.to_le_bytes()); // width
        out.extend_from_slice(&1u16.to_le_bytes()); // height
        out.push(0x00); // packed (no global color table)
        out.push(0); // background
        out.push(0); // aspect
        out.push(0x2c); // image descriptor
        out.extend_from_slice(&[0u8; 8]); // left/top/width/height
        out.push(0x00); // packed (no local color table)
        out.push(2); // LZW minimum code size
        out.push(2); // sub-block size
        out.extend_from_slice(&[0x44, 0x01]); // data
        out.push(0x00); // block terminator
        out.push(0x3b); // trailer
        out
    }

    fn minimal_ico() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // type = icon
        out.extend_from_slice(&1u16.to_le_bytes()); // count
        out.push(16); // width
        out.push(16); // height
        out.push(0); // colors
        out.push(0); // reserved
        out.extend_from_slice(&1u16.to_le_bytes()); // planes
        out.extend_from_slice(&32u16.to_le_bytes()); // bitcount
        out.extend_from_slice(&4u32.to_le_bytes()); // bytes in resource
        out.extend_from_slice(&22u32.to_le_bytes()); // offset of data
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // data
        out
    }

    fn minimal_lnk() -> Vec<u8> {
        let mut out = vec![0u8; 0x4c];
        out[..4].copy_from_slice(&0x4cu32.to_le_bytes()); // HeaderSize
        out[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        out[0x14..0x18].copy_from_slice(&0u32.to_le_bytes()); // flags = 0
        out
    }

    #[test]
    fn all_new_validators_accept_minimal_fixtures() {
        let cases: Vec<(&str, CarveKind, Vec<u8>)> = vec![
            ("class", CarveKind::Class, minimal_class()),
            ("dex", CarveKind::Dex, minimal_dex()),
            ("tar", CarveKind::Tar, minimal_tar()),
            ("pcap", CarveKind::Pcap, minimal_pcap()),
            ("pcapng", CarveKind::Pcapng, minimal_pcapng()),
            ("evtx", CarveKind::Evtx, minimal_evtx()),
            ("flac", CarveKind::Flac, minimal_flac()),
            ("ogg", CarveKind::Ogg, minimal_ogg(false)),
            ("opus", CarveKind::Opus, minimal_ogg(true)),
            ("mp3-frame", CarveKind::Mp3, minimal_mp3_frame()),
            ("mp3-id3", CarveKind::Mp3, minimal_mp3_with_id3()),
            ("gif", CarveKind::Gif, minimal_gif()),
            ("ico", CarveKind::Ico, minimal_ico()),
            ("lnk", CarveKind::Lnk, minimal_lnk()),
        ];
        for (name, kind, payload) in cases {
            let report = carve_one(name, kind, &payload);
            assert_eq!(report.files.len(), 1, "{name}: {report:?}");
            assert_eq!(report.files[0].kind, kind, "{name}");
            assert!(report.files[0].complete, "{name}: {:?}", report.files[0]);
        }
    }

    #[test]
    fn aliases_map_to_shared_validators() {
        for (name, list) in [
            ("docx", "docx"),
            ("xlsx", "xlsx"),
            ("pptx", "pptx"),
            ("odt", "odt"),
            ("ods", "ods"),
            ("jar", "jar"),
            ("apk", "apk"),
            ("doc", "doc"),
            ("xls", "xls"),
            ("ppt", "ppt"),
            ("msi", "msi"),
            ("msg", "msg"),
            ("so", "so"),
            ("dll", "dll"),
            ("sys", "sys"),
            ("db", "db"),
            ("sqlite3", "sqlite3"),
            ("mov", "mov"),
            ("m4a", "m4a"),
            ("jpg", "jpg"),
            ("tiff", "tiff"),
        ] {
            assert!(CarveKind::from_list(list).is_ok(), "{name} must parse");
        }
        assert_eq!(CarveKind::from_list("docx").unwrap(), vec![CarveKind::Zip]);
        assert_eq!(CarveKind::from_list("msi").unwrap(), vec![CarveKind::Ole]);
        assert_eq!(CarveKind::from_list("db").unwrap(), vec![CarveKind::Sqlite]);
    }
}

#[cfg(test)]
mod naming_tests {
    use super::*;

    const SHA: &str = "9f3c1e2a77aa00bb11cc22dd33ee44ff";

    #[test]
    fn whole_file_name_keeps_the_original_extension_before_carved() {
        let name = carved_file_name(0x1a2b0, CarveKind::Zip, CarveRole::Whole, SHA);
        assert_eq!(name, "0001a2b0-zip-9f3c1e2a.zip.carved");
        let name = carved_file_name(0x4f0000, CarveKind::Pe, CarveRole::Whole, SHA);
        assert_eq!(name, "004f0000-pe-9f3c1e2a.exe.carved");
        let name = carved_file_name(0, CarveKind::Jpeg, CarveRole::Whole, SHA);
        assert_eq!(name, "00000000-jpeg-9f3c1e2a.jpg.carved");
    }

    #[test]
    fn plaintext_without_evidence_is_txt_carved() {
        let name = carved_file_name(0x2bc7c, CarveKind::Text, CarveRole::Whole, SHA);
        assert_eq!(name, "0002bc7c-text-9f3c1e2a.txt.carved");
    }

    #[test]
    fn a_salvaged_tail_says_so_in_its_name() {
        let name = carved_file_name(0x9000, CarveKind::Png, CarveRole::Tail, SHA);
        assert_eq!(name, "00009000-png-9f3c1e2a.png.tail.carved");
    }

    #[test]
    fn reassembled_files_use_the_extension_and_no_hash() {
        let name = carved_file_name(0x1000, CarveKind::Pdf, CarveRole::Reassembled, "");
        assert_eq!(name, "00001000-pdf-reassembled.pdf.carved");
    }

    #[test]
    fn short_or_empty_hash_never_panics() {
        let name = carved_file_name(1, CarveKind::Gif, CarveRole::Whole, "ab");
        assert_eq!(name, "00000001-gif-ab.gif.carved");
        let name = carved_file_name(1, CarveKind::Gif, CarveRole::Whole, "");
        assert_eq!(name, "00000001-gif-.gif.carved");
    }

    #[test]
    fn every_kind_has_a_safe_whitelisted_extension_and_ends_in_carved() {
        let mut kinds: Vec<CarveKind> = CarveKind::ALL.to_vec();
        kinds.push(CarveKind::Text);
        for kind in kinds {
            let ext = kind.default_ext();
            assert!(
                (1..=8).contains(&ext.len())
                    && ext.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{kind:?}: bad extension {ext:?}"
            );
            for role in [CarveRole::Whole, CarveRole::Tail, CarveRole::Reassembled] {
                let name = carved_file_name(0xdead_beef, kind, role, SHA);
                assert!(name.ends_with(".carved"), "{name}");
                assert!(name.contains(&format!(".{ext}.")), "{name}");
                assert!(!name.contains(['/', '\\', ':']), "{name}");
                assert!(name.len() < 100, "{name}");
            }
        }
    }
}
