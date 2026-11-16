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
/// Largest periodicity (in windows) scanned by the partial-encryption
/// heuristic; period is `windows * SPIKE_WINDOW` (64 KiB here).
const PARTIAL_ENC_MAX_PERIOD: usize = 16;
/// Minimum number of complete windows needed before the periodic scan reports
/// anything: 8 full periods of the shortest detectable cycle (period 2).
/// Larger periods are skipped when the file is too small for 8 periods.
const PARTIAL_ENC_MIN_WINDOWS: usize = 8 * 2;
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
/// Block size of the `--carve bin` pass: one entropy score per block.
const BIN_BLOCK: usize = 4096;
/// Smallest unclassified high-entropy run worth writing (4 blocks).
const BIN_MIN_REGION: u64 = 16 * 1024;

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
    /// MP4 container rebuilt around a surviving `moov` box (ROADMAP 8.11):
    /// fresh `ftyp`/`mdat` headers, sample tables shifted. Frames in the
    /// still-encrypted head may be unusable.
    Rebuilt,
    /// MP4 rebuilt like [`CarveRole::Rebuilt`] plus an edit list that
    /// starts playback at the first intact sync sample (ROADMAP 8.11.5).
    /// Same payload and sample tables; each `trak` gains an `edts`→`elst`
    /// with `media_time` set to the first intact sync sample's time.
    /// Emitted alongside the full rebuild, never instead of it.
    Cut,
}

impl CarveRole {
    /// Stable id used in the carve index: `whole`, `tail` or `reassembled`.
    pub fn as_str(self) -> &'static str {
        match self {
            CarveRole::Whole => "whole",
            CarveRole::Tail => "tail",
            CarveRole::Reassembled => "reassembled",
            CarveRole::Rebuilt => "rebuilt",
            CarveRole::Cut => "cut",
        }
    }
}

/// How sure the carver is that a file opens as its extension says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CarveConfidence {
    High,
    Medium,
    Low,
}

impl CarveConfidence {
    /// Stable id used in the carve index: `high`, `medium` or `low`.
    pub fn as_str(self) -> &'static str {
        match self {
            CarveConfidence::High => "high",
            CarveConfidence::Medium => "medium",
            CarveConfidence::Low => "low",
        }
    }
}

/// Evidence tier (ROADMAP 8.10.1), the checks that back it and the resulting
/// confidence. Only facts the carver actually established are listed:
///
/// * tier 1: header matched, the validator walked the structure and reached
///   the terminator (`complete`); plus the sniff rule when one refined `ext`;
/// * tier 2: header valid but the structure stops early, or a tail found from
///   its footer (head missing);
/// * tier 3: no structural evidence, only readable text.
///
/// Attach the partial-encryption hint to the evidence list when present.
fn with_suspect(
    mut evidence: Vec<&'static str>,
    hint: Option<PartialEncryption>,
) -> Vec<&'static str> {
    if hint.is_some() {
        evidence.push("suspected-partial-encryption");
    }
    evidence
}

fn evidence_for(
    role: CarveRole,
    kind: CarveKind,
    complete: bool,
    ext_source: &'static str,
) -> (u8, Vec<&'static str>, CarveConfidence) {
    match role {
        CarveRole::Tail => (2, vec!["footer"], CarveConfidence::Low),
        CarveRole::Reassembled => (2, vec!["magic", "reassembled"], CarveConfidence::Medium),
        // The three tables the rebuild actually cross-checked (8.11.1):
        // moov parsed, chunk tables cross-checked against stsz/stts, and
        // every chunk offset inside the payload.
        CarveRole::Rebuilt => (
            2,
            vec!["moov_ok", "tables_cross_ok", "chunk_range_ok"],
            CarveConfidence::Medium,
        ),
        // Same checks plus the edit list that starts playback at the
        // first intact sync sample.
        CarveRole::Cut => (
            2,
            vec!["moov_ok", "tables_cross_ok", "chunk_range_ok", "elst_cut"],
            CarveConfidence::Medium,
        ),
        CarveRole::Whole if kind == CarveKind::Text => {
            (3, vec!["text_ratio"], CarveConfidence::Low)
        }
        CarveRole::Whole if kind == CarveKind::Bin => (3, vec!["entropy"], CarveConfidence::Low),
        CarveRole::Whole if complete => {
            let mut evidence = vec!["magic", "structure_ok", "terminator_ok"];
            if ext_source.starts_with("sniff:") {
                evidence.push(ext_source);
            }
            (1, evidence, CarveConfidence::High)
        }
        CarveRole::Whole => (
            2,
            vec!["magic", "structure_partial"],
            CarveConfidence::Medium,
        ),
    }
}

/// Writer for one rebuilt/cut MP4 variant (same payload, different
/// `moov`): creates `partial/`, refuses to overwrite, streams the payload
/// out of the dump. Returns the path.
fn write_mp4_variant(
    dump_path: &str,
    payload_start: u64,
    payload_len: u64,
    moov: &[u8],
    out_dir: &Path,
    name: &str,
) -> io::Result<PathBuf> {
    let partial = out_dir.join("partial");
    std::fs::create_dir_all(&partial)?;
    let path = partial.join(name);
    if path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to overwrite '{}'; use a fresh --carve-out",
                path.display()
            ),
        ));
    }
    let mut source = File::open(dump_path)?;
    let mut out = BufWriter::new(File::create(&path)?);
    out.write_all(&rebuilt_header(payload_len))?;
    stream_region(&mut source, payload_start, payload_len, |chunk| {
        out.write_all(chunk)
    })?;
    out.write_all(moov)?;
    out.flush()?;
    Ok(path)
}

/// Result of the own-validator post-check on a just-written MP4 variant.
enum CarvedCheck {
    /// The file parses as a valid MP4; it may be handed out.
    Ok,
    /// The validator rejected it; the file has been deleted and the caller
    /// records a rejection with this reason.
    Rejected(String),
}

/// End-to-end post-check: the written file must pass our own MP4
/// validator before we hand it out. On rejection the file is removed.
fn check_carved_mp4(path: &Path) -> io::Result<CarvedCheck> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut check = Source::new(&mut file, 0, len);
    Ok(match carve_mp4(&mut check)? {
        Verdict::Valid => CarvedCheck::Ok,
        Verdict::Truncated(reason) | Verdict::Invalid(reason) => {
            std::fs::remove_file(path).ok();
            CarvedCheck::Rejected(reason)
        }
    })
}

/// One record for a rebuilt/cut MP4 pair (ROADMAP 8.11.5): evidence,
/// confidence, dedupe and the size/file-count limits. Returns `false`
/// when a limit was reached (the caller stops the salvage pass).
#[allow(clippy::too_many_arguments)]
fn push_carved_mp4(
    report: &mut CarveReport,
    by_hash: &mut HashMap<String, usize>,
    payload_start: u64,
    size: u64,
    sha256: String,
    entropy: f64,
    notes: String,
    path: Option<PathBuf>,
    role: CarveRole,
    trailer: (Option<u64>, Option<u64>, Option<String>, Option<String>),
    tracks_intact: &[TrackIntact],
    max_files: usize,
    max_total: u64,
) -> bool {
    by_hash.insert(sha256.clone(), report.files.len());
    report.bytes_written += size;
    let (tier, mut evidence, mut confidence) = evidence_for(role, CarveKind::Mp4, false, "kind");
    // Confidence reflects the NAL oracle when it could check a track:
    // high only when every checked video track is intact and the head sits
    // at byte 0; low when nothing survived.
    if !tracks_intact.is_empty() {
        evidence.push("nal_oracle");
        let all_intact = tracks_intact
            .iter()
            .all(|track| track.intact == track.samples);
        let any_intact = tracks_intact.iter().any(|track| track.intact > 0);
        if payload_start == 0 && all_intact {
            confidence = CarveConfidence::High;
        } else if !any_intact {
            confidence = CarveConfidence::Low;
        }
    }
    let tracks_intact = (!tracks_intact.is_empty()).then(|| tracks_intact.to_vec());
    report.files.push(CarvedFile {
        offset: payload_start,
        kind: CarveKind::Mp4,
        size,
        complete: false,
        sha256,
        entropy,
        notes,
        path,
        duplicates: Vec::new(),
        corrupted_offset: Some(payload_start),
        entropy_spike_at: None,
        partial_encryption: None,
        trailer_offset: trailer.0,
        trailer_len: trailer.1,
        trailer_sha256: trailer.2,
        trailer_preview: trailer.3,
        tracks_intact,
        ext: "mp4".to_string(),
        ext_source: "kind".to_string(),
        role,
        tier,
        evidence,
        confidence,
    });
    if max_files != 0 && report.files.len() >= max_files {
        report.truncated = true;
        return false;
    }
    if max_total != 0 && report.bytes_written >= max_total {
        report.truncated = true;
        return false;
    }
    true
}

/// Builds the one canonical output name: `{offset:08x}-{kind}-{sha8}.{ext}.carved`.
///
/// `.carved` is always the last extension so nothing auto-opens or runs the
/// file; `ext` comes only from the static [`CarveKind::default_ext`] table,
/// never from file contents, so the name cannot carry path separators or
/// other surprises. A salvaged tail gets `.tail` (`...png.tail.carved`) and a
/// reassembled file replaces the hash with `reassembled`.
pub fn carved_file_name(offset: u64, kind: CarveKind, role: CarveRole, sha256: &str) -> String {
    carved_file_name_with_ext(offset, kind, kind.default_ext(), role, sha256)
}

/// Like [`carved_file_name`] but with an extension already refined by the
/// content sniff. An `ext` outside `[a-z0-9]{1,8}` is ignored in favour of
/// the kind's default, so a name can never carry anything unexpected.
pub fn carved_file_name_with_ext(
    offset: u64,
    kind: CarveKind,
    ext: &str,
    role: CarveRole,
    sha256: &str,
) -> String {
    let ext = if (1..=8).contains(&ext.len())
        && ext
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        ext
    } else {
        kind.default_ext()
    };
    let kind_id = kind.as_str();
    match role {
        CarveRole::Whole => {
            format!("{offset:08x}-{kind_id}-{}.{ext}.carved", short_hash(sha256))
        }
        CarveRole::Tail => {
            format!(
                "{offset:08x}-{kind_id}-{}.{ext}.tail.carved",
                short_hash(sha256)
            )
        }
        CarveRole::Reassembled => {
            format!("{offset:08x}-{kind_id}-reassembled.{ext}.carved")
        }
        CarveRole::Rebuilt => {
            format!(
                "{offset:08x}-{kind_id}-{}.{ext}.rebuilt.carved",
                short_hash(sha256)
            )
        }
        CarveRole::Cut => {
            format!(
                "{offset:08x}-{kind_id}-{}.{ext}.cut.carved",
                short_hash(sha256)
            )
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
    /// Unclassified high-entropy data (compressed, encrypted or packed) that
    /// no other kind claimed. It has no magic number either, so the bin pass
    /// finds it by entropy and it is **not** part of [`CarveKind::ALL`]: ask
    /// for it with `--carve bin` (or `all,bin`).
    Bin,
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
            CarveKind::Bin => "bin",
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
            CarveKind::Bin => "bin",
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
            "zip" | "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp" | "jar" | "apk" => {
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
            "bin" => Some(CarveKind::Bin),
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

/// Exact-extension restriction derived from a `--carve` list (ROADMAP 8.10.6).
///
/// The dump is still scanned once per [`CarveKind`]; this only decides which
/// finished files are kept. A list token is either a whole format (`zip`,
/// `ole`, `pe`, `mp4`, `elf`, `jpg`, ...), which keeps every file of that
/// kind, or a specific extension that shares a container (`docx`, `xlsx`,
/// `pptx`, `odt`, `ods`, `odp`, `jar`, `apk`, `doc`, `xls`, `ppt`, `msi`,
/// `msg`, `dll`, `sys`, `mov`, `m4a`, `so`), which keeps only files whose
/// refined extension matches. Naming a kind both ways (`docx,zip`) keeps the
/// whole kind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtFilter {
    exact: Vec<(CarveKind, Vec<String>)>,
}

impl ExtFilter {
    /// Specific-extension aliases: the kind that carries them and the
    /// extension `refine_ext` gives such a file.
    fn specific(name: &str) -> Option<(CarveKind, &'static str)> {
        Some(match name {
            "docx" => (CarveKind::Zip, "docx"),
            "xlsx" => (CarveKind::Zip, "xlsx"),
            "pptx" => (CarveKind::Zip, "pptx"),
            "odt" => (CarveKind::Zip, "odt"),
            "ods" => (CarveKind::Zip, "ods"),
            "odp" => (CarveKind::Zip, "odp"),
            "jar" => (CarveKind::Zip, "jar"),
            "apk" => (CarveKind::Zip, "apk"),
            "doc" => (CarveKind::Ole, "doc"),
            "xls" => (CarveKind::Ole, "xls"),
            "ppt" => (CarveKind::Ole, "ppt"),
            "msi" => (CarveKind::Ole, "msi"),
            "msg" => (CarveKind::Ole, "msg"),
            "dll" => (CarveKind::Pe, "dll"),
            "sys" => (CarveKind::Pe, "sys"),
            "mov" => (CarveKind::Mp4, "mov"),
            "m4a" => (CarveKind::Mp4, "m4a"),
            "so" => (CarveKind::Elf, "so"),
            _ => return None,
        })
    }

    /// Build the filter from the same list `CarveKind::from_list` reads.
    pub fn from_list(list: &str) -> Result<Self, String> {
        let mut whole: Vec<CarveKind> = Vec::new();
        let mut exact: Vec<(CarveKind, Vec<String>)> = Vec::new();
        for raw in list.split(|ch: char| ch == ',' || ch == ';' || ch.is_whitespace()) {
            let name = raw.trim().to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            match Self::specific(&name) {
                Some((kind, ext)) => match exact.iter_mut().find(|(known, _)| *known == kind) {
                    Some((_, exts)) => {
                        if !exts.iter().any(|known| known == ext) {
                            exts.push(ext.to_string());
                        }
                    }
                    None => exact.push((kind, vec![ext.to_string()])),
                },
                None => {
                    for kind in CarveKind::from_list(&name)? {
                        if !whole.contains(&kind) {
                            whole.push(kind);
                        }
                    }
                }
            }
        }
        exact.retain(|(kind, _)| !whole.contains(kind));
        Ok(Self { exact })
    }

    /// True when no kind is restricted (every file is kept).
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty()
    }

    /// Whether a finished file of `kind` with refined extension `ext` is kept.
    pub fn allows(&self, kind: CarveKind, ext: &str) -> bool {
        match self.exact.iter().find(|(known, _)| *known == kind) {
            Some((_, exts)) => exts.iter().any(|known| known == ext),
            None => true,
        }
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

/// Periodic partial-encryption hint (ROADMAP 8.7.3): a repeating phase of
/// high-entropy windows inside an otherwise structured file, the signature of
/// file-system encryption that encrypts a fraction of every file (e.g.
/// every 4th 4 KiB block). This is a *heuristic label*, not a verdict:
/// compressed data scores as high entropy too, and the threshold alone
/// cannot tell the two apart.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PartialEncryption {
    /// Length of one repeat, in bytes (window size x windows per period).
    pub period: u64,
    /// Share of the analysed region covered by high-entropy windows.
    pub duty: f64,
    /// Window entropy threshold used to classify a window as encrypted.
    pub threshold: f64,
}

impl std::fmt::Display for PartialEncryption {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "suspected-partial-encryption (period={} B, duty={:.0}%, threshold={:.1})",
            self.period,
            self.duty * 100.0,
            self.threshold
        )
    }
}

/// Detect a recurring high-entropy phase in a window mask:
/// `high[i]` is true when window `i` has entropy >= [`SPIKE_HIGH`].
///
/// For every candidate period `P` (in windows), the windows are bucketed by
/// index modulo `P`. A cycle counts as recurring when at least one bucket is
/// almost always high (>= 80%) and every remaining bucket is almost always
/// structured (<= 30%). A uniformly high (or uniformly low) file is not
/// *partial* encryption: it fails the `duty >= 0.9` / `< 3 high windows`
/// guards. The smallest acceptable period is 2 windows; period 1 is
/// indistinguishable from uniform encryption and is rejected.
fn detect_periodic_high(high: &[bool]) -> Option<(u64, f64)> {
    let n = high.len();
    if n < PARTIAL_ENC_MIN_WINDOWS {
        return None;
    }
    let total_high = high.iter().filter(|&&flag| flag).count();
    if total_high < 3 {
        return None;
    }
    let overall_duty = total_high as f64 / n as f64;
    if overall_duty >= 0.9 {
        return None; // uniformly high (or almost): not *partial*
    }
    for period in 2..=PARTIAL_ENC_MAX_PERIOD {
        if n < period * 8 {
            break; // larger periods need more windows than the file holds
        }
        let mut per_bucket = [0usize; PARTIAL_ENC_MAX_PERIOD];
        let mut bucket_total = [0usize; PARTIAL_ENC_MAX_PERIOD];
        for (index, &flag) in high.iter().enumerate() {
            let bucket = index % period;
            bucket_total[bucket] += 1;
            if flag {
                per_bucket[bucket] += 1;
            }
        }
        let mut hot = 0usize;
        let mut cold = 0usize;
        for bucket in 0..period {
            let fraction = per_bucket[bucket] as f64 / bucket_total[bucket] as f64;
            if fraction >= 0.8 {
                hot += 1;
            } else if fraction <= 0.3 {
                cold += 1;
            }
        }
        if hot >= 1 && cold == period - hot {
            return Some((period as u64 * SPIKE_WINDOW as u64, overall_duty));
        }
    }
    None
}

/// Scan `[offset, offset + size)` in [`SPIKE_WINDOW`]-byte windows and report
/// a periodic high-entropy phase when one is found (ROADMAP 8.7.3).
/// Files too small to hold 8 full periods of any cycle return `None`.
fn periodic_encryption_scan(
    file: &mut File,
    offset: u64,
    size: u64,
) -> io::Result<Option<PartialEncryption>> {
    if size < (PARTIAL_ENC_MIN_WINDOWS * SPIKE_WINDOW) as u64 {
        return Ok(None);
    }
    let mut counts = [0u64; 256];
    let mut filled = 0usize;
    let mut mask: Vec<bool> = Vec::with_capacity((size / SPIKE_WINDOW as u64) as usize);
    stream_region(file, offset, size, |chunk| {
        for &byte in chunk {
            counts[byte as usize] += 1;
            filled += 1;
            if filled == SPIKE_WINDOW {
                mask.push(entropy(&counts, SPIKE_WINDOW as u64) >= SPIKE_HIGH);
                counts = [0u64; 256];
                filled = 0;
            }
        }
        Ok(())
    })?;
    Ok(
        detect_periodic_high(&mask).map(|(period, duty)| PartialEncryption {
            period,
            duty,
            threshold: SPIKE_HIGH,
        }),
    )
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
    /// ≥ 7.8 bits/byte after structured (< 7.0) data: a hint of where an
    /// encrypted region begins. Heuristic only (compressed data looks the
    /// same). `None` for complete files or when no such jump exists.
    pub entropy_spike_at: Option<u64>,
    /// Periodic high-entropy phase detected inside the file (ROADMAP
    /// 8.7.3): heuristic label for file-system encryption that encrypts a
    /// fraction of every file. `None` when the file is too small, fully
    /// structured or uniformly high (compressed/encrypted end to end).
    /// Compressed data also scores high, so this is a hint, not a verdict.
    pub partial_encryption: Option<PartialEncryption>,
    /// Trailer after the end of a rebuilt MP4's `moov` box (ROADMAP 8.11.3):
    /// whatever the ransomware appended after the original file (often a
    /// victim ID). Offset/len/sha256/preview describe the recorded slice,
    /// capped to 1 MiB of the source remainder. `None` for every other role.
    pub trailer_offset: Option<u64>,
    pub trailer_len: Option<u64>,
    pub trailer_sha256: Option<String>,
    pub trailer_preview: Option<String>,
    /// Per-track NAL oracle verdicts (ROADMAP 8.11.4); `None` outside
    /// rebuilt MP4s and for tracks with no AVC/HEVC video codec.
    pub tracks_intact: Option<Vec<TrackIntact>>,
    /// Extension carried before `.carved`: the kind's default, or a more
    /// specific one proven by the content sniff (ROADMAP 8.10.3).
    pub ext: String,
    /// Why `ext` was chosen: `kind`, `sniff:<rule>` or `fallback` (the sniff
    /// could not read enough structure, so the default stays).
    pub ext_source: String,
    /// Which piece of a file this output holds (whole, tail, reassembled).
    pub role: CarveRole,
    /// Evidence tier: 1 = structure validated to the terminator, 2 = header
    /// valid but incomplete (or a tail), 3 = readable text only.
    pub tier: u8,
    /// Checks that back the tier (`magic`, `structure_ok`, `terminator_ok`,
    /// `structure_partial`, `footer`, `text_ratio`, `sniff:<rule>`).
    pub evidence: Vec<&'static str>,
    pub confidence: CarveConfidence,
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
    /// Valid files left out because their extension did not match an exact
    /// extension filter (`--carve docx` skips a plain ZIP).
    pub filtered: usize,
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
        if !self.files.is_empty() {
            let mut tiers = [0usize; 3];
            let mut exts: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for file in &self.files {
                if let Some(slot) = tiers.get_mut(usize::from(file.tier).wrapping_sub(1)) {
                    *slot += 1;
                }
                *exts.entry(file.ext.as_str()).or_insert(0) += 1;
            }
            let tier_text = tiers
                .iter()
                .enumerate()
                .filter(|(_, count)| **count > 0)
                .map(|(index, count)| format!("T{}={count}", index + 1))
                .collect::<Vec<_>>()
                .join(" ");
            let ext_text = exts
                .iter()
                .map(|(ext, count)| format!("{ext}={count}"))
                .collect::<Vec<_>>()
                .join(" ");
            line.push_str(&format!(" (tier {tier_text}; ext {ext_text})"));
        }
        if self.duplicates > 0 {
            line.push_str(&format!(
                ", {} duplicate(s) skipped ({} bytes)",
                self.duplicates, self.duplicate_bytes
            ));
        }
        if self.filtered > 0 {
            line.push_str(&format!(
                ", {} file(s) filtered by extension",
                self.filtered
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
    ext_filter: ExtFilter,
}

impl Carver {
    pub fn new(options: CarveOptions) -> Self {
        Self {
            options,
            incomplete_dir: false,
            salvage: false,
            ext_filter: ExtFilter::default(),
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

    /// Keep only files whose refined extension passes `filter` (ROADMAP
    /// 8.10.6): `--carve docx` writes docx files, not every ZIP. The scan
    /// itself is unchanged; a filtered file still owns its bytes (nested hits
    /// stay suppressed) but is not written, deduplicated or counted against
    /// `max_files`/`max_total`, and is tallied in [`CarveReport::filtered`].
    pub fn with_ext_filter(mut self, filter: ExtFilter) -> Self {
        self.ext_filter = filter;
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
                // Heuristic: periodic high-entropy phase (1 in N blocks kept
                // encrypted). Cheap no-op for files too small to show one.
                let partial_encryption = match periodic_encryption_scan(&mut source, offset, size) {
                    Ok(hint) => hint,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                // Refine the extension from the bytes just validated (bounded
                // reads inside this region, no extra pass over the dump).
                let choice = crate::carve_ext::refine_ext(kind, &mut source, offset, size);
                // `--carve docx` keeps only files whose refined extension is
                // `docx` (ROADMAP 8.10.6). The file still owns its bytes, so
                // nested signatures stay suppressed, but it is not written,
                // hashed for dedupe or counted against the caps.
                if !self.ext_filter.allows(kind, choice.ext) {
                    report.filtered += 1;
                    covered_end = offset + size;
                    continue;
                }
                let path = match out_dir {
                    Some(dir) => {
                        let name = carved_file_name_with_ext(
                            offset,
                            kind,
                            choice.ext,
                            CarveRole::Whole,
                            &sha256,
                        );
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
                let (tier, evidence, confidence) =
                    evidence_for(CarveRole::Whole, kind, notes.is_empty(), choice.source);
                let evidence = with_suspect(evidence, partial_encryption);
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
                    partial_encryption,
                    trailer_offset: None,
                    trailer_len: None,
                    trailer_sha256: None,
                    trailer_preview: None,
                    tracks_intact: None,
                    ext: choice.ext.to_string(),
                    ext_source: choice.source.to_string(),
                    role: CarveRole::Whole,
                    tier,
                    evidence,
                    confidence,
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
        if self.options.kinds.contains(&CarveKind::Bin) {
            self.bin_pass(dump_path, out_dir, file_len, &mut report)?;
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
                if kind == CarveKind::Mp4 {
                    // 8.11: rebuild the container instead of salvaging a
                    // tail. The head is gone, `moov` survived; emit a fresh
                    // `ftyp`/`mdat` header and shift every chunk offset.
                    let rebuilt = match mp4_rebuild(
                        &mut source,
                        position,
                        file_len,
                        self.options.max_size,
                        &covered,
                    ) {
                        Ok(Ok(rebuilt)) => rebuilt,
                        Ok(Err(reason)) => {
                            report.rejected += 1;
                            if report.rejected_details.len() < 16 {
                                report.rejected_details.push(format!(
                                    "{:#x} mp4: {reason}",
                                    position.saturating_sub(4)
                                ));
                            }
                            continue;
                        }
                        Err(error) => {
                            failure = Some(error);
                            return false;
                        }
                    };
                    let size = rebuilt.rebuilt_len;
                    if size < self.options.min_size {
                        report.rejected += 1;
                        continue;
                    }
                    // The original moov box end in the dump:
                    let moov_end = rebuilt.moov_end;
                    if !self.ext_filter.allows(CarveKind::Mp4, "mp4") {
                        covered.push((rebuilt.payload_start, moov_end));
                        report.filtered += 1;
                        continue;
                    }
                    let sha256 = rebuilt.sha256.clone();
                    let entropy = rebuilt.entropy;
                    let trailer = (
                        rebuilt.trailer_offset,
                        rebuilt.trailer_len,
                        rebuilt.trailer_sha256.clone(),
                        rebuilt.trailer_preview.clone(),
                    );
                    covered.push((rebuilt.payload_start, moov_end));
                    let rebuilt_duplicate = by_hash.get(&sha256).copied();
                    if let Some(&index) = rebuilt_duplicate.as_ref() {
                        report.duplicates += 1;
                        report.duplicate_bytes += size;
                        report.files[index].duplicates.push(rebuilt.payload_start);
                    }
                    let path = match rebuilt_duplicate {
                        Some(_) => None,
                        None => match out_dir {
                            Some(dir) => {
                                // A rebuilt MP4 is incomplete by definition,
                                // so it always goes beside the other
                                // partial files.
                                let name = carved_file_name_with_ext(
                                    rebuilt.payload_start,
                                    CarveKind::Mp4,
                                    "mp4",
                                    CarveRole::Rebuilt,
                                    &sha256,
                                );
                                match write_mp4_variant(
                                    dump_path,
                                    rebuilt.payload_start,
                                    rebuilt.payload_len,
                                    &rebuilt.moov,
                                    dir,
                                    &name,
                                ) {
                                    Ok(path) => Some(path),
                                    Err(error) => {
                                        failure = Some(error);
                                        return false;
                                    }
                                }
                            }
                            None => None,
                        },
                    };
                    if rebuilt_duplicate.is_none() {
                        // End-to-end: the written file must pass our own MP4
                        // validator before we hand it out.
                        if let Some(path) = &path {
                            match check_carved_mp4(path) {
                                Ok(CarvedCheck::Ok) => {}
                                Ok(CarvedCheck::Rejected(reason)) => {
                                    report.rejected += 1;
                                    if report.rejected_details.len() < 16 {
                                        report.rejected_details.push(format!(
                                            "{:#x} mp4: rebuilt file invalid at own validator: {reason}",
                                            rebuilt.payload_start
                                        ));
                                    }
                                    covered.pop();
                                    continue;
                                }
                                Err(error) => {
                                    failure = Some(error);
                                    return false;
                                }
                            }
                        }
                        if !push_carved_mp4(
                            report,
                            &mut by_hash,
                            rebuilt.payload_start,
                            size,
                            sha256,
                            entropy,
                            rebuilt.notes.clone(),
                            path,
                            CarveRole::Rebuilt,
                            trailer.clone(),
                            &rebuilt.tracks_intact,
                            self.options.max_files,
                            self.options.max_total,
                        ) {
                            stop = true;
                            return false;
                        }
                    }

                    // ROADMAP 8.11.5: the cut sibling — never instead of the
                    // full rebuild. Same payload and tables; each track
                    // gains an edit list so playback starts at the first
                    // intact sync sample.
                    if let Some(cut) = &rebuilt.cut {
                        if let Some(&index) = by_hash.get(&cut.sha256) {
                            report.duplicates += 1;
                            report.duplicate_bytes += cut.len;
                            report.files[index].duplicates.push(rebuilt.payload_start);
                            continue;
                        }
                        let path = match out_dir {
                            Some(dir) => {
                                let name = carved_file_name_with_ext(
                                    rebuilt.payload_start,
                                    CarveKind::Mp4,
                                    "mp4",
                                    CarveRole::Cut,
                                    &cut.sha256,
                                );
                                match write_mp4_variant(
                                    dump_path,
                                    rebuilt.payload_start,
                                    rebuilt.payload_len,
                                    &cut.moov,
                                    dir,
                                    &name,
                                ) {
                                    Ok(path) => Some(path),
                                    Err(error) => {
                                        failure = Some(error);
                                        return false;
                                    }
                                }
                            }
                            None => None,
                        };
                        let mut cut_ok = true;
                        if let Some(path) = &path {
                            match check_carved_mp4(path) {
                                Ok(CarvedCheck::Ok) => {}
                                Ok(CarvedCheck::Rejected(reason)) => {
                                    report.rejected += 1;
                                    if report.rejected_details.len() < 16 {
                                        report.rejected_details.push(format!(
                                            "{:#x} mp4: cut file invalid at own validator: {reason}",
                                            rebuilt.payload_start
                                        ));
                                    }
                                    cut_ok = false;
                                }
                                Err(error) => {
                                    failure = Some(error);
                                    return false;
                                }
                            }
                        }
                        if cut_ok
                            && !push_carved_mp4(
                                report,
                                &mut by_hash,
                                rebuilt.payload_start,
                                cut.len,
                                cut.sha256.clone(),
                                cut.entropy,
                                cut.notes.clone(),
                                path,
                                CarveRole::Cut,
                                trailer,
                                &rebuilt.tracks_intact,
                                self.options.max_files,
                                self.options.max_total,
                            )
                        {
                            stop = true;
                            return false;
                        }
                    }
                    continue;
                }
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
                // A salvaged tail keeps the kind's default extension (its
                // header is gone, so nothing can be sniffed): an exact
                // extension filter cannot vouch for it and skips it.
                if !self.ext_filter.allows(kind, kind.default_ext()) {
                    covered.push((tail.start, tail.end));
                    report.filtered += 1;
                    continue;
                }
                let (sha256, entropy) = match digest_region(&mut source, tail.start, size) {
                    Ok(digest) => digest,
                    Err(error) => {
                        failure = Some(error);
                        return false;
                    }
                };
                let partial_encryption =
                    match periodic_encryption_scan(&mut source, tail.start, size) {
                        Ok(hint) => hint,
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
                let (tier, evidence, confidence) =
                    evidence_for(CarveRole::Tail, kind, false, "kind");
                let evidence = with_suspect(evidence, partial_encryption);
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
                    partial_encryption,
                    trailer_offset: None,
                    trailer_len: None,
                    trailer_sha256: None,
                    trailer_preview: None,
                    tracks_intact: None,
                    ext: kind.default_ext().to_string(),
                    ext_source: "kind".to_string(),
                    role: CarveRole::Tail,
                    tier,
                    evidence,
                    confidence,
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
                    let name = carved_file_name(start, CarveKind::Text, CarveRole::Whole, &sha256);
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
            let (tier, evidence, confidence) =
                evidence_for(CarveRole::Whole, CarveKind::Text, false, "kind");
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
                partial_encryption: None,
                trailer_offset: None,
                trailer_len: None,
                trailer_sha256: None,
                trailer_preview: None,
                tracks_intact: None,
                ext: CarveKind::Text.default_ext().to_string(),
                ext_source: "kind".to_string(),
                role: CarveRole::Whole,
                tier,
                evidence,
                confidence,
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

    /// Fourth pass behind `--carve bin` (it runs only when [`CarveKind::Bin`]
    /// is in the wanted kinds, after the text pass): cut out runs of
    /// high-entropy blocks that no carved file already covers. They have no
    /// structure to check, so each is `complete: false`, tier 3 with the
    /// `entropy` evidence, written to `partial/` as `...bin.carved`. A run
    /// longer than `max_size` is split into `max_size` pieces; dedupe and the
    /// `max_files`/`max_total` caps match the other passes. Nothing is
    /// decrypted or repaired.
    fn bin_pass(
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
        let max_chunk = if self.options.max_size == 0 {
            u64::MAX
        } else {
            self.options.max_size
        };
        let min_region = self.options.min_size.max(1).max(BIN_MIN_REGION);

        'regions: for (region_start, region_end) in bin_regions(&mut source, file_len, &covered)? {
            let mut start = region_start;
            while start < region_end {
                let end = region_end.min(start.saturating_add(max_chunk));
                let at = start;
                start = end;
                let size = end - at;
                if size < min_region {
                    continue;
                }
                let (sha256, entropy) = digest_region(&mut source, at, size)?;
                if let Some(&index) = by_hash.get(&sha256) {
                    report.duplicates += 1;
                    report.duplicate_bytes += size;
                    report.files[index].duplicates.push(at);
                    continue;
                }
                let path = match out_dir {
                    Some(dir) => {
                        // Unclassified data has no structure to vouch for it,
                        // so it always goes beside the other partial files.
                        let partial = dir.join("partial");
                        std::fs::create_dir_all(&partial)?;
                        let name = carved_file_name(at, CarveKind::Bin, CarveRole::Whole, &sha256);
                        let path = partial.join(name);
                        if path.exists() {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                format!(
                                    "refusing to overwrite '{}'; use a fresh --carve-out",
                                    path.display()
                                ),
                            ));
                        }
                        write_region(&mut source, at, size, &path)?;
                        Some(path)
                    }
                    None => None,
                };
                let partial_encryption = periodic_encryption_scan(&mut source, at, size)?;
                let notes = format!(
                    "bin:region 0x{at:x}-0x{end:x}; entropy {entropy:.2} bits/byte; unclassified (compressed, encrypted or packed)"
                );
                by_hash.insert(sha256.clone(), report.files.len());
                report.bytes_written += size;
                let (tier, evidence, confidence) =
                    evidence_for(CarveRole::Whole, CarveKind::Bin, false, "kind");
                let evidence = with_suspect(evidence, partial_encryption);
                report.files.push(CarvedFile {
                    offset: at,
                    kind: CarveKind::Bin,
                    size,
                    complete: false,
                    sha256,
                    entropy,
                    notes,
                    path,
                    duplicates: Vec::new(),
                    corrupted_offset: None,
                    entropy_spike_at: None,
                    partial_encryption,
                    trailer_offset: None,
                    trailer_len: None,
                    trailer_sha256: None,
                    trailer_preview: None,
                    tracks_intact: None,
                    ext: CarveKind::Bin.default_ext().to_string(),
                    ext_source: "kind".to_string(),
                    role: CarveRole::Whole,
                    tier,
                    evidence,
                    confidence,
                });

                if self.options.max_files != 0 && report.files.len() >= self.options.max_files {
                    report.truncated = true;
                    break 'regions;
                }
                if self.options.max_total != 0 && report.bytes_written >= self.options.max_total {
                    report.truncated = true;
                    break 'regions;
                }
            }
        }
        Ok(())
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
    // `ftyp` box sizes seen in the wild: 0x14 (QuickTime), 0x18 (phones:
    // `isom` + one compatible brand), 0x1c, 0x20 (ffmpeg/`isom`+`mp42`), 0x24,
    // 0x28. The box size is part of the needle, so each needs its own entry;
    // matching only 0x20 sent every real 24-byte-`ftyp` MP4 down the rebuild
    // path. `carve_mp4` walks boxes generically, so any size validates.
    Signature {
        bytes: b"\x00\x00\x00\x14ftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x18ftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x1cftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x20ftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x24ftyp",
        kind: "MP4/QuickTime media",
        carve: Some("mp4"),
    },
    Signature {
        bytes: b"\x00\x00\x00\x28ftyp",
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
/// MP4 `moov` box type. Short and common in random data, so the salvage
/// pass only accepts it after the full `moov` structure validates (8.11).
const MP4_MOOV: &[u8] = b"moov";
/// How far back from an IEND the PNG tail salvage reads at most.
const PNG_SALVAGE_WINDOW: u64 = 64 * 1024 * 1024;
/// Longest footer minus one: chunk overlap so a footer split across two
/// chunks is still seen once.
const FOOTER_OVERLAP: usize = 11;

/// Footers the salvage pass understands. Only formats whose footer is long or
/// can be checked structurally are listed: a bare JPEG `FF D9` would flood the
/// pass with false positives, and JPEG bodies are compressed already, so an
/// entropy boundary says nothing about them. PNG is walked back chunk by
/// chunk (CRC-verified) instead of by entropy. An MP4 `moov` is accepted only
/// when the whole box parses and its chunk tables cross-check (8.11).
fn has_footer(kind: CarveKind) -> bool {
    matches!(
        kind,
        CarveKind::Zip | CarveKind::Pdf | CarveKind::Png | CarveKind::Mp4
    )
}

struct FooterMatcher {
    aho: AhoCorasick,
    kinds: [CarveKind; 4],
}

fn footer_matcher() -> &'static FooterMatcher {
    static MATCHER: OnceLock<FooterMatcher> = OnceLock::new();
    MATCHER.get_or_init(|| FooterMatcher {
        aho: AhoCorasickBuilder::new()
            .build([ZIP_EOCD, PDF_EOF, PNG_IEND, MP4_MOOV])
            .expect("footer patterns are valid"),
        kinds: [
            CarveKind::Zip,
            CarveKind::Pdf,
            CarveKind::Png,
            CarveKind::Mp4,
        ],
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
fn salvage_read(
    file: &mut File,
    offset: u64,
    len: usize,
    file_len: u64,
) -> io::Result<Option<Vec<u8>>> {
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
    if !bytes[i + 2..i + len]
        .iter()
        .all(|b| (0x80..=0xbf).contains(b))
    {
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

/// Absolute offsets of the unclassified high-entropy runs in `file`: runs of
/// consecutive full [`BIN_BLOCK`] blocks whose Shannon entropy is at least
/// [`crate::ENTROPY_DEFAULT_THRESHOLD`], with already-covered ranges
/// subtracted and pieces under [`BIN_MIN_REGION`] dropped. Streams the file
/// once; no block list is held in memory.
fn bin_regions(
    file: &mut File,
    file_len: u64,
    covered: &[(u64, u64)],
) -> io::Result<Vec<(u64, u64)>> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    let mut current: Option<(u64, u64)> = None;
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
        for block in buffer[..filled].chunks(BIN_BLOCK) {
            let high = block.len() == BIN_BLOCK
                && crate::shannon_entropy(block) >= crate::ENTROPY_DEFAULT_THRESHOLD;
            let end = abs + block.len() as u64;
            if high {
                match current.as_mut() {
                    Some(run) => run.1 = end,
                    None => current = Some((abs, end)),
                }
            } else if let Some(run) = current.take() {
                runs.push(run);
            }
            abs = end;
        }
    }
    if let Some(run) = current.take() {
        runs.push(run);
    }
    debug_assert!(abs <= file_len);

    let mut out = Vec::new();
    for run in runs {
        for piece in subtract_covered(run, covered) {
            if piece.1 - piece.0 >= BIN_MIN_REGION {
                out.push(piece);
            }
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
        CarveKind::Mp4 => Ok(None), // handled by mp4_rebuild() in the salvage pass
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

// --- MP4/MOV rebuild from a surviving `moov` (ROADMAP 8.11) ------------------

/// Largest `moov` box we read into memory to rebuild a file whose head is
/// missing. Anything bigger is rejected before allocation.
const MAX_MOOV_READ: u64 = 64 * 1024 * 1024;
/// `stsc` entry cap per track (real files: hundreds to a few thousand).
const MAX_STSC_ENTRIES: u64 = 1_000_000;
/// `stts` entry cap per track.
const MAX_STTS_ENTRIES: u64 = 200_000;
/// Sample count cap per track (from `stsz`/`stz2`).
const MAX_SAMPLES: u64 = 20_000_000;
/// Chunk (`stco`/`co64`) count cap per track.
const MAX_CHUNKS: u64 = 20_000_000;
/// Depth of the `moov` box tree we walk while checking it.
const MAX_BOX_DEPTH: usize = 6;
/// Box cap for one `moov`, guarding pathological nesting.
const MAX_BOXES_IN_MOOV: u64 = 200_000;
/// Ransomware trailer recorded in the index, capped to this many bytes.
const MP4_TRAILER_CAP: u64 = 1024 * 1024;
/// `ftyp` we regenerate: major brand `isom`, minor version 0, compatible
/// brands `isom` + `mp42`. 24 bytes.
const FTYP_BOX: &[u8] = b"\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isommp42";
/// Payload this large needs a 64-bit `mdat` size header.
const MDAT_LARGE_THRESHOLD: u64 = u32::MAX as u64 - 8;

/// One box in the `moov` tree. `children` is non-empty only for the
/// container types the patcher understands.
#[derive(Clone)]
struct MoovBox {
    typ: [u8; 4],
    /// Raw box contents (without the 8- or 16-byte box header).
    data: Vec<u8>,
    /// Child boxes in file order (empty for leaf types).
    children: Vec<MoovBox>,
    /// `stco` table the rebuild promotes to `co64` because an entry would
    /// not fit in 32 bits once the shift is added (8.11.3).
    promote_to_co64: bool,
}

/// MP4 box types whose children we walk/patch; anything else is raw bytes.
fn mp4_is_container(typ: &[u8; 4]) -> bool {
    matches!(
        typ,
        b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf" | b"mvex"
    )
}

/// Parse the box at `[at, limit)` into a tree. Bounds are checked against
/// the parent box, never trusted from the header itself.
fn parse_mp4_box(
    buf: &[u8],
    at: usize,
    limit: usize,
    depth: usize,
    seen: &mut u64,
) -> Result<(MoovBox, usize), String> {
    if depth > MAX_BOX_DEPTH {
        return Err("boxes nested too deeply".to_string());
    }
    if at.checked_add(8).map_or(true, |end| end > limit) {
        return Err("box header runs past the end of its parent".to_string());
    }
    let size32 = u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]) as u64;
    let typ: [u8; 4] = buf[at + 4..at + 8]
        .try_into()
        .expect("slice of four bytes is four bytes");
    let (header, size) = if size32 == 1 {
        if at.checked_add(16).map_or(true, |end| end > limit) {
            return Err("extended box header runs past the end of its parent".to_string());
        }
        let large = u64::from_be_bytes(
            buf[at + 8..at + 16]
                .try_into()
                .expect("slice of eight bytes is eight bytes"),
        );
        if large < 16 {
            return Err("extended box size is smaller than its header".to_string());
        }
        (16usize, large)
    } else if size32 == 0 {
        // Box runs to the end of its parent: legal for the last box in a
        // container.
        (8usize, (limit - at) as u64)
    } else {
        (8usize, size32)
    };
    if size < header as u64 {
        return Err("box is smaller than its header".to_string());
    }
    let end = at as u64 + size;
    if end > limit as u64 {
        return Err("box extends past the end of its parent".to_string());
    }
    *seen += 1;
    if *seen > MAX_BOXES_IN_MOOV {
        return Err("too many boxes in moov".to_string());
    }
    let body = &buf[at + header..end as usize];
    if mp4_is_container(&typ) {
        let mut node = MoovBox {
            typ,
            data: Vec::new(),
            children: Vec::new(),
            promote_to_co64: false,
        };
        let mut cursor = 0usize;
        while cursor < body.len() {
            let (child, next) = parse_mp4_box(body, cursor, body.len(), depth + 1, seen)?;
            node.children.push(child);
            cursor = next;
        }
        Ok((node, end as usize))
    } else {
        Ok((
            MoovBox {
                typ,
                data: body.to_vec(),
                children: Vec::new(),
                promote_to_co64: false,
            },
            end as usize,
        ))
    }
}

/// `u32` sample-size cursor over the raw `stsz`/`stz2` table bytes.
enum SampleSizeCursor<'a> {
    Constant {
        sample_size: u32,
        count: u64,
        index: u64,
    },
    Fixed32 {
        data: &'a [u8],
        count: u64,
        index: u64,
    },
    Fixed16 {
        data: &'a [u8],
        count: u64,
        index: u64,
    },
    Fixed8 {
        data: &'a [u8],
        count: u64,
        index: u64,
    },
    Nibble {
        data: &'a [u8],
        count: u64,
        index: u64,
    },
}

impl<'a> SampleSizeCursor<'a> {
    fn count(&self) -> u64 {
        match self {
            SampleSizeCursor::Constant { count, .. }
            | SampleSizeCursor::Fixed32 { count, .. }
            | SampleSizeCursor::Fixed16 { count, .. }
            | SampleSizeCursor::Fixed8 { count, .. }
            | SampleSizeCursor::Nibble { count, .. } => *count,
        }
    }

    fn next(&mut self) -> Result<u64, String> {
        let count = self.count();
        // Copy the index out so the borrow ends before the size lookup.
        let at: u64 = *match &mut *self {
            SampleSizeCursor::Constant { index, .. }
            | SampleSizeCursor::Fixed32 { index, .. }
            | SampleSizeCursor::Fixed16 { index, .. }
            | SampleSizeCursor::Fixed8 { index, .. }
            | SampleSizeCursor::Nibble { index, .. } => index,
        };
        if at >= count {
            return Err("chunk tables reference more samples than stsz holds".to_string());
        }
        let size = match &*self {
            SampleSizeCursor::Constant { sample_size, .. } => u64::from(*sample_size),
            SampleSizeCursor::Fixed32 { data, .. } => {
                let at = at as usize * 4;
                u64::from(u32::from_be_bytes(data[at..at + 4].try_into().unwrap()))
            }
            SampleSizeCursor::Fixed16 { data, .. } => {
                let at = at as usize * 2;
                u64::from(u16::from_be_bytes(data[at..at + 2].try_into().unwrap()))
            }
            SampleSizeCursor::Fixed8 { data, .. } => u64::from(data[at as usize]),
            SampleSizeCursor::Nibble { data, .. } => {
                let byte = data[at as usize / 2];
                if at % 2 == 0 {
                    u64::from(byte >> 4)
                } else {
                    u64::from(byte & 0x0f)
                }
            }
        };
        match &mut *self {
            SampleSizeCursor::Constant { index, .. }
            | SampleSizeCursor::Fixed32 { index, .. }
            | SampleSizeCursor::Fixed16 { index, .. }
            | SampleSizeCursor::Fixed8 { index, .. }
            | SampleSizeCursor::Nibble { index, .. } => *index += 1,
        }
        Ok(size)
    }
}

/// `stco`/`co64` chunk offsets, in file order.
enum ChunkOffsets<'a> {
    Stco32 { data: &'a [u8], count: u64 },
    Co64 { data: &'a [u8], count: u64 },
}

impl<'a> ChunkOffsets<'a> {
    fn count(&self) -> u64 {
        match self {
            ChunkOffsets::Stco32 { count, .. } | ChunkOffsets::Co64 { count, .. } => *count,
        }
    }

    fn get(&self, index: u64) -> Result<u64, String> {
        match self {
            ChunkOffsets::Stco32 { data, .. } => {
                let at = index as usize * 4;
                Ok(u64::from(u32::from_be_bytes(
                    data[at..at + 4].try_into().unwrap(),
                )))
            }
            ChunkOffsets::Co64 { data, .. } => {
                let at = index as usize * 8;
                Ok(u64::from_be_bytes(data[at..at + 8].try_into().unwrap()))
            }
        }
    }
}

/// One `stbl` box, parsed and cross-checked (8.11.1). Raw tables are kept
/// for the NAL oracle (8.11.4).
struct StblTables<'a> {
    /// Raw `stsd` box bytes: version/flags + entry_count + sample entries.
    stsd: &'a [u8],
    total_samples: u64,
    /// `(sample_count, sample_delta)` pairs from `stts`.
    stts: Vec<(u32, u32)>,
    /// `(first_chunk, samples_per_chunk)` pairs from `stsc`.
    stsc: Vec<(u32, u32)>,
    sizes: SampleSizeCursor<'a>,
    chunks: ChunkOffsets<'a>,
    /// `stss` sample numbers (1-based, ascending), when the table exists.
    stss: Option<Vec<u32>>,
}

/// Parse and fully cross-check one `stbl` (8.11.1): `stsd`, `stts`, `stsc`,
/// `stsz`/`stz2`, `stco`/`co64`. Shared by [`analyze_stbl`] (rebuild) and
/// the NAL oracle (8.11.4).
fn parse_stbl_tables(stbl: &MoovBox) -> Result<StblTables<'_>, String> {
    let find = |typ: &[u8; 4]| stbl.children.iter().find(|child| &child.typ == typ);

    // stsd must exist and hold at least one sample entry.
    let stsd = find(b"stsd").ok_or_else(|| "stbl has no stsd".to_string())?;
    if stsd.data.len() < 16 {
        return Err("stsd is truncated".to_string());
    }
    let entry_count_stsd = u32::from_be_bytes(stsd.data[4..8].try_into().unwrap());
    if entry_count_stsd == 0 {
        return Err("stsd has no sample entries".to_string());
    }

    // stts: total sample count, cross-checked against stsz below.
    let stts = find(b"stts").ok_or_else(|| "stbl has no stts".to_string())?;
    if stts.data.len() < 8 {
        return Err("stts truncated".to_string());
    }
    let stts_entries = u64::from(u32::from_be_bytes(stts.data[4..8].try_into().unwrap()));
    if stts_entries > MAX_STTS_ENTRIES {
        return Err("stts has too many entries".to_string());
    }
    if stts.data.len() != 8 + 8 * stts_entries as usize {
        return Err("stts size does not match its entry count".to_string());
    }
    let mut stts_table: Vec<(u32, u32)> = Vec::with_capacity(stts_entries as usize);
    let mut total_samples = 0u64;
    for index in 0..stts_entries {
        let base = 8 + index as usize * 8;
        let count = u32::from_be_bytes(stts.data[base..base + 4].try_into().unwrap());
        let delta = u32::from_be_bytes(stts.data[base + 4..base + 8].try_into().unwrap());
        total_samples += u64::from(count);
        if total_samples > MAX_SAMPLES {
            return Err("track has too many samples".to_string());
        }
        stts_table.push((count, delta));
    }

    // stsc: (first_chunk, samples_per_chunk) pairs, strictly increasing.
    let stsc = find(b"stsc").ok_or_else(|| "stbl has no stsc".to_string())?;
    if stsc.data.len() < 8 {
        return Err("stsc truncated".to_string());
    }
    let stsc_entries = u64::from(u32::from_be_bytes(stsc.data[4..8].try_into().unwrap()));
    if stsc_entries == 0 {
        return Err("stsc has no entries".to_string());
    }
    if stsc_entries > MAX_STSC_ENTRIES {
        return Err("stsc has too many entries".to_string());
    }
    if stsc.data.len() != 8 + 12 * stsc_entries as usize {
        return Err("stsc size does not match its entry count".to_string());
    }
    let mut stsc_table: Vec<(u32, u32)> = Vec::with_capacity(stsc_entries as usize);
    for index in 0..stsc_entries {
        let base = 8 + index as usize * 12;
        let first_chunk = u32::from_be_bytes(stsc.data[base..base + 4].try_into().unwrap());
        let samples_per_chunk =
            u32::from_be_bytes(stsc.data[base + 4..base + 8].try_into().unwrap());
        if samples_per_chunk == 0 {
            return Err("stsc entry has zero samples per chunk".to_string());
        }
        if let Some(&(previous, _)) = stsc_table.last() {
            if first_chunk <= previous {
                return Err("stsc first_chunk values are not increasing".to_string());
            }
        }
        stsc_table.push((first_chunk, samples_per_chunk));
    }

    // stsz or stz2: one of them, exactly.
    let stsz = find(b"stsz");
    let stz2 = find(b"stz2");
    let sizes = match (stsz, stz2) {
        (Some(stsz), None) => {
            if stsz.data.len() < 12 {
                return Err("stsz truncated".to_string());
            }
            let sample_size = u32::from_be_bytes(stsz.data[4..8].try_into().unwrap());
            let entry_count = u64::from(u32::from_be_bytes(stsz.data[8..12].try_into().unwrap()));
            if entry_count != total_samples {
                return Err("stsz entry count does not match stts".to_string());
            }
            if entry_count > MAX_SAMPLES {
                return Err("track has too many samples".to_string());
            }
            if sample_size != 0 {
                if stsz.data.len() != 12 {
                    return Err(
                        "stsz with a constant sample size has a table it should not".to_string()
                    );
                }
                SampleSizeCursor::Constant {
                    sample_size,
                    count: entry_count,
                    index: 0,
                }
            } else {
                if stsz.data.len() != 12 + 4 * entry_count as usize {
                    return Err("stsz table size does not match its entry count".to_string());
                }
                SampleSizeCursor::Fixed32 {
                    data: &stsz.data[12..],
                    count: entry_count,
                    index: 0,
                }
            }
        }
        (None, Some(stz2)) => {
            if stz2.data.len() < 12 {
                return Err("stz2 truncated".to_string());
            }
            let field_size = stz2.data[7];
            if !matches!(field_size, 4 | 8 | 16) {
                return Err("stz2 field size is not 4, 8 or 16".to_string());
            }
            let entry_count = u64::from(u32::from_be_bytes(stz2.data[8..12].try_into().unwrap()));
            if entry_count != total_samples {
                return Err("stz2 entry count does not match stts".to_string());
            }
            if entry_count > MAX_SAMPLES {
                return Err("track has too many samples".to_string());
            }
            let packed = (entry_count * u64::from(field_size)).div_ceil(8) as usize;
            if stz2.data.len() != 12 + packed {
                return Err("stz2 table size does not match its entry count".to_string());
            }
            match field_size {
                4 => SampleSizeCursor::Nibble {
                    data: &stz2.data[12..],
                    count: entry_count,
                    index: 0,
                },
                8 => SampleSizeCursor::Fixed8 {
                    data: &stz2.data[12..],
                    count: entry_count,
                    index: 0,
                },
                _ => SampleSizeCursor::Fixed16 {
                    data: &stz2.data[12..],
                    count: entry_count,
                    index: 0,
                },
            }
        }
        (Some(_), Some(_)) => return Err("stbl has both stsz and stz2".to_string()),
        (None, None) => return Err("stbl has neither stsz nor stz2".to_string()),
    };

    // stco or co64: chunk offsets.
    let stco = find(b"stco");
    let co64 = find(b"co64");
    let offsets = match (stco, co64) {
        (Some(stco), None) => {
            if stco.data.len() < 8 {
                return Err("stco truncated".to_string());
            }
            let count = u64::from(u32::from_be_bytes(stco.data[4..8].try_into().unwrap()));
            if count == 0 || count > MAX_CHUNKS {
                return Err("stco has an implausible chunk count".to_string());
            }
            if stco.data.len() != 8 + 4 * count as usize {
                return Err("stco size does not match its entry count".to_string());
            }
            ChunkOffsets::Stco32 {
                data: &stco.data[8..],
                count,
            }
        }
        (None, Some(co64)) => {
            if co64.data.len() < 8 {
                return Err("co64 truncated".to_string());
            }
            let count = u64::from(u32::from_be_bytes(co64.data[4..8].try_into().unwrap()));
            if count == 0 || count > MAX_CHUNKS {
                return Err("co64 has an implausible chunk count".to_string());
            }
            if co64.data.len() != 8 + 8 * count as usize {
                return Err("co64 size does not match its entry count".to_string());
            }
            ChunkOffsets::Co64 {
                data: &co64.data[8..],
                count,
            }
        }
        (Some(_), Some(_)) => return Err("stbl has both stco and co64".to_string()),
        (None, None) => return Err("stbl has neither stco nor co64".to_string()),
    };

    // stss: optional sync-sample table (ascending sample numbers, 1-based).
    let stss = match find(b"stss") {
        Some(stss_box) => {
            if stss_box.data.len() < 8 {
                return Err("stss truncated".to_string());
            }
            let count = u64::from(u32::from_be_bytes(stss_box.data[4..8].try_into().unwrap()));
            if count > MAX_SAMPLES {
                return Err("stss has too many entries".to_string());
            }
            if stss_box.data.len() != 8 + 4 * count as usize {
                return Err("stss size does not match its entry count".to_string());
            }
            let mut table = Vec::with_capacity(count as usize);
            for index in 0..count {
                let base = 8 + index as usize * 4;
                let sample = u32::from_be_bytes(stss_box.data[base..base + 4].try_into().unwrap());
                if sample == 0 || u64::from(sample) > total_samples {
                    return Err("stss sample number outside the track".to_string());
                }
                if let Some(&previous) = table.last() {
                    if sample <= previous {
                        return Err("stss sample numbers are not increasing".to_string());
                    }
                }
                table.push(sample);
            }
            Some(table)
        }
        None => None,
    };

    Ok(StblTables {
        stsd: &stsd.data,
        total_samples,
        stts: stts_table,
        stsc: stsc_table,
        sizes,
        chunks: offsets,
        stss,
    })
}

/// One `stbl` box, fully cross-checked against `stsz`/`stts` (8.11.1).
/// Returns `E`, the highest end offset of any chunk (original-file
/// coordinates).
fn analyze_stbl(stbl: &MoovBox) -> Result<u64, String> {
    let mut tables = parse_stbl_tables(stbl)?;

    // Walk chunks in order, summing sample sizes into chunk lengths; every
    // offset must be non-decreasing and every sample must find its chunk.
    let mut e = 0u64;
    let mut sample_index = 0u64;
    let mut previous_offset = 0u64;
    let mut stsc_index = 0usize;
    for chunk in 1..=tables.chunks.count() {
        while stsc_index + 1 < tables.stsc.len()
            && u64::from(tables.stsc[stsc_index + 1].0) <= chunk
        {
            stsc_index += 1;
        }
        let samples_in_chunk = u64::from(tables.stsc[stsc_index].1);
        let offset = tables.chunks.get(chunk - 1)?;
        if offset < previous_offset {
            return Err("chunk offsets decrease inside a track".to_string());
        }
        previous_offset = offset;
        let mut chunk_len = 0u64;
        for _ in 0..samples_in_chunk {
            chunk_len += tables.sizes.next()?;
        }
        sample_index += samples_in_chunk;
        e = e.max(offset + chunk_len);
    }
    if sample_index != tables.total_samples {
        return Err("chunk tables and stsz disagree on the sample count".to_string());
    }
    Ok(e)
}

/// Parse and fully cross-check the `moov` box at the start of `bytes`.
/// Returns `(E, tracks)` where `E` is the highest end offset of any chunk in
/// original-file coordinates.
fn analyze_moov(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut seen = 0u64;
    let (root, _) = parse_mp4_box(bytes, 0, bytes.len(), 0, &mut seen)?;
    if &root.typ != b"moov" {
        return Err("not a moov box".to_string());
    }
    // Reject fragmented or compressed moov anywhere in the tree.
    let mut stack: Vec<&MoovBox> = vec![&root];
    while let Some(node) = stack.pop() {
        if &node.typ == b"mvex" {
            return Err("fragmented MP4 (mvex) is not supported".to_string());
        }
        if &node.typ == b"cmov" {
            return Err("compressed moov (cmov) is not supported".to_string());
        }
        stack.extend(node.children.iter());
    }
    let mut e = 0u64;
    let mut tracks = 0usize;
    let mut stack: Vec<&MoovBox> = vec![&root];
    while let Some(node) = stack.pop() {
        if &node.typ == b"stbl" {
            let track_e = analyze_stbl(node)?;
            if track_e > e {
                e = track_e;
            }
            tracks += 1;
        }
        stack.extend(node.children.iter());
    }
    if tracks == 0 {
        return Err("moov has no track (stbl)".to_string());
    }
    if tracks > 64 {
        return Err("moov has an implausible number of tracks".to_string());
    }
    Ok((e, tracks))
}

// --- NAL validity oracle (ROADMAP 8.11.4) -----------------------------------

/// What the NAL scan learned about one video track. `None` for every role
/// other than rebuilt MP4s; per-track details for video tracks with a
/// usable configuration record.
#[derive(Debug, Clone, PartialEq)]
pub struct TrackIntact {
    /// Fourcc of the first sample entry (`avc1`, `hvc1`...).
    pub codec: String,
    /// Total samples in the track.
    pub samples: u64,
    /// Samples whose NAL walk consumed the sample exactly.
    pub intact: u64,
    /// Fraction of intact samples (1.0 when the track has no samples).
    pub intact_ratio: f64,
    /// Consecutive broken samples from the start of the track.
    pub broken_prefix: u64,
    /// 1-based sample number of the first intact sync sample, if any.
    pub first_intact_sync_sample: Option<u64>,
    /// Seconds from the start of the track to the first intact sync sample
    /// (mvhd timescale + stts deltas), when both are known.
    pub first_intact_sync_time: Option<f64>,
}

#[derive(Clone, Copy)]
enum NalKind {
    Avc,
    Hevc,
}

/// NAL header byte acceptance: AVC clears forbidden_zero_bit and the type is
/// not `unspecified`; HEVC clears forbidden_zero_bit and reserved_zero_bit.
fn valid_nal_header(byte: u8, kind: NalKind) -> bool {
    match kind {
        NalKind::Avc => (byte & 0x80) == 0 && (byte & 0x1f) != 0,
        NalKind::Hevc => (byte & 0x81) == 0,
    }
}

/// Walk the NALs of one sample. `true` when the NAL lengths consume the
/// sample exactly (every header valid) — the encoder's own guarantee, so a
/// "perfect" parse is overwhelming evidence the sample survived.
fn sample_nals_intact(sample: &[u8], kind: NalKind, length_size: usize) -> bool {
    let mut pos = 0usize;
    while pos < sample.len() {
        if pos + length_size > sample.len() {
            return false;
        }
        let mut len = 0usize;
        for &byte in &sample[pos..pos + length_size] {
            len = (len << 8) | byte as usize;
        }
        pos += length_size;
        if len == 0 || pos + len > sample.len() {
            return false;
        }
        if !valid_nal_header(sample[pos], kind) {
            return false;
        }
        pos += len;
    }
    pos == sample.len()
}

/// The NAL length-prefix size from `avcC`/`hvcC` inside a sample entry.
fn nal_length_size(entry: &[u8], kind: NalKind) -> Option<u8> {
    let mut pos = 8usize;
    while pos + 8 <= entry.len() {
        let size = u32::from_be_bytes(entry[pos..pos + 4].try_into().unwrap()) as usize;
        let typ: &[u8] = &entry[pos + 4..pos + 8];
        if size < 8 || pos + size > entry.len() {
            return None;
        }
        if matches!(typ, b"avcC" | b"hvcC") {
            let body = &entry[pos + 8..pos + size];
            return match kind {
                NalKind::Avc => body.get(4).map(|byte| (byte & 0x03) + 1),
                NalKind::Hevc => body.get(21).map(|byte| (byte & 0x03) + 1),
            };
        }
        pos += size;
    }
    None
}

/// First sample entry of an stsd plus its fourcc.
fn first_sample_entry(stsd: &[u8]) -> Option<(&[u8], [u8; 4])> {
    if stsd.len() < 16 {
        return None;
    }
    let entry = &stsd[8..];
    if entry.len() < 8 {
        return None;
    }
    let codec: [u8; 4] = entry[4..8].try_into().unwrap();
    Some((entry, codec))
}

fn find_box_tree<'a>(node: &'a MoovBox, want: &[u8; 4]) -> Option<&'a MoovBox> {
    if &node.typ == want {
        return Some(node);
    }
    node.children
        .iter()
        .find_map(|child| find_box_tree(child, want))
}

/// `mvhd` timescale (ISO 14496-12: v0 at 12..16, v1 at 24..28).
fn mvhd_timescale(mvhd: &MoovBox) -> Option<u32> {
    let data = &mvhd.data;
    let scale = if data.len() >= 20 && data[0] == 0 {
        u32::from_be_bytes(data[12..16].try_into().unwrap())
    } else if data.len() >= 28 && data[0] == 1 {
        u32::from_be_bytes(data[24..28].try_into().unwrap())
    } else {
        return None;
    };
    (1..=10_000_000).contains(&scale).then_some(scale)
}

/// `stss` sample numbers are ascending (parse enforces it); membership with a
/// moving cursor.
struct StssCursor<'a> {
    table: &'a [u32],
    index: usize,
}

impl<'a> StssCursor<'a> {
    fn is_sync(&mut self, sample: u64) -> bool {
        while self.index < self.table.len() && u64::from(self.table[self.index]) < sample {
            self.index += 1;
        }
        self.index < self.table.len() && u64::from(self.table[self.index]) == sample
    }
}

/// Run the NAL scan over every track. Returns the video-track verdicts and
/// note fragments for anything that could not be checked (audio, missing
/// configuration, container trouble).
fn nal_oracle(
    file: &mut File,
    payload_start: u64,
    file_len: u64,
    moov_bytes: &[u8],
) -> (Vec<TrackIntact>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let mut seen = 0u64;
    let Ok((root, _)) = parse_mp4_box(moov_bytes, 0, moov_bytes.len(), 0, &mut seen) else {
        return (out, notes);
    };
    let timescale = find_box_tree(&root, b"mvhd").and_then(mvhd_timescale);
    if timescale.is_none() {
        notes.push("mvhd missing: timestamps unavailable".to_string());
    }
    let mut stack: Vec<&MoovBox> = vec![&root];
    while let Some(node) = stack.pop() {
        if &node.typ == b"stbl" {
            match nal_oracle_track(file, payload_start, file_len, node, timescale) {
                Ok(verdict) => out.push(verdict),
                Err(reason) => notes.push(reason),
            }
        }
        stack.extend(node.children.iter());
    }
    (out, notes)
}

fn nal_oracle_track(
    file: &mut File,
    payload_start: u64,
    file_len: u64,
    stbl: &MoovBox,
    timescale: Option<u32>,
) -> Result<TrackIntact, String> {
    let tables = parse_stbl_tables(stbl)?;
    let (entry, codec) = first_sample_entry(tables.stsd)
        .ok_or_else(|| "oracle: stsd sample entry not parseable".to_string())?;
    let kind = match &codec {
        b"avc1" | b"avc3" => NalKind::Avc,
        b"hvc1" | b"hev1" => NalKind::Hevc,
        other => {
            return Err(format!(
                "{} ({}): no oracle (not AVC/HEVC video)",
                String::from_utf8_lossy(other),
                String::from_utf8_lossy(other)
            ))
        }
    };
    let length_size = nal_length_size(entry, kind).ok_or_else(|| {
        format!(
            "{}: oracle unavailable (no avcC/hvcC configuration record)",
            String::from_utf8_lossy(&codec)
        )
    })? as usize;

    let total = tables.total_samples;
    let mut intact = 0u64;
    let mut broken_prefix = 0u64;
    let mut in_prefix = true;
    let mut first_intact_sync: Option<(u64, u64)> = None;
    let mut sample_number = 0u64;
    let mut time_units = 0u64;
    let mut sizes = tables.sizes;
    let mut stsc_index = 0usize;
    let mut stts_index = 0usize;
    let mut stts_left = tables
        .stts
        .first()
        .map(|&(count, _)| u64::from(count))
        .unwrap_or(0);
    let mut stss_cursor = tables
        .stss
        .as_deref()
        .map(|table| StssCursor { table, index: 0 });

    for chunk in 1..=tables.chunks.count() {
        while stsc_index + 1 < tables.stsc.len()
            && u64::from(tables.stsc[stsc_index + 1].0) <= chunk
        {
            stsc_index += 1;
        }
        let samples_in_chunk = u64::from(tables.stsc[stsc_index].1);
        let chunk_offset = tables.chunks.get(chunk - 1)?;
        let mut offset = chunk_offset;
        for _ in 0..samples_in_chunk {
            let size = sizes.next()? as usize;
            let sample_abs = payload_start + offset;
            let ok = match salvage_read(file, sample_abs, size, file_len)
                .map_err(|error| format!("oracle: read failed: {error}"))?
            {
                Some(bytes) => sample_nals_intact(&bytes, kind, length_size),
                None => {
                    return Err("oracle: sample extends past the payload".to_string());
                }
            };
            sample_number += 1;
            if ok {
                intact += 1;
                in_prefix = false;
                let is_sync = match &mut stss_cursor {
                    Some(cursor) => cursor.is_sync(sample_number),
                    None => true,
                };
                if is_sync && first_intact_sync.is_none() {
                    first_intact_sync = Some((sample_number, time_units));
                }
            } else if in_prefix {
                broken_prefix += 1;
            }
            let delta = loop {
                if stts_index >= tables.stts.len() {
                    break 0u64;
                }
                if stts_left == 0 {
                    stts_index += 1;
                    stts_left = tables
                        .stts
                        .get(stts_index)
                        .map(|&(count, _)| u64::from(count))
                        .unwrap_or(0);
                    continue;
                }
                stts_left -= 1;
                break u64::from(tables.stts[stts_index].1);
            };
            time_units += delta;
            offset += size as u64;
        }
    }

    let intact_ratio = if total == 0 {
        1.0
    } else {
        intact as f64 / total as f64
    };
    let first_intact_sync_sample = first_intact_sync.map(|(sample, _)| sample);
    let first_intact_sync_time =
        first_intact_sync.and_then(|(_, units)| timescale.map(|scale| units as f64 / scale as f64));
    Ok(TrackIntact {
        codec: String::from_utf8_lossy(&codec).into_owned(),
        samples: total,
        intact,
        intact_ratio,
        broken_prefix,
        first_intact_sync_sample,
        first_intact_sync_time,
    })
}

// --- Cut from the first intact sync sample (ROADMAP 8.11.5) ----------------

/// `mdhd` v0/v1: the track's media timescale and duration.
fn mdhd_time_and_duration(mdhd: &MoovBox) -> Option<(u32, Option<u64>)> {
    let d = &mdhd.data;
    if d.len() >= 20 && d[0] == 0 {
        let timescale = u32::from_be_bytes(d[12..16].try_into().unwrap());
        let duration = u64::from(u32::from_be_bytes(d[16..20].try_into().unwrap()));
        Some((timescale, Some(duration)))
    } else if d.len() >= 32 && d[0] == 1 {
        let timescale = u32::from_be_bytes(d[20..24].try_into().unwrap());
        let duration = u64::from_be_bytes(d[24..32].try_into().unwrap());
        Some((timescale, Some(duration)))
    } else {
        None
    }
}

/// Build the cut `moov` (ROADMAP 8.11.5): the rebuilt box with an
/// `edts`→`elst` pair inserted into every `trak` so playback starts at
/// `t_seconds`. Sample tables are untouched — the head garbage is simply
/// never presented — and the full rebuilt file is always kept alongside.
/// Returns the serialized moov and the number of tracks that gained an
/// edit list; `Ok(None)` when nothing can be cut (no `trak` with a usable
/// `mdhd`, `t_seconds` rounds to zero media time, …).
fn build_cut_moov(
    rebuilt_root: &MoovBox,
    shift: u64,
    t_seconds: f64,
) -> Result<Option<(Vec<u8>, usize)>, String> {
    if !t_seconds.is_finite() || t_seconds <= 0.0 {
        return Ok(None);
    }
    let mut tree = rebuilt_root.clone();
    let mut patched = 0usize;
    for child in &mut tree.children {
        if &child.typ != b"trak" {
            continue;
        }
        let Some((timescale, duration)) =
            find_box_tree(child, b"mdhd").and_then(mdhd_time_and_duration)
        else {
            continue; // no usable mdhd: leave the track untouched
        };
        if timescale == 0 || timescale > 10_000_000 {
            continue;
        }
        let media_time = (t_seconds * f64::from(timescale)).round();
        // 0 = nothing to skip for this track; elst v0 `media_time` is a
        // signed 32-bit field, so larger values stay out.
        if !media_time.is_finite() || media_time < 1.0 || media_time > 2_147_483_647.0 {
            continue;
        }
        let media_time = media_time as u64;
        if let Some(limit) = duration {
            if media_time > limit {
                continue; // starts past the end of the track
            }
        }
        let mut elst_body = Vec::with_capacity(20);
        elst_body.extend_from_slice(&0u32.to_be_bytes()); // version/flags
        elst_body.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        elst_body.extend_from_slice(&u32::MAX.to_be_bytes()); // segment_duration: rest of the track
        elst_body.extend_from_slice(&(media_time as u32).to_be_bytes()); // media_time
        elst_body.extend_from_slice(&0x0001_0000u32.to_be_bytes()); // rate 1.0
        let elst = MoovBox {
            typ: *b"elst",
            data: elst_body,
            children: Vec::new(),
            promote_to_co64: false,
        };
        let edts = MoovBox {
            typ: *b"edts",
            data: Vec::new(),
            children: vec![elst],
            promote_to_co64: false,
        };
        // Spec order inside `trak`: `tkhd`, `edts`?, `mdia`.
        let at = child
            .children
            .iter()
            .position(|node| &node.typ == b"tkhd")
            .map(|index| index + 1)
            .unwrap_or(0);
        child.children.insert(at, edts);
        patched += 1;
    }
    if patched == 0 {
        return Ok(None);
    }
    Ok(Some((serialize_moov(&tree, shift)?, patched)))
}

/// Mark `stco` tables whose entries overflow 32 bits once `shift` is added;
/// those become `co64` on serialize. Returns how many tables were promoted.
fn promote_overflowing_stco(node: &mut MoovBox, shift: u64) -> usize {
    let mut promoted = 0usize;
    if &node.typ == b"stco" && node.data.len() >= 8 {
        let count = u32::from_be_bytes(node.data[4..8].try_into().unwrap()) as usize;
        let entries_fit = node.data.len() == 8 + 4 * count;
        if entries_fit {
            for index in 0..count {
                let at = 8 + index * 4;
                let value = u64::from(u32::from_be_bytes(
                    node.data[at..at + 4].try_into().unwrap(),
                ));
                if value + shift > u64::from(u32::MAX) {
                    node.promote_to_co64 = true;
                    promoted += 1;
                    break;
                }
            }
        }
    }
    for child in &mut node.children {
        promoted += promote_overflowing_stco(child, shift);
    }
    promoted
}

/// Serialize a `moov` tree, adding `shift` to every chunk offset.
fn serialize_moov(node: &MoovBox, shift: u64) -> Result<Vec<u8>, String> {
    let body = if !node.children.is_empty() {
        let mut out = Vec::new();
        for child in &node.children {
            out.extend_from_slice(&serialize_moov(child, shift)?);
        }
        out
    } else if &node.typ == b"stco" && node.promote_to_co64 {
        let count = u32::from_be_bytes(node.data[4..8].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(8 + 8 * count);
        out.extend_from_slice(&node.data[0..4]); // version/flags
        out.extend_from_slice(&(count as u32).to_be_bytes());
        for index in 0..count {
            let at = 8 + index * 4;
            let value = u64::from(u32::from_be_bytes(
                node.data[at..at + 4].try_into().unwrap(),
            ));
            out.extend_from_slice(&(value + shift).to_be_bytes());
        }
        out
    } else if &node.typ == b"stco" && !node.data.is_empty() {
        let count = u32::from_be_bytes(node.data[4..8].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(node.data.len());
        out.extend_from_slice(&node.data[0..8]); // version/flags + count
        for index in 0..count {
            let at = 8 + index * 4;
            let value = u64::from(u32::from_be_bytes(
                node.data[at..at + 4].try_into().unwrap(),
            ));
            out.extend_from_slice(&((value + shift) as u32).to_be_bytes());
        }
        out
    } else if &node.typ == b"co64" && !node.data.is_empty() {
        let count = u32::from_be_bytes(node.data[4..8].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(node.data.len());
        out.extend_from_slice(&node.data[0..8]); // version/flags + count
        for index in 0..count {
            let at = 8 + index * 8;
            let value = u64::from_be_bytes(node.data[at..at + 8].try_into().unwrap());
            out.extend_from_slice(&(value + shift).to_be_bytes());
        }
        out
    } else {
        node.data.clone()
    };
    let size = 8 + body.len() as u64;
    if size > u64::from(u32::MAX) {
        // The promotion grew a box past the 32-bit box limit; extremely
        // unlikely in practice (moov is capped at 64 MiB), but fail loudly
        // instead of emitting an invalid file.
        return Err("moov grew past the 32-bit box limit after patching".to_string());
    }
    // A promoted stco becomes co64: same flow, wider entries.
    let out_typ: &[u8; 4] = if &node.typ == b"stco" && node.promote_to_co64 {
        b"co64"
    } else {
        &node.typ
    };
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&(size as u32).to_be_bytes());
    out.extend_from_slice(out_typ);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Everything the rebuild pass learned, ready to write to disk.
struct RebuiltMp4 {
    /// Payload start in the dump (where the original file's byte 0 lives
    /// once `moov`'s chunk tables agree with its size).
    payload_start: u64,
    /// Payload length (bytes before `moov`).
    payload_len: u64,
    /// End of the original `moov` box in the dump (start of any trailer).
    moov_end: u64,
    /// Serialized `moov` box with patched chunk offsets.
    moov: Vec<u8>,
    /// Total size of the rebuilt file.
    rebuilt_len: u64,
    sha256: String,
    entropy: f64,
    trailer_offset: Option<u64>,
    trailer_len: Option<u64>,
    trailer_sha256: Option<String>,
    trailer_preview: Option<String>,
    notes: String,
    /// NAL oracle verdicts for the track(s) with an AVC/HEVC video codec
    /// (8.11.4); empty when nothing could be checked.
    tracks_intact: Vec<TrackIntact>,
    /// ROADMAP 8.11.5: a sibling `moov` whose edit lists start playback at
    /// the first intact sync sample; always written alongside the full
    /// rebuild. `None` when there is nothing to skip.
    cut: Option<CutMp4>,
}

/// The edit-list-cut sibling of a rebuilt MP4 (ROADMAP 8.11.5): same
/// payload and sample tables, but every patched `trak` carries an
/// `edts`→`elst` that starts presentation at the first intact sync
/// sample, so the encrypted head is never presented.
struct CutMp4 {
    /// Serialized `moov` for the cut file.
    moov: Vec<u8>,
    /// Total size of the cut file.
    len: u64,
    sha256: String,
    entropy: f64,
    /// The rebuilt notes plus the cut suffix.
    notes: String,
}

/// The regenerated `ftyp` + `mdat` header bytes. `payload_len` picks the
/// 8- vs 16-byte `mdat` header form.
fn rebuilt_header(payload_len: u64) -> Vec<u8> {
    let mut header = FTYP_BOX.to_vec();
    if payload_len >= MDAT_LARGE_THRESHOLD {
        header.extend_from_slice(&(payload_len + 16).to_be_bytes());
        header.extend_from_slice(b"mdat");
    } else {
        header.extend_from_slice(&((payload_len + 8) as u32).to_be_bytes());
        header.extend_from_slice(b"mdat");
    }
    header
}

/// Shake out an `moov` box found at `position` (the offset of the `moov`
/// fourcc, i.e. where the 4-byte box size sits just before it) and compute
/// everything the rebuilt file needs. `Ok(Err(reason))` = the moov is not
/// usable and the candidate is rejected with a reason; `Ok(Ok(_))` =
/// rebuild ready.
fn mp4_rebuild(
    file: &mut File,
    position: u64,
    file_len: u64,
    max_size: u64,
    covered: &[(u64, u64)],
) -> io::Result<Result<RebuiltMp4, String>> {
    if position < 4 {
        return Ok(Err("moov fourcc at the very start of the dump".to_string()));
    }
    let box_at = position - 4;
    let Some(header) = salvage_read(file, box_at, 16, file_len)? else {
        return Ok(Err("moov header does not fit in the dump".to_string()));
    };
    if &header[4..8] != b"moov" {
        return Ok(Err(
            "moov fourcc is not at the box type position".to_string()
        ));
    }
    let size32 = u32::from_be_bytes(header[0..4].try_into().unwrap()) as u64;
    let (header_len, moov_len) = if size32 == 1 {
        let large = u64::from_be_bytes(header[8..16].try_into().unwrap());
        if large < 16 {
            return Ok(Err(
                "moov extended box size is smaller than its header".to_string()
            ));
        }
        (16u64, large)
    } else if size32 == 0 {
        (8, file_len - box_at)
    } else {
        if size32 < 8 {
            return Ok(Err("moov box size is smaller than its header".to_string()));
        }
        (8, size32)
    };
    if moov_len > MAX_MOOV_READ {
        return Ok(Err(
            "moov box is larger than the 64 MiB rebuild limit".to_string()
        ));
    }
    let Some(moov_end) = box_at.checked_add(moov_len) else {
        return Ok(Err("moov box size wraps around".to_string()));
    };
    if moov_end > file_len {
        return Ok(Err("moov box extends past the end of the dump".to_string()));
    }
    let _ = header_len;

    // A moov inside a region the header pass already carved is not ours.
    if covered
        .iter()
        .any(|&(start, end)| start <= box_at && box_at < end)
    {
        return Ok(Err("moov already belongs to a carved file".to_string()));
    }
    let prior_end = covered
        .iter()
        .filter(|&&(start, _)| start < box_at)
        .map(|&(_, end)| end)
        .max()
        .unwrap_or(0);

    let Some(moov_bytes) = salvage_read(file, box_at, moov_len as usize, file_len)? else {
        return Ok(Err("moov box could not be read back".to_string()));
    };
    let (e, tracks) = match analyze_moov(&moov_bytes) {
        Ok(ok) => ok,
        Err(reason) => return Ok(Err(reason)),
    };
    // E is the original file's mdat end; the original file started at
    // box_at - E in this dump (moov sits right after mdat).
    let Some(payload_start) = box_at.checked_sub(e) else {
        return Ok(Err(
            "moov chunk tables point past the start of this dump (moov-first layout?)".to_string(),
        ));
    };
    if payload_start < prior_end {
        return Ok(Err(
            "rebuilt payload overlaps a file the carver already wrote".to_string(),
        ));
    }
    if covered
        .iter()
        .any(|&(start, end)| start < box_at && end > payload_start)
    {
        return Ok(Err(
            "rebuilt payload overlaps a file the carver already wrote".to_string(),
        ));
    }
    let payload_len = box_at - payload_start;
    let large = payload_len >= MDAT_LARGE_THRESHOLD;
    let shift = FTYP_BOX.len() as u64 + if large { 16 } else { 8 };
    if shift + payload_len + moov_len > max_size {
        return Ok(Err("rebuilt file would exceed --carve-max-size".to_string()));
    }

    // Promote stco tables that overflow, then serialize with the shift.
    let mut root = match parse_mp4_box(&moov_bytes, 0, moov_bytes.len(), 0, &mut 0u64) {
        Ok((node, _)) => node,
        Err(reason) => return Ok(Err(reason)),
    };
    let promoted = promote_overflowing_stco(&mut root, shift);
    let moov_new = match serialize_moov(&root, shift) {
        Ok(bytes) => bytes,
        Err(reason) => return Ok(Err(reason)),
    };

    // Post-condition: the rebuilt moov must parse cleanly and its end-of-mdat
    // must land exactly on the moov box start of the rebuilt file.
    match analyze_moov(&moov_new) {
        Ok((e_new, _)) => {
            if e_new != shift + payload_len {
                return Ok(Err(
                    "rebuilt moov does not add up (shift mismatch)".to_string()
                ));
            }
        }
        Err(reason) => return Ok(Err(reason)),
    }

    // NAL oracle (8.11.4): which frames survived? Runs before the hash
    // pass because the cut variant (8.11.5) is decided from its verdicts.
    let (tracks_intact, oracle_notes) = nal_oracle(file, payload_start, file_len, &moov_bytes);

    // ROADMAP 8.11.5: a cut `moov` beside the full rebuild. Playback
    // starts at the earliest first-intact sync sample across checked
    // video tracks; every track just gains an edit list. The full
    // rebuilt file is always kept alongside.
    let mut cut_reject_reason: Option<String> = None;
    let cut_start = tracks_intact
        .iter()
        .filter_map(|track| track.first_intact_sync_time)
        .fold(f64::INFINITY, f64::min);
    let cut_moov = match build_cut_moov(&root, shift, cut_start) {
        Ok(Some((bytes, patched))) => match analyze_moov(&bytes) {
            Ok((e_cut, _)) if e_cut == shift + payload_len => Some((bytes, patched)),
            Ok((e_cut, _)) => {
                cut_reject_reason = Some(format!(
                    "end offset {e_cut} != shift + payload after edit lists"
                ));
                None
            }
            Err(reason) => {
                cut_reject_reason = Some(reason);
                None
            }
        },
        Ok(None) => None,
        Err(reason) => {
            cut_reject_reason = Some(reason);
            None
        }
    };

    // Second pass over the dump: hash and entropy of the rebuilt bytes.
    // One pass feeds both the full rebuild and (when there is one) the cut.
    let header = rebuilt_header(payload_len);
    let want_cut = cut_moov.is_some();
    let mut sha = Sha256::new();
    let mut sha_cut = Sha256::new();
    let mut counts = [0u64; 256];
    let mut counts_cut = [0u64; 256];
    let mut total = 0u64;
    let mut total_cut = 0u64;
    {
        let mut account = |bytes: &[u8]| {
            sha.update(bytes);
            for &byte in bytes {
                counts[byte as usize] += 1;
            }
            total += bytes.len() as u64;
            if want_cut {
                sha_cut.update(bytes);
                for &byte in bytes {
                    counts_cut[byte as usize] += 1;
                }
                total_cut += bytes.len() as u64;
            }
        };
        account(&header);
        stream_region(file, payload_start, payload_len, |chunk| {
            account(chunk);
            Ok(())
        })?;
    }
    sha.update(&moov_new);
    for &byte in &moov_new {
        counts[byte as usize] += 1;
    }
    total += moov_new.len() as u64;
    let rebuilt_len = total;
    let entropy_full = entropy(&counts, total);

    // Trailer after moov: whatever the ransomware appended. Recorded in the
    // index, cut out of the rebuilt file.
    let trailer_full = file_len - moov_end;
    let trailer_len = trailer_full.min(MP4_TRAILER_CAP);
    let (trailer_offset, trailer_len_out, trailer_sha, trailer_preview) = if trailer_full > 0 {
        let Some(trailer) = salvage_read(file, moov_end, trailer_len as usize, file_len)? else {
            return Ok(Err("trailer could not be read back".to_string()));
        };
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(&trailer);
            hex(&hasher.finalize())
        };
        let preview_bytes = &trailer[..trailer.len().min(64)];
        let ascii: String = preview_bytes
            .iter()
            .map(|&byte| {
                if (0x20..=0x7e).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect();
        let preview = format!("{} | {ascii}", hex(preview_bytes));
        (
            Some(moov_end),
            Some(trailer_len),
            Some(digest),
            Some(preview),
        )
    } else {
        (None, None, None, None)
    };

    // When the payload does not start at byte 0 of the input, the input is
    // treated as a disk image (file starts inside it) or as a file with a
    // free/skip box before moov: either way the head bytes at the start of
    // the payload are preserved verbatim, and the rebuilt file is only as
    // good as the frame structure behind it.
    let start_confidence = if payload_start == 0 { "high" } else { "low" };
    let mut notes = format!(
        "rebuild: ftyp+mdat header regenerated (shift={shift}); moov preserved with chunk offsets +={shift}; payload at 0x{payload_start:x} ({payload_len} B); {tracks} track(s); start_confidence={start_confidence}"
    );
    if promoted > 0 {
        notes.push_str(&format!("; {promoted} stco table(s) promoted to co64"));
    }
    if trailer_full > MP4_TRAILER_CAP {
        notes.push_str(&format!("; trailer after moov (first {MP4_TRAILER_CAP} of {trailer_full} B) cut from the file, recorded in the index"));
    } else if trailer_full > 0 {
        notes.push_str(&format!(
            "; trailer after moov ({trailer_full} B) cut from the file, recorded in the index"
        ));
    }

    // The verdicts were computed before the hash pass (above).
    if let Some(reason) = &cut_reject_reason {
        notes.push_str("; cut rejected: ");
        notes.push_str(reason);
    }
    for note in oracle_notes {
        notes.push_str("; ");
        notes.push_str(&note);
    }
    if !tracks_intact.is_empty() {
        let summary = tracks_intact
            .iter()
            .map(|track| {
                let ratio = if track.samples == 0 {
                    100.0
                } else {
                    100.0 * track.intact as f64 / track.samples as f64
                };
                match track.first_intact_sync_sample {
                    Some(sample) => {
                        let at = track
                            .first_intact_sync_time
                            .map(|t| format!(", t~{t:.2}s"))
                            .unwrap_or_default();
                        format!(
                            "{} {:.1}% samples intact (from sample {sample}{at})",
                            track.codec, ratio
                        )
                    }
                    None => format!("{} {:.1}% samples intact", track.codec, ratio),
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        notes.push_str("; video: ");
        notes.push_str(&summary);
    }

    // Assemble the cut record now that `notes` is final; drop it when it
    // would push the pair past the size cap.
    let cut = cut_moov.map(|(bytes, patched)| {
        sha_cut.update(&bytes);
        for &byte in &bytes {
            counts_cut[byte as usize] += 1;
        }
        total_cut += bytes.len() as u64;
        let cut_notes = format!(
            "{notes}; cut: {patched} edit list(s), playback starts at the first intact sync sample (t~{cut_start:.2}s); full rebuilt file kept alongside"
        );
        CutMp4 {
            moov: bytes,
            len: total_cut,
            sha256: hex(&sha_cut.finalize()),
            entropy: entropy(&counts_cut, total_cut),
            notes: cut_notes,
        }
    });
    let cut = match cut {
        Some(cut) if cut.len > max_size => {
            notes.push_str("; cut dropped: exceeds --carve-max-size");
            None
        }
        other => other,
    };

    Ok(Ok(RebuiltMp4 {
        payload_start,
        payload_len,
        moov_end,
        moov: moov_new,
        rebuilt_len,
        sha256: hex(&sha.finalize()),
        entropy: entropy_full,
        trailer_offset,
        trailer_len: trailer_len_out,
        trailer_sha256: trailer_sha,
        trailer_preview,
        notes,
        tracks_intact,
        cut,
    }))
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
        CarveKind::Text => {
            Verdict::Invalid("text has no header; it is found by the text pass".to_string())
        }
        CarveKind::Bin => {
            Verdict::Invalid("bin has no header; it is found by the bin pass".to_string())
        }
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

/// Top-level box types that may follow the payload of an ISO-BMFF file.
const MP4_TOP_LEVEL: &[&[u8]] = &[
    b"ftyp", b"styp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof",
    b"mfra", b"sidx", b"ssix", b"pdin", b"junk", b"udta", b"pnot",
];

fn carve_ole(source: &mut Source<'_>) -> io::Result<Verdict> {
    // OLE Compound File Binary Format (.doc, .xls, .ppt pre-2007).
    // Signature: D0 CF 11 E0 A1 B1 1A E1.
    let Some(header) = peek_array::<32>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the OLE header".to_string(),
        ));
    };
    if &header[0..8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" {
        return Ok(Verdict::Invalid("missing OLE signature".to_string()));
    }
    // Sector size is stored as a power of two at offset 0x1E (2 bytes LE);
    // real values are 9 (512 bytes) or 12 (4096 bytes). Offset 0x1C holds the
    // byte-order mark (0xFFFE), so reading there rejects every real file.
    let sector_pow = u16::from_le_bytes([header[30], header[31]]) as u64;
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
    let mut seen_moov = false;
    let mut seen_mdat = false;
    let mut seen_moof = false;
    while boxes < MAX_MP4_BOXES {
        let Some(header) = peek_array::<8>(source)? else {
            if seen_mdat || seen_moov {
                // The file ended exactly after its payload box.
                break;
            }
            return Ok(Verdict::Truncated(
                "dump ended inside an MP4 box header".to_string(),
            ));
        };
        let mut size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let box_type = &header[4..8];
        // Once a payload box is in, only a known top-level box may continue
        // the file; anything else is whatever follows it in the dump.
        if (seen_mdat || seen_moov) && !MP4_TOP_LEVEL.contains(&box_type) {
            break;
        }
        if size == 1 {
            // 64-bit extended size follows the box type.
            let Some(wide) = peek_array::<16>(source)? else {
                return Ok(Verdict::Truncated(
                    "dump ended inside an MP4 extended box size".to_string(),
                ));
            };
            // `peek_array` starts at the box header, so the size is bytes 8..16.
            size = u64::from_be_bytes([
                wide[8], wide[9], wide[10], wide[11], wide[12], wide[13], wide[14], wide[15],
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
        let remaining = source.end.saturating_sub(source.abs());
        if (seen_mdat || seen_moov) && size > remaining {
            // A box cut off by the window after the payload: a short `moov`
            // means the file is incomplete, anything else just ends here.
            if box_type == *b"moov" {
                return Ok(Verdict::Truncated(
                    "MP4 moov box runs past the end of the candidate window".to_string(),
                ));
            }
            break;
        }
        if size > source.end.saturating_sub(source.origin) {
            return Ok(Verdict::Truncated(
                "MP4 declares more data than the dump has".to_string(),
            ));
        }
        // peek_array does not consume the header; move past the whole box.
        source.skip(size)?;
        boxes += 1;
        // The file is complete once both payload (`mdat`) and index (`moov`)
        // are in, whichever order they come in (`moov` is last unless the file
        // was fast-started). Stopping at the first of the two used to cut a
        // non-fast-start file off before its `moov`. A fragmented file
        // (`moof` seen) keeps walking until the next box is not a known one.
        match box_type {
            b if b == *b"mdat" => {
                seen_mdat = true;
                found_payload = true;
            }
            b if b == *b"moov" => {
                seen_moov = true;
                found_payload = true;
            }
            b if b == *b"moof" => seen_moof = true,
            _ => {}
        }
        if seen_moov && seen_mdat && !seen_moof {
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
    // The file ends where the furthest raw data its headers declare ends:
    // every section's `PointerToRawData + SizeOfRawData`, the certificate
    // table and the headers themselves. An overlay appended after the last
    // section is not declared anywhere, so it is not counted.
    let table = source.peek(PE_HEADERS_PEEK)?.to_vec();
    let layout = match pe_layout(&table, e_lfanew) {
        Ok(layout) => layout,
        Err(reason) => return pe_header_only(source, reason),
    };
    let window = source.end.saturating_sub(source.origin);
    let extent = layout
        .data_ends
        .iter()
        .copied()
        .fold(layout.headers_end, u64::max);
    if extent <= window {
        source.skip(extent.saturating_sub(e_lfanew))?;
        return Ok(Verdict::Valid);
    }
    // The headers promise more than the carve window holds: either the dump
    // cuts the file, or this is a false positive with wild offsets. Keep only
    // what the headers vouch for inside the window and never the whole window,
    // so a bogus PE cannot swallow the items behind it.
    let kept = layout
        .data_ends
        .iter()
        .copied()
        .filter(|&end| end <= window)
        .fold(layout.headers_end.min(window), u64::max)
        .max((e_lfanew + PE_HEADER_ONLY_BYTES).min(window));
    source.skip(kept.saturating_sub(e_lfanew))?;
    Ok(Verdict::Truncated(
        "PE section data runs past the end of the carve window".to_string(),
    ))
}

/// Bytes read from the PE signature on: signature (4), COFF header (20), an
/// optional header of at most 1024 bytes and 96 section headers (the
/// loader's maximum) of 40 bytes each.
const PE_HEADERS_PEEK: usize = 4 + 20 + 1024 + 96 * 40;

/// What a PE whose section table cannot be validated is cut to, as before the
/// section table was walked.
const PE_HEADER_ONLY_BYTES: u64 = 4096;

/// Where a PE's declared contents end, as offsets from the start of the file.
struct PeLayout {
    /// End of the headers (signature, COFF, optional header, section table).
    headers_end: u64,
    /// End of each piece of raw data the headers declare: the sections that
    /// have any, and the certificate table.
    data_ends: Vec<u64>,
}

fn pe_u16(bytes: &[u8], at: usize) -> u64 {
    u64::from(u16::from_le_bytes([bytes[at], bytes[at + 1]]))
}

fn pe_u32(bytes: &[u8], at: usize) -> u64 {
    u64::from(u32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}

/// Parse the headers in `table` (which starts at the `PE\0\0` signature, at
/// file offset `e_lfanew`). Errs with the reason when they are not a
/// structurally sound PE32 / PE32+ header set.
fn pe_layout(table: &[u8], e_lfanew: u64) -> Result<PeLayout, &'static str> {
    if table.len() < 24 {
        return Err("dump ended inside the COFF header");
    }
    let sections = pe_u16(table, 6) as usize;
    let opt_size = pe_u16(table, 20) as usize;
    if sections == 0 || sections > 96 {
        return Err("implausible section count");
    }
    if !(96..=1024).contains(&opt_size) {
        return Err("implausible optional header size");
    }
    let table_start = 24 + opt_size;
    let table_end = table_start + sections * 40;
    if table.len() < table_end {
        return Err("dump ended inside the section table");
    }
    let opt = &table[24..table_start];
    // PE32 (0x10b) keeps its data directories at 96, PE32+ (0x20b) at 112.
    let (directories_at, count_at) = match pe_u16(opt, 0) {
        0x10b => (96, 92),
        0x20b => (112, 108),
        _ => return Err("unknown optional header magic"),
    };
    let size_of_headers = pe_u32(opt, 60);
    if size_of_headers > 1 << 20 {
        return Err("implausible SizeOfHeaders");
    }
    let mut data_ends = Vec::with_capacity(sections + 1);
    for index in 0..sections {
        let at = table_start + index * 40;
        let raw_size = pe_u32(table, at + 16);
        let raw_ptr = pe_u32(table, at + 20);
        if raw_size > 0 {
            data_ends.push(raw_ptr + raw_size);
        }
    }
    // Data directory 4 is the certificate table; unlike the others its
    // address is a file offset, not an RVA.
    if pe_u32(opt, count_at) > 4 && opt.len() >= directories_at + 5 * 8 {
        let cert_offset = pe_u32(opt, directories_at + 4 * 8);
        let cert_size = pe_u32(opt, directories_at + 4 * 8 + 4);
        if cert_size > 0 {
            data_ends.push(cert_offset + cert_size);
        }
    }
    Ok(PeLayout {
        headers_end: (e_lfanew + table_end as u64).max(size_of_headers),
        data_ends,
    })
}

/// A PE whose section table could not be validated is still worth carving,
/// but only as far as the header: the verdict says it was not walked.
fn pe_header_only(source: &mut Source<'_>, reason: &str) -> io::Result<Verdict> {
    source.skip(PE_HEADER_ONLY_BYTES.min(source.end.saturating_sub(source.abs())))?;
    Ok(Verdict::Truncated(format!("PE header only: {reason}")))
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
    // The file ends where the furthest data its headers declare ends: the
    // section header table, the program header table and every segment's
    // file image. Bytes appended after that are not declared anywhere.
    let head = source.peek(64)?.to_vec();
    let fields = match elf_header(&head) {
        Ok(fields) => fields,
        Err(reason) => return elf_header_only(source, reason),
    };
    let window = source.end.saturating_sub(source.origin);
    let table_len = fields.phnum * fields.phentsize;
    let mut ends = vec![fields.header_size];
    if table_len > 0 {
        ends.push(fields.phoff + table_len);
    }
    if fields.shnum > 0 {
        ends.push(fields.shoff + fields.shnum * fields.shentsize);
    }
    if table_len > 0 && fields.phoff + table_len <= window {
        // Segments sit at arbitrary offsets: read the program headers where
        // they are, then come back to the start of the candidate.
        let start = source.abs();
        source.skip(fields.phoff)?;
        let table = source.peek(table_len as usize)?.to_vec();
        source.rewind_to(start);
        for entry in table.chunks_exact(fields.phentsize as usize) {
            let (offset_at, size_at, width) = if fields.wide { (8, 32, 8) } else { (4, 16, 4) };
            let offset = elf_uint(entry, offset_at, width, fields.little);
            let size = elf_uint(entry, size_at, width, fields.little);
            if size > 0 {
                ends.push(offset.saturating_add(size));
            }
        }
    }
    let extent = ends.iter().copied().max().unwrap_or(fields.header_size);
    if extent <= window {
        source.skip(extent)?;
        return Ok(Verdict::Valid);
    }
    // The headers promise more than the carve window holds: either the dump
    // cuts the file, or this is a false positive with wild offsets. Keep only
    // what the headers vouch for inside the window, never the whole window.
    let kept = ends
        .iter()
        .copied()
        .filter(|&end| end <= window)
        .max()
        .unwrap_or(0)
        .max(ELF_HEADER_ONLY_BYTES.min(window));
    source.skip(kept)?;
    Ok(Verdict::Truncated(
        "ELF segments or section table run past the end of the carve window".to_string(),
    ))
}

/// What an ELF whose headers cannot be validated is cut to, as before the
/// program and section headers were read.
const ELF_HEADER_ONLY_BYTES: u64 = 4096;

/// The ELF header fields that locate the rest of the file.
struct ElfFields {
    /// 64-bit class (`ELFCLASS64`).
    wide: bool,
    /// Little-endian data encoding.
    little: bool,
    header_size: u64,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    shoff: u64,
    shnum: u64,
    shentsize: u64,
}

/// Unsigned integer of `width` bytes (2, 4 or 8) at `at`, in the file's byte
/// order. The caller has checked the bounds.
fn elf_uint(bytes: &[u8], at: usize, width: usize, little: bool) -> u64 {
    let mut value = 0u64;
    for index in 0..width {
        let byte = if little {
            bytes[at + width - 1 - index]
        } else {
            bytes[at + index]
        };
        value = (value << 8) | u64::from(byte);
    }
    value
}

/// Read the table locations out of the ELF header in `head` (the first 64
/// bytes of the candidate). Errs with the reason when they make no sense.
fn elf_header(head: &[u8]) -> Result<ElfFields, &'static str> {
    let wide = head.get(4) == Some(&2);
    let little = head.get(5) == Some(&1);
    let header_size = if wide { 64 } else { 52 };
    if head.len() < header_size {
        return Err("dump ended inside the ELF header");
    }
    let word = if wide { 8 } else { 4 };
    let (phoff_at, shoff_at, sizes_at) = if wide { (32, 40, 54) } else { (28, 32, 42) };
    let phoff = elf_uint(head, phoff_at, word, little);
    let shoff = elf_uint(head, shoff_at, word, little);
    let phentsize = elf_uint(head, sizes_at, 2, little);
    let phnum = elf_uint(head, sizes_at + 2, 2, little);
    let shentsize = elf_uint(head, sizes_at + 4, 2, little);
    let shnum = elf_uint(head, sizes_at + 6, 2, little);
    if phnum == 0 && shnum == 0 {
        return Err("no program or section headers");
    }
    if phnum > 1024 {
        return Err("implausible program header count");
    }
    if phnum > 0 && phentsize != if wide { 56 } else { 32 } {
        return Err("unexpected program header size");
    }
    if shnum > 0 && shentsize != if wide { 64 } else { 40 } {
        return Err("unexpected section header size");
    }
    // Offsets this large are noise, and would overflow the sums below.
    if phoff >= 1 << 48 || shoff >= 1 << 48 {
        return Err("implausible header table offset");
    }
    Ok(ElfFields {
        wide,
        little,
        header_size: header_size as u64,
        phoff,
        phnum,
        phentsize,
        shoff,
        shnum,
        shentsize,
    })
}

/// An ELF whose headers could not be validated is still worth carving, but
/// only as far as the header: the verdict says it was not walked.
fn elf_header_only(source: &mut Source<'_>, reason: &str) -> io::Result<Verdict> {
    source.skip(ELF_HEADER_ONLY_BYTES.min(source.end.saturating_sub(source.abs())))?;
    Ok(Verdict::Truncated(format!("ELF header only: {reason}")))
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
    let Some(first) = peek_u8(source)? else {
        return Ok(None);
    };
    let mut length = 1usize;
    let mut mask = 0x80u8;
    while mask != 0 && first & mask == 0 {
        length += 1;
        mask >>= 1;
    }
    if length > 4 {
        return Ok(None);
    }
    let Some(bytes) = take_bytes(source, length)? else {
        return Ok(None);
    };
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
            return Ok(Verdict::Truncated(
                "EBML element id desyncs from the stream".to_string(),
            ));
        };
        let Some((size, slen)) = ebml_vint(source)? else {
            return Ok(Verdict::Truncated(
                "EBML element size desyncs from the stream".to_string(),
            ));
        };
        let unknown_size = size == (1u64 << (7 * slen as u64)) - 1;
        let element_end = if unknown_size {
            source.end
        } else {
            match source.abs().checked_add(size) {
                Some(end) if end <= source.end => end,
                _ => {
                    return Ok(Verdict::Truncated(
                        "EBML element extends past the candidate".to_string(),
                    ))
                }
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
        None => Ok(Verdict::Invalid(
            "EBML DocType element not found".to_string(),
        )),
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
            return Ok(Verdict::Truncated(
                "OGG page count exceeded the limit".to_string(),
            ));
        }
        // Dump padding (all zero bytes) follows the last page; treat it as
        // the end of the stream.
        if let Some(next) = peek_array::<4>(source)? {
            if next.iter().all(|&byte| byte == 0) {
                break;
            }
        }
        let Some(header) = peek_array::<27>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside an OGG page header".to_string(),
            ));
        };
        if &header[..4] != b"OggS" || header[4] != 0 {
            return Ok(Verdict::Invalid(
                "OGG page magic/version mismatch".to_string(),
            ));
        }
        let flags = header[5];
        if flags & 0x80 != 0 {
            return Ok(Verdict::Invalid(
                "OGG continuation flag is not supported".to_string(),
            ));
        }
        if first && flags & 0x02 == 0 {
            return Ok(Verdict::Invalid(
                "OGG stream does not start with a BOS page".to_string(),
            ));
        }
        let serial = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
        if !serials.contains(&serial) {
            if serials.len() >= 64 {
                return Ok(Verdict::Invalid(
                    "OGG serial count exceeded the limit".to_string(),
                ));
            }
            serials.push(serial);
        }
        source.skip(27)?;
        let segment_count = usize::from(header[26]);
        let table = match take_bytes(source, segment_count)? {
            Some(table) => table,
            None => {
                return Ok(Verdict::Truncated(
                    "dump ended inside an OGG segment table".to_string(),
                ))
            }
        };
        let payload: u64 = table.iter().map(|&size| u64::from(size)).sum();
        if !room_left(source, payload) {
            return Ok(Verdict::Truncated(
                "dump ended inside an OGG page payload".to_string(),
            ));
        }
        let page = take_bytes(source, payload as usize)?.unwrap_or_default();
        if first && page.windows(8).any(|w| w == b"OpusHead") {
            opus_head = true;
        }
        first = false;
    }
    if expect_opus && !opus_head {
        return Ok(Verdict::Invalid(
            "OGG stream has no OpusHead packet on its first page".to_string(),
        ));
    }
    Ok(Verdict::Valid)
}

fn carve_flac(source: &mut Source<'_>) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"fLaC") {
        return Ok(Verdict::Invalid("missing fLaC signature".to_string()));
    }
    source.skip(4)?;
    let Some(streaminfo) = peek_array::<4>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside a FLAC STREAMINFO header".to_string(),
        ));
    };
    let streaminfo_type = streaminfo[0] & 0x7f;
    let streaminfo_last = streaminfo[0] & 0x80 != 0;
    let streaminfo_len = u32::from_be_bytes([0, streaminfo[1], streaminfo[2], streaminfo[3]]);
    if streaminfo_type != 0 || streaminfo_len != 34 {
        return Ok(Verdict::Invalid(
            "FLAC STREAMINFO block is missing or mis-sized".to_string(),
        ));
    }
    source.skip(4 + 34)?;
    if streaminfo_last {
        return Ok(Verdict::Valid);
    }
    for _ in 0..4096u64 {
        let Some(block) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a FLAC metadata block".to_string(),
            ));
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
    Ok(Verdict::Truncated(
        "FLAC metadata block count exceeded the limit".to_string(),
    ))
}

fn carve_riff(source: &mut Source<'_>, expected_form: &[u8; 4]) -> io::Result<Verdict> {
    if peek_array::<4>(source)? != Some(*b"RIFF") {
        return Ok(Verdict::Invalid("missing RIFF signature".to_string()));
    }
    let Some(header) = peek_array::<12>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the RIFF header".to_string(),
        ));
    };
    let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if &header[8..12] != expected_form {
        return Ok(Verdict::Invalid(
            "RIFF form type does not match this kind".to_string(),
        ));
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
            return Ok(Verdict::Truncated(
                "dump ended inside a RIFF chunk header".to_string(),
            ));
        };
        let chunk_size = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]);
        let padded = u64::from(chunk_size) + (u64::from(chunk_size) & 1);
        source.skip(8)?;
        if source
            .abs()
            .checked_add(padded)
            .map_or(true, |end| end > riff_end)
        {
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
    if peek_array::<6>(source)? != Some(*b"GIF87a") && peek_array::<6>(source)? != Some(*b"GIF89a")
    {
        return Ok(Verdict::Invalid(
            "missing GIF87a/GIF89a signature".to_string(),
        ));
    }
    source.skip(6)?;
    let Some(lsd) = peek_array::<7>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the GIF logical screen descriptor".to_string(),
        ));
    };
    let packed = lsd[4];
    source.skip(7)?;
    if packed & 0x80 != 0 {
        // Global color table: 3 * 2^(bits+1) bytes (6 << bits).
        let gct = 3u64 << (u32::from(packed & 0x07) + 1);
        if !room_left(source, gct) {
            return Ok(Verdict::Truncated(
                "dump ended inside the GIF global color table".to_string(),
            ));
        }
        source.skip(gct)?;
    }
    for _ in 0..MAX_GIF_BLOCKS {
        let Some(marker) = peek_u8(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a GIF block".to_string(),
            ));
        };
        match marker {
            0x3b => {
                source.skip(1)?;
                return Ok(Verdict::Valid);
            }
            0x21 => {
                source.skip(1)?;
                let Some(_label) = peek_u8(source)? else {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a GIF extension block".to_string(),
                    ));
                };
                source.skip(1)?;
                if let Some(v) = gif_subblocks(source)? {
                    return Ok(v);
                }
            }
            0x2c => {
                source.skip(1)?;
                let Some(desc) = peek_array::<9>(source)? else {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a GIF image descriptor".to_string(),
                    ));
                };
                let image_packed = desc[8];
                source.skip(9)?;
                if image_packed & 0x80 != 0 {
                    // Local color table: 3 * 2^(bits+1) bytes (6 << bits).
                    let lct = 3u64 << (u32::from(image_packed & 0x07) + 1);
                    if !room_left(source, lct) {
                        return Ok(Verdict::Truncated(
                            "dump ended inside a GIF local color table".to_string(),
                        ));
                    }
                    source.skip(lct)?;
                }
                let Some(_) = peek_u8(source)? else {
                    return Ok(Verdict::Truncated(
                        "dump ended at the GIF LZW minimum code size".to_string(),
                    ));
                };
                source.skip(1)?;
                if let Some(v) = gif_subblocks(source)? {
                    return Ok(v);
                }
            }
            _ => {
                return Ok(Verdict::Invalid(format!(
                    "unexpected GIF block marker 0x{marker:02x}"
                )))
            }
        }
    }
    Ok(Verdict::Truncated(
        "GIF block count exceeded the limit".to_string(),
    ))
}

/// Walk GIF data sub-blocks up to the zero terminator.
fn gif_subblocks(source: &mut Source<'_>) -> io::Result<Option<Verdict>> {
    loop {
        let Some(size) = peek_u8(source)? else {
            return Ok(Some(Verdict::Truncated(
                "dump ended inside a GIF data sub-block".to_string(),
            )));
        };
        if size == 0 {
            source.skip(1)?;
            return Ok(None);
        }
        if !room_left(source, 1 + u64::from(size)) {
            return Ok(Some(Verdict::Truncated(
                "dump ended inside a GIF data sub-block".to_string(),
            )));
        }
        source.skip(1 + u64::from(size))?;
    }
}

fn carve_ico(source: &mut Source<'_>) -> io::Result<Verdict> {
    let window = window_len(source);
    let Some(header) = peek_array::<6>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the ICO header".to_string(),
        ));
    };
    let reserved = u16::from_le_bytes([header[0], header[1]]);
    let kind = u16::from_le_bytes([header[2], header[3]]);
    let count = u16::from_le_bytes([header[4], header[5]]);
    if reserved != 0 || !matches!(kind, 1 | 2) || count == 0 || count > 256 {
        return Ok(Verdict::Invalid(
            "implausible ICO reserved/kind/count fields".to_string(),
        ));
    }
    source.skip(6)?;
    let mut data_end: u64 = 6 + u64::from(count) * 16;
    for _ in 0..count {
        let Some(entry) = peek_array::<16>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside an ICO directory entry".to_string(),
            ));
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
        None => {
            return Ok(Verdict::Truncated(
                "dump ended inside the TAR header block".to_string(),
            ))
        }
    };
    if &first[257..262] != b"ustar" {
        return Ok(Verdict::Invalid(
            "ustar marker is missing from the TAR header".to_string(),
        ));
    }
    let stored = parse_octal(&first[148..156]);
    let computed = {
        let mut sum: u64 = 0;
        for (index, &byte) in first.iter().enumerate() {
            let byte = if (148..156).contains(&index) {
                b' '
            } else {
                byte
            };
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
            return Ok(Verdict::Truncated(
                "dump ended inside a TAR file".to_string(),
            ));
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
            return Ok(Verdict::Invalid(
                "TAR file boundary does not line up with a header block".to_string(),
            ));
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
    Ok(Verdict::Truncated(
        "TAR entry count exceeded the limit".to_string(),
    ))
}

fn carve_pcap(source: &mut Source<'_>) -> io::Result<Verdict> {
    if !room_left(source, 24) {
        return Ok(Verdict::Truncated(
            "dump ended inside the PCAP global header".to_string(),
        ));
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
        return Ok(Verdict::Invalid(format!(
            "implausible PCAP snaplen {snaplen}"
        )));
    }
    source.skip(24)?;
    for _ in 0..1_000_000u64 {
        if source.abs() >= source.end {
            break;
        }
        let Some(record) = peek_array::<16>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a PCAP packet record".to_string(),
            ));
        };
        let incl_len = read32(&record[8..12]);
        let orig_len = read32(&record[12..16]);
        if incl_len > snaplen || orig_len > snaplen.max(0x7fff_ffff) {
            return Ok(Verdict::Invalid(
                "PCAP packet record exceeds the snaplen".to_string(),
            ));
        }
        if !room_left(source, 16 + u64::from(incl_len)) {
            return Ok(Verdict::Truncated(
                "dump ended inside a PCAP packet".to_string(),
            ));
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
        _ => {
            return Ok(Verdict::Invalid(
                "PCAPNG byte-order magic is wrong".to_string(),
            ))
        }
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
        return Ok(Verdict::Invalid(
            "PCAPNG section length is implausible".to_string(),
        ));
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
            return Ok(Verdict::Truncated(
                "PCAPNG block length is implausible".to_string(),
            ));
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
        return Ok(Verdict::Invalid(
            "unsupported WebAssembly binary version".to_string(),
        ));
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
        return Ok(Verdict::Truncated(
            "dump ended inside the LNK header".to_string(),
        ));
    };
    let clsid = [
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ];
    if &header[..4] != b"L\0\0\0" || header[4..20] != clsid {
        return Ok(Verdict::Invalid(
            "implausible LNK header (magic/CLSID)".to_string(),
        ));
    }
    let flags = u32::from_le_bytes([header[0x14], header[0x15], header[0x16], header[0x17]]);
    let is_unicode = flags & 0x0000_0080 != 0;
    source.skip(0x4c)?;
    if flags & 0x0000_0001 != 0 {
        let Some(size) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(
                "LNK LinkTargetIDListSize is missing".to_string(),
            ));
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
            return Ok(Verdict::Truncated(
                "LNK LinkInfoSize is missing".to_string(),
            ));
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
            return Ok(Verdict::Truncated(
                "dump ended inside the PEM label".to_string(),
            ));
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
        return Ok(Verdict::Truncated(
            "dump ended inside the KDBX signature".to_string(),
        ));
    };
    if magic[..4] != [0x03, 0xd9, 0xa2, 0x9a]
        || !matches!(
            &magic[4..8],
            [0x67, 0xfb, 0x4b, 0xb5] | [0x66, 0xfb, 0x4b, 0xb5] | [0x65, 0xfb, 0x4b, 0xb5]
        )
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
            return Ok(Verdict::Truncated(
                "dump ended inside a KDBX header field".to_string(),
            ));
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
            return Ok(Verdict::Truncated(
                "dump ended inside a KDBX block header".to_string(),
            ));
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
        return Ok(Verdict::Truncated(
            "dump ended inside the DEX header".to_string(),
        ));
    };
    if &header[..4] != b"dex\n"
        || !matches!(
            &header[4..8],
            b"035\x00" | b"036\x00" | b"037\x00" | b"038\x00" | b"039\x00" | b"040\x00"
        )
    {
        return Ok(Verdict::Invalid(
            "implausible DEX magic/version".to_string(),
        ));
    }
    let read_u32 =
        |bytes: &[u8]| -> u32 { u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) };
    let header_size = read_u32(&header[36..40]);
    let endian_tag = read_u32(&header[40..44]);
    let file_size = u64::from(read_u32(&header[32..36]));
    let map_off = u64::from(read_u32(&header[52..56]));
    let string_ids_size = u64::from(read_u32(&header[56..60]));
    let string_ids_off = u64::from(read_u32(&header[60..64]));
    let type_ids_size = u64::from(read_u32(&header[64..68]));
    let type_ids_off = u64::from(read_u32(&header[68..72]));
    if header_size != 0x70 || endian_tag != 0x1234_5678 {
        return Ok(Verdict::Invalid(
            "DEX header size/endian tag mismatch".to_string(),
        ));
    }
    if file_size < 0x70 || file_size > window {
        return Ok(Verdict::Truncated(format!(
            "DEX declares {file_size} bytes but the candidate window is smaller"
        )));
    }
    if map_off >= file_size
        || string_ids_off >= file_size
        || type_ids_off >= file_size
        || string_ids_size * 4 > file_size
        || type_ids_size * 4 > file_size
    {
        return Ok(Verdict::Invalid(
            "DEX offsets point outside the file".to_string(),
        ));
    }
    // Verify integrity: Adler-32 of everything past the checksum field.
    let checksum = read_u32(&header[8..12]);
    source.skip(12)?;
    let checksum_read = {
        let amount = (file_size - 12) as usize;
        let mut buffer = vec![0u8; amount];
        source
            .file
            .seek(std::io::SeekFrom::Start(source.origin + 12))?;
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
        return Ok(Verdict::Truncated(
            "dump ended inside the TIFF magic".to_string(),
        ));
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
        None => {
            return Ok(Verdict::Truncated(
                "TIFF IFD0 offset is missing".to_string(),
            ))
        }
    };
    let window = window_len(source);
    if ifd0 >= window {
        return Ok(Verdict::Invalid(
            "TIFF IFD0 offset points outside the file".to_string(),
        ));
    }
    source.skip(4)?;
    let type_size: u64 = 8; // upper bound used only for inline-value decisions
    let _ = type_size;
    let mut ifd = ifd0;
    for _ in 0..MAX_TIFF_IFDS {
        if ifd >= window {
            return Ok(Verdict::Invalid(
                "TIFF IFD offset points outside the file".to_string(),
            ));
        }
        source.skip(ifd - source.abs())?;
        let Some(count_bytes) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a TIFF IFD".to_string(),
            ));
        };
        let count = read16(&count_bytes);
        if count == 0 || count > 4096 {
            return Ok(Verdict::Invalid(format!(
                "TIFF IFD entry count {count} is implausible"
            )));
        }
        source.skip(2)?;
        for _ in 0..count {
            let Some(entry) = peek_array::<12>(source)? else {
                return Ok(Verdict::Truncated(
                    "dump ended inside a TIFF IFD entry".to_string(),
                ));
            };
            let tag = read16(&entry[0..2]);
            let entry_type = read16(&entry[2..4]);
            let _ = tag;
            let type_len: u64 = match entry_type {
                1 | 2 | 6 | 7 => 1,
                3 | 8 => 2,
                4 | 9 | 11 => 4,
                5 | 10 | 12 => 8,
                16..=18 => 8,
                _ => {
                    return Ok(Verdict::Invalid(format!(
                        "TIFF field type {entry_type} is not defined"
                    )))
                }
            };
            let value_count = read32(&entry[4..8]) as u64;
            if value_count > 1_000_000_000 {
                return Ok(Verdict::Invalid(
                    "TIFF field count is implausible".to_string(),
                ));
            }
            let total = type_len * value_count;
            if total > 4 {
                let offset = read32(&entry[8..12]) as u64;
                if offset.checked_add(total).map_or(true, |end| end > window) {
                    return Ok(Verdict::Truncated(
                        "TIFF field data extends past the candidate".to_string(),
                    ));
                }
            }
            source.skip(12)?;
        }
        let Some(next) = peek_array::<4>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside a TIFF IFD trailer".to_string(),
            ));
        };
        let next_ifd = read32(&next) as u64;
        source.skip(4)?;
        if next_ifd == 0 {
            return Ok(Verdict::Valid);
        }
        ifd = next_ifd;
    }
    Ok(Verdict::Truncated(
        "TIFF IFD count exceeded the limit".to_string(),
    ))
}

fn carve_mp3(source: &mut Source<'_>) -> io::Result<Verdict> {
    let window = window_len(source);
    let mut frames_start = 0u64;
    if peek_array::<3>(source)? == Some(*b"ID3") {
        // ID3v2 header: "ID3", ver(2), flags(1), syncsafe size(4).
        let Some(header) = peek_array::<10>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside the ID3v2 header".to_string(),
            ));
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
        const MPEG1: [u32; 16] = [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0,
        ];
        const MPEG2: [u32; 16] = [
            0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0,
        ];
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
            return Ok(Verdict::Truncated(
                "dump ended inside an MP3 frame header".to_string(),
            ));
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
                    return Ok(Verdict::Invalid(
                        "MP3 frame has an invalid bitrate index".to_string(),
                    ));
                }
                break;
            }
        };
        let samplerate = match mpeg_samplerate(version, samplerate_index) {
            Some(value) if value > 0 => value,
            _ => {
                if frames == 0 {
                    return Ok(Verdict::Invalid(
                        "MP3 frame has an invalid sample rate index".to_string(),
                    ));
                }
                break;
            }
        };
        let coefficient: u64 = if version == 3 { 144 } else { 72 };
        let frame_len =
            coefficient * u64::from(bitrate) * 1000 / u64::from(samplerate) + u64::from(padding);
        if frame_len < 4 || !room_left(source, frame_len) {
            return Ok(Verdict::Truncated(
                "dump ended inside an MP3 frame".to_string(),
            ));
        }
        source.skip(frame_len)?;
        frames += 1;
        if frames > 10_000_000 {
            return Ok(Verdict::Truncated(
                "MP3 frame count exceeded the limit".to_string(),
            ));
        }
    }
    let _ = frames_start;
    if frames < 2 {
        // A single noise-matching frame is not a file (measured on the
        // carver bench: random data matches the frame-sync predicate
        // often enough to fill an entire output directory). A real MP3
        // has many consecutive frames; require the stream to resync at
        // least once.
        return Ok(Verdict::Invalid(
            "MP3 stream has fewer than two consecutive frames".to_string(),
        ));
    }
    Ok(Verdict::Valid)
}

fn carve_bz2(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<10>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the BZIP2 header".to_string(),
        ));
    };
    if &header[..3] != b"BZh" || !(b'1'..=b'9').contains(&header[3]) {
        return Ok(Verdict::Invalid(
            "implausible BZIP2 magic/level".to_string(),
        ));
    }
    if &header[4..10] != b"1AY&SY" {
        return Ok(Verdict::Invalid(
            "BZIP2 block magic is missing after the stream header".to_string(),
        ));
    }
    // The body is a bit-packed stream we do not decode, but it ends with a
    // 48-bit end-of-stream marker (0x177245385090) and a 32-bit combined CRC,
    // at *any* bit alignment. Scan for the marker so the extent is the real
    // stream instead of the whole candidate window (which would swallow every
    // neighbouring carve inside it).
    const BZ2_EOS: u64 = 0x1772_4538_5090;
    const MASK48: u64 = 0xffff_ffff_ffff;
    source.skip(4)?;
    let mut acc: u64 = 0;
    // Bytes fed into `acc`, counted from the stream origin (header = 4).
    let mut fed: u64 = 4;
    let mut end_off: Option<u64> = None;
    'scan: loop {
        source.fill(1)?;
        let available = source.len - source.at;
        if available == 0 {
            break;
        }
        for k in 0..available {
            acc = (acc << 8) | u64::from(source.buf[source.at + k]);
            let count = fed + k as u64 + 1;
            // 48 bits at a shift of up to 7 need 7 whole stream bytes, so the
            // match can never overlap the 4-byte header.
            if count >= 4 + 7 && (0..8).any(|shift| (acc >> shift) & MASK48 == BZ2_EOS) {
                // The marker ends `shift` bits before byte `count`; the CRC
                // adds 32 bits and the stream is padded to a byte, which is
                // always exactly 4 more bytes.
                end_off = Some(count + 4);
                break 'scan;
            }
        }
        fed += available as u64;
        source.skip(available as u64)?;
    }
    match end_off {
        Some(off) if off <= window_len(source) => {
            source.rewind_to(source.origin + off);
            Ok(Verdict::Valid)
        }
        _ => {
            source.skip(window_len(source))?;
            Ok(Verdict::Truncated(
                "bz2 end-of-stream marker not found; extent ends at the candidate window"
                    .to_string(),
            ))
        }
    }
}

fn carve_xz(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<12>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the XZ header".to_string(),
        ));
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
    // XZ stream-header CRC32 covers only the two stream-flag bytes,
    // conditioned the zlib way (init 0xffffffff, final xor 0xffffffff).
    if crc32(0xffff_ffff, &header[6..8]) ^ 0xffff_ffff != expected_crc {
        return Ok(Verdict::Invalid(
            "XZ header CRC-32 does not match".to_string(),
        ));
    }
    // The stream ends with a 12-byte footer: CRC-32 (4) | backward size (4) |
    // stream flags (2, equal to the header's) | "YZ". Find the first footer
    // that checks out so the extent is the real stream, not the whole
    // candidate window (which would swallow every neighbouring carve).
    let needle = [header[6], header[7], b'Y', b'Z'];
    let origin = source.origin;
    source.skip(12)?;
    while let Some(hit) = find_bytes(source, &needle)? {
        // `hit` is where the flags start; the footer starts 8 bytes earlier.
        // The skip(12) above guarantees `hit >= origin + 12`.
        let footer_at = hit - 8;
        source.rewind_to(footer_at);
        let Some(footer) = take_bytes(source, 12)? else {
            break;
        };
        let stored_crc = u32::from_le_bytes([footer[0], footer[1], footer[2], footer[3]]);
        let backward = u64::from(u32::from_le_bytes([
            footer[4], footer[5], footer[6], footer[7],
        ]));
        let index_size = (backward + 1) * 4;
        let end = footer_at + 12;
        let crc_ok = crc32(0xffff_ffff, &footer[4..10]) ^ 0xffff_ffff == stored_crc;
        // A whole stream is a multiple of four bytes and holds header +
        // index + footer; the index starts with a 0x00 indicator byte.
        let shape_ok =
            crc_ok && (end - origin) % 4 == 0 && footer_at >= origin + 12 + index_size && {
                source.rewind_to(footer_at - index_size);
                peek_u8(source)? == Some(0x00)
            };
        if shape_ok {
            source.rewind_to(end);
            return Ok(Verdict::Valid);
        }
        // False positive: resume just past this hit.
        source.rewind_to(hit + 1);
    }
    source.skip(window_len(source))?;
    Ok(Verdict::Truncated(
        "XZ footer not found; extent ends at the candidate window".to_string(),
    ))
}

fn carve_class(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(magic) = peek_array::<8>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the CLASS magic".to_string(),
        ));
    };
    if &magic[..4] != b"\xca\xfe\xba\xbe" {
        return Ok(Verdict::Invalid("missing CLASS magic".to_string()));
    }
    let minor = u16::from_be_bytes([magic[4], magic[5]]);
    let major = u16::from_be_bytes([magic[6], magic[7]]);
    let _ = minor;
    if !(45..=70).contains(&major) {
        return Ok(Verdict::Invalid(format!(
            "implausible CLASS major version {major}"
        )));
    }
    source.skip(8)?;
    let Some(cp_count_bytes) = peek_array::<2>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the CLASS constant pool".to_string(),
        ));
    };
    let cp_count = u64::from(u16::from_be_bytes(cp_count_bytes));
    if cp_count == 0 || cp_count > MAX_CLASS_POOL {
        return Ok(Verdict::Invalid(format!(
            "CLASS constant pool count {cp_count} is implausible"
        )));
    }
    source.skip(2)?;
    let mut index = 1u64;
    while index < cp_count {
        let Some(tag) = peek_u8(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside the CLASS constant pool".to_string(),
            ));
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
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS UTF-8 entry".to_string(),
                    ));
                };
                let len = u64::from(u16::from_be_bytes(len_bytes));
                source.skip(2)?;
                if read_cp_value(source, len)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS UTF-8 entry".to_string(),
                    ));
                }
            }
            3 | 4 => {
                if read_cp_value(source, 4)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS integer entry".to_string(),
                    ));
                }
            }
            5 | 6 => {
                if read_cp_value(source, 8)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS long entry".to_string(),
                    ));
                }
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => {
                if read_cp_value(source, 2)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS reference entry".to_string(),
                    ));
                }
            }
            9 | 10 | 11 | 12 | 17 | 18 => {
                if read_cp_value(source, 4)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS reference entry".to_string(),
                    ));
                }
            }
            15 => {
                if read_cp_value(source, 3)?.is_none() {
                    return Ok(Verdict::Truncated(
                        "dump ended inside a CLASS method-handle entry".to_string(),
                    ));
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
        return Ok(Verdict::Truncated(
            "CLASS interface count is missing".to_string(),
        ));
    };
    let interfaces = u64::from(u16::from_be_bytes(interface_count));
    source.skip(2)?;
    if !room_left(source, interfaces * 2) {
        return Ok(Verdict::Truncated(
            "dump ended inside the CLASS interface list".to_string(),
        ));
    }
    source.skip(interfaces * 2)?;
    // Fields then methods, each { access_flags(2), name(2), descriptor(2),
    // attributes_count(2), attributes[{ name_index(2), length(4), bytes }] }.
    for section in ["field", "method"] {
        let Some(count_bytes) = peek_array::<2>(source)? else {
            return Ok(Verdict::Truncated(format!(
                "CLASS {section} count is missing"
            )));
        };
        let count = u64::from(u16::from_be_bytes(count_bytes));
        source.skip(2)?;
        for _ in 0..count {
            if !room_left(source, 8) {
                return Ok(Verdict::Truncated(format!(
                    "dump ended inside a CLASS {section} entry"
                )));
            }
            source.skip(6)?;
            let Some(attr_count_bytes) = peek_array::<2>(source)? else {
                return Ok(Verdict::Truncated(format!(
                    "CLASS {section} attribute count is missing"
                )));
            };
            let attr_count = u64::from(u16::from_be_bytes(attr_count_bytes));
            source.skip(2)?;
            for _ in 0..attr_count {
                let Some(attr_len_bytes) = peek_array::<6>(source)? else {
                    return Ok(Verdict::Truncated(format!(
                        "CLASS {section} attribute header is missing"
                    )));
                };
                let attr_len = u32::from_be_bytes([
                    attr_len_bytes[2],
                    attr_len_bytes[3],
                    attr_len_bytes[4],
                    attr_len_bytes[5],
                ]) as u64;
                source.skip(6)?;
                if !room_left(source, attr_len) {
                    return Ok(Verdict::Truncated(format!(
                        "dump ended inside a CLASS {section} attribute"
                    )));
                }
                source.skip(attr_len)?;
            }
        }
    }
    // Class-level attributes.
    let Some(attr_count_bytes) = peek_array::<2>(source)? else {
        return Ok(Verdict::Truncated(
            "CLASS attribute count is missing".to_string(),
        ));
    };
    let attr_count = u64::from(u16::from_be_bytes(attr_count_bytes));
    source.skip(2)?;
    for _ in 0..attr_count {
        let Some(attr_len_bytes) = peek_array::<6>(source)? else {
            return Ok(Verdict::Truncated(
                "CLASS attribute header is missing".to_string(),
            ));
        };
        let attr_len = u32::from_be_bytes([
            attr_len_bytes[2],
            attr_len_bytes[3],
            attr_len_bytes[4],
            attr_len_bytes[5],
        ]) as u64;
        source.skip(6)?;
        if !room_left(source, attr_len) {
            return Ok(Verdict::Truncated(
                "dump ended inside a CLASS attribute".to_string(),
            ));
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
            return Ok(Verdict::Truncated(
                "dump ended inside the RTF document".to_string(),
            ));
        };
        match byte {
            0x00 => {
                return Ok(Verdict::Invalid(
                    "NUL byte inside the RTF document".to_string(),
                ))
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
        return Ok(Verdict::Truncated(
            "dump ended inside the EVTX file header".to_string(),
        ));
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
        return Ok(Verdict::Invalid("EVTX chunk range is reversed".to_string()));
    }
    source.skip(u64::from(header_size))?;
    let mut chunks: u64 = 0;
    loop {
        if source.abs() >= source.end {
            break;
        }
        let Some(chunk) = peek_array::<8>(source)? else {
            return Ok(Verdict::Truncated(
                "dump ended inside an EVTX chunk header".to_string(),
            ));
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
            return Ok(Verdict::Truncated(
                "dump ended inside an EVTX chunk".to_string(),
            ));
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
        return Ok(Verdict::Truncated(
            "dump ended inside the VDI header".to_string(),
        ));
    };
    if !rest[..58]
        .iter()
        .all(|&byte| byte == 0x00 || (0x20..=0x7e).contains(&byte))
    {
        return Ok(Verdict::Invalid(
            "VDI creator string is not printable".to_string(),
        ));
    }
    let carved = window_len(source).min(4096);
    source.skip(carved)?;
    Ok(Verdict::Truncated(
        "VDI body not parsed; only the 4 KiB header was carved".to_string(),
    ))
}

fn carve_vmdk(source: &mut Source<'_>) -> io::Result<Verdict> {
    let Some(header) = peek_array::<512>(source)? else {
        return Ok(Verdict::Truncated(
            "dump ended inside the VMDK sparse header".to_string(),
        ));
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
        return Ok(Verdict::Invalid(
            "implausible VMDK sparse header fields".to_string(),
        ));
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
        assert_eq!(
            complete.path.as_ref().unwrap().parent(),
            Some(out.as_path())
        );
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
    fn sniffed_extensions_reach_file_names_and_the_report() {
        // ODF text document: stored `mimetype` entry first.
        let odt = zip_bytes("mimetype", b"application/vnd.oasis.opendocument.text");
        // Same minimal PE as `carves_pe_executable`, with IMAGE_FILE_DLL set.
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.extend_from_slice(&[0u8; 0x3a]);
        pe.extend_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0");
        pe.extend_from_slice(&[0u8; 64]);
        pe[0x40 + 22 + 1] = 0x20; // Characteristics 0x2000

        let mut dump = vec![0u8; 64];
        let odt_at = dump.len() as u64;
        dump.extend_from_slice(&odt);
        dump.extend_from_slice(&[0u8; 64]);
        let pe_at = dump.len() as u64;
        dump.extend_from_slice(&pe);
        dump.extend_from_slice(&[0u8; 64]);

        let path = write_dump("sniff-names", &dump);
        let out = temp_dir("sniff-names-out");
        let report = Carver::new(CarveOptions::default())
            .carve_to_dir(path.to_str().unwrap(), &out)
            .unwrap();

        let odt_file = report.files.iter().find(|f| f.offset == odt_at).unwrap();
        assert_eq!(
            (odt_file.ext.as_str(), odt_file.ext_source.as_str()),
            ("odt", "sniff:zip/odf-text")
        );
        let name = odt_file
            .path
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        assert!(name.ends_with(".odt.carved"), "{name}");
        // The bytes are untouched: only the name changed.
        assert_eq!(std::fs::read(odt_file.path.as_ref().unwrap()).unwrap(), odt);

        let pe_file = report.files.iter().find(|f| f.offset == pe_at).unwrap();
        assert_eq!(
            (pe_file.ext.as_str(), pe_file.ext_source.as_str()),
            ("dll", "sniff:pe/dll")
        );
        let name = pe_file
            .path
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy();
        assert!(name.ends_with(".dll.carved"), "{name}");
        // The PE validator reads past the headers (size is not exact), so the
        // file may carry trailing padding: it must still start with the PE.
        let written = std::fs::read(pe_file.path.as_ref().unwrap()).unwrap();
        assert!(written.starts_with(&pe));

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(&out).ok();
    }

    #[test]
    fn ext_filter_separates_whole_formats_from_specific_extensions() {
        let filter = ExtFilter::from_list("docx,xlsx").unwrap();
        assert!(filter.allows(CarveKind::Zip, "docx"));
        assert!(filter.allows(CarveKind::Zip, "xlsx"));
        assert!(!filter.allows(CarveKind::Zip, "zip"));
        assert!(!filter.allows(CarveKind::Zip, "jar"));
        // Kinds the list does not restrict are untouched.
        assert!(filter.allows(CarveKind::Pdf, "pdf"));

        for list in [
            "zip",
            "docx,zip",
            "all,docx",
            "jpg,pdf,exe,office",
            "text,bin",
        ] {
            assert!(ExtFilter::from_list(list).unwrap().is_empty(), "{list}");
        }
        // `exe` stays a whole-format alias (every PE), as before 8.10.6.
        assert!(ExtFilter::from_list("exe")
            .unwrap()
            .allows(CarveKind::Pe, "dll"));
        assert!(!ExtFilter::from_list("dll")
            .unwrap()
            .allows(CarveKind::Pe, "exe"));
        assert!(ExtFilter::from_list("nope").is_err());
    }

    #[test]
    fn every_specific_extension_alias_names_its_container_kind() {
        for name in [
            "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "doc", "xls", "ppt", "msi",
            "msg", "dll", "sys", "mov", "m4a", "so",
        ] {
            let (kind, ext) = ExtFilter::specific(name).expect(name);
            assert_eq!(ext, name);
            assert_eq!(CarveKind::from_list(name).unwrap(), vec![kind], "{name}");
        }
    }

    #[test]
    fn exact_extension_filter_writes_only_the_named_extension() {
        let odt = zip_bytes("mimetype", b"application/vnd.oasis.opendocument.text");
        // Same minimal PE as `sniffed_extensions_reach_file_names_and_the_report`.
        let mut pe = Vec::new();
        pe.extend_from_slice(b"MZ");
        pe.extend_from_slice(&[0u8; 0x3a]);
        pe.extend_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0");
        pe.extend_from_slice(&[0u8; 64]);
        pe[0x40 + 22 + 1] = 0x20; // IMAGE_FILE_DLL

        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&odt);
        dump.extend_from_slice(&[0u8; 64]);
        dump.extend_from_slice(&pe);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump("ext-filter", &dump);

        let run = |list: &str| {
            let options = CarveOptions {
                kinds: CarveKind::from_list(list).unwrap(),
                ..Default::default()
            };
            Carver::new(options)
                .with_ext_filter(ExtFilter::from_list(list).unwrap())
                .scan(path.to_str().unwrap())
                .unwrap()
        };
        let exts = |report: &CarveReport| {
            let mut exts: Vec<String> = report.files.iter().map(|f| f.ext.clone()).collect();
            exts.sort();
            exts
        };

        // Both named exactly: both kept.
        let report = run("odt,dll");
        assert_eq!(exts(&report), ["dll", "odt"], "{report:?}");
        assert_eq!(report.filtered, 0);

        // docx does not match an odt: it is skipped, the dll stays.
        let report = run("docx,dll");
        assert_eq!(exts(&report), ["dll"], "{report:?}");
        assert_eq!(report.filtered, 1);
        assert!(report
            .summary_line()
            .contains("1 file(s) filtered by extension"));

        // sys does not match a dll; the whole-format zip keeps the odt.
        let report = run("zip,sys");
        assert_eq!(exts(&report), ["odt"], "{report:?}");
        assert_eq!(report.filtered, 1);

        // Whole formats (and a kind named both ways) keep everything.
        for list in ["zip,pe", "docx,zip,dll", "all"] {
            let report = run(list);
            assert_eq!(exts(&report), ["dll", "odt"], "{list}: {report:?}");
            assert_eq!(report.filtered, 0, "{list}");
        }

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
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

    /// ROADMAP 8.10.8: with the new `{offset}-{kind}-{sha8}.{ext}.carved`
    /// names, a file already sitting at the target name is refused and left
    /// exactly as it was; nothing else is written into that directory.
    #[test]
    fn existing_file_at_the_target_name_is_refused_and_untouched() {
        let png = png_bytes(b"refuse-me");
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump("refuse", &dump);

        // First run learns the canonical name.
        let first = temp_dir("refuse-first");
        let report = Carver::new(CarveOptions::default())
            .carve_to_dir(path.to_str().unwrap(), &first)
            .unwrap();
        let name = report.files[0]
            .path
            .as_ref()
            .unwrap()
            .file_name()
            .unwrap()
            .to_owned();
        assert!(name.to_string_lossy().ends_with(".png.carved"), "{name:?}");

        // Second directory already holds something at that exact name.
        let second = temp_dir("refuse-second");
        let sentinel = b"do not clobber me".to_vec();
        std::fs::write(second.join(&name), &sentinel).unwrap();
        let err = Carver::new(CarveOptions::default())
            .carve_to_dir(path.to_str().unwrap(), &second)
            .expect_err("must refuse to overwrite");
        assert!(err.to_string().contains("refusing to overwrite"), "{err}");
        assert_eq!(std::fs::read(second.join(&name)).unwrap(), sentinel);
        assert_eq!(std::fs::read_dir(&second).unwrap().count(), 1);

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(&first).ok();
        std::fs::remove_dir_all(&second).ok();
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

    /// One cycle = 3 zero windows + 1 high-entropy window (1:3 duty).
    fn one_in_four_windows(cycles: usize, seed: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(cycles * 4 * SPIKE_WINDOW);
        for cycle in 0..cycles {
            out.extend_from_slice(&vec![0u8; SPIKE_WINDOW * 3]);
            out.extend_from_slice(&pseudo_random(SPIKE_WINDOW, seed + cycle as u64));
        }
        out
    }

    /// A ZIP local entry (stored, no EOCD) whose data is the 1:3 pattern.
    /// The name is padded so the entry data starts exactly at the second
    /// 4 KiB window of the region, keeping the cycle grid aligned.
    fn zip_entry_with_periodic_payload() -> Vec<u8> {
        let payload = one_in_four_windows(16, 0xF00D_1550_CA11_0FF1); // 256 KiB, 16 cycles
        let name_len = SPIKE_WINDOW - 30; // local header is 30 bytes
        let mut out = Vec::with_capacity(SPIKE_WINDOW + payload.len());
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (never checked)
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_len as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(&vec![b'A'; name_len]);
        out.extend_from_slice(&payload);
        out
    }

    /// A minimal MP4: `ftyp` + `mdat` (two chunks of pseudo-random video
    /// data) + `moov`. Chunk offsets default to the file's own layout;
    /// `stco` values can be overridden to build hostile tables.
    ///
    /// Returns `(file_bytes, moov_offset, moov_box_len)`.
    fn synthetic_mp4_with_stco(
        stco: (u32, u32),
        extra_moov_children: &[&[u8]],
    ) -> (Vec<u8>, usize, usize) {
        let payload_size = 8192usize;
        let mut file = Vec::new();
        file.extend_from_slice(FTYP_BOX); // 24 B, same brand the rebuild uses
        file.extend_from_slice(&((payload_size + 8) as u32).to_be_bytes());
        file.extend_from_slice(b"mdat");
        file.extend_from_slice(&pseudo_random(payload_size, 0xFEED_F00D_1234_5678));

        let bx = |typ: &[u8; 4], body: &[u8]| {
            let mut out = Vec::with_capacity(8 + body.len());
            out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
            out.extend_from_slice(typ);
            out.extend_from_slice(body);
            out
        };
        let u32be = |value: u32| value.to_be_bytes().to_vec();
        // stsd: one avc1 sample entry, 32 bytes.
        let mut stsd = Vec::new();
        stsd.extend_from_slice(&u32be(0)); // version/flags
        stsd.extend_from_slice(&u32be(1)); // entry_count
        stsd.extend_from_slice(&u32be(32)); // entry size
        stsd.extend_from_slice(b"avc1");
        stsd.extend_from_slice(&[0u8; 24]);
        // stts: 1 entry, 2 samples of delta 1000.
        let mut stts = Vec::new();
        stts.extend_from_slice(&u32be(0)); // version/flags
        stts.extend_from_slice(&u32be(1)); // entry_count
        stts.extend_from_slice(&u32be(2)); // sample_count
        stts.extend_from_slice(&u32be(1000)); // sample_delta
                                              // stsc: 1 entry, every chunk holds 1 sample.
        let mut stsc = Vec::new();
        stsc.extend_from_slice(&u32be(0)); // version/flags
        stsc.extend_from_slice(&u32be(1)); // entry_count
        stsc.extend_from_slice(&u32be(1)); // first_chunk
        stsc.extend_from_slice(&u32be(1)); // samples_per_chunk
        stsc.extend_from_slice(&u32be(1)); // sample_description_index
                                           // stsz: variable sizes, 2 entries.
        let mut stsz = Vec::new();
        stsz.extend_from_slice(&u32be(0)); // version/flags
        stsz.extend_from_slice(&u32be(0)); // sample_size (0 = variable)
        stsz.extend_from_slice(&u32be(2)); // entry_count
        stsz.extend_from_slice(&u32be(4096));
        stsz.extend_from_slice(&u32be(4096));
        // stco: the two chunk offsets, in file order.
        let chunk1 = 24 + 8;
        let chunk2 = chunk1 + 4096;
        let _ = (chunk1, chunk2); // kept for clarity; values come from `stco` argument
        let mut stco_box = Vec::new();
        stco_box.extend_from_slice(&u32be(0)); // version/flags
        stco_box.extend_from_slice(&u32be(2)); // entry_count
        stco_box.extend_from_slice(&u32be(stco.0));
        stco_box.extend_from_slice(&u32be(stco.1));

        let stbl = bx(
            b"stbl",
            &[
                bx(b"stsd", &stsd),
                bx(b"stts", &stts),
                bx(b"stsc", &stsc),
                bx(b"stsz", &stsz),
                bx(b"stco", &stco_box),
            ]
            .concat(),
        );
        let minf = bx(b"minf", &stbl);
        let mdia = bx(b"mdia", &minf);
        let trak = bx(b"trak", &mdia);
        let mut moov_body = trak;
        for extra in extra_moov_children {
            moov_body.extend_from_slice(extra);
        }
        let moov = bx(b"moov", &moov_body);
        let moov_offset = file.len();
        let moov_len = moov.len();
        file.extend_from_slice(&moov);
        (file, moov_offset, moov_len)
    }

    fn synthetic_mp4() -> (Vec<u8>, usize, usize) {
        let chunk1 = 24 + 8;
        let chunk2 = chunk1 + 4096;
        synthetic_mp4_with_stco((chunk1 as u32, chunk2 as u32), &[])
    }

    /// One NAL sample: `[len][header][payload]`, len = 1 + payload.
    fn nal_sample(header: u8, payload_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + payload_len);
        out.extend_from_slice(&((1 + payload_len) as u32).to_be_bytes());
        out.push(header);
        out.extend_from_slice(&vec![0x5A; payload_len]);
        out
    }

    /// A minimal AVC/HEVC MP4 with `stss` and an mvhd (timescale 1000),
    /// built from ready-made samples. One track, two chunks, two samples
    /// per chunk. `codec` is `avc1` or `mp4a` (audio, no oracle).
    fn mp4_nal_fixture(codec: &[u8; 4], frames: &[Vec<u8>], stss: Option<&[u32]>) -> Vec<u8> {
        let payload_len: usize = frames.iter().map(Vec::len).sum();
        let u32be = |value: u32| value.to_be_bytes().to_vec();
        let bx = |typ: &[u8; 4], body: Vec<u8>| {
            let mut out = Vec::with_capacity(8 + body.len());
            out.extend_from_slice(&((8 + body.len()) as u32).to_be_bytes());
            out.extend_from_slice(typ);
            out.extend_from_slice(&body);
            out
        };
        let mut file = Vec::new();
        file.extend_from_slice(FTYP_BOX); // 24 B
        file.extend_from_slice(&((payload_len + 8) as u32).to_be_bytes());
        file.extend_from_slice(b"mdat");
        let payload_at = file.len();
        for frame in frames {
            file.extend_from_slice(frame);
        }
        // stsd: one avc1/mp4a sample entry with avcC inside it.
        let avcc = bx(b"avcC", vec![1, 100, 0, 30, 0xFF, 0xFE, 0xF2, 0x00]);
        let mut entry = Vec::new();
        entry.extend_from_slice(&((8 + avcc.len()) as u32).to_be_bytes());
        entry.extend_from_slice(codec);
        entry.extend_from_slice(&avcc);
        let mut stsd = Vec::new();
        stsd.extend_from_slice(&u32be(0));
        stsd.extend_from_slice(&u32be(1)); // entry_count
        stsd.extend_from_slice(&entry);
        // stts: 1 entry, delta 1000 per sample.
        let mut stts = Vec::new();
        stts.extend_from_slice(&u32be(0));
        stts.extend_from_slice(&u32be(1));
        stts.extend_from_slice(&u32be(frames.len() as u32));
        stts.extend_from_slice(&u32be(1000));
        // stsc: one entry, two samples per chunk.
        let mut stsc = Vec::new();
        stsc.extend_from_slice(&u32be(0));
        stsc.extend_from_slice(&u32be(1));
        stsc.extend_from_slice(&u32be(1));
        stsc.extend_from_slice(&u32be(2));
        stsc.extend_from_slice(&u32be(1));
        // stsz: per-sample sizes.
        let mut stsz = Vec::new();
        stsz.extend_from_slice(&u32be(0));
        stsz.extend_from_slice(&u32be(0)); // variable sizes
        stsz.extend_from_slice(&u32be(frames.len() as u32));
        for frame in frames {
            stsz.extend_from_slice(&u32be(frame.len() as u32));
        }
        // stco: two chunks.
        let mut stco = Vec::new();
        stco.extend_from_slice(&u32be(0));
        stco.extend_from_slice(&u32be(2));
        let per_chunk = 2usize;
        let mut chunk_starts = Vec::new();
        let mut running = payload_at;
        for (index, frame) in frames.iter().enumerate() {
            if index % per_chunk == 0 {
                chunk_starts.push(running as u32);
            }
            running += frame.len();
        }
        stco.extend_from_slice(&u32be(chunk_starts[0]));
        stco.extend_from_slice(&u32be(chunk_starts[1]));
        // stss: sync table when asked.
        let stss_box = stss.map(|table| {
            let mut body = Vec::new();
            body.extend_from_slice(&u32be(0)); // version/flags
            body.extend_from_slice(&u32be(table.len() as u32));
            for &sample in table {
                body.extend_from_slice(&u32be(sample));
            }
            bx(b"stss", body)
        });
        let stbl_body: Vec<u8> = [
            bx(b"stsd", stsd),
            bx(b"stts", stts),
            bx(b"stsc", stsc),
            bx(b"stsz", stsz),
            bx(b"stco", stco),
        ]
        .into_iter()
        .chain(stss_box)
        .collect::<Vec<_>>()
        .concat();
        let stbl = bx(b"stbl", stbl_body);
        let minf = bx(b"minf", stbl);
        // mdhd: v0, timescale 1000 (needed by the cut builder's elst).
        let mut mdhd = Vec::new();
        mdhd.extend_from_slice(&u32be(0)); // version/flags
        mdhd.extend_from_slice(&u32be(0)); // creation
        mdhd.extend_from_slice(&u32be(0)); // modification
        mdhd.extend_from_slice(&u32be(1000)); // timescale
        mdhd.extend_from_slice(&u32be(10_000)); // duration (10 s)
        mdhd.extend_from_slice(&u32be(0)); // language + quality
        let mdia = bx(b"mdia", [bx(b"mdhd", mdhd), minf].concat());
        let trak = bx(b"trak", mdia);
        // mvhd: timescale 1000.
        let mut mvhd = Vec::new();
        mvhd.extend_from_slice(&u32be(0)); // version/flags
        mvhd.extend_from_slice(&u32be(0)); // creation
        mvhd.extend_from_slice(&u32be(0)); // modification
        mvhd.extend_from_slice(&u32be(1000)); // timescale
        mvhd.extend_from_slice(&u32be(10_000)); // duration
        mvhd.extend_from_slice(&u32be(0x0001_0000)); // rate
        let moov = bx(b"moov", [bx(b"mvhd", mvhd), trak].concat());
        file.extend_from_slice(&moov);
        file
    }

    fn sample_frames() -> Vec<Vec<u8>> {
        vec![
            nal_sample(0x67, 15), // IDR
            nal_sample(0x61, 15), // non-IDR
            nal_sample(0x61, 15),
            nal_sample(0x61, 15),
        ]
    }

    #[test]
    fn an_intact_mp4_with_a_24_byte_ftyp_is_carved_whole() {
        // Phone/ffmpeg MP4s usually carry a 24-byte ftyp; the header needle used
        // to match only the 32-byte form, so every such file went down the
        // rebuild path instead of being carved as itself.
        let (orig, _, _) = synthetic_mp4();
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&orig);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump("mp4-intact-24", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.role, CarveRole::Whole, "{file:?}");
        assert_eq!(file.offset, 64);
        assert_eq!(file.size, orig.len() as u64, "{file:?}");
        assert!(file.complete, "{file:?}");
    }

    #[test]
    fn a_ruined_head_with_a_surviving_moov_rebuilds_the_container() {
        // The classic partial-encryption leftover for a phone video: ftyp and
        // mdat header gone, moov (at the end) intact, plus a ransomware
        // trailer. Expect a fresh ftyp+mdat header, chunk offsets shifted by
        // 32, and the trailer recorded in the index fields.
        let (orig, moov_offset, moov_len) = synthetic_mp4();
        let mut dump = vec![0xAAu8; 64]; // ruined ftyp + mdat header + start of payload
        dump.extend_from_slice(&orig[64..]);
        dump.extend_from_slice(b"VICTIM-ID-777"); // ransomware trailer
        let path = write_dump("mp4-rebuild", &dump);
        let out_dir = temp_dir("mp4-rebuild-out");
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .carve_to_dir(path.to_str().unwrap(), &out_dir)
            .unwrap();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.kind, CarveKind::Mp4);
        assert_eq!(file.role, CarveRole::Rebuilt);
        assert!(!file.complete, "{file:?}");
        assert_eq!(file.offset, 0, "the original file started at dump byte 0");
        // ftyp (24) + mdat header (8) + payload (8224) + moov (unchanged).
        let expected_len = 32 + 8224 + moov_len as u64;
        assert_eq!(file.size, expected_len, "{file:?}");
        assert_eq!(file.corrupted_offset, Some(0));
        assert!(file.evidence.contains(&"moov_ok"));
        assert!(file.evidence.contains(&"tables_cross_ok"));
        assert!(file.evidence.contains(&"chunk_range_ok"));
        assert!(file.notes.contains("rebuild"), "{}", file.notes);
        assert!(file.notes.contains("shift=32"), "{}", file.notes);
        assert!(file.notes.contains("13 B"), "{}", file.notes);
        let moov_end = (moov_offset + moov_len) as u64;
        assert_eq!(file.trailer_offset, Some(moov_end));
        assert_eq!(file.trailer_len, Some(13)); // "VICTIM-ID-777" is 13 bytes
        assert!(file.trailer_sha256.is_some());
        let preview = file.trailer_preview.as_deref().unwrap_or("");
        assert!(preview.contains("VICTIM-ID-777"), "{preview}");

        // The rebuilt file on disk must pass our own MP4 validator and carry
        // the shifted chunk offsets.
        let out_path = file.path.clone().expect("written to disk");
        let bytes = std::fs::read(&out_path).unwrap();
        assert_eq!(bytes.len() as u64, file.size);
        let mut rebuilt_file = std::fs::File::open(&out_path).unwrap();
        let mut cursor = Source::new(&mut rebuilt_file, 0, bytes.len() as u64);
        match carve_mp4(&mut cursor) {
            Ok(Verdict::Valid) => {}
            Ok(Verdict::Truncated(_)) => panic!("rebuilt file must validate: truncated"),
            Ok(Verdict::Invalid(reason)) => panic!("rebuilt file must validate: {reason}"),
            Err(error) => panic!("rebuilt file must validate: {error}"),
        }
        // The rebuilt moov sits at 32 + 8224 and its end-of-mdat lands on it.
        let moov_in_rebuilt = 32 + 8224;
        let (e_new, _) = analyze_moov(&bytes[moov_in_rebuilt..]).expect("rebuilt moov parses");
        assert_eq!(
            e_new, moov_in_rebuilt as u64,
            "end-of-mdat must shift with the header"
        );
        let _ = moov_offset;
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        std::fs::remove_dir_all(&out_dir).ok();
    }

    #[test]
    fn the_nal_oracle_marks_the_broken_prefix_and_finds_the_first_intact_sync() {
        // Sample 1 (the IDR) is corrupted: the NAL oracle must call it
        // broken, keep the other 3, notice the broken prefix, and report
        // sample 3 as the first intact sync sample (syncs are 1 and 3).
        let mut frames = sample_frames();
        frames[0][0] ^= 0xFF; // the NAL length MSB: an absurd length
        let dump = mp4_nal_fixture(b"avc1", &frames, Some(&[1, 3]));
        let path = write_dump("mp4-oracle-partial", &without_ftyp(dump));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        // The damaged first sample yields a first intact sync sample (3),
        // so a cut sibling is emitted alongside the full rebuild.
        assert_eq!(report.files.len(), 2, "{report:?}");
        let file = report
            .files
            .iter()
            .find(|file| file.role == CarveRole::Rebuilt)
            .expect("rebuilt file present");
        let tracks = file.tracks_intact.as_ref().expect("oracle ran");
        assert_eq!(tracks.len(), 1);
        let track = &tracks[0];
        assert_eq!(track.codec, "avc1");
        assert_eq!(track.samples, 4);
        assert_eq!(track.intact, 3);
        assert_eq!(track.broken_prefix, 1);
        assert!((track.intact_ratio - 0.75).abs() < 1e-9);
        assert_eq!(track.first_intact_sync_sample, Some(3));
        assert_eq!(track.first_intact_sync_time, Some(2.0)); // (1000+1000)/1000
        assert!(file.evidence.contains(&"nal_oracle"));
        assert_eq!(file.confidence, CarveConfidence::Medium);
        assert!(file.notes.contains("avc1"), "{}", file.notes);
        assert!(file.notes.contains("75.0%"), "{}", file.notes);
    }

    #[test]
    fn a_fully_intact_track_scores_confidence_high() {
        let dump = mp4_nal_fixture(b"avc1", &sample_frames(), Some(&[1, 3]));
        let path = write_dump("mp4-oracle-intact", &without_ftyp(dump));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        let tracks = file.tracks_intact.as_ref().expect("oracle ran");
        assert_eq!(tracks[0].intact, 4);
        assert_eq!(tracks[0].intact_ratio, 1.0);
        assert_eq!(tracks[0].first_intact_sync_sample, Some(1));
        assert_eq!(tracks[0].first_intact_sync_time, Some(0.0));
        assert_eq!(file.confidence, CarveConfidence::High);
    }

    #[test]
    fn the_first_sync_sample_is_found_without_an_stss_table() {
        // stss missing: every sample counts as sync, so the first intact
        // one after the broken prefix is sample 2.
        let mut frames = sample_frames();
        frames[0][0] ^= 0xFF;
        let dump = mp4_nal_fixture(b"avc1", &frames, None);
        let path = write_dump("mp4-oracle-no-stss", &without_ftyp(dump));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 2, "{report:?}");
        let file = report
            .files
            .iter()
            .find(|file| file.role == CarveRole::Rebuilt)
            .expect("rebuilt file present");
        let track = &file.tracks_intact.as_ref().unwrap()[0];
        assert_eq!(track.broken_prefix, 1);
        assert_eq!(track.first_intact_sync_sample, Some(2));
        assert_eq!(track.first_intact_sync_time, Some(1.0)); // one delta before it
    }

    #[test]
    fn an_audio_track_or_a_missing_configuration_record_skips_the_oracle() {
        // mp4a: no AVC/HEVC codec, so nothing is checked and the notes say so.
        let dump = mp4_nal_fixture(b"mp4a", &sample_frames(), None);
        let path = write_dump("mp4-oracle-audio", &without_ftyp(dump));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(file.tracks_intact.is_none(), "{file:?}");
        assert!(!file.evidence.contains(&"nal_oracle"));
        assert!(file.notes.contains("no oracle"), "{}", file.notes);
        assert_eq!(file.confidence, CarveConfidence::Medium);
    }

    #[test]
    fn a_cut_mp4_is_written_alongside_the_rebuilt_one() {
        // Sample 1 (the IDR) is damaged; the first intact sync sample is 3
        // at t = 2.0 s. The cut variant must start playback there via an
        // edit list; the full rebuild is kept alongside.
        let mut frames = sample_frames();
        frames[0][0] ^= 0xFF;
        let mut dump = mp4_nal_fixture(b"avc1", &frames, Some(&[1, 3]));
        // The ftyp is gone (what the rebuild path is for); an intact ftyp now
        // carves as a whole file instead.
        dump[4..8].copy_from_slice(&[0xAA; 4]);
        let path = write_dump("mp4-cut", &dump);
        let root = path.parent().unwrap().to_path_buf();
        let out_dir = root.join("out");
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .carve_to_dir(path.to_str().unwrap(), &out_dir)
            .unwrap();

        let rebuilt = report
            .files
            .iter()
            .find(|file| file.role == CarveRole::Rebuilt)
            .expect("rebuilt file present");
        let cut = report
            .files
            .iter()
            .find(|file| file.role == CarveRole::Cut)
            .expect("cut file present");
        assert_eq!(report.files.len(), 2, "{report:?}");
        assert_eq!(cut.offset, rebuilt.offset);
        assert_ne!(cut.sha256, rebuilt.sha256);
        assert_eq!(cut.tier, 2);
        assert_eq!(cut.confidence, CarveConfidence::Medium);
        assert!(cut.evidence.contains(&"nal_oracle"), "{cut:?}");
        assert!(cut.evidence.contains(&"elst_cut"), "{cut:?}");
        assert!(cut.evidence.contains(&"moov_ok"), "{cut:?}");
        assert!(cut.notes.contains("cut:"), "{}", cut.notes);
        assert_eq!(
            cut.tracks_intact.as_ref().unwrap()[0].first_intact_sync_sample,
            Some(3)
        );
        let cut_path = cut.path.clone().expect("cut file was written");
        let rebuilt_path = rebuilt.path.clone().expect("rebuilt file was written");
        assert!(rebuilt_path.is_file());
        assert!(cut_path.is_file());
        assert!(cut_path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".mp4.cut.carved"));
        assert_eq!(
            cut_path.parent().unwrap(),
            out_dir.join("partial").as_path()
        );
        assert_eq!(std::fs::metadata(&cut_path).unwrap().len(), cut.size);

        // elst layout: [size 4]['elst' 4][v/f 4][count 4][seg 4][time 4][rate 4]
        let bytes = std::fs::read(&cut_path).unwrap();
        let edts = bytes
            .windows(4)
            .position(|window| window == b"edts")
            .expect("edts box present");
        let elst = bytes
            .windows(4)
            .position(|window| window == b"elst")
            .expect("elst box present");
        assert_eq!(elst, edts + 8, "elst box follows the edts header");
        // [size]['elst'][v/f 4][count 4][seg 4][media_time 4][rate 4]
        let segment_duration = u32::from_be_bytes(bytes[elst + 12..elst + 16].try_into().unwrap());
        assert_eq!(segment_duration, u32::MAX, "rest of the track");
        let media_time = u32::from_be_bytes(bytes[elst + 16..elst + 20].try_into().unwrap());
        assert_eq!(media_time, 2000, "t = 2.0 s at a 1000 Hz mdhd");
        let rate = u32::from_be_bytes(bytes[elst + 20..elst + 24].try_into().unwrap());
        assert_eq!(rate, 0x0001_0000, "rate 1.0");

        // The cut file must pass our own MP4 validator end to end.
        let mut file = std::fs::File::open(&cut_path).unwrap();
        let len = file.metadata().unwrap().len();
        let mut source = Source::new(&mut file, 0, len);
        assert!(matches!(carve_mp4(&mut source).unwrap(), Verdict::Valid));

        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_fully_intact_mp4_gets_no_cut_sibling() {
        // Ftyp ruined, everything else intact and the first sync sample is
        // sample 1 (t = 0): there is nothing to skip, so no cut is emitted.
        let mut dump = mp4_nal_fixture(b"avc1", &sample_frames(), Some(&[1, 3]));
        dump[4..8].copy_from_slice(&[0xAA; 4]);
        let path = write_dump("mp4-cut-skip", &dump);
        let root = path.parent().unwrap().to_path_buf();
        let out_dir = root.join("out");
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .carve_to_dir(path.to_str().unwrap(), &out_dir)
            .unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].role, CarveRole::Rebuilt);
    }

    #[test]
    fn sample_nals_intact_rejects_garbage_lengths_and_headers() {
        let good = nal_sample(0x67, 15);
        assert!(sample_nals_intact(&good, NalKind::Avc, 4));
        // Corrupted length: absurd, overruns the sample.
        let mut bad_len = good.clone();
        bad_len[0] = 0xFF;
        assert!(!sample_nals_intact(&bad_len, NalKind::Avc, 4));
        // NAL header with the forbidden bit set.
        let mut bad_header = good.clone();
        bad_header[4] = 0x80;
        assert!(!sample_nals_intact(&bad_header, NalKind::Avc, 4));
        // Truncated sample: length points past the end.
        assert!(!sample_nals_intact(&good[..10], NalKind::Avc, 4));
        // Zero-length NAL is rejected.
        let mut zero_len = good.clone();
        zero_len[0] = 0;
        zero_len[1] = 0;
        zero_len[2] = 0;
        zero_len[3] = 0;
        assert!(!sample_nals_intact(&zero_len, NalKind::Avc, 4));
    }

    #[test]
    fn an_moov_with_non_monotonic_chunk_offsets_is_rejected() {
        // stco claims chunk 2 sits before chunk 1: impossible on disk, so the
        // table is corrupt and the moov is not usable.
        let chunk1 = (24 + 8) as u32;
        let chunk2 = chunk1 + 4096;
        let (misordered, _, _) = synthetic_mp4_with_stco((chunk2, chunk1), &[]);
        let path = write_dump("mp4-misordered", &without_ftyp(misordered));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
        assert!(
            report
                .rejected_details
                .iter()
                .any(|detail| detail.contains("mp4")),
            "{report:?}"
        );
    }

    #[test]
    fn a_fragmented_moov_is_rejected() {
        // mvex present: movie fragments, not supported by the rebuild (8.11.1).
        // An mvex container with no children is enough to mark the file as
        // fragmented (8.11.1: rejected unsupported).
        let mvex = {
            let mut out = Vec::new();
            out.extend_from_slice(&8u32.to_be_bytes()); // box size
            out.extend_from_slice(b"mvex");
            out
        };
        let chunk1 = (24 + 8) as u32;
        let chunk2 = chunk1 + 4096;
        let (file, _, _) = synthetic_mp4_with_stco((chunk1, chunk2), &[&mvex]);
        let path = write_dump("mp4-fragmented", &without_ftyp(file));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
        assert!(
            report
                .rejected_details
                .iter()
                .any(|detail| detail.contains("mvex")),
            "{report:?}"
        );
    }

    #[test]
    fn an_mp4_with_a_64_bit_mdat_size_is_carved_whole() {
        // size == 1 means the real size follows the type as a u64. The walk
        // used to re-read the 8 header bytes instead, so every box with an
        // extended size was mis-parsed.
        let mut mp4 = Vec::new();
        mp4.extend_from_slice(&24u32.to_be_bytes());
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend_from_slice(&0u32.to_be_bytes());
        mp4.extend_from_slice(b"isommp42");
        let payload = [0x5Au8; 200];
        mp4.extend_from_slice(&1u32.to_be_bytes());
        mp4.extend_from_slice(b"mdat");
        mp4.extend_from_slice(&(16 + payload.len() as u64).to_be_bytes());
        mp4.extend_from_slice(&payload);
        mp4.extend_from_slice(&8u32.to_be_bytes());
        mp4.extend_from_slice(b"moov");
        let mut dump = vec![0u8; 64];
        dump.extend_from_slice(&mp4);
        dump.extend_from_slice(&[0u8; 64]);
        let path = write_dump("mp4-ext-size", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.role, CarveRole::Whole, "{file:?}");
        assert_eq!(file.offset, 64);
        assert_eq!(file.size, mp4.len() as u64, "{file:?}");
        assert!(file.complete, "{file:?}");
    }

    /// Ruins the `ftyp` type of a fixture, the way a partial encryption does.
    /// Fixtures that exercise the rebuild path need this: an intact `ftyp` +
    /// `mdat` + `moov` is carved as a whole file and never reaches the rebuild.
    fn without_ftyp(mut dump: Vec<u8>) -> Vec<u8> {
        dump[4..8].copy_from_slice(&[0xAA; 4]);
        dump
    }

    /// Depth-first search for a box of type `want` between `from` and `to`.
    fn find_box(data: &[u8], from: usize, to: usize, want: &[u8; 4]) -> Option<usize> {
        let mut pos = from;
        while pos + 8 <= to {
            let size = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
            let typ: &[u8] = &data[pos + 4..pos + 8];
            if typ == want {
                return Some(pos);
            }
            if size == 0 || size < 8 || pos + size > to {
                return None;
            }
            if matches!(
                typ,
                b"moov" | b"trak" | b"mdia" | b"minf" | b"stbl" | b"edts" | b"dinf" | b"mvex"
            ) {
                if let Some(at) = find_box(data, pos + 8, pos + size, want) {
                    return Some(at);
                }
            }
            pos += size;
        }
        None
    }

    #[test]
    fn an_stsz_that_disagrees_with_stts_is_rejected() {
        // stts says 2 samples, stsz says 3: the tables cannot both be right.
        let chunk1 = (24 + 8) as u32;
        let chunk2 = chunk1 + 4096;
        let (file, _, _) = synthetic_mp4_with_stco((chunk1, chunk2), &[]);
        let mut file = file;
        let at = find_box(&file, 0, file.len(), b"stsz").expect("stsz present");
        // box header (8) + version/flags (4) + sample_size (4) + entry_count.
        file[at + 16..at + 20].copy_from_slice(&3u32.to_be_bytes());
        let path = write_dump("mp4-stsz-mismatch", &without_ftyp(file));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn an_stco_table_that_would_overflow_is_promoted_to_co64() {
        // Unit test of the patcher: an stco entry near u32::MAX cannot hold
        // `entry + 32`, so the table is rewritten as co64 and the shift is
        // applied exactly once.
        let stco = MoovBox {
            typ: *b"stco",
            data: {
                let mut data = vec![0u8; 4]; // version/flags
                data.extend_from_slice(&1u32.to_be_bytes()); // entry_count
                data.extend_from_slice(&0xFFFF_FFFEu32.to_be_bytes());
                data
            },
            children: Vec::new(),
            promote_to_co64: false,
        };
        let mut root = MoovBox {
            typ: *b"moov",
            data: Vec::new(),
            children: vec![stco],
            promote_to_co64: false,
        };
        let promoted = promote_overflowing_stco(&mut root, 32);
        assert_eq!(promoted, 1);
        let out = serialize_moov(&root, 32).unwrap();
        let at = out.windows(4).position(|window| window == b"co64").unwrap();
        let body = &out[at + 4..];
        assert_eq!(&body[0..4], &[0, 0, 0, 0]); // version/flags
        assert_eq!(u32::from_be_bytes(body[4..8].try_into().unwrap()), 1); // count
        assert_eq!(
            u64::from_be_bytes(body[8..16].try_into().unwrap()),
            0xFFFF_FFFE_u64 + 32,
            "the shift is applied exactly once"
        );
    }

    #[test]
    fn an_moov_whose_size_exceeds_the_dump_is_rejected_gracefully() {
        let (mut file, moov_offset, _) = synthetic_mp4();
        // Claim the moov is ~4 GiB: unreadable, must not panic or allocate.
        file[moov_offset..moov_offset + 4].copy_from_slice(&0xFFFF_FFF0u32.to_be_bytes());
        let path = write_dump("mp4-huge-moov", &without_ftyp(file));
        let options = CarveOptions {
            kinds: vec![CarveKind::Mp4],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn a_partial_encrypted_zip_with_only_the_header_left_reports_corruption_and_spike_offsets() {
        // Case "con header": the local header survived but the central
        // directory is gone (truncated), the classic partial-encryption
        // leftover. Expect: incomplete, corrupted_offset at the end of the
        // carved region, an entropy spike at the first random window, and
        // the suspected-partial-encryption label.
        let entry = zip_entry_with_periodic_payload();
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&entry);
        dump.extend_from_slice(&[0u8; 32]);
        let path = write_dump("periodic-zip-header", &dump);
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
        assert_eq!(file.offset, 32);
        // The size runs to the EOCD search frontier, slightly past the
        // local entry data; the only hard invariant is that it covers the
        // entry and that corrupted_offset sits at the end of the region.
        assert!(file.size >= entry.len() as u64, "{file:?}");
        assert_eq!(file.corrupted_offset, Some(file.offset + file.size));
        // Window 0 is the header (structured); the first high window is the
        // 4th data window == region window 4.
        assert_eq!(
            file.entropy_spike_at,
            Some(file.offset + 4 * SPIKE_WINDOW as u64),
            "{file:?}"
        );
        let hint = file
            .partial_encryption
            .expect("the 1:3 cycle must be detected");
        assert_eq!(hint.period, 16_384); // 4 windows * 4 KiB
                                         // 65 windows in the region, 16 high ones.
        assert!((hint.duty - 16.0 / 65.0).abs() < 1e-9, "duty {}", hint.duty);
        assert!(file.evidence.contains(&"suspected-partial-encryption"));
    }

    #[test]
    fn a_partial_encrypted_zip_with_only_the_footer_left_reports_the_tail_offsets() {
        // Case "con footer, mat header": local header and payload are gone,
        // the central directory + EOCD survived (footer-first salvage). The
        // tail is tiny, so the periodic label does not apply; expect
        // corrupted_offset == tail start and a spike at the boundary window.
        let zip = zip_bytes(
            "report.docx",
            &one_in_four_windows(16, 0x0FF1_CE57_0000_0001),
        );
        let eocd_at = zip
            .windows(4)
            .rposition(|chunk| chunk == b"PK\x05\x06")
            .unwrap();
        let cd_size =
            u32::from_le_bytes(zip[eocd_at + 12..eocd_at + 16].try_into().unwrap()) as usize;
        let cd_at = eocd_at - cd_size;
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&one_in_four_windows(16, 0x0FF1_CE57_0000_0002));
        let tail_at = dump.len() as u64;
        dump.extend_from_slice(&zip[cd_at..]);
        dump.extend_from_slice(&[0u8; 32]);
        let path = write_dump("periodic-zip-footer", &dump);
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
        assert_eq!(tail.offset, tail_at);
        assert_eq!(tail.corrupted_offset, Some(tail_at));
        // The boundary window right before the CD is the last random one.
        assert_eq!(
            tail.entropy_spike_at,
            Some(tail_at - SPIKE_WINDOW as u64),
            "{tail:?}"
        );
        assert!(tail.evidence.contains(&"footer"));
        // The CD + EOCD tail is far below the 64 KiB minimum for the
        // periodic scan, so the label stays off (by design).
        assert!(tail.partial_encryption.is_none());
        assert!(!tail.evidence.contains(&"suspected-partial-encryption"));
    }

    #[test]
    fn a_partial_encrypted_blob_with_no_header_and_no_footer_carves_nothing() {
        // Case "mat ca hai": a bare 1:3 region, no signature anywhere. No
        // header-first candidate, no footer for salvage, and alternating
        // high/zero 4 KiB blocks keep the bin pass below BIN_MIN_REGION,
        // so the region is deliberately not written out as a file in v1.
        let dump = one_in_four_windows(16, 0x0FF1_CE57_0000_0003);
        let path = write_dump("periodic-bare", &dump);
        let options = CarveOptions {
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .with_salvage(true)
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(
            report
                .files
                .iter()
                .all(|file| !file.evidence.contains(&"suspected-partial-encryption")),
            "no file means no label: {report:?}"
        );
        assert!(
            report.files.iter().all(|file| file.kind != CarveKind::Zip
                && file.kind != CarveKind::Pdf
                && file.kind != CarveKind::Png),
            "a bare 1:3 blob must not be rescued: {report:?}"
        );
    }

    #[test]
    fn a_bmp_with_a_periodic_encrypted_payload_is_labelled_suspected_partial_encryption() {
        // A BMP whose pixel region repeats 3 zero windows + 1 high-entropy
        // window (1:3 duty cycle) - the signature of file-system encryption
        // that keeps every 4th 4 KiB block. The header is padded to exactly
        // one window so the 4 KiB scan windows line up with the cycle.
        let mut bmp = Vec::new();
        let pixel_bytes = 64 * SPIKE_WINDOW; // 256 KiB
        let size = 4096 + pixel_bytes;
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&(size as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes()); // reserved
        bmp.extend_from_slice(&4096u32.to_le_bytes()); // data offset
        bmp.extend_from_slice(&40u32.to_le_bytes()); // DIB header
        bmp.extend_from_slice(&2i32.to_le_bytes()); // width
        bmp.extend_from_slice(&2i32.to_le_bytes()); // height
        bmp.extend_from_slice(&[1, 0]); // planes
        bmp.extend_from_slice(&24u16.to_le_bytes()); // bpp
        bmp.extend_from_slice(&[0u8; 24]); // colour table size + rest of DIB
        bmp.resize(4096, 0);
        for window in 0..16usize {
            bmp.extend_from_slice(&vec![0u8; SPIKE_WINDOW * 3]);
            bmp.extend_from_slice(&pseudo_random(SPIKE_WINDOW, 0x1234_5678 + window as u64));
        }
        assert_eq!(bmp.len(), size);

        let path = write_dump("periodic-bmp", &bmp);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.kind, CarveKind::Bmp);
        assert!(file.complete, "{file:?}");
        let hint = file
            .partial_encryption
            .expect("the 1:3 cycle must be detected");
        assert_eq!(hint.period, 16_384); // 4 windows * 4 KiB
        assert!(hint.duty > 0.2 && hint.duty < 0.3, "duty {}", hint.duty);
        assert!(file.evidence.contains(&"suspected-partial-encryption"));
        assert_eq!(hint.threshold, SPIKE_HIGH);
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
        // byte-order mark 0xFFFE at 0x1C, then sector size power = 9 (512 bytes) at 0x1E
        ole.extend_from_slice(&[0u8; 20]);
        ole.extend_from_slice(&0xFFFEu16.to_le_bytes());
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

    /// A structurally sound PE32+ whose sections are `(PointerToRawData,
    /// SizeOfRawData)`, padded out to the end of the last one.
    fn minimal_pe(sections: &[(u32, u32)]) -> Vec<u8> {
        const E_LFANEW: usize = 0x40;
        const OPT: usize = E_LFANEW + 24;
        const OPT_SIZE: usize = 240; // PE32+: 112 bytes + 16 data directories
        let headers = OPT + OPT_SIZE + sections.len() * 40;
        let size_of_headers = headers.next_multiple_of(0x200);
        let mut pe = vec![0u8; size_of_headers];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());
        pe[E_LFANEW..E_LFANEW + 4].copy_from_slice(b"PE\0\0");
        pe[E_LFANEW + 6..E_LFANEW + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        pe[E_LFANEW + 20..E_LFANEW + 22].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        pe[OPT..OPT + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[OPT + 60..OPT + 64].copy_from_slice(&(size_of_headers as u32).to_le_bytes());
        pe[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes());
        for (index, &(ptr, size)) in sections.iter().enumerate() {
            let at = OPT + OPT_SIZE + index * 40;
            pe[at..at + 5].copy_from_slice(b".text");
            pe[at + 16..at + 20].copy_from_slice(&size.to_le_bytes());
            pe[at + 20..at + 24].copy_from_slice(&ptr.to_le_bytes());
        }
        let end = sections
            .iter()
            .map(|&(ptr, size)| (ptr + size) as usize)
            .max()
            .unwrap_or(0)
            .max(pe.len());
        pe.resize(end, 0xCC);
        pe
    }

    #[test]
    fn pe_size_follows_the_section_table_and_is_complete() {
        let pe = minimal_pe(&[(0x200, 0x1000), (0x1200, 0x800)]);
        assert_eq!(pe.len(), 0x1a00);
        let mut dump = vec![0u8; 32];
        dump.extend_from_slice(&pe);
        dump.extend_from_slice(&[0u8; 8192]);
        let path = write_dump("pe-sections", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!((file.kind, file.offset), (CarveKind::Pe, 32));
        assert_eq!(file.size, pe.len() as u64);
        assert!(file.complete, "{report:?}");
        assert_eq!(file.confidence, CarveConfidence::High);
    }

    #[test]
    fn pe_certificate_table_extends_the_size() {
        let mut pe = minimal_pe(&[(0x200, 0x1000)]);
        let cert_at = pe.len() as u32;
        pe.resize(pe.len() + 0x400, 0xEE);
        // Data directory 4 (certificate table): file offset, then size.
        let directory = 0x40 + 24 + 112 + 4 * 8;
        pe[directory..directory + 4].copy_from_slice(&cert_at.to_le_bytes());
        pe[directory + 4..directory + 8].copy_from_slice(&0x400u32.to_le_bytes());
        let mut dump = pe.clone();
        dump.extend_from_slice(&[0u8; 8192]);
        let path = write_dump("pe-cert", &dump);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        assert_eq!(report.files[0].size, pe.len() as u64);
        assert!(report.files[0].complete);
    }

    #[test]
    fn pe_cut_inside_a_section_is_not_claimed_complete() {
        let pe = minimal_pe(&[(0x200, 0x1000), (0x1200, 0x800)]);
        // The dump ends in the middle of the second section.
        let path = write_dump("pe-cut", &pe[..0x1500]);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(!file.complete, "{report:?}");
        assert!(file.notes.contains("runs past"), "{}", file.notes);
        assert_eq!(file.confidence, CarveConfidence::Medium);
        // The whole first section is vouched for by the headers; the cut
        // second one is not.
        assert!(file.size >= 0x1200 && file.size <= 0x1500, "{}", file.size);
    }

    #[test]
    fn pe_with_a_bad_section_table_stays_header_only() {
        let mut pe = minimal_pe(&[(0x200, 0x1000)]);
        pe[0x40 + 24] = 0xFF; // optional header magic no longer 0x10b / 0x20b
        let path = write_dump("pe-bad-table", &pe);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(!file.complete);
        assert!(file.notes.contains("PE header only"), "{}", file.notes);
        assert_eq!(file.confidence, CarveConfidence::Medium);
        // Not the whole dump: the same 4 KiB as before the table was walked.
        assert!(file.size <= 0x40 + 4096, "{}", file.size);
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
        // This fixture has no section table, so nothing past the header was
        // validated: it is carved, but not claimed complete.
        assert!(!report.files[0].complete, "{report:?}");
        assert!(report.files[0].notes.contains("PE header only"));
        assert_eq!(report.files[0].confidence, CarveConfidence::Medium);

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

    /// A structurally sound ELF with one segment and two section headers; its
    /// size is `0x400 + 2 * section header size`.
    fn minimal_elf(wide: bool, little: bool) -> Vec<u8> {
        fn put(elf: &mut [u8], little: bool, at: usize, width: usize, value: u64) {
            let bytes = if little {
                value.to_le_bytes()[..width].to_vec()
            } else {
                value.to_be_bytes()[8 - width..].to_vec()
            };
            elf[at..at + width].copy_from_slice(&bytes);
        }
        let (header, phsize, shsize) = if wide { (64, 56, 64) } else { (52, 32, 40) };
        let data_end = 0x400usize;
        let mut elf = vec![0u8; data_end + 2 * shsize];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = if wide { 2 } else { 1 };
        elf[5] = if little { 1 } else { 2 };
        elf[6] = 1;
        let image = (header + phsize) as u64;
        let image_len = data_end as u64 - image;
        if wide {
            put(&mut elf, little, 32, 8, header as u64);
            put(&mut elf, little, 40, 8, data_end as u64);
            put(&mut elf, little, 54, 2, phsize as u64);
            put(&mut elf, little, 56, 2, 1);
            put(&mut elf, little, 58, 2, shsize as u64);
            put(&mut elf, little, 60, 2, 2);
            put(&mut elf, little, header + 8, 8, image);
            put(&mut elf, little, header + 32, 8, image_len);
        } else {
            put(&mut elf, little, 28, 4, header as u64);
            put(&mut elf, little, 32, 4, data_end as u64);
            put(&mut elf, little, 42, 2, phsize as u64);
            put(&mut elf, little, 44, 2, 1);
            put(&mut elf, little, 46, 2, shsize as u64);
            put(&mut elf, little, 48, 2, 2);
            put(&mut elf, little, header + 4, 4, image);
            put(&mut elf, little, header + 16, 4, image_len);
        }
        for byte in &mut elf[header + phsize..data_end] {
            *byte = 0x90;
        }
        elf
    }

    #[test]
    fn elf_size_follows_the_headers_for_every_class_and_byte_order() {
        for (wide, little) in [(true, true), (false, true), (false, false), (true, false)] {
            let elf = minimal_elf(wide, little);
            let mut dump = vec![0u8; 32];
            dump.extend_from_slice(&elf);
            dump.extend_from_slice(&[0u8; 8192]);
            let path = write_dump("elf-headers", &dump);
            let report = Carver::new(CarveOptions::default())
                .scan(path.to_str().unwrap())
                .unwrap();
            std::fs::remove_dir_all(path.parent().unwrap()).ok();

            assert_eq!(
                report.files.len(),
                1,
                "wide={wide} little={little} {report:?}"
            );
            let file = &report.files[0];
            assert_eq!((file.kind, file.offset), (CarveKind::Elf, 32));
            assert_eq!(file.size, elf.len() as u64, "wide={wide} little={little}");
            assert!(file.complete, "wide={wide} little={little} {report:?}");
            assert_eq!(file.confidence, CarveConfidence::High);
        }
    }

    #[test]
    fn elf_cut_inside_its_segment_is_not_claimed_complete() {
        let elf = minimal_elf(true, true);
        let path = write_dump("elf-cut", &elf[..0x200]);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(!file.complete, "{report:?}");
        assert!(file.notes.contains("run past"), "{}", file.notes);
        assert_eq!(file.confidence, CarveConfidence::Medium);
        assert!(file.size <= 0x200, "{}", file.size);
    }

    #[test]
    fn elf_with_a_wrong_header_entry_size_stays_header_only() {
        let mut elf = minimal_elf(true, true);
        elf[54..56].copy_from_slice(&7u16.to_le_bytes()); // e_phentsize
        let path = write_dump("elf-bad-phentsize", &elf);
        let report = Carver::new(CarveOptions::default())
            .scan(path.to_str().unwrap())
            .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert!(!file.complete);
        assert!(file.notes.contains("ELF header only"), "{}", file.notes);
        assert_eq!(file.confidence, CarveConfidence::Medium);
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
        // No program or section headers: nothing past the header was
        // validated, so it is carved but not claimed complete.
        assert!(!report.files[0].complete, "{report:?}");
        assert!(report.files[0].notes.contains("ELF header only"));
        assert_eq!(report.files[0].confidence, CarveConfidence::Medium);

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

    #[test]
    fn bin_pass_cuts_the_high_entropy_run_and_skips_text_and_zeros() {
        let mut dump = vec![0u8; 0x4000];
        dump.extend_from_slice(&pseudo_random(0x10000, 0x5eed_0000_0000_0001));
        dump.extend_from_slice(&md_text(4));
        dump.extend_from_slice(&vec![0u8; 0x2000]);
        let path = write_dump("bin-basic", &dump);
        let out = path.parent().unwrap().join("out");
        let options = CarveOptions {
            kinds: vec![CarveKind::Bin],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options)
            .carve_to_dir(path.to_str().unwrap(), &out)
            .unwrap();

        assert_eq!(report.files.len(), 1, "{report:?}");
        let file = &report.files[0];
        assert_eq!(file.kind, CarveKind::Bin);
        assert_eq!(file.offset, 0x4000);
        assert_eq!(file.size, 0x10000);
        assert!(!file.complete);
        assert!(file.entropy > 7.5, "{file:?}");
        assert!(file.notes.starts_with("bin:region"), "{file:?}");
        assert_eq!(file.ext, "bin");
        assert_eq!(file.role, CarveRole::Whole);
        assert_eq!(file.tier, 3);
        assert_eq!(file.evidence, vec!["entropy"]);
        assert_eq!(file.confidence.as_str(), "low");

        let on_disk = file.path.as_ref().expect("written to disk");
        let name = on_disk.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.ends_with(".bin.carved"), "{name}");
        assert!(name.starts_with("00004000-bin-"), "{name}");
        assert_eq!(on_disk.parent().unwrap().file_name().unwrap(), "partial");
        assert_eq!(std::fs::read(on_disk).unwrap(), dump[0x4000..0x14000]);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn bin_pass_ignores_runs_below_the_minimum_region() {
        let mut dump = vec![0u8; 0x4000];
        dump.extend_from_slice(&pseudo_random(0x2000, 0x5eed_0000_0000_0002));
        dump.extend_from_slice(&vec![0u8; 0x4000]);
        let path = write_dump("bin-small", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Bin],
            min_size: 0,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(report.files.is_empty(), "{report:?}");
    }

    #[test]
    fn bin_pass_splits_a_run_longer_than_max_size() {
        let dump = pseudo_random(0x30000, 0x5eed_0000_0000_0003);
        let path = write_dump("bin-split", &dump);
        let options = CarveOptions {
            kinds: vec![CarveKind::Bin],
            min_size: 0,
            max_size: 0x10000,
            ..Default::default()
        };
        let report = Carver::new(options).scan(path.to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        let offsets: Vec<u64> = report.files.iter().map(|file| file.offset).collect();
        assert_eq!(offsets, vec![0, 0x10000, 0x20000], "{report:?}");
        assert!(report.files.iter().all(|file| file.size == 0x10000));
    }

    #[test]
    fn bin_pass_is_opt_in_and_all_does_not_include_it() {
        assert!(!CarveKind::ALL.contains(&CarveKind::Bin));
        assert_eq!(
            CarveKind::from_list("all").unwrap(),
            CarveKind::ALL.to_vec()
        );
        assert!(CarveKind::from_list("bin")
            .unwrap()
            .contains(&CarveKind::Bin));
        assert!(CarveKind::from_list("all,bin")
            .unwrap()
            .contains(&CarveKind::Bin));
        assert_eq!(CarveKind::Bin.default_ext(), "bin");

        let dump = pseudo_random(0x20000, 0x5eed_0000_0000_0004);
        let path = write_dump("bin-optin", &dump);
        let report = Carver::new(CarveOptions {
            kinds: CarveKind::ALL.to_vec(),
            min_size: 0,
            ..Default::default()
        })
        .scan(path.to_str().unwrap())
        .unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).ok();

        assert!(
            report.files.iter().all(|file| file.kind != CarveKind::Bin),
            "{report:?}"
        );
    }

    /// Block-aligned deterministic text fixture: `blocks` blocks of 64-byte
    /// lines, ending on a newline. The first line is exactly 64 bytes.
    fn md_text(blocks: usize) -> Vec<u8> {
        let line = format!(
            "{:<63}\n",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
        );
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
        let mut dump = pseudo_random(0x10000, 0x0000_ca11_ab1e_0000_0001);
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
        assert!(CarveKind::from_list("text")
            .unwrap()
            .contains(&CarveKind::Text));
        assert!(CarveKind::from_list("txt")
            .unwrap()
            .contains(&CarveKind::Text));
        assert!(CarveKind::from_list("all,text")
            .unwrap()
            .contains(&CarveKind::Text));

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
            text_file.offset >= zip_end
                && text_file.offset + text_file.size
                    <= zip_at + zip.len() as u64 + text.len() as u64 + 1,
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
        // MPEG1 Layer III, 128 kbps, 44100 Hz: frame length is
        // 144 * 128000 / 44100 = 417 bytes INCLUDING the 4-byte header
        // (so 413 bytes of payload per frame). Two consecutive frames:
        // a lone frame is (correctly) not a file.
        let mut out = vec![0xff, 0xfb, 0x90, 0x00];
        out.extend(std::iter::repeat(0u8).take(413));
        out.extend_from_slice(&[0xff, 0xfb, 0x90, 0x00]);
        out.extend(std::iter::repeat(0u8).take(413));
        out
    }

    fn minimal_mp3_with_id3() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"ID3");
        out.extend_from_slice(&[3, 0, 0, 0, 0, 0, 0]); // ver 3, syncsafe size 0
        out.extend_from_slice(&minimal_mp3_frame());
        out
    }

    /// Minimal but structurally valid XZ: magic + stream flags 0x0000 +
    /// CRC32 of the two flag bytes (which is all the spec covers).
    fn minimal_xz() -> Vec<u8> {
        vec![
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, // magic
            0x00, 0x00, // stream flags (check = 0x00)
            0xff, 0x12, 0xd9, 0x41, // CRC32 of the stream flags, little-endian
        ]
    }

    /// A complete empty XZ stream (header + empty index + footer, 32 bytes).
    fn minimal_xz_stream() -> Vec<u8> {
        let flags = [0x00u8, 0x04]; // check = CRC64
        let zlib_crc = |bytes: &[u8]| (crc32(0xffff_ffff, bytes) ^ 0xffff_ffff).to_le_bytes();
        let mut out = vec![0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
        out.extend_from_slice(&flags);
        out.extend_from_slice(&zlib_crc(&flags));
        let index = [0x00u8; 4]; // indicator, zero records, padding
        out.extend_from_slice(&index);
        out.extend_from_slice(&zlib_crc(&index));
        let mut tail = Vec::new();
        tail.extend_from_slice(&1u32.to_le_bytes()); // backward size: (1 + 1) * 4 = 8
        tail.extend_from_slice(&flags);
        out.extend_from_slice(&zlib_crc(&tail));
        out.extend_from_slice(&tail);
        out.extend_from_slice(b"YZ");
        out
    }

    /// A BZIP2 stream whose end-of-stream marker sits at a non-byte-aligned
    /// bit offset (the real-world case).
    fn minimal_bz2_stream() -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        let mut push = |value: u64, width: u32| {
            for i in (0..width).rev() {
                bits.push((value >> i) & 1 == 1);
            }
        };
        push(0x3141_5926_5359, 48); // block magic
        for _ in 0..13 {
            push(0, 7); // 91 junk bits: the marker starts 3 bits into a byte
        }
        push(0x1772_4538_5090, 48); // end-of-stream magic
        push(0xdead_beef, 32); // combined CRC
        let mut out = b"BZh9".to_vec();
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    byte |= 0x80 >> i;
                }
            }
            out.push(byte);
        }
        out
    }
    /// 0b1000_0000): the table is 6 bytes, so any off-by-one in the size
    /// check lands the walker in the middle of the table.
    fn minimal_gif_gct() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GIF89a");
        out.extend_from_slice(&1u16.to_le_bytes()); // width
        out.extend_from_slice(&1u16.to_le_bytes()); // height
        out.push(0x80); // packed: GCT present, size bits = 0 (2 entries)
        out.push(0); // background
        out.push(0); // aspect
        out.extend_from_slice(&[0u8; 6]); // GCT (2 entries * 3 bytes)
        out.push(0x2c); // image descriptor
        out.extend_from_slice(&[0u8; 8]); // left/top/width/height
        out.push(0x00); // packed: no local color table
        out.push(2); // LZW minimum code size
        out.push(2); // sub-block size
        out.extend_from_slice(&[0x44, 0x01]); // data
        out.push(0x00); // block terminator
        out.push(0x3b); // trailer
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
    fn xz_and_gif_with_a_global_color_table_are_carved() {
        // XZ validates magic + stream flags + their CRC, then carves to the
        // candidate window: it is *never* complete (the body is a Huffman
        // bit stream we do not decode).
        let report = carve_one("xz", CarveKind::Xz, &minimal_xz());
        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(!report.files[0].complete, "{:?}", report.files[0]);
        assert_eq!(report.files[0].kind, CarveKind::Xz);
        // A GIF with a 2-entry global color table (6 bytes) must walk out of
        // the table cleanly; before the fix the walker desynced inside it.
        let report = carve_one("gif-gct", CarveKind::Gif, &minimal_gif_gct());
        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(report.files[0].complete, "{:?}", report.files[0]);
    }

    #[test]
    fn xz_and_bz2_extents_stop_at_their_own_terminator() {
        // Before: the extent was the whole candidate window, so a small .xz
        // swallowed every carve behind it. Now it ends at the XZ footer / the
        // BZIP2 end-of-stream marker, and trailing bytes stay out.
        let junk = std::iter::repeat(0xaau8).take(4096);
        for (name, kind, stream) in [
            ("xz-term", CarveKind::Xz, minimal_xz_stream()),
            ("bz2-term", CarveKind::Bz2, minimal_bz2_stream()),
        ] {
            let mut payload = stream.clone();
            payload.extend(junk.clone());
            let report = carve_one(name, kind, &payload);
            assert_eq!(report.files.len(), 1, "{name}: {report:?}");
            assert!(report.files[0].complete, "{name}: {:?}", report.files[0]);
            assert_eq!(report.files[0].size, stream.len() as u64, "{name}");
        }
    }

    #[test]
    fn xz_with_a_corrupt_footer_is_not_trusted() {
        let mut stream = minimal_xz_stream();
        let len = stream.len();
        stream[len - 12] ^= 0xff; // footer CRC-32
        let report = carve_one("xz-bad-footer", CarveKind::Xz, &stream);
        assert_eq!(report.files.len(), 1, "{report:?}");
        assert!(!report.files[0].complete, "{:?}", report.files[0]);
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

    /// ROADMAP 8.10.9: the static table covers every one of the 41 kinds and
    /// each kind keeps the extension users expect.
    #[test]
    fn default_ext_table_covers_all_41_kinds() {
        use CarveKind::*;
        let expected: [(CarveKind, &str); 41] = [
            (Jpeg, "jpg"),
            (Png, "png"),
            (Zip, "zip"),
            (Rar4, "rar"),
            (Rar5, "rar"),
            (SevenZip, "7z"),
            (Pdf, "pdf"),
            (Gzip, "gz"),
            (Bmp, "bmp"),
            (Sqlite, "sqlite"),
            (Ole, "ole"),
            (Mp4, "mp4"),
            (Pe, "exe"),
            (Elf, "elf"),
            (Gif, "gif"),
            (Ico, "ico"),
            (Tar, "tar"),
            (Pcap, "pcap"),
            (Pcapng, "pcapng"),
            (Lnk, "lnk"),
            (Wasm, "wasm"),
            (Dex, "dex"),
            (Kdbx, "kdbx"),
            (Pem, "pem"),
            (Avi, "avi"),
            (Wav, "wav"),
            (Webp, "webp"),
            (Mkv, "mkv"),
            (Webm, "webm"),
            (Ogg, "ogg"),
            (Opus, "opus"),
            (Flac, "flac"),
            (Mp3, "mp3"),
            (Tiff, "tif"),
            (Vdi, "vdi"),
            (Vmdk, "vmdk"),
            (Bz2, "bz2"),
            (Xz, "xz"),
            (Class, "class"),
            (Rtf, "rtf"),
            (Evtx, "evtx"),
        ];
        assert_eq!(CarveKind::ALL.len(), 41);
        for (kind, ext) in expected {
            assert_eq!(kind.default_ext(), ext, "{kind:?}");
            assert!(CarveKind::ALL.contains(&kind), "{kind:?} missing from ALL");
        }
        // Only the two RAR generations share an extension.
        let mut exts: Vec<&str> = CarveKind::ALL.iter().map(|k| k.default_ext()).collect();
        exts.sort_unstable();
        exts.dedup();
        assert_eq!(exts.len(), 40);
        assert_eq!(CarveKind::Text.default_ext(), "txt");
        assert_eq!(CarveKind::Bin.default_ext(), "bin");
    }

    /// An extension that is not `[a-z0-9]{1,8}` never reaches the file name.
    #[test]
    fn hostile_or_malformed_ext_falls_back_to_the_kind_default() {
        for ext in [
            "",
            "../x",
            "..",
            "DOCX",
            "docx.exe",
            "123456789",
            "a b",
            "é",
            "doc\0",
            "a/b",
            "a\\b",
            "c:",
            " ",
        ] {
            let name = carved_file_name_with_ext(1, CarveKind::Zip, ext, CarveRole::Whole, SHA);
            assert_eq!(name, "00000001-zip-9f3c1e2a.zip.carved", "{ext:?}");
        }
        let name = carved_file_name_with_ext(1, CarveKind::Zip, "docx", CarveRole::Whole, SHA);
        assert_eq!(name, "00000001-zip-9f3c1e2a.docx.carved");
        let name = carved_file_name_with_ext(1, CarveKind::Zip, "..", CarveRole::Tail, SHA);
        assert_eq!(name, "00000001-zip-9f3c1e2a.zip.tail.carved");
    }

    /// Names start with a hex digit and only use `[a-z0-9.-]`, so they can
    /// never be a Windows device name (`CON`, `NUL`, `COM1`...), end in a dot
    /// or space, hide a `..`, and stay far below 255 bytes even at the
    /// largest offset.
    #[test]
    fn names_are_never_reserved_windows_names_or_too_long() {
        const RESERVED: [&str; 8] = [
            "con", "prn", "aux", "nul", "clock$", "conin$", "conout$", "com1",
        ];
        let mut kinds: Vec<CarveKind> = CarveKind::ALL.to_vec();
        kinds.push(CarveKind::Text);
        kinds.push(CarveKind::Bin);
        let sha = "e".repeat(64);
        for kind in kinds {
            for role in [CarveRole::Whole, CarveRole::Tail, CarveRole::Reassembled] {
                for offset in [0u64, 0xc0de, u64::MAX] {
                    let name = carved_file_name(offset, kind, role, &sha);
                    assert!(name.len() <= 100, "{name}");
                    assert!(name.as_bytes()[0].is_ascii_hexdigit(), "{name}");
                    assert!(
                        name.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
                        }),
                        "{name}"
                    );
                    assert!(!name.contains(".."), "{name}");
                    assert!(!name.ends_with('.') && !name.ends_with(' '), "{name}");
                    // Windows reserves the part before the first dot.
                    let stem = name.split('.').next().unwrap();
                    assert!(!RESERVED.contains(&stem), "{name}");
                    assert!(
                        !(stem.starts_with("com") || stem.starts_with("lpt")),
                        "{name}"
                    );
                }
            }
        }
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
                    && ext
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
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

#[cfg(test)]
mod evidence_tests {
    use super::*;

    fn file(tier: u8, ext: &str, role: CarveRole) -> CarvedFile {
        CarvedFile {
            offset: 0,
            kind: CarveKind::Zip,
            size: 1,
            complete: tier == 1,
            sha256: "0".repeat(64),
            entropy: 0.0,
            notes: String::new(),
            path: None,
            duplicates: Vec::new(),
            corrupted_offset: None,
            entropy_spike_at: None,
            partial_encryption: None,
            trailer_offset: None,
            trailer_len: None,
            trailer_sha256: None,
            trailer_preview: None,
            tracks_intact: None,
            ext: ext.to_string(),
            ext_source: "kind".to_string(),
            role,
            tier,
            evidence: Vec::new(),
            confidence: CarveConfidence::High,
        }
    }

    #[test]
    fn evidence_tiers_follow_what_was_established() {
        let (tier, evidence, confidence) =
            evidence_for(CarveRole::Whole, CarveKind::Pe, true, "kind");
        assert_eq!(tier, 1);
        assert_eq!(evidence, ["magic", "structure_ok", "terminator_ok"]);
        assert_eq!(confidence, CarveConfidence::High);

        // A sniff rule that refined the extension is part of the evidence.
        let (_, evidence, _) =
            evidence_for(CarveRole::Whole, CarveKind::Zip, true, "sniff:zip/word");
        assert_eq!(evidence.last().copied(), Some("sniff:zip/word"));

        let (tier, evidence, confidence) =
            evidence_for(CarveRole::Whole, CarveKind::Zip, false, "fallback");
        assert_eq!(tier, 2);
        assert_eq!(evidence, ["magic", "structure_partial"]);
        assert_eq!(confidence, CarveConfidence::Medium);
        // `fallback` is not evidence of anything.
        assert!(!evidence.contains(&"fallback"));

        let (tier, evidence, confidence) =
            evidence_for(CarveRole::Tail, CarveKind::Png, false, "kind");
        assert_eq!((tier, confidence), (2, CarveConfidence::Low));
        assert_eq!(evidence, ["footer"]);

        let (tier, evidence, confidence) =
            evidence_for(CarveRole::Whole, CarveKind::Text, false, "kind");
        assert_eq!((tier, confidence), (3, CarveConfidence::Low));
        assert_eq!(evidence, ["text_ratio"]);
    }

    #[test]
    fn role_and_confidence_ids_are_stable() {
        assert_eq!(CarveRole::Whole.as_str(), "whole");
        assert_eq!(CarveRole::Tail.as_str(), "tail");
        assert_eq!(CarveRole::Reassembled.as_str(), "reassembled");
        assert_eq!(CarveConfidence::High.as_str(), "high");
        assert_eq!(CarveConfidence::Medium.as_str(), "medium");
        assert_eq!(CarveConfidence::Low.as_str(), "low");
    }

    #[test]
    fn periodic_encryption_hint_is_attached_to_evidence() {
        let evidence = with_suspect(
            vec!["magic"],
            Some(PartialEncryption {
                period: 16_384,
                duty: 0.25,
                threshold: 7.8,
            }),
        );
        assert_eq!(evidence, ["magic", "suspected-partial-encryption"]);
        assert_eq!(with_suspect(vec!["magic"], None), ["magic"]);
    }

    #[test]
    fn periodic_high_cycle_is_detected_at_the_right_period() {
        // 1 of every 4 windows is high entropy, 64 windows (16 cycles),
        // starting at residue 3.
        let mut mask = vec![false; 64];
        for index in (3..64).step_by(4) {
            mask[index] = true;
        }
        let (period, duty) = detect_periodic_high(&mask).expect("1:3 cycle detected");
        assert_eq!(period, 16_384); // 4 windows * 4 KiB
        assert!((duty - 16.0 / 64.0).abs() < 1e-9);

        // Period 2 (every other window), 32 windows = 16 cycles.
        let mut mask = vec![false; 32];
        for index in (0..32).step_by(2) {
            mask[index] = true;
        }
        let (period, duty) = detect_periodic_high(&mask).expect("1:1 cycle detected");
        assert_eq!(period, 8_192);
        assert!((duty - 0.5).abs() < 1e-9);
    }

    #[test]
    fn uniformly_high_or_low_data_is_not_partial_encryption() {
        // All random, no structure: not *partial*.
        assert_eq!(detect_periodic_high(&[true; 64]), None);
        // All structured: no high-entropy phase at all.
        assert_eq!(detect_periodic_high(&[false; 64]), None);
        // 9 of 10 windows high (uniform encryption / compression) but the
        // trailing window varies: still uniform-ish, not *partial*.
        let mut mask = vec![true; 64];
        mask[1] = false;
        mask[33] = false;
        mask[49] = false; // 61/64 = 95% high overall
        assert_eq!(detect_periodic_high(&mask), None);
        // Fewer than 3 high windows: nothing to find.
        let mut mask = vec![false; 64];
        mask[0] = true;
        mask[17] = true;
        assert_eq!(detect_periodic_high(&mask), None);
        // Not enough windows for 8 full cycles of any period.
        assert_eq!(detect_periodic_high(&[true, false, true, false]), None);
        // No bucket reaches the 80% hot threshold for any period:
        // high windows at scattered indices with no common residue class.
        let mut mask = vec![false; 64];
        for index in [0usize, 7, 23, 41] {
            mask[index] = true;
        }
        assert_eq!(detect_periodic_high(&mask), None);
    }

    #[test]
    fn phase_where_one_bucket_is_hot_and_the_rest_are_cold_is_detected() {
        // 3 cold, 1 hot buckets, but the hot phase starts at residue 2.
        let mut mask = vec![false; 64];
        for index in (2..64).step_by(4) {
            mask[index] = true;
        }
        assert!(detect_periodic_high(&mask).is_some());
    }

    #[test]
    fn summary_line_counts_tiers_and_extensions() {
        let mut report = CarveReport::default();
        report.files.push(file(1, "docx", CarveRole::Whole));
        report.files.push(file(1, "docx", CarveRole::Whole));
        report.files.push(file(2, "png", CarveRole::Tail));
        report.files.push(file(3, "txt", CarveRole::Whole));
        let line = report.summary_line();
        assert!(
            line.contains("(tier T1=2 T2=1 T3=1; ext docx=2 png=1 txt=1)"),
            "{line}"
        );

        // No files, no tier/ext clutter.
        assert!(!CarveReport::default().summary_line().contains("tier"));
    }
}
