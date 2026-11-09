use super::*;
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::sync::OnceLock;

pub fn build_user_stats(artifacts: &[Artifact], filter_appdata: bool) -> Vec<UserStat> {
    use std::collections::HashMap;

    #[derive(Default)]
    struct Accumulator {
        total: usize,
        appdata: usize,
    }

    let mut map: HashMap<String, Accumulator> = HashMap::new();

    for artifact in artifacts.iter() {
        if artifact.kind != bxmap::artifacts::ArtifactKind::Path {
            continue;
        }
        let detail = artifact.detail.as_deref();
        if let Some((user, category)) = detail.and_then(parse_path_detail) {
            let entry = map.entry(user).or_default();
            entry.total += 1;
            if category == "appdata" {
                entry.appdata += 1;
            }
        }
    }

    let mut stats: Vec<UserStat> = map
        .into_iter()
        .map(|(name, acc)| {
            let visible_total = if filter_appdata {
                acc.total.saturating_sub(acc.appdata)
            } else {
                acc.total
            };
            let pct_appdata = if visible_total > 0 {
                acc.appdata as f64 * 100.0 / visible_total as f64
            } else {
                0.0
            };
            UserStat {
                name,
                file_count: acc.total,
                appdata_file_count: acc.appdata,
                pct_appdata,
            }
        })
        .collect();

    stats.sort_by_key(|a| std::cmp::Reverse(a.file_count));
    stats
}

/// Print consolidated per-user file list (one line per user).
pub fn print_user_report(stats: &[UserStat], min_files: usize, filter_appdata: bool) {
    if stats.is_empty() {
        eprintln!("[user-report] no user-profile paths found");
        return;
    }

    let label = if filter_appdata {
        "files (excl. AppData)"
    } else {
        "files (incl. AppData)"
    };
    eprintln!("[user-report] per-user {label} (min={min_files}):");
    for stat in stats {
        if stat.file_count < min_files {
            continue;
        }
        eprintln!(
            "  {:<20}  {:>6} files  AppData: {:>4} ({:>5.1}%)",
            stat.name, stat.file_count, stat.appdata_file_count, stat.pct_appdata
        );
    }
}

pub static DUMP_MAP: OnceLock<bxmap::minidump::Minidump> = OnceLock::new();

/// Virtual address and a short module/region label for a file offset,
/// when `--map-va` loaded a minidump and the offset lies in a captured range.
pub fn va_annotation(offset: u64) -> Option<(u64, String)> {
    let dump = DUMP_MAP.get()?;
    let va = dump.offset_to_va(offset)?;
    let label = match dump.module_for_va(va) {
        Some(m) => m
            .name
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&m.name)
            .to_string(),
        None => dump.region_for_va(va).map_or("-".to_string(), |r| {
            format!(
                "{} {}",
                r.kind_name(),
                bxmap::minidump::protect_name(r.protect)
            )
        }),
    };
    Some((va, label))
}

pub fn passes_region_filter(
    offset: u64,
    module: &Option<String>,
    rwx_only: bool,
    heap_only: bool,
) -> bool {
    if module.is_none() && !rwx_only && !heap_only {
        return true;
    }
    let dump = match DUMP_MAP.get() {
        Some(dump) => dump,
        None => return true,
    };
    let va = match dump.offset_to_va(offset) {
        Some(va) => va,
        None => return false,
    };
    if let Some(needle) = module {
        let needle = needle.to_ascii_lowercase();
        match dump.module_for_va(va) {
            Some(m) if m.name.to_ascii_lowercase().contains(&needle) => {}
            _ => return false,
        }
    }
    if rwx_only {
        match dump.region_for_va(va) {
            Some(r) if r.is_executable() && r.is_writable() => {}
            _ => return false,
        }
    }
    if heap_only {
        match dump.region_for_va(va) {
            Some(r) if r.kind == 0x20000 => {}
            _ => return false,
        }
    }
    true
}

pub const MAX_XOR_CANDIDATES: usize = 256;
pub const MAX_XOR_CANDIDATE_LEN: usize = 100;
pub const MIN_XOR_CANDIDATE_LEN: usize = 10;
pub const MAX_XOR_RESULTS_PER_CANDIDATE: usize = 5;
pub const MIN_XOR_ALNUM_CHARS: usize = 3;
/// Cap on unique artifacts kept in memory. Memory dumps can contain millions of
/// distinct paths; the cap keeps `--extract` bounded on huge inputs.
pub const MAX_ARTIFACTS: usize = 20_000;
/// Encodings the scanner can emit, in report order.
pub const ENCODING_LABELS: [&str; 9] = [
    "ascii",
    "utf16le",
    "utf16be",
    "utf32le",
    "utf32be",
    "latin1",
    "cp1252",
    "utf8",
    "shift_jis",
];

pub fn count_encodings(results: &[ExtractedString]) -> [usize; ENCODING_LABELS.len()] {
    let mut counts = [0usize; ENCODING_LABELS.len()];
    for result in results {
        if let Some(slot) = ENCODING_LABELS
            .iter()
            .position(|label| *label == result.encoding)
        {
            counts[slot] += 1;
        }
    }
    counts
}

/// `ascii 12 | utf16le 3`, skipping encodings that produced nothing.
pub fn encoding_breakdown(counts: &[usize; ENCODING_LABELS.len()]) -> String {
    let parts: Vec<String> = ENCODING_LABELS
        .iter()
        .zip(counts.iter())
        .filter(|(_, count)| **count > 0)
        .map(|(label, count)| format!("{label} {count}"))
        .collect();
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(" | ")
    }
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Format {
    Text,
    Json,
    JsonTree,
    /// Newline-delimited JSON: one self-contained record per line, with a
    /// `"type"` discriminator so mixed record kinds stay parseable.
    Ndjson,
    /// RFC 4180 CSV with a fixed header; strings, findings and artifacts.
    Csv,
    /// Self-contained HTML report (CSS/JS inline) for case sharing.
    Html,
    /// Markdown report for case notes and notebooks.
    Markdown,
}

/// How a JSON record is framed when written one at a time.
#[derive(Clone, Copy, PartialEq)]
pub enum JsonLayout {
    /// Inside a pretty-printed array: `,\n` separator, two-space indent.
    Array,
    /// Inside a minified array: `,` separator, no indent.
    ArrayCompact,
    /// NDJSON: `\n` separator, no indent, plus a `type` discriminator.
    Lines,
}

/// Pick the record layout for the requested format and `--compact` flag.
pub fn json_layout_for(format: Format, compact: bool) -> JsonLayout {
    match format {
        Format::Ndjson => JsonLayout::Lines,
        _ if compact => JsonLayout::ArrayCompact,
        _ => JsonLayout::Array,
    }
}

/// Infer the output format from the `-o` path. A trailing `.gz` is
/// transparent, so `case.ndjson.gz` still maps to ndjson. Unknown extensions
/// return `None` and the caller keeps the current default.
pub fn infer_format_from_output_path(path: &str) -> Option<Format> {
    let lower = path.to_ascii_lowercase();
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    let ext = std::path::Path::new(stem).extension()?.to_str()?;
    Some(match ext {
        "json" => Format::Json,
        "ndjson" | "jsonl" => Format::Ndjson,
        "csv" => Format::Csv,
        "md" | "markdown" => Format::Markdown,
        "html" | "htm" => Format::Html,
        "txt" | "text" | "log" => Format::Text,
        _ => return None,
    })
}

/// Output sink: plain file/stdout, or gzip-compressed when the `-o` path ends
/// in `.gz`.
///
/// `finish` must be called before the process exits so the gzip trailer is
/// written even on early exits (e.g. `--max-strings` truncation).
pub enum Sink {
    Plain(BufWriter<Box<dyn Write>>),
    Gzip(BufWriter<flate2::write::GzEncoder<File>>),
}

impl Sink {
    pub fn open(path: Option<&str>) -> Result<Self, String> {
        let Some(path) = path else {
            return Ok(Sink::Plain(BufWriter::new(Box::new(io::stdout().lock()))));
        };
        let file = File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?;
        if path.to_ascii_lowercase().ends_with(".gz") {
            Ok(Sink::Gzip(BufWriter::new(flate2::write::GzEncoder::new(
                file,
                flate2::Compression::default(),
            ))))
        } else {
            Ok(Sink::Plain(BufWriter::new(Box::new(file))))
        }
    }

    /// Flush everything and write the gzip trailer when compressing.
    pub fn finish(self) -> io::Result<()> {
        match self {
            Sink::Plain(mut writer) => writer.flush(),
            Sink::Gzip(writer) => {
                let encoder = writer.into_inner().map_err(|error| error.into_error())?;
                encoder.finish().map(|_| ())
            }
        }
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Plain(writer) => writer.write(buf),
            Sink::Gzip(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sink::Plain(writer) => writer.flush(),
            Sink::Gzip(writer) => writer.flush(),
        }
    }
}

/// Detector output shape. `Flat` preserves the historical behaviour (replace
/// the source string with the matched token); `Rich` emits `DetectedFinding`
/// records with rule/confidence/severity/context.
#[derive(Clone, Copy, PartialEq)]
pub enum DetectFormat {
    Flat,
    Rich,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    /// Same defaults the CLI has always had; `--mode quick` is a no-op.
    Quick,
    Triage,
    Deep,
}

pub fn parse_mode(value: &str) -> Result<Mode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "quick" => Ok(Mode::Quick),
        "triage" => Ok(Mode::Triage),
        "deep" => Ok(Mode::Deep),
        other => Err(format!(
            "invalid --mode '{other}' (expected quick, triage or deep)"
        )),
    }
}

/// Flags the user spelled out. A preset only fills the ones left untouched, so
/// explicit flags win regardless of where they appear on the command line.
#[derive(Default)]
pub struct ExplicitFlags {
    pub min_len: bool,
    pub max_strings: bool,
    pub encoding: bool,
    pub dedupe: bool,
    pub extract: bool,
    pub report: bool,

    pub detectors: bool,
    pub entropy: bool,
    pub carve: bool,
    pub carve_out: bool,
    pub signature: bool,
    pub map_va: bool,
}

pub fn apply_mode_preset(mode: Mode, explicit: &ExplicitFlags, has_output: bool, args: &mut Args) {
    match mode {
        // `quick` keeps the historical defaults; it exists so scripts can be
        // explicit without changing behaviour.
        Mode::Quick => {}
        Mode::Triage => {
            if !explicit.encoding {
                // ascii/utf16/utf8 is roughly 7x faster than every encoding
                // and drops most of the UTF-32 noise.
                args.encoding = Encoding::Set(ENC_ASCII | ENC_UTF16 | ENC_UTF8);
            }
            if !explicit.min_len {
                args.min_len = 5;
            }
            if !explicit.dedupe {
                args.dedupe = true;
            }
            if !explicit.detectors {
                args.detectors = vec![
                    Detector::Ip,
                    Detector::Url,
                    Detector::Domain,
                    Detector::Base64,
                    Detector::Secret,
                ];
            }
            if !explicit.extract {
                args.extract = ArtifactKinds::ALL;
            }
            if !explicit.signature {
                args.signature = Some("magic".to_string());
            }
            if !explicit.report {
                args.report_mode = ReportMode::Summary;
            }
            if !explicit.max_strings {
                args.max_strings = if has_output { usize::MAX } else { MAX_STRINGS };
            }
        }
        Mode::Deep => {
            if !explicit.encoding {
                args.encoding = Encoding::All;
            }
            if !explicit.dedupe {
                args.dedupe = true;
            }
            if !explicit.detectors {
                args.detectors = vec![
                    Detector::Ip,
                    Detector::Url,
                    Detector::Domain,
                    Detector::Base64,
                    Detector::Secret,
                ];
            }
            if !explicit.extract {
                args.extract = ArtifactKinds::ALL;
            }
            if !explicit.signature {
                args.signature = Some("magic,keys".to_string());
            }
            if !explicit.entropy {
                args.entropy = true;
                args.entropy_merge = true;
                args.entropy_no_data = true;
            }
            if !explicit.carve {
                args.carve = Some("all".to_string());
            }
            if !explicit.carve_out && args.carve.is_some() {
                args.carve_out = Some(format!(
                    "{}.bxmap{sep}carved",
                    args.path,
                    sep = std::path::MAIN_SEPARATOR
                ));
            }
            if !explicit.report {
                args.report_mode = ReportMode::All;
            }
            args.max_strings = usize::MAX;
        }
    }
}

/// Default output directory for carving when a preset/bundle enables carving
/// but the user did not name one.
fn default_carve_out(path: &str) -> String {
    format!("{}.bxmap{sep}carved", path, sep = std::path::MAIN_SEPARATOR)
}

/// Apply `--with <tokens>` after any `--mode` preset. Tokens map onto the same
/// machinery as the classic feature flags, but never override an explicitly
/// passed flag, so `--with all --entropy` / `--entropy --with all` behave
/// identically.
pub fn apply_with_features(
    tokens: &[String],
    explicit: &ExplicitFlags,
    _has_output: bool,
    args: &mut Args,
) -> Result<(), String> {
    const IOC_TOKENS: &[&str] = &["ip", "url", "domain", "b64", "secret", "base64"];
    fn push_detector(list: &mut Vec<Detector>, detector: Detector) {
        if !list.contains(&detector) {
            list.push(detector);
        }
    }
    for token in tokens {
        match token.as_str() {
            "ioc" | "iocs" => {
                if !explicit.detectors {
                    push_detector(&mut args.detectors, Detector::Ip);
                    push_detector(&mut args.detectors, Detector::Url);
                    push_detector(&mut args.detectors, Detector::Domain);
                    push_detector(&mut args.detectors, Detector::Base64);
                    push_detector(&mut args.detectors, Detector::Secret);
                }
            }
            "ip" | "url" | "domain" | "b64" | "base64" | "secret" => {
                if !explicit.detectors {
                    let detector = match token.as_str() {
                        "ip" => Detector::Ip,
                        "url" => Detector::Url,
                        "domain" => Detector::Domain,
                        "b64" | "base64" => Detector::Base64,
                        _ => Detector::Secret,
                    };
                    push_detector(&mut args.detectors, detector);
                }
            }
            "artifact" | "artifacts" => {
                if !explicit.extract {
                    args.extract = ArtifactKinds::ALL;
                }
            }
            "magic" => {
                if !explicit.signature {
                    args.signature = Some("magic".to_string());
                }
            }
            "keys" => {
                if !explicit.signature {
                    args.signature = Some("keys".to_string());
                }
            }
            "entropy" => {
                if !explicit.entropy {
                    args.entropy = true;
                }
            }
            "dedupe" => {
                if !explicit.dedupe {
                    args.dedupe = true;
                }
            }
            "map-va" | "minidump" => {
                if !explicit.map_va {
                    args.map_va = true;
                }
            }
            "carve" => {
                if !explicit.carve {
                    args.carve = Some("all".to_string());
                }
                if !explicit.carve_out && args.carve_out.is_none() {
                    args.carve_out = Some(default_carve_out(&args.path));
                }
            }
            "summarize" | "summary" => {
                if !explicit.report {
                    args.report_mode = ReportMode::Summary;
                }
                if !explicit.extract && args.extract == ArtifactKinds::NONE {
                    args.extract = ArtifactKinds::ALL;
                }
                // A summary written to a file is a full triage: like the
                // `triage`/`deep` presets, drop the 200000 default cap when
                // the user gave `-o` so the report covers the whole input.
                if _has_output && !explicit.max_strings && args.max_strings == MAX_STRINGS {
                    args.max_strings = usize::MAX;
                }
            }
            "all" => {
                for extra in [
                    "iocs",
                    "artifacts",
                    "magic",
                    "keys",
                    "entropy",
                    "carve",
                    "map-va",
                ] {
                    // Dùng `?` để lan truyền lỗi (clippy::question_mark)
                    apply_with_features(&[extra.to_string()], explicit, _has_output, args)?;
                }
            }
            other => {
                return Err(format!(
                    "unknown --with feature '{other}' (expected {} or all)",
                    IOC_TOKENS.join(", ")
                ));
            }
        }
    }
    Ok(())
}

/// Option implies feature: passing `--entropy-window` alone turns entropy on,
/// `--carve-out` starts an all-kinds carve, `--report user` collects paths,
/// minidump filters switch on `--map-va`. This removes the old
/// "sub-flag requires parent flag" hard errors: the obvious thing happens
/// instead.
pub fn apply_implications(args: &mut Args) {
    if !args.entropy
        && (args.entropy_no_data
            || args.entropy_window.is_some()
            || args.entropy_threshold.is_some()
            || args.entropy_merge
            || args.entropy_max_data.is_some())
    {
        args.entropy = true;
    }
    if args.carve.is_none()
        && (args.carve_out.is_some() || args.carve_index.is_some() || args.reassemble)
    {
        args.carve = Some("all".to_string());
    }
    if args.carve.is_some() && args.carve_out.is_none() {
        args.carve_out = Some(default_carve_out(&args.path));
    }
    if args.detectors.is_empty()
        && (args.detect_format == DetectFormat::Rich
            || args.detect_strict
            || args.custom_rules.is_some())
    {
        args.detectors.push(Detector::Secret);
    }
    if matches!(args.report_mode, ReportMode::User | ReportMode::All)
        && args.extract == ArtifactKinds::NONE
    {
        args.extract = ArtifactKinds::paths();
    }
    if args.in_module.is_some() || args.rwx_only || args.heap_only {
        args.map_va = true;
    }
}

/// Short help: the one-command workflow. Full flag list printed on
/// `--help-advanced` (everything the classic enums supported stays valid).
pub const HELP: &str = concat!(
    include_str!("banner.txt"),
    "\nUSAGE:
    bxmap <path> [MODES / FEATURES / OPTIONS]

FEATURES -- one flag does one complete job:
    --with <list>        Turn capabilities on in one flag. Tokens: iocs,
                           artifacts, magic, keys, entropy, carve, minidump,
                           dedupe, summarize, all (comma-separated and
                           repeatable). `bxmap dump.raw --with all` is a full
                           blind triage in a single command.
    --mode <quick|triage|deep>
                           Ready-made bundles: quick = raw strings; triage =
                           strings + IOCs + artifacts + magic bytes + summary;
                           deep = triage + all 9 encodings + entropy regions +
                           carving into <input>.bxmap/carved with no result cap.
                           Options you pass explicitly always win, wherever
                           they appear.

ESSENTIAL OPTIONS:
    -o, --output <PATH>  Write to a file; the extension picks the format
                           (.json .ndjson .csv .md .html .txt, trailing .gz ok).
    --format <FMT>       text|json|json-tree|ndjson|csv|html|markdown
    --encoding <list>    Restrict encodings (default all): ascii,utf16,utf32,
                           latin1,cp1252,utf8,shift_jis
    --min-len <N>        Minimum string length (default 4)
    --max-strings <N>    Maximum results (default 200000; 0 = unlimited)
    --threads <N>        Parallel worker count
    --auto-tune          Choose a safe worker count for this machine
    --report <mode>      none|summary|user|all (top artifacts, per-user lists)
    --stats              Per-encoding counts and timing on stderr

SUB-FLAGS IMPLY THEIR FEATURE:
    --entropy-window/threshold/merge/max-data imply --entropy;
    --carve-out/-index imply carving (default dir: <input>.bxmap/carved);
    --in-module/--rwx-only/--heap-only imply --map-va; --report user/all
    collect path artifacts automatically.

    -V, --version        Print the bxmap-cli version
    -h, --help           Show this help (`--help-advanced` for every flag)
"
);

pub const HELP_ADVANCED: &str = concat!(
    include_str!("banner.txt"),
    "\nUSAGE:
    bxmap <path> [OPTIONS]

MODES:
    --mode <quick|triage|deep>
                         Opt-in preset. Without --mode the CLI keeps its
                         historical defaults. quick = those defaults; triage =
                         ascii/utf16/utf8, --min-len 5, detectors, artifacts,
                         dedupe, magic bytes and --report summary (unlimited
                         --max-strings when -o is used); deep = triage plus all
                         encodings, entropy regions and carving into
                         <input>.bxmap/carved. Flags you pass explicitly always
                         win, wherever they appear on the command line.

OPTIONS:
    --with <list>        One-flag feature bundle (repeatable, comma-separated):
                           iocs, artifacts, magic, keys, entropy, carve,
                           minidump (implies --map-va), dedupe, summarize or
                           all. Never overrides a flag you passed explicitly.
    --min-len <N>        Minimum string length (default 4)
    --max-str-len <N>    Truncate very long strings to N chars in output (default unlimited)
    --max-strings <N>    Maximum results (default 200000; 0 = unlimited)
                           Exits 3 with a warning when the limit truncates the scan.
    --start <OFFSET>     Only emit strings that start at or after this byte
                           offset (decimal or 0x hex). Forces the sequential
                           streaming scanner.
    --end <OFFSET>       Only emit strings that start before this byte offset
                           (decimal or 0x hex).
    --progress           Show a progress line on stderr (auto when stderr is a
                           terminal and results are not going to the terminal).
    --no-progress        Disable the progress line.
    --dedupe             Emit each unique string once with `count=` and the
                           first offset. Buffers results in memory.
    --compact            Minify json/json-tree output (no indentation or
                           newlines). No effect on ndjson/csv/text.
    --extract <list>     Also emit deduped artifacts: paths, env, urls, emails,
                           registry, tools or all (comma-separated). Artifacts
                           are collected from the extracted strings, sorted
                           rarest-first and appended after the normal rows.
                           `tools` reports memory-capture/analysis traces
                           (DumpIt, WinPmem, FTK Imager, ...) plus default
                           .raw/.mem image names. Not supported with
                           --format json-tree.
    --report <mode>      Report mode: none, summary, user, or all (default none).
                           summary: string counts per encoding, scanned range, limit
                           status, top artifacts (requires --extract).
                           user: consolidated per-user file list (one line per user),
                           requires --extract paths. Shows file count, AppData count,
                           and AppData percentage. Filter with --min-files-in-user.
                           all: both summary and user reports.
    --min-files-in-user <N>
                           Minimum file count for a user to appear in --report user/all
                           (default 0).
    --filter-appdata     In --report user/all, compute AppData percentage using
                           visible files (total minus AppData) as denominator.
                           Does not remove AppData paths from collection.
    --format <text|json|json-tree|ndjson|csv>
                           Output format (default text). json-tree emits
                           grouped classification tree. ndjson emits one JSON
                           object per line with a `type` field. csv emits
                           string/finding/artifact rows with a header.
    --encoding <list>    Restrict output by encoding (default all). Accepts one
                          name or a comma-separated list (ascii,utf16,utf8).
                          utf-16 includes both LE & BE; utf-32 includes both LE
                          & BE; latin1=ISO-8859-1; cp1252=Windows-1252;
                          shift_jis aliases: shiftjis, sjis
    -o, --output <PATH>  Write results to a file. The extension picks the format
                           (.json .ndjson .csv .md .html .txt, an optional .gz
                           is ignored) unless --format is given.
    --noise-threshold <N>
                          Repeat-noise threshold; 0 disables filtering
    --threads <N>        Parallel worker count
    --auto-tune          Choose a safe worker count for this machine
    --entropy            Scan and export high-entropy regions
    --entropy-window <N> Bytes per entropy window (default 65536)
    --entropy-threshold <F>
                           Minimum entropy in bits/byte (default 7.2, max 8)
    --entropy-merge      Merge contiguous high-entropy windows into one record
    --entropy-max-data <N>
                           Keep at most N payload bytes per region (default
                           4096, 0 = no payload)
    --entropy-no-data    Omit the data_hex payload from entropy records
    --yar <PATH>         Compile and match a YARA/YARA-X rule file while streaming
    --brute-xor <1b;2b;3b>
                          Brute-force XOR candidates using selected key sizes
                          (parallel; 3-byte keys use a frequency-guided search)
    --xor-exhaustive      With --brute-xor 3b: enumerate all 16,777,216 keys
                          instead of the frequency-guided search (slow)
    --parse-pid          Map PID markers in extracted strings
    --detect <list>       Detect IOCs: ip, url, domain, b64, secret, all (comma-separated)
    --detect-format <flat|rich>
                           Detector output shape (default flat). rich keeps the
                           original text and adds rule/confidence/severity/context.
    --detect-strict        Drop findings that fail structural validation
                           (Base58Check, Bech32, JWT, Luhn, provider prefix)
                           instead of lowering their confidence.
    --detect-rules <PATH>  Load custom detector rules from a TOML file. Each rule
                           needs id, regex, severity, confidence, description and
                           optional keywords (used as a cheap prefilter). Rules
                           are only applied with --detect-format rich.
    --signature <types>   Report binary signatures in the dump. Types: magic
                          (PE/ELF/ZIP/PDF/PNG/RAR/7z/PDF/GZIP/SQLite magic
                          bytes), keys (DER PKCS#8 RSA/EC and OpenSSH private
                          key blobs), all, none (comma-separated). For `keys`
                          only metadata + SHA-1 fingerprint is reported; raw
                          key bytes never leave this process and nothing is
                          decrypted.
    --carve <types>       Recover structured files from the dump and write them
                          to --carve-out. Types: jpeg,png,zip,rar,7z,pdf,gzip,
                          bmp,sqlite,all (comma-separated). Every candidate is
                          structurally validated before it is written; nothing
                          is decrypted or executed.
    --carve-out <dir>     Destination directory for carved files (required with
                          --carve). Existing files are never overwritten.
    --carve-index <file>  Write the carve index (.ndjson = one record per line,
                          anything else = JSON array)
    --carve-min-size <N>  Skip files smaller than N bytes (default 64)
    --carve-max-size <N>  Per-file ceiling; header sizes are clamped to it
                          (default 64 MiB)
    --carve-max-total <N> Stop after writing N bytes (default 512 MiB, 0 = no
                          limit). Hitting it exits with code 3.
    --carve-max-files <N> Stop after N files (default 1000)
    --reassemble          Reassemble carved fragments in page order (requires
                          --carve and a minidump input). Merges adjacent
                          fragments back into whole files using the minidump's
                          virtual-address map, so files split across page
                          boundaries are recovered as one.
    --tree                Parse a Windows minidump and print its process tree
                          (modules, threads, memory regions), then exit.
                          Auto-enabled for files with the MDMP magic.
    --no-tree             Do not auto-enable --tree for MDMP files
    --map-va              For a minidump, add virtual address and module/region
                          to every extracted string. Auto-enabled for MDMP files.
    --no-map-va           Do not auto-enable --map-va for MDMP files
    --in-module <NAME>    Minidump only: keep strings inside modules whose name
                          contains NAME (case-insensitive, implies --map-va)
    --vmware-info         Inspect a VMware .vmss/.vmsn file (groups, sibling .vmem,
                          memory tags, CR registers), then exit. Auto-enabled for
                          .vmss/.vmsn inputs.
    --no-vmware-info      Scan a .vmss/.vmsn like a normal memory image instead
    --rwx-only            Minidump only: keep strings in committed RWX regions
                          (implies --map-va)
    --filter-regex <RE>   Legacy generic regex filter
    --stats              Always-on report compatibility flag
    -V, --version        Print the bxmap-cli version
    -h, --help           Show the short help (--help-advanced shows this list)
"
);

pub fn parse_offset(value: &str, flag: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse::<u64>()
    };
    parsed.map_err(|_| format!("invalid {flag} offset '{value}' (use decimal or 0x hex)"))
}

pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }
    // Only ASCII hex digits were pushed, so this cannot fail.
    String::from_utf8(encoded).expect("hex digits are ASCII")
}

pub fn matches_filter(regex: Option<&Regex>, text: &str) -> bool {
    regex.map_or(true, |regex| regex.is_match(text))
}

pub fn scan_magic_bytes(path: &str) -> io::Result<Vec<MagicMatch>> {
    let matches = bxmap::magic::scan_file(path, MAX_MAGIC_MATCHES)?;
    Ok(matches
        .into_iter()
        .map(|found| MagicMatch {
            offset: found.offset,
            kind: found.kind(),
        })
        .collect())
}

/// Separator written before a JSON record, plus the record's indent and the
/// optional `type` discriminator used by NDJSON.
pub fn json_record_open(
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
    record_type: Option<&str>,
) -> io::Result<()> {
    if *result_count > 0 {
        match layout {
            JsonLayout::Array => writeln!(writer, ",")?,
            JsonLayout::ArrayCompact => write!(writer, ",")?,
            JsonLayout::Lines => writeln!(writer)?,
        }
    }
    match (layout, record_type) {
        (JsonLayout::Array, _) => write!(writer, "  {{")?,
        (JsonLayout::ArrayCompact, _) => write!(writer, "{{")?,
        (JsonLayout::Lines, Some(kind)) => write!(writer, "{{\"type\":\"{kind}\",")?,
        (JsonLayout::Lines, None) => write!(writer, "{{")?,
    }
    Ok(())
}

pub fn write_ndjson_metadata(
    writer: &mut dyn Write,
    records: usize,
    truncated: bool,
    scanned_until: u64,
) -> io::Result<()> {
    if records > 0 {
        writeln!(writer)?;
    }
    writeln!(
        writer,
        "{{\"type\":\"metadata\",\"total_records\":{records},\"truncated\":{truncated},\"scanned_until\":{scanned_until}}}"
    )
}

/// Fixed CSV header. Rows always emit all columns so spreadsheet/pandas
/// imports stay rectangular; columns that do not apply to a row stay empty.
pub const CSV_HEADER: &str =
    "type,offset,encoding,text,rule,value,severity,confidence,context,count,pid";

pub fn write_csv_header(writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "{CSV_HEADER}")
}

/// Write one RFC 4180 field, quoting when it contains a separator or quote.
/// Control characters are already escaped by `display_text`, so a record never
/// spans multiple lines.
pub fn write_csv_field(writer: &mut dyn Write, field: &str) -> io::Result<()> {
    if field
        .chars()
        .any(|c| c == ',' || c == '"' || c == '\n' || c == '\r')
    {
        write!(writer, "\"{}\"", field.replace('"', "\"\""))
    } else {
        write!(writer, "{field}")
    }
}

pub fn write_csv_row(writer: &mut dyn Write, fields: &[&str]) -> io::Result<()> {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            write!(writer, ",")?;
        }
        write_csv_field(writer, field)?;
    }
    writeln!(writer)
}

pub fn write_csv_string_row(
    result: &ExtractedString,
    writer: &mut dyn Write,
    parse_pid: bool,
    max_str_len: usize,
    count: Option<usize>,
) -> io::Result<()> {
    let offset = format!("{:#010x}", result.offset);
    let text = display_text(&result.text, max_str_len);
    let count_text = count.map(|value| value.to_string()).unwrap_or_default();
    let pid_text = if parse_pid {
        parse_pid_marker(&result.text)
            .map(|pid| pid.to_string())
            .unwrap_or_default()
    } else {
        String::new()
    };
    write_csv_row(
        writer,
        &[
            "string",
            &offset,
            result.encoding,
            &text,
            "",
            "",
            "",
            "",
            "",
            &count_text,
            &pid_text,
        ],
    )
}

pub fn write_csv_finding_row(
    finding: &bxmap::classifier::DetectedFinding,
    writer: &mut dyn Write,
    max_str_len: usize,
    count: Option<usize>,
) -> io::Result<()> {
    let offset = format!("{:#010x}", finding.offset);
    let confidence = format!("{:.4}", finding.confidence);
    let text = display_text(&finding.text, max_str_len);
    let context = display_text(&finding.context, max_str_len);
    let count_text = count.map(|value| value.to_string()).unwrap_or_default();
    write_csv_row(
        writer,
        &[
            "finding",
            &offset,
            finding.encoding,
            &text,
            finding.rule,
            &finding.value,
            finding.severity,
            &confidence,
            &context,
            &count_text,
            "",
        ],
    )
}

pub fn write_string_json(
    result: &ExtractedString,
    writer: &mut dyn Write,
    result_count: &mut usize,
    parse_pid: bool,
    count: Option<usize>,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("string"))?;
    write!(
        writer,
        "\"offset\":{},\"encoding\":{},\"text\":{}",
        result.offset,
        json_escape(result.encoding),
        json_escape(&result.text)
    )?;
    if let Some(count) = count {
        write!(writer, ",\"count\":{count}")?;
    }
    if parse_pid {
        match parse_pid_marker(&result.text) {
            Some(pid) => write!(writer, ",\"pid\":{pid}")?,
            None => write!(writer, ",\"pid\":null")?,
        }
    }
    if DUMP_MAP.get().is_some() {
        match va_annotation(result.offset) {
            Some((va, label)) => write!(
                writer,
                ",\"va\":\"{va:#x}\",\"module\":{}",
                json_escape(&label)
            )?,
            None => write!(writer, ",\"va\":null,\"module\":null")?,
        }
    }
    write!(writer, "}}")?;
    *result_count += 1;
    Ok(())
}

pub fn parse_pid_marker(text: &str) -> Option<u32> {
    let tokens: Vec<&str> = text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    for (index, token) in tokens.iter().enumerate() {
        if token.eq_ignore_ascii_case("pid") || token.eq_ignore_ascii_case("processid") {
            if let Some(value) = tokens.get(index + 1) {
                if value.bytes().all(|byte| byte.is_ascii_digit()) {
                    if let Ok(pid) = value.parse::<u32>() {
                        return Some(pid);
                    }
                }
            }
        }
    }
    None
}

pub fn important_reason(text: &str) -> Option<&'static str> {
    let refanged = refang_ioc_text(text);
    let lower = refanged.to_ascii_lowercase();
    if is_repetitive_noise(&refanged) {
        return None;
    }
    if contains_credential_marker(&lower) {
        Some("credential")
    } else if contains_public_ip(&refanged) {
        Some("ip-address")
    } else if contains_crypto_address(text) {
        Some("crypto-wallet")
    } else if lower.contains("http://") || lower.contains("https://") {
        Some("url")
    } else if has_c2_token(&lower) || lower.contains("gate.php") {
        Some("network")
    } else if is_email_address(&refanged) {
        Some("email")
    } else if contains_meaningful_base64(&refanged) {
        Some("base64")
    } else if lower.contains("\\temp\\")
        || lower.contains("\\appdata\\")
        || lower.contains("\\startup\\")
        || lower.contains("\\public\\")
    {
        Some("suspicious-path")
    } else {
        None
    }
}

pub fn is_email_address(text: &str) -> bool {
    static EMAIL: OnceLock<Regex> = OnceLock::new();
    EMAIL
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
            )
            .unwrap()
        })
        .is_match(text)
}

pub fn contains_credential_marker(text: &str) -> bool {
    let tokens: Vec<&str> = text
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect();
    let markers = ["password", "passwd", "token", "secret", "apikey"];
    let marker_hit = tokens.iter().enumerate().any(|(index, token)| {
        markers.contains(token)
            && (tokens
                .get(index.saturating_sub(1))
                .is_some_and(|neighbor| *neighbor != *token)
                || tokens.get(index + 1).is_some())
    });
    marker_hit || contains_jwt_shape(text)
}

/// `c2` as a standalone word (`c2`, `c2 server`, `/c2/`), not as a substring of
/// random identifiers such as `uC2I` or `abc2def`.
pub fn has_c2_token(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token == "c2")
}

/// A JWT-shaped value: three dot-separated base64url segments starting with `eyJ`.
/// The bare word "jwt" next to random text is not a credential signal.
pub fn contains_jwt_shape(text: &str) -> bool {
    text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '=' || c == ':')
        .any(|part| {
            let mut segments = part.split('.');
            match (
                segments.next(),
                segments.next(),
                segments.next(),
                segments.next(),
            ) {
                (Some(h), Some(p), Some(sig), None) => {
                    h.len() >= 10
                        && h.to_ascii_lowercase().starts_with("eyj")
                        && p.len() >= 6
                        && !sig.is_empty()
                        && [h, p, sig].iter().all(|seg| {
                            seg.bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                        })
                }
                _ => false,
            }
        })
}

pub fn contains_crypto_address(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(is_crypto_address)
}

pub fn is_crypto_address(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    if token.len() < 14
        || shannon_entropy(token) < 2.5
        || token
            .bytes()
            .collect::<std::collections::HashSet<_>>()
            .len()
            < 6
    {
        return false;
    }

    // Ethereum and EVM-compatible addresses.
    if token.len() == 42
        && lower.starts_with("0x")
        && token[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return true;
    }

    // Bitcoin legacy (1/3...), native SegWit (bc1...), and testnet (tb1...).
    if (token.starts_with('1') || token.starts_with('3'))
        && (26..=35).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
    {
        return true;
    }
    if (lower.starts_with("bc1") || lower.starts_with("tb1"))
        && token.len() >= 14
        && token[3..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b.is_ascii_alphanumeric()))
    {
        return true;
    }

    // Monero primary addresses are 95-character Base58 strings beginning 4.
    if token.starts_with('4')
        && token.len() == 95
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
    {
        return true;
    }

    // Solana addresses are typically 32-44 characters of Base58.
    token.len() >= 32
        && token.len() <= 44
        && token.bytes().any(|b| b.is_ascii_digit())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() && !matches!(b, b'0' | b'O' | b'I' | b'l'))
}

#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        contains_crypto_address, contains_jwt_shape, contains_meaningful_base64,
        detected_domain_value, detected_ip_value, detected_url_value, hex_encode, important_reason,
        is_email_address, matches_filter, parse_pid_marker, refang_ioc_text, scan_magic_bytes,
        xor_printable_score, ExtractedString,
    };
    use regex::Regex;

    #[test]
    fn highlights_ipv4_and_ipv6() {
        assert!(!super::contains_public_ip("connect 192.168.56.101:4444"));
        assert!(!super::contains_public_ip("fe80::1"));
    }

    #[test]
    fn highlights_common_wallet_formats() {
        assert!(contains_crypto_address(
            "0x52908400098527886E0F7030069857D2E4169EE7"
        ));
        assert!(contains_crypto_address(
            "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
        ));
    }

    #[test]
    fn prioritizes_ip_and_wallet_signals() {
        assert_eq!(important_reason("server=8.8.8.8"), Some("ip-address"));
        assert_eq!(
            important_reason("wallet=0x52908400098527886E0F7030069857D2E4169EE7"),
            Some("crypto-wallet")
        );
    }

    #[test]
    fn parses_common_pid_markers() {
        assert_eq!(parse_pid_marker("ProcessId=4242 image.exe"), Some(4242));
        assert_eq!(parse_pid_marker("pid: 1337"), Some(1337));
        assert_eq!(parse_pid_marker("no process marker"), None);
    }

    #[test]
    fn filters_strings_with_regex() {
        let regex = Regex::new("(?i)(password|token)").unwrap();
        assert!(matches_filter(Some(&regex), "access_token=abc"));
        assert!(!matches_filter(Some(&regex), "ordinary filename"));
        assert!(matches_filter(None, "anything"));
    }

    #[test]
    fn rejects_xor_plaintext_without_alphanumeric_content() {
        assert_eq!(xor_printable_score(b"????????????????"), 0.0);
        assert_eq!(xor_printable_score(b"abc????????????"), 0.0);
        assert!(xor_printable_score(b"password=secret") > 0.0);
    }

    fn xor_encrypt(plain: &[u8], key: &[u8]) -> Vec<u8> {
        plain
            .iter()
            .enumerate()
            .map(|(index, &byte)| byte ^ key[index % key.len()])
            .collect()
    }

    #[test]
    fn recovers_single_byte_xor_key() {
        let plain = b"password=hunter2 and http://evil.example/payload.exe";
        let cipher = xor_encrypt(plain, b"K");
        let top = super::xor_top_results(&cipher, 0x100, 1, false);
        let best = top.first().expect("at least one candidate key");
        assert_eq!(best.key, b"K");
        assert_eq!(best.plaintext, plain);
    }

    #[test]
    fn recovers_three_byte_xor_key_with_frequency_search() {
        // Long enough for the per-column frequency ranking to see the real
        // key bytes: a 3-byte key used to require 16.7M full scans.
        let plain = b"MZ\x90\x00This program cannot be run in DOS mode. \
                      http://update.example.com/payload.dll";
        let cipher = xor_encrypt(plain, b"KEY");
        let top = super::xor_top_results(&cipher, 0x2000, 3, false);
        let best = top.first().expect("at least one candidate key");
        assert_eq!(best.key, b"KEY");
        assert_eq!(best.plaintext, plain);
        assert!(best.score > 1.0, "crib hits should boost the score");
    }

    #[test]
    fn xor_exhaustive_and_frequency_agree_on_two_byte_keys() {
        let plain = b"Authorization: Bearer abcdef0123456789 .dll";
        let cipher = xor_encrypt(plain, b"Qz");
        let top = super::xor_top_results(&cipher, 0, 2, true);
        assert_eq!(top.first().expect("candidate").key, b"Qz");
    }

    #[test]
    fn refangs_common_ioc_obfuscation() {
        assert_eq!(
            refang_ioc_text("https://example[.]com user [at] example[.]com"),
            "https://example.com user@example.com"
        );
    }

    #[test]
    fn ignores_private_ip_and_low_entropy_base64_noise() {
        assert_ne!(important_reason("connect 192.168.1.10"), Some("ip-address"));
        assert_ne!(important_reason("docs 203.0.113.10"), Some("ip-address"));
        assert_eq!(important_reason("publicKeyToken=abc"), None);
        assert_eq!(important_reason("token=abc"), Some("credential"));
        // regression: random junk must not be flagged just for containing "jwt" / "c2"
        assert_eq!(important_reason("rW)jWT"), None);
        assert_eq!(important_reason("uC2I"), None);
        assert_eq!(important_reason("abc2def"), None);
        assert_eq!(important_reason("beacon to c2 server"), Some("network"));
        assert_eq!(
            important_reason("Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123_-"),
            Some("credential")
        );
        assert!(contains_meaningful_base64(
            "VGhpcyBpcyBhIHJlYWwgYmFzZTY0IHBheWxvYWQxMjM="
        ));
        assert!(!contains_meaningful_base64(&"A".repeat(48)));
        assert_eq!(important_reason("14666666666DDDDDDDDDDDDDDDDDDDD"), None);
        assert_eq!(important_reason("))))FFFFFFFF)))))......66@"), None);
        assert!(!is_email_address("H      %     ?     2     @"));
        assert!(is_email_address("analyst@example.com"));
    }

    #[test]
    fn detectors_return_only_the_detected_value() {
        assert_eq!(
            detected_ip_value("connect to 8.8.8.8:443 now").as_deref(),
            Some("8.8.8.8")
        );
        assert_eq!(
            detected_url_value("C2=https://example.com/api?q=1;").as_deref(),
            Some("https://example.com/api?q=1")
        );
        assert_eq!(
            detected_domain_value("prefix example.org suffix").as_deref(),
            Some("example.org")
        );
        let result = ExtractedString {
            offset: 4,
            encoding: "ascii",
            text: "prefix AKIAIOSFODNN7EXAMPLE suffix".to_string(),
        };
        assert_eq!(
            super::apply_detectors(result, &[super::Detector::Secret])[0].text,
            "AKIAIOSFODNN7EXAMPLE"
        );
    }

    #[test]
    fn rich_detectors_keep_original_text_and_context() {
        let result = ExtractedString {
            offset: 4,
            encoding: "ascii",
            text: "prefix AKIAIOSFODNN7EXAMPLE suffix".to_string(),
        };
        let findings = super::detect_findings(&result, &[super::Detector::Secret], false);
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.rule, "AWS_ACCESS_KEY");
        assert_eq!(finding.value, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(finding.text, result.text);
        assert!(finding.context.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(finding.confidence >= 0.9);
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.offset, 4);
        assert_eq!(finding.encoding, "ascii");
    }

    #[test]
    fn rich_ip_detector_uses_ipv4_rule() {
        let result = ExtractedString {
            offset: 0,
            encoding: "ascii",
            text: "beacon 8.8.8.8:443".to_string(),
        };
        let findings = super::detect_findings(&result, &[super::Detector::Ip], false);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "IPV4");
        assert_eq!(findings[0].value, "8.8.8.8");
        assert_eq!(findings[0].severity, "medium");
    }

    #[test]
    fn result_limit_only_fires_when_the_probe_result_is_returned() {
        // Scanner asked for max+1: exactly max means EOF was reached.
        assert!(!super::hit_result_limit(10, 10));
        assert!(super::hit_result_limit(11, 10));
        assert!(!super::hit_result_limit(9, 10));
        assert!(!super::hit_result_limit(usize::MAX, usize::MAX));
    }

    fn sample_string(offset: u64, text: &str) -> ExtractedString {
        ExtractedString {
            offset,
            encoding: "ascii",
            text: text.to_string(),
        }
    }

    #[test]
    fn dedupe_keeps_first_offset_and_counts_repeats() {
        let input = vec![
            sample_string(0, "aaaa"),
            sample_string(5, "bbbb"),
            sample_string(10, "aaaa"),
            sample_string(15, "aaaa"),
        ];
        let (unique, counts) = super::dedupe_strings(input);
        assert_eq!(unique.len(), 2);
        assert_eq!(unique[0].offset, 0);
        assert_eq!(unique[0].text, "aaaa");
        assert_eq!(counts["aaaa"], 3);
        assert_eq!(counts["bbbb"], 1);
    }

    #[test]
    fn dedupe_findings_groups_by_value_across_rules() {
        // Same AWS key in two strings: one row, two offsets.
        let result = sample_string(0, "key AKIAIOSFODNN7EXAMPLE");
        let mut findings = super::detect_findings(&result, &[super::Detector::Secret], false);
        findings.extend(super::detect_findings(
            &sample_string(30, "again AKIAIOSFODNN7EXAMPLE"),
            &[super::Detector::Secret],
            false,
        ));
        let deduped = super::dedupe_findings(findings);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].finding.rule, "AWS_ACCESS_KEY");
        assert_eq!(deduped[0].count, 2);
        assert_eq!(deduped[0].offsets, vec![0, 30]);
        assert!(!deduped[0].offsets_truncated);

        // The same AIza key is a public client key in one string and a plain
        // API key in another. Dedupe must keep the lower-confidence rule so a
        // public key is never promoted back to a server secret.
        let key = "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567";
        let public = sample_string(100, &format!("https://clients6.google.com/?key={key}"));
        let plain = sample_string(200, &format!("config key {key}"));
        let mut mixed = super::detect_findings(&public, &[super::Detector::Secret], false);
        mixed.extend(super::detect_findings(
            &plain,
            &[super::Detector::Secret],
            false,
        ));
        assert_eq!(mixed.len(), 2);
        let deduped = super::dedupe_findings(mixed);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped[0].finding.rule, "PUBLIC_CLIENT_KEY");
        assert!((deduped[0].finding.confidence - 0.30).abs() < 1e-9);
        assert_eq!(deduped[0].count, 2);
    }

    #[test]
    fn magic_scan_handles_chunk_boundaries_without_duplicates() {
        let path =
            std::env::temp_dir().join(format!("bxmap-magic-test-{}.dmp", std::process::id()));
        let mut data = vec![b'x'; 65_535];
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(&[b'y'; 65_535]);
        data.extend_from_slice(b"%PDF-");
        fs::write(&path, data).unwrap();

        let matches = scan_magic_bytes(path.to_str().unwrap()).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].offset, 65_535);
        assert_eq!(matches[0].kind, "PE/DOS executable");
        assert_eq!(matches[1].kind, "PDF document");
    }
    #[test]
    fn hex_encode_matches_reference_for_all_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        let reference: String = data.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex_encode(&data), reference);
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn jwt_shape_requires_three_segments() {
        assert!(contains_jwt_shape(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_1-"
        ));
        assert!(!contains_jwt_shape("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0"));
        assert!(!contains_jwt_shape("rW)jWT"));
    }
}

pub fn print_banner(path: &str, size: u64, format: Format) {
    if !io::stderr().is_terminal() {
        return;
    }
    let format = match format {
        Format::Text => "text",
        Format::Json => "json",
        Format::JsonTree => "json-tree",
        Format::Ndjson => "ndjson",
        Format::Csv => "csv",
        Format::Html => "html",
        Format::Markdown => "markdown",
    };
    eprintln!("  input      : {path}");
    eprintln!("  size/format: {size} bytes / {format}");
    eprintln!("  \x1b[1;34m[..] scanning\x1b[0m");
}

/// Opening line of `--report summary`, printed even when stderr is piped so the
/// scan scope ends up in logs next to the closing summary.
pub fn print_summary_header(
    range_start: u64,
    range_end: u64,
    file_size: u64,
    encoding: Encoding,
    extract: ArtifactKinds,
) {
    let scope = encoding_scope_label(encoding);
    let artifacts = if extract.is_empty() { "off" } else { "on" };
    let span = range_end.saturating_sub(range_start);
    eprintln!(
        "  [report] window {range_start:#010x}-{range_end:#010x} ({span} of {file_size} bytes) \
         | encodings {scope} | artifacts {artifacts}"
    );
}

/// Print a truncation warning when the result limit stopped the scan early.
///
/// `last_absolute` is the absolute offset of the last emitted string and
/// `range_start`/`span` describe the scanned window (the whole file when no
/// `--start`/`--end` was given).
pub fn print_truncation_notice(
    max_strings: usize,
    last_absolute: u64,
    range_start: u64,
    span: u64,
) {
    let relative = last_absolute.saturating_sub(range_start);
    let pct = if span == 0 {
        100.0
    } else {
        relative as f64 * 100.0 / span as f64
    };
    eprintln!(
        "  [!] TRUNCATED: reached --max-strings {max_strings} near offset {last_absolute:#x} (~{pct:.1}% of the scanned range)."
    );
    eprintln!("      The remaining data was NOT scanned; results are incomplete.");
    eprintln!(
        "      Re-run with a larger --max-strings (0 = unlimited) to cover the entire input."
    );
}

/// True when the scanner returned one more result than requested, which means
/// the `--max-strings` cap (not EOF) stopped the scan.
pub fn hit_result_limit(result_count: usize, max_strings: usize) -> bool {
    max_strings != usize::MAX && result_count > max_strings
}

/// Printing tens of thousands of lines to a terminal is slow (and the scroll
/// back is unusable), so point the user at `-o` once the result set is large.
pub fn hint_large_terminal_output(result_count: usize, output_is_file: bool) {
    if !output_is_file && io::stdout().is_terminal() && result_count > 10_000 {
        eprintln!(
            "  [i] {result_count} results were printed to the terminal; next time add \
             `-o results.txt` (or `--format ndjson -o results.ndjson.gz`) to write them \
             much faster and keep them."
        );
    }
}

/// Collapse identical strings, keeping the first occurrence (lowest offset)
/// and the number of times each text appeared.
pub fn dedupe_strings(
    results: Vec<ExtractedString>,
) -> (
    Vec<ExtractedString>,
    std::collections::HashMap<String, usize>,
) {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut unique: Vec<ExtractedString> = Vec::new();
    for result in results {
        if counts.contains_key(&result.text) {
            if let Some(count) = counts.get_mut(&result.text) {
                *count += 1;
            }
        } else {
            counts.insert(result.text.clone(), 1);
            unique.push(result);
        }
    }
    (unique, counts)
}

/// A detector finding collapsed by `(rule, value)`, with the number of
/// occurrences and a (truncated) list of byte offsets where it appeared.
///
/// `offsets` holds at most `MAX_DEDUPE_OFFSETS` entries; `offsets_truncated`
/// is true when more occurrences exist beyond the list.
#[derive(Debug, Clone)]
pub struct DedupedFinding {
    pub finding: bxmap::classifier::DetectedFinding,
    pub count: usize,
    pub offsets: Vec<u64>,
    pub offsets_truncated: bool,
}

/// Maximum number of offsets kept per deduped finding.
pub const MAX_DEDUPE_OFFSETS: usize = 100;

/// Collapse identical detector findings by `value`, keeping a count and a
/// (truncated) list of byte offsets.
///
/// The same bytes can match several rules (an `AIza...` key is
/// `GOOGLE_API_KEY` in one string and `PUBLIC_CLIENT_KEY` when a Google
/// client domain is nearby). Deduplicating by value and keeping the
/// *lowest-confidence* rule prevents a public client key from being promoted
/// back to a high-confidence API key by an unrelated occurrence.
pub fn dedupe_findings(findings: Vec<bxmap::classifier::DetectedFinding>) -> Vec<DedupedFinding> {
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut unique: Vec<DedupedFinding> = Vec::new();
    for finding in findings {
        let key = finding.value.clone();
        if let Some(&slot) = index.get(&key) {
            let entry = &mut unique[slot];
            entry.count += 1;
            if entry.offsets.len() < MAX_DEDUPE_OFFSETS {
                entry.offsets.push(finding.offset);
            } else {
                entry.offsets_truncated = true;
            }
            if finding.confidence < entry.finding.confidence {
                entry.finding = finding;
            }
        } else {
            index.insert(key, unique.len());
            let offset = finding.offset;
            unique.push(DedupedFinding {
                finding,
                count: 1,
                offsets: vec![offset],
                offsets_truncated: false,
            });
        }
    }
    unique
}

#[allow(clippy::too_many_arguments)]
/// Everything the stderr summary needs. Grouped into a struct because the
/// report grew past a readable argument list.
pub struct ReportData<'a> {
    pub result_count: usize,
    pub short: usize,
    pub medium: usize,
    pub long: usize,
    pub important: &'a [ExtractedString],
    pub entropy_regions: &'a [EntropyRegion],
    pub artifacts: &'a [Artifact],
    pub encodings: [usize; ENCODING_LABELS.len()],
    pub file_size: u64,
    pub range_start: u64,
    pub range_end: u64,
    pub elapsed: f64,
    pub threads: usize,
    pub truncated: bool,
    pub max_strings: usize,
    pub scanned_until: u64,
    /// `--report summary`: add encoding, coverage and artifact details.
    pub detailed: bool,
    /// Whether results went to `-o <file>` (suppresses the terminal hint).
    pub output_is_file: bool,
    /// `--carve` summary, when the carve stage ran.
    pub carve: Option<&'a CarveReport>,
}

/// Exit with code `3` when the carve stage stopped at a cap, after saying why.
pub fn exit_if_carve_truncated(report: &Option<CarveReport>) {
    let Some(report) = report else {
        return;
    };
    if !report.truncated {
        return;
    }
    eprintln!(
        "  [!] CARVE TRUNCATED: stopped after {} file(s) / {} bytes (--carve-max-total or --carve-max-files).",
        report.files.len(),
        report.bytes_written
    );
    eprintln!("      The carved files are valid, but the dump was not scanned to the end.");
    std::process::exit(3);
}

pub fn print_carve_summary(report: &CarveReport) {
    let color = io::stderr().is_terminal();
    if color {
        eprintln!("\x1b[1;36m  [i] carve: {}\x1b[0m", report.summary_line());
    } else {
        eprintln!("  [i] carve: {}", report.summary_line());
    }
    for file in report.files.iter().filter(|file| !file.complete).take(5) {
        eprintln!(
            "      - incomplete {:#010x} {:<6} {} bytes: {}",
            file.offset,
            file.kind.as_str(),
            file.size,
            file.notes
        );
    }
    for detail in report.rejected_details.iter().take(3) {
        eprintln!("      - rejected {detail}");
    }
    if let Some(dir) = report
        .files
        .iter()
        .filter_map(|file| file.path.as_ref())
        .next()
        .and_then(|path| path.parent())
    {
        eprintln!("      wrote files under '{}'", dir.display());
    }
}

pub fn print_reassembly_summary(report: &ReassemblyReport) {
    let color = io::stderr().is_terminal();
    if color {
        eprintln!(
            "\x1b[1;36m  [i] reassemble: {}/{} fragments merged into {} file(s)\x1b[0m",
            report.fragments,
            report.merged_groups,
            report.files.len()
        );
    } else {
        eprintln!(
            "  [i] reassemble: {}/{} fragments merged into {} file(s)",
            report.fragments,
            report.merged_groups,
            report.files.len()
        );
    }
    for file in report.files.iter().take(5) {
        let complete = if file.complete { "complete" } else { "partial" };
        eprintln!(
            "      - {complete} {:#010x} {:<6} {} bytes (va={:#010x})",
            file.file_offset,
            file.kind.as_str(),
            file.size,
            file.va_start
        );
    }
    if let Some(dir) = report
        .files
        .iter()
        .filter_map(|file| file.path.as_ref())
        .next()
        .and_then(|path| path.parent())
    {
        eprintln!("      wrote reassembled files under '{}'", dir.display());
    }
}

/// Write the carve index. `.ndjson` writes one record per line, anything else
/// writes a JSON array. The index is a separate channel from `--format` so
/// carving never reshapes the string output.
pub fn print_report(data: &ReportData<'_>) {
    let color = io::stderr().is_terminal();
    if color {
        eprintln!("\x1b[1;32m  [OK] scan complete\x1b[0m");
        eprintln!("\x1b[1;36m+-------------------- summary -----------------------------+\x1b[0m");
    } else {
        eprintln!("  [OK] scan complete");
        eprintln!("+-------------------- summary -----------------------------+");
    }
    eprintln!("  results    : {}", data.result_count);
    if !data.artifacts.is_empty() {
        eprintln!("  artifacts  : {} unique", data.artifacts.len());
    }
    eprintln!(
        "  length     : {} short | {} medium | {} long",
        data.short, data.medium, data.long
    );
    if data.detailed {
        eprintln!("  encodings  : {}", encoding_breakdown(&data.encodings));
        eprintln!(
            "  scanned    : {:#010x}-{:#010x} ({})",
            data.range_start,
            data.covered_end(),
            data.coverage_text()
        );
        if data.truncated {
            eprintln!(
                "  limit      : --max-strings {} reached at {:#010x} (exit 3)",
                data.max_strings, data.scanned_until
            );
        } else if data.max_strings == usize::MAX {
            eprintln!("  limit      : not reached (unlimited)");
        } else {
            eprintln!(
                "  limit      : not reached (--max-strings {})",
                data.max_strings
            );
        }
    }
    eprintln!("  threads    : {}", data.threads);
    eprintln!("  file size  : {} bytes", data.file_size);
    eprintln!("  elapsed    : {:.3} ms", data.elapsed * 1000.0);
    // Throughput must describe what was actually scanned: a `--max-strings`
    // cap stops early, and dividing the whole file size by that short elapsed
    // time reported absurd numbers (e.g. 400 MiB/s after 0.1% of the dump).
    let scanned = data.covered_end().saturating_sub(data.range_start);
    eprintln!(
        "  throughput : {:.2} MiB/s (over {} scanned bytes)",
        scanned as f64 / data.elapsed.max(f64::MIN_POSITIVE) / 1_048_576.0,
        scanned
    );
    eprintln!("+------------------------------------------------------------+");
    hint_large_terminal_output(data.result_count, data.output_is_file);
    if data.detailed && !data.artifacts.is_empty() {
        eprintln!("  [!] top artifacts (rarest first, up to 10)");
        for artifact in data.artifacts.iter().take(10) {
            eprintln!(
                "      - {:<8} count={:<5} offset {:#010x}  {}",
                artifact.kind.as_str(),
                artifact.count,
                artifact.offset,
                artifact.value
            );
        }
    }
    if !data.important.is_empty() {
        eprintln!("  [!] priority findings (up to 12)");
        for result in data.important {
            let reason = important_reason(&result.text).unwrap_or("interesting");
            eprintln!(
                "      - {:<12} | offset {:#010x} | {:<7} | {}",
                reason, result.offset, result.encoding, result.text
            );
        }
    }
    if !data.entropy_regions.is_empty() {
        eprintln!("  [!] high-entropy regions (showing up to 12)");
        for region in data.entropy_regions {
            eprintln!(
                "      offset {:#010x}  {:>6} bytes  entropy {:.3}/8.000",
                region.offset, region.length, region.entropy
            );
        }
    }
    if let Some(carve) = data.carve {
        eprintln!("  carve      : {}", carve.summary_line());
    }
}

impl ReportData<'_> {
    /// Last byte actually reached: the scan window end, or the last emitted
    /// offset when `--max-strings` stopped the scan early.
    fn covered_end(&self) -> u64 {
        if self.truncated {
            self.scanned_until.min(self.range_end).max(self.range_start)
        } else {
            self.range_end
        }
    }

    fn coverage_text(&self) -> String {
        let span = self.range_end.saturating_sub(self.range_start);
        let covered = self.covered_end().saturating_sub(self.range_start);
        let window_pct = if span == 0 {
            100.0
        } else {
            covered as f64 * 100.0 / span as f64
        };
        let file_pct = if self.file_size == 0 {
            100.0
        } else {
            covered as f64 * 100.0 / self.file_size as f64
        };
        if self.range_start == 0 && self.range_end >= self.file_size {
            format!("{covered} bytes, {file_pct:.1}% of file")
        } else {
            format!(
                "{covered} bytes, {window_pct:.1}% of {span}-byte window, {file_pct:.1}% of file"
            )
        }
    }
}

pub fn display_text(text: &str, max_str_len: usize) -> String {
    let mut s = text.to_string();
    if max_str_len > 0 {
        let count = s.chars().count();
        if count > max_str_len {
            s = s.chars().take(max_str_len).collect::<String>();
            s.push_str("...");
        }
    }
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub fn update_stats(
    result: &ExtractedString,
    short: &mut usize,
    medium: &mut usize,
    long: &mut usize,
    important: &mut Vec<ExtractedString>,
) {
    match result.text.chars().count() {
        0..=7 => *short += 1,
        8..=31 => *medium += 1,
        _ => *long += 1,
    }
    if important.len() < 12 && important_reason(&result.text).is_some() {
        important.push(result.clone());
    }
}

#[allow(clippy::too_many_arguments)]
pub fn record_result(
    result: ExtractedString,
    writer: &mut dyn Write,
    format: Format,
    result_count: &mut usize,
    short: &mut usize,
    medium: &mut usize,
    long: &mut usize,
    important: &mut Vec<ExtractedString>,
    parse_pid: bool,
    max_str_len: usize,
    count: Option<usize>,
    compact: bool,
) -> io::Result<()> {
    match format {
        Format::Text => {
            write!(
                writer,
                "{:#010x}\t{}\t{}",
                result.offset,
                result.encoding,
                display_text(&result.text, max_str_len)
            )?;
            if let Some(count) = count {
                write!(writer, "\tcount={count}")?;
            }
            if parse_pid {
                match parse_pid_marker(&result.text) {
                    Some(pid) => write!(writer, "\tpid={pid}")?,
                    None => write!(writer, "\tpid=-")?,
                }
            }
            writeln!(writer)?;
        }
        Format::Json | Format::Ndjson => {
            write_string_json(
                &result,
                writer,
                result_count,
                parse_pid,
                count,
                json_layout_for(format, compact),
            )?;
        }
        Format::JsonTree => {
            // handled separately in main(); no-op here
        }
        Format::Csv => {
            write_csv_string_row(&result, writer, parse_pid, max_str_len, count)?;
        }
        Format::Html | Format::Markdown => {
            // Handled in write_report_html_markdown
        }
    }
    // `write_string_json` already bumps the counter for JSON/NDJSON records;
    // counting again here would skew record totals and separators.
    if !matches!(format, Format::Json | Format::Ndjson) {
        *result_count += 1;
    }
    update_stats(&result, short, medium, long, important);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn record_finding(
    finding: &bxmap::classifier::DetectedFinding,
    writer: &mut dyn Write,
    format: Format,
    result_count: &mut usize,
    max_str_len: usize,
    count: Option<usize>,
    offsets: Option<&[u64]>,
    offsets_truncated: bool,
    compact: bool,
) -> io::Result<()> {
    match format {
        Format::Text => {
            write!(
                writer,
                "{:#010x}\t{}\trule={}\tconf={:.2}\tsev={}\tvalue={}\tcontext={}\ttext={}",
                finding.offset,
                finding.encoding,
                finding.rule,
                finding.confidence,
                finding.severity,
                display_text(&finding.value, max_str_len),
                display_text(&finding.context, max_str_len),
                display_text(&finding.text, max_str_len)
            )?;
            if let Some(count) = count {
                write!(writer, "\tcount={count}")?;
            }
            if let Some(offsets) = offsets {
                write!(
                    writer,
                    "\toffsets={}",
                    offsets
                        .iter()
                        .map(|o| o.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                )?;
                if offsets_truncated {
                    write!(writer, "\toffsets_truncated=1")?;
                }
            }
            writeln!(writer)?;
        }
        Format::Json | Format::Ndjson => {
            let layout = json_layout_for(format, compact);
            json_record_open(writer, result_count, layout, Some("finding"))?;
            write!(
                writer,
                "\"offset\":{},\"encoding\":{},\"rule\":{},\"value\":{},\"confidence\":{:.4},\"severity\":{},\"context\":{},\"text\":{}",
                finding.offset,
                json_escape(finding.encoding),
                json_escape(finding.rule),
                json_escape(&finding.value),
                finding.confidence,
                json_escape(finding.severity),
                json_escape(&finding.context),
                json_escape(&finding.text)
            )?;
            if let Some(count) = count {
                write!(writer, ",\"count\":{count}")?;
            }
            if let Some(offsets) = offsets {
                write!(writer, ",\"offsets\":[")?;
                for (i, o) in offsets.iter().enumerate() {
                    if i > 0 {
                        write!(writer, ",")?;
                    }
                    write!(writer, "{o}")?;
                }
                write!(writer, "]")?;
                if offsets_truncated {
                    write!(writer, ",\"offsets_truncated\":true")?;
                }
            }
            write!(writer, "}}")?;
        }
        Format::JsonTree => {
            // rejected during argument validation
        }
        Format::Csv => {
            write_csv_finding_row(finding, writer, max_str_len, count)?;
        }
        Format::Html | Format::Markdown => {
            // Handled in write_report_html_markdown
        }
    }
    *result_count += 1;
    Ok(())
}

/// Generate a self-contained HTML or Markdown report for case sharing.
pub fn format_encodings(encodings: &[usize; 9]) -> String {
    let mut parts = Vec::new();
    for (i, &count) in encodings.iter().enumerate() {
        if count > 0 {
            parts.push(format!("{}={}", ENCODING_LABELS[i], count));
        }
    }
    parts.join(", ")
}

pub fn parse_path_detail(detail: &str) -> Option<(String, String)> {
    let mut user = None;
    let mut category = None;
    for pair in detail.split(';') {
        if let Some((key, value)) = pair.split_once('=') {
            match key.trim().to_lowercase().as_str() {
                "user" => user = Some(value.to_string()),
                "category" => category = Some(value.to_string()),
                _ => {}
            }
        }
    }
    match (user, category) {
        (Some(u), Some(c)) => Some((u, c)),
        _ => None,
    }
}
