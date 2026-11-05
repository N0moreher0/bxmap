// Argument parsing and validation for bxmap-cli.
//
// Extracted from main.rs to keep the entry point readable. Types that are
// shared with the rest of the crate (Format, ReportMode, ...) stay in the
// crate root and are reached through `crate::`.

use super::*;
use bxmap::artifacts::ArtifactKinds;
use bxmap::{EncodingFilter, MAX_STRINGS, MIN_STRING_LEN};
pub struct Args {
    pub path: String,
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub min_len: usize,
    pub max_str_len: usize,
    pub max_strings: usize,
    pub progress: Option<bool>,
    pub dedupe: bool,
    pub compact: bool,
    pub extract: ArtifactKinds,
    pub report_mode: ReportMode,
    pub format: Format,
    pub detect_format: DetectFormat,
    pub encoding: Encoding,
    pub output: Option<String>,
    pub noise_threshold: Option<usize>,
    pub threads: usize,
    pub auto_tune: bool,
    pub entropy: bool,
    pub entropy_no_data: bool,
    pub entropy_window: Option<usize>,
    pub entropy_threshold: Option<f64>,
    pub entropy_merge: bool,
    pub entropy_max_data: Option<usize>,
    pub yar: Option<String>,
    pub brute_xor: Option<Vec<usize>>,
    pub xor_exhaustive: bool,
    pub parse_pid: bool,
    pub stats: bool,
    pub filter_regex: Option<String>,
    pub min_files_in_user: usize,
    pub filter_appdata: bool,
    pub detectors: Vec<Detector>,
    pub signature: Option<String>,
    pub carve: Option<String>,
    pub carve_out: Option<String>,
    pub carve_index: Option<String>,
    pub carve_min_size: u64,
    pub carve_max_size: u64,
    pub carve_max_total: u64,
    pub carve_max_files: usize,
    pub tree: bool,
    pub map_va: bool,
    pub no_tree: bool,
    pub no_map_va: bool,
    pub no_vmware_info: bool,
    pub in_module: Option<String>,
    pub rwx_only: bool,
    pub vmware_info: bool,
    pub heap_only: bool,
    pub detect_strict: bool,
    pub custom_rules: Option<String>,
    pub reassemble: bool,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Detector {
    Ip,
    Url,
    Domain,
    Base64,
    Secret,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Encoding {
    All,
    Ascii,
    Utf16,
    Utf32,
    Latin1,
    Cp1252,
    Utf8,
    ShiftJis,
    /// Comma-separated `--encoding` list, e.g. `ascii,utf16,utf8`.
    /// Bit layout is the `ENC_*` mask below.
    Set(u8),
}

// One bit per encoding family, used by the comma-separated `--encoding` form.
pub const ENC_ASCII: u8 = 1 << 0;
pub const ENC_UTF16: u8 = 1 << 1;
pub const ENC_UTF32: u8 = 1 << 2;
pub const ENC_LATIN1: u8 = 1 << 3;
pub const ENC_CP1252: u8 = 1 << 4;
pub const ENC_UTF8: u8 = 1 << 5;
pub const ENC_SHIFT_JIS: u8 = 1 << 6;
pub const ENC_ALL_BITS: u8 =
    ENC_ASCII | ENC_UTF16 | ENC_UTF32 | ENC_LATIN1 | ENC_CP1252 | ENC_UTF8 | ENC_SHIFT_JIS;

pub fn encoding_bit_for_name(name: &str) -> Option<u8> {
    Some(match name {
        "ascii" => ENC_ASCII,
        "utf16" | "utf-16" => ENC_UTF16,
        "utf32" | "utf-32" => ENC_UTF32,
        "latin1" | "iso-8859-1" => ENC_LATIN1,
        "cp1252" | "windows-1252" => ENC_CP1252,
        "utf8" | "utf-8" => ENC_UTF8,
        "shift_jis" | "shiftjis" | "sjis" => ENC_SHIFT_JIS,
        _ => return None,
    })
}

/// Parse one `--encoding` value: either a single name (`latin1`, the
/// historical form) or a comma-separated list (`ascii,utf16,utf8`).
///
/// Single names still map to their dedicated variant so the existing filter
/// semantics stay byte-for-byte identical; only real lists become `Set`.
pub fn parse_encoding_spec(spec: &str) -> Result<Encoding, String> {
    let trimmed = spec.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        return Ok(Encoding::All);
    }
    let mut bits = 0u8;
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let bit = encoding_bit_for_name(&part.to_ascii_lowercase()).ok_or_else(|| {
            format!(
                "invalid encoding '{part}' (expected all, ascii, utf16, utf32, latin1, cp1252, \
                 utf8 or shift_jis)"
            )
        })?;
        bits |= bit;
    }
    if bits == 0 {
        return Err("--encoding needs at least one value".to_string());
    }
    Ok(match bits {
        ENC_ASCII => Encoding::Ascii,
        ENC_UTF16 => Encoding::Utf16,
        ENC_UTF32 => Encoding::Utf32,
        ENC_LATIN1 => Encoding::Latin1,
        ENC_CP1252 => Encoding::Cp1252,
        ENC_UTF8 => Encoding::Utf8,
        ENC_SHIFT_JIS => Encoding::ShiftJis,
        other => Encoding::Set(other),
    })
}

pub fn encoding_mask(encoding: Encoding) -> u8 {
    match encoding {
        Encoding::All => ENC_ALL_BITS,
        Encoding::Ascii => ENC_ASCII,
        Encoding::Utf16 => ENC_UTF16,
        Encoding::Utf32 => ENC_UTF32,
        Encoding::Latin1 => ENC_LATIN1,
        Encoding::Cp1252 => ENC_CP1252,
        Encoding::Utf8 => ENC_UTF8,
        Encoding::ShiftJis => ENC_SHIFT_JIS,
        Encoding::Set(bits) => bits,
    }
}

/// Human-readable scope used by `--report summary` and the startup banner.
pub fn encoding_scope_label(encoding: Encoding) -> String {
    let mask = encoding_mask(encoding);
    if mask == ENC_ALL_BITS {
        return "all".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for (bit, label) in [
        (ENC_ASCII, "ascii"),
        (ENC_UTF16, "utf16"),
        (ENC_UTF32, "utf32"),
        (ENC_LATIN1, "latin1"),
        (ENC_CP1252, "cp1252"),
        (ENC_UTF8, "utf8"),
        (ENC_SHIFT_JIS, "shift_jis"),
    ] {
        if mask & bit != 0 {
            parts.push(label);
        }
    }
    parts.join(", ")
}

/// Does an extracted string with this `ExtractedString::encoding` label pass
/// the `--encoding` filter?
pub fn encoding_accepts(encoding: Encoding, label: &str) -> bool {
    if matches!(encoding, Encoding::All) {
        return true;
    }
    let bit = match label {
        "ascii" => ENC_ASCII,
        "utf16le" | "utf16be" => ENC_UTF16,
        "utf32le" | "utf32be" => ENC_UTF32,
        "latin1" => ENC_LATIN1,
        "cp1252" => ENC_CP1252,
        "utf8" => ENC_UTF8,
        "shift_jis" => ENC_SHIFT_JIS,
        _ => return false,
    };
    encoding_mask(encoding) & bit != 0
}

/// Build the scanner-side filter straight from the requested families.
///
/// `--encoding latin1 | cp1252 | utf8 | shift_jis` no longer pulls in the
/// ascii scanner: an all-ASCII run is still emitted as a "<family>" record
/// (latin1's printable range already covers ASCII), and the library's new
/// duplicate suppression needs the real user intent - scanning ASCII on a
/// `--encoding latin1` call previously looked like "ascii enabled" only
/// because a Latin-1 scan started and stopped at the same places.
pub fn encoding_filter_for(encoding: Encoding) -> EncodingFilter {
    if matches!(encoding, Encoding::All) {
        return EncodingFilter::all();
    }
    let mask = encoding_mask(encoding);
    EncodingFilter {
        ascii: mask & ENC_ASCII != 0,
        utf16le: mask & ENC_UTF16 != 0,
        utf16be: mask & ENC_UTF16 != 0,
        utf32le: mask & ENC_UTF32 != 0,
        utf32be: mask & ENC_UTF32 != 0,
        latin1: mask & ENC_LATIN1 != 0,
        cp1252: mask & ENC_CP1252 != 0,
        utf8: mask & ENC_UTF8 != 0,
        shift_jis: mask & ENC_SHIFT_JIS != 0,
    }
}

pub fn completions_for(shell: &str) -> String {
    let flags = [
        "--min-len",
        "--max-str-len",
        "--max-strings",
        "--start",
        "--end",
        "--encoding",
        "--noise-threshold",
        "--threads",
        "--auto-tune",
        "--format",
        "--compact",
        "--dedupe",
        "--extract",
        "--report",
        "--detect",
        "--detect-format",
        "--filter-regex",
        "--stats",
        "--entropy",
        "--entropy-window",
        "--entropy-threshold",
        "--entropy-merge",
        "--entropy-no-data",
        "--entropy-max-data",
        "--signature",
        "--yar",
        "--brute-xor",
        "--xor-exhaustive",
        "--tree",
        "--no-tree",
        "--map-va",
        "--no-map-va",
        "--in-module",
        "--rwx-only",
        "--heap-only",
        "--vmware-info",
        "--no-vmware-info",
        "--reassemble",
        "--signature",
        "--carve",
        "--carve-out",
        "--carve-index",
        "--carve-min-size",
        "--carve-max-size",
        "--carve-max-total",
        "--carve-max-files",
        "--mode",
        "-o",
        "--output",
        "-h",
        "--help",
        "-V",
        "--version",
    ];
    match shell {
        "bash" => {
            let mut out = String::from("_bxmap() {\n  local cur=\"${COMP_WORDS[COMP_CWORD]}\"\n  COMPREPLY=( $(compgen -W \"");
            out.push_str(&flags.join(" "));
            out.push_str("\" -- \"$cur\") )\n}\ncomplete -F _bxmap bxmap\n");
            out
        }
        "zsh" => {
            let mut out = String::from("#compdef bxmap\n_arguments -s \\\n");
            for f in flags {
                out.push_str(&format!("  '{}' \\\n", f));
            }
            out.push_str("  '*:file:_files'\n");
            out
        }
        "fish" => flags
            .iter()
            .map(|f| format!("complete -c bxmap -l {}\n", f.trim_start_matches('-')))
            .collect(),
        "powershell" => {
            let mut out = String::from("Register-ArgumentCompleter -Native -CommandName bxmap -ScriptBlock {\n  param($wordToComplete)\n  @(");
            for f in flags {
                out.push_str(&format!("\n    '{}'", f));
            }
            out.push_str("\n  ) | Where-Object { $_ -like \"$wordToComplete*\" }\n}\n");
            out
        }
        other => format!(
            "unknown shell '{}'; expected bash, zsh, fish or powershell\n",
            other
        ),
    }
}

pub fn parse_args() -> Result<Args, String> {
    let mut values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|v| v == "-h" || v == "--help") {
        print!("{HELP}");
        std::process::exit(0);
    }
    if values.iter().any(|v| v == "-V" || v == "--version") {
        // Version of THIS crate (bxmap-cli), never the library's.
        println!("bxmap-cli {}", env!("CARGO_PKG_VERSION"));
        println!(
            "features: yara={}, shift-jis={}",
            cfg!(feature = "yara"),
            cfg!(feature = "shift-jis")
        );
        println!("target: {}", std::env::consts::ARCH);
        std::process::exit(0);
    }
    if !values.is_empty() && values[0] == "completions" {
        let shell = values.get(1).cloned().unwrap_or_default();
        print!("{}", completions_for(&shell));
        std::process::exit(0);
    }
    let path = values.remove(0);
    let mut args = Args {
        path,
        start: None,
        end: None,
        min_len: MIN_STRING_LEN,
        max_str_len: 0,
        max_strings: MAX_STRINGS,
        progress: None,
        dedupe: false,
        compact: false,
        extract: ArtifactKinds::NONE,
        report_mode: ReportMode::None,
        min_files_in_user: 0,
        filter_appdata: false,
        format: Format::Text,
        detect_format: DetectFormat::Flat,
        encoding: Encoding::All,
        output: None,
        noise_threshold: None,
        threads: 1,
        auto_tune: false,
        entropy: false,
        entropy_no_data: false,
        entropy_window: None,
        entropy_threshold: None,
        entropy_merge: false,
        entropy_max_data: None,
        yar: None,
        brute_xor: None,
        xor_exhaustive: false,
        parse_pid: false,
        stats: false,
        filter_regex: None,
        detectors: Vec::new(),
        carve: None,
        carve_out: None,
        carve_index: None,
        carve_min_size: bxmap::carve::DEFAULT_MIN_SIZE,
        carve_max_size: bxmap::carve::DEFAULT_MAX_SIZE,
        carve_max_total: bxmap::carve::DEFAULT_MAX_TOTAL,
        carve_max_files: bxmap::carve::DEFAULT_MAX_FILES,
        signature: None,
        tree: false,
        map_va: false,
        no_tree: false,
        no_map_va: false,
        no_vmware_info: false,
        in_module: None,
        rwx_only: false,
        vmware_info: false,
        heap_only: false,
        detect_strict: false,
        custom_rules: None,
        reassemble: false,
    };
    let mut i = 0;
    let mut format_explicit = false;
    let mut mode: Option<Mode> = None;
    let mut explicit = ExplicitFlags::default();
    while i < values.len() {
        let flag = values[i].as_str();
        let next = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            values
                .get(*i)
                .cloned()
                .ok_or_else(|| format!("missing value after '{flag}'"))
        };
        match flag {
            "--mode" => mode = Some(parse_mode(&next(&mut i)?)?),
            "--min-len" => {
                explicit.min_len = true;
                args.min_len = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --min-len".to_string())?
            }
            "--start" => args.start = Some(parse_offset(&next(&mut i)?, "--start")?),
            "--end" => args.end = Some(parse_offset(&next(&mut i)?, "--end")?),
            "--progress" => args.progress = Some(true),
            "--no-progress" => args.progress = Some(false),
            "--dedupe" => {
                explicit.dedupe = true;
                args.dedupe = true;
            }
            "--compact" => args.compact = true,
            "--extract" => {
                explicit.extract = true;
                args.extract = ArtifactKinds::from_list(&next(&mut i)?)?;
            }
            "--report" => {
                explicit.report = true;
                let value = next(&mut i)?;
                args.report_mode = match value.as_str() {
                    "none" => ReportMode::None,
                    "summary" => ReportMode::Summary,
                    "user" => ReportMode::User,
                    "all" => ReportMode::All,
                    other => {
                        return Err(format!(
                            "invalid --report mode '{other}' (expected none, summary, user or all)"
                        ))
                    }
                };
            }
            "--min-files-in-user" => {
                args.min_files_in_user = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --min-files-in-user".to_string())?
            }
            "--filter-appdata" => args.filter_appdata = true,
            "--max-str-len" => {
                args.max_str_len = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --max-str-len".to_string())?
            }
            "--max-strings" => {
                explicit.max_strings = true;
                args.max_strings = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --max-strings".to_string())?
            }
            "--format" => {
                format_explicit = true;
                args.format = match next(&mut i)?.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    "json-tree" => Format::JsonTree,
                    "ndjson" => Format::Ndjson,
                    "csv" => Format::Csv,
                    "html" => Format::Html,
                    "markdown" | "md" => Format::Markdown,
                    other => return Err(format!("invalid format '{other}'")),
                };
            }
            "--encoding" => {
                explicit.encoding = true;
                args.encoding = parse_encoding_spec(&next(&mut i)?)?;
            }
            "-o" | "--output" => args.output = Some(next(&mut i)?),
            "--noise-threshold" => {
                args.noise_threshold = Some(
                    next(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --noise-threshold".to_string())?,
                )
            }
            "--threads" => {
                args.threads = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --threads".to_string())?;
                if args.threads == 0 {
                    return Err("--threads must be at least 1".to_string());
                }
            }
            "--auto-tune" => args.auto_tune = true,
            "--entropy" => {
                explicit.entropy = true;
                args.entropy = true;
            }
            "--entropy-no-data" => args.entropy_no_data = true,
            "--entropy-window" => {
                args.entropy_window = Some(
                    next(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --entropy-window".to_string())?,
                )
            }
            "--entropy-threshold" => {
                args.entropy_threshold = Some(
                    next(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --entropy-threshold".to_string())?,
                )
            }
            "--entropy-merge" => args.entropy_merge = true,
            "--entropy-max-data" => {
                args.entropy_max_data = Some(
                    next(&mut i)?
                        .parse()
                        .map_err(|_| "invalid --entropy-max-data".to_string())?,
                )
            }
            "--yar" => args.yar = Some(next(&mut i)?),
            "--brute-xor" => {
                let value = next(&mut i)?;
                let mut sizes = Vec::new();
                for part in value.split([';', ',']) {
                    let size = part
                        .strip_suffix('b')
                        .unwrap_or(part)
                        .parse::<usize>()
                        .map_err(|_| "invalid --brute-xor key size".to_string())?;
                    if !(1..=3).contains(&size) {
                        return Err("--brute-xor supports key sizes 1b, 2b, and 3b".to_string());
                    }
                    if !sizes.contains(&size) {
                        sizes.push(size);
                    }
                }
                if sizes.is_empty() {
                    return Err("--brute-xor requires at least one key size".to_string());
                }
                args.brute_xor = Some(sizes);
            }
            "--parse-pid" => args.parse_pid = true,
            "--xor-exhaustive" => args.xor_exhaustive = true,
            "--stats" => args.stats = true,
            "--filter-regex" => args.filter_regex = Some(next(&mut i)?),
            "--carve" => {
                explicit.carve = true;
                args.carve = Some(next(&mut i)?);
            }
            "--carve-out" => {
                explicit.carve_out = true;
                args.carve_out = Some(next(&mut i)?);
            }
            "--carve-index" => args.carve_index = Some(next(&mut i)?),
            "--carve-min-size" => {
                args.carve_min_size = parse_offset(&next(&mut i)?, "--carve-min-size")?;
            }
            "--carve-max-size" => {
                args.carve_max_size = parse_offset(&next(&mut i)?, "--carve-max-size")?;
            }
            "--carve-max-total" => {
                args.carve_max_total = parse_offset(&next(&mut i)?, "--carve-max-total")?;
            }
            "--carve-max-files" => {
                args.carve_max_files = parse_offset(&next(&mut i)?, "--carve-max-files")? as usize;
            }
            "--tree" => args.tree = true,
            "--no-tree" => args.no_tree = true,
            "--map-va" => args.map_va = true,
            "--no-map-va" => args.no_map_va = true,
            "--in-module" => args.in_module = Some(next(&mut i)?),
            "--rwx-only" => args.rwx_only = true,
            "--heap-only" => args.heap_only = true,
            "--vmware-info" => args.vmware_info = true,
            "--no-vmware-info" => args.no_vmware_info = true,
            "--reassemble" => args.reassemble = true,
            "--signature" => {
                explicit.signature = true;
                args.signature = Some(next(&mut i)?);
            }
            "--detect" => {
                explicit.detectors = true;
                let value = if i + 1 < values.len() && !values[i + 1].starts_with("--") {
                    next(&mut i)?
                } else {
                    "secret".to_string()
                };
                for part in value.split(',') {
                    let d = match part.trim() {
                        "ip" => Detector::Ip,
                        "url" => Detector::Url,
                        "domain" => Detector::Domain,
                        "b64" | "base64" => Detector::Base64,
                        "secret" | "all" => Detector::Secret,
                        other => return Err(format!("unknown detector '{other}'")),
                    };
                    push_detector(&mut args.detectors, d)?;
                }
            }
            "--detect-format" => {
                args.detect_format = match next(&mut i)?.as_str() {
                    "flat" => DetectFormat::Flat,
                    "rich" => DetectFormat::Rich,
                    other => return Err(format!("invalid detect format '{other}'")),
                };
            }
            "--detect-strict" => {
                args.detect_strict = true;
            }
            "--detect-rules" => {
                args.custom_rules = Some(next(&mut i)?);
            }
            other => return Err(format!("unknown option '{other}'")),
        }

        fn push_detector(list: &mut Vec<Detector>, detector: Detector) -> Result<(), String> {
            if !list.contains(&detector) {
                list.push(detector);
            }
            Ok(())
        }
        i += 1;
    }
    // Presets only fill flags the user did not spell out, so the order on the
    // command line never matters: `--mode triage --encoding ascii` and
    // `--encoding ascii --mode triage` behave identically.
    if let Some(mode) = mode {
        let has_output = args.output.is_some();
        apply_mode_preset(mode, &explicit, has_output, &mut args);
    }
    // `-o case.ndjson` picks the writer from the extension unless --format was
    // given explicitly.
    if !format_explicit {
        if let Some(inferred) = args
            .output
            .as_deref()
            .and_then(infer_format_from_output_path)
        {
            args.format = inferred;
        }
    }
    if args.max_strings == 0 {
        // 0 means "no limit"; internal code uses usize::MAX as the sentinel.
        args.max_strings = usize::MAX;
    }
    if let (Some(start), Some(end)) = (args.start, args.end) {
        if start >= end {
            return Err(format!(
                "--start ({start:#x}) must be less than --end ({end:#x})"
            ));
        }
    }
    Ok(args)
}

pub fn validate(args: &Args, filter_regex: Option<&Regex>) -> Result<(), String> {
    if !args.detectors.is_empty() && filter_regex.is_some() {
        return Err("--filter-regex cannot be combined with a detector".to_string());
    }
    if args.detect_format == DetectFormat::Rich {
        if args.detectors.is_empty() {
            return Err("--detect-format rich requires --detect".to_string());
        }
        if args.format == Format::JsonTree {
            return Err("--detect-format rich supports --format text or json".to_string());
        }
    }
    if !args.entropy {
        for (flag, set) in [
            ("--entropy-no-data", args.entropy_no_data),
            ("--entropy-window", args.entropy_window.is_some()),
            ("--entropy-threshold", args.entropy_threshold.is_some()),
            ("--entropy-merge", args.entropy_merge),
            ("--entropy-max-data", args.entropy_max_data.is_some()),
        ] {
            if set {
                return Err(format!("{flag} requires --entropy"));
            }
        }
    }
    if !args.extract.is_empty() && args.format == Format::JsonTree {
        return Err(
            "--extract does not support --format json-tree; use text, json, ndjson or csv"
                .to_string(),
        );
    }
    if args.xor_exhaustive && args.brute_xor.is_none() {
        return Err("--xor-exhaustive requires --brute-xor".to_string());
    }
    if args.carve.is_none() {
        for (flag, set) in [
            ("--carve-out", args.carve_out.is_some()),
            ("--carve-index", args.carve_index.is_some()),
        ] {
            if set {
                return Err(format!("{flag} requires --carve"));
            }
        }
    } else {
        if args.carve_out.is_none() {
            return Err("--carve requires --carve-out <dir>".to_string());
        }
        if args.carve_max_size == 0 {
            return Err("--carve-max-size must be greater than 0".to_string());
        }
        if args.carve_min_size > args.carve_max_size {
            return Err("--carve-min-size must not exceed --carve-max-size".to_string());
        }
    }
    if args.reassemble && args.carve.is_none() {
        return Err("--reassemble requires --carve".to_string());
    }
    if args.entropy_window == Some(0) {
        return Err("--entropy-window must be greater than 0".to_string());
    }
    if let Some(threshold) = args.entropy_threshold {
        if !(0.0..=8.0).contains(&threshold) {
            return Err("--entropy-threshold must be between 0 and 8".to_string());
        }
    }
    if args.format == Format::Csv
        && (args.signature.is_some()
            || args.yar.is_some()
            || args.brute_xor.is_some()
            || args.entropy)
    {
        return Err(
            "--format csv supports strings, findings and artifacts only; use --format json or \
             ndjson for --signature/--yar/--brute-xor/--entropy"
                .to_string(),
        );
    }
    Ok(())
}

/// Parse `--signature <list>` into `(want_magic, want_keys)`.
///
/// Accepted values: `magic`, `keys`, `all`, `none`, or a comma-separated
/// combination such as `magic,keys`.
pub fn parse_signature(spec: &Option<String>) -> Result<(bool, bool), String> {
    let Some(spec) = spec else {
        return Ok((false, false));
    };
    let mut want_magic = false;
    let mut want_keys = false;
    for part in spec.split(',') {
        match part.trim().to_ascii_lowercase().as_str() {
            "magic" => want_magic = true,
            "keys" => want_keys = true,
            "all" => {
                want_magic = true;
                want_keys = true;
            }
            "none" => {}
            other => {
                return Err(format!(
                    "invalid --signature '{other}' (expected magic, keys, all or none)"
                ))
            }
        }
    }
    Ok((want_magic, want_keys))
}

pub fn apply_input_autodetect(args: &mut Args) {
    let lower = args.path.to_ascii_lowercase();
    if (lower.ends_with(".vmss") || lower.ends_with(".vmsn")) && !args.no_vmware_info {
        args.vmware_info = true;
        eprintln!(
            "  [i] VMware snapshot input: running --vmware-info (disable with --no-vmware-info)"
        );
        return;
    }
    let mut magic = [0u8; 4];
    let minidump = std::fs::File::open(&args.path)
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut magic))
        .is_ok()
        && magic == *b"MDMP";
    if !minidump {
        return;
    }
    let mut enabled = Vec::new();
    if !args.no_tree {
        args.tree = true;
        enabled.push("--tree");
    }
    if !args.no_map_va {
        args.map_va = true;
        enabled.push("--map-va");
    }
    if !enabled.is_empty() {
        eprintln!(
            "  [i] MDMP minidump detected: enabled {} (disable with --no-tree/--no-map-va)",
            enabled.join(" + ")
        );
    }
}
