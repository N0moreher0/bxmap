use bxmap::{
    extract_strings_from_file_parallel_with_encodings,
    extract_strings_from_file_streaming_range_with_encodings,
    extract_strings_from_file_streaming_range_with_encodings_progress,
    extract_strings_from_file_with_noise_config_and_encodings,
    scan_entropy_from_file_streaming_with_data, scan_yara_from_file_streaming, EncodingFilter,
    EntropyRegion, ExtractedString, NoiseConfig, MAX_STRINGS, MIN_STRING_LEN,
};
use regex::Regex;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, IsTerminal, Read, Write};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

static DUMP_MAP: OnceLock<bxmap::minidump::Minidump> = OnceLock::new();

/// Virtual address and a short module/region label for a file offset,
/// when `--map-va` loaded a minidump and the offset lies in a captured range.
fn va_annotation(offset: u64) -> Option<(u64, String)> {
    let dump = DUMP_MAP.get()?;
    let va = dump.offset_to_va(offset)?;
    let label = match dump.module_for_va(va) {
        Some(m) => m
            .name
            .rsplit(|c| c == '\\' || c == '/')
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

fn passes_region_filter(
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

const ENTROPY_THRESHOLD: f64 = 7.2;
const MAX_ENTROPY_REPORTS: usize = 12;
const MAX_XOR_CANDIDATES: usize = 256;
const MAX_XOR_CANDIDATE_LEN: usize = 100;
const MIN_XOR_CANDIDATE_LEN: usize = 10;
const MAX_XOR_RESULTS_PER_CANDIDATE: usize = 5;
const MIN_XOR_ALNUM_CHARS: usize = 3;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    Text,
    Json,
    JsonTree,
}

/// Detector output shape. `Flat` preserves the historical behaviour (replace
/// the source string with the matched token); `Rich` emits `DetectedFinding`
/// records with rule/confidence/severity/context.
#[derive(Clone, Copy, PartialEq)]
enum DetectFormat {
    Flat,
    Rich,
}

struct Args {
    path: String,
    start: Option<u64>,
    end: Option<u64>,
    min_len: usize,
    max_str_len: usize,
    max_strings: usize,
    progress: Option<bool>,
    format: Format,
    detect_format: DetectFormat,
    encoding: Encoding,
    output: Option<String>,
    noise_threshold: Option<usize>,
    threads: usize,
    auto_tune: bool,
    entropy: bool,
    yar: Option<String>,
    brute_xor: Option<Vec<usize>>,
    parse_pid: bool,
    stats: bool,
    filter_regex: Option<String>,
    detectors: Vec<Detector>,
    magic_bytes: bool,
    tree: bool,
    map_va: bool,
    in_module: Option<String>,
    rwx_only: bool,
    vmware_info: bool,
    heap_only: bool,
}

#[derive(Clone, Copy, PartialEq)]
enum Detector {
    Ip,
    Url,
    Domain,
    Base64,
    Secret,
}

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    All,
    Ascii,
    Utf16,
    Utf32,
}

const HELP: &str = "\
+-----------------------------------------+
|  BBBB    X   X   MMM MMM    AAA    PPPP |
|  B   B    X X    M M M M   A   A   P   P|
|  BBBB      X     M  M  M   AAAAA   PPPP |
|  B   B    X X    M     M   A   A   P    |
|  BBBB    X   X   M     M   A   A   P    |
+-----------------------------------------+
bxmap — fast memory-dump string extraction

USAGE:
    bxmap <path> [OPTIONS]

OPTIONS:
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
    --format <text|json|json-tree>
                           Output format (default text). json-tree emits
                           grouped classification tree.
    --encoding <all|ascii|utf16|utf32>
                          Restrict output by encoding (default all). utf-16 includes both LE & BE; utf-32 includes both LE & BE
    -o, --output <PATH>  Write results to a file
    --noise-threshold <N>
                          Repeat-noise threshold; 0 disables filtering
    --threads <N>        Parallel worker count
    --auto-tune          Choose a safe worker count for this machine
    --entropy            Scan and export high-entropy regions
    --yar <PATH>         Compile and match a YARA/YARA-X rule file while streaming
    --brute-xor <1b;2b;3b>
                          Brute-force XOR candidates using selected key sizes
    --parse-pid          Map PID markers in extracted strings
    --detect <list>       Detect IOCs: ip, url, domain, b64, secret, all (comma-separated)
    --detect-format <flat|rich>
                           Detector output shape (default flat). rich keeps the
                           original text and adds rule/confidence/severity/context.
    --magic-bytes         Report executable/document magic-byte signatures
    --tree                Parse a Windows minidump and print its process tree
                          (modules, threads, memory regions), then exit
    --map-va              For a minidump, add virtual address and module/region
                          to every extracted string
    --in-module <NAME>    Minidump only: keep strings inside modules whose name
                          contains NAME (case-insensitive, implies --map-va)
    --vmware-info         Inspect a VMware .vmss/.vmsn file (groups, sibling .vmem,
                          memory tags, CR registers), then exit
    --rwx-only            Minidump only: keep strings in committed RWX regions
                          (implies --map-va)
    --filter-regex <RE>   Legacy generic regex filter
    --stats              Always-on report compatibility flag
    -h, --help           Show this help
";

fn parse_offset(value: &str, flag: &str) -> Result<u64, String> {
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

fn parse_args() -> Result<Args, String> {
    let mut values = std::env::args().skip(1).collect::<Vec<_>>();
    if values.is_empty() || values.iter().any(|v| v == "-h" || v == "--help") {
        print!("{HELP}");
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
        format: Format::Text,
        detect_format: DetectFormat::Flat,
        encoding: Encoding::All,
        output: None,
        noise_threshold: None,
        threads: 1,
        auto_tune: false,
        entropy: false,
        yar: None,
        brute_xor: None,
        parse_pid: false,
        stats: false,
        filter_regex: None,
        detectors: Vec::new(),
        magic_bytes: false,
        tree: false,
        map_va: false,
        in_module: None,
        rwx_only: false,
        vmware_info: false,
        heap_only: false,
    };
    let mut i = 0;
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
            "--min-len" => {
                args.min_len = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --min-len".to_string())?
            }
            "--start" => args.start = Some(parse_offset(&next(&mut i)?, "--start")?),
            "--end" => args.end = Some(parse_offset(&next(&mut i)?, "--end")?),
            "--progress" => args.progress = Some(true),
            "--no-progress" => args.progress = Some(false),
            "--max-str-len" => {
                args.max_str_len = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --max-str-len".to_string())?
            }
            "--max-strings" => {
                args.max_strings = next(&mut i)?
                    .parse()
                    .map_err(|_| "invalid --max-strings".to_string())?
            }
            "--format" => {
                args.format = match next(&mut i)?.as_str() {
                    "text" => Format::Text,
                    "json" => Format::Json,
                    "json-tree" => Format::JsonTree,
                    other => return Err(format!("invalid format '{other}'")),
                };
            }
            "--encoding" => {
                args.encoding = match next(&mut i)?.as_str() {
                    "all" => Encoding::All,
                    "ascii" => Encoding::Ascii,
                    "utf16" => Encoding::Utf16,
                    "utf32" => Encoding::Utf32,
                    other => return Err(format!("invalid encoding '{other}'")),
                };
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
            "--entropy" => args.entropy = true,
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
            "--stats" => args.stats = true,
            "--filter-regex" => args.filter_regex = Some(next(&mut i)?),
            "--magic-bytes" => args.magic_bytes = true,
            "--tree" => args.tree = true,
            "--map-va" => args.map_va = true,
            "--in-module" => args.in_module = Some(next(&mut i)?),
            "--rwx-only" => args.rwx_only = true,
            "--heap-only" => args.heap_only = true,
            "--vmware-info" => args.vmware_info = true,
            "--detect" => {
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

fn json_escape(value: &str) -> String {
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

fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = Vec::with_capacity(data.len() * 2);
    for &byte in data {
        encoded.push(HEX[(byte >> 4) as usize]);
        encoded.push(HEX[(byte & 0x0f) as usize]);
    }
    // Only ASCII hex digits were pushed, so this cannot fail.
    String::from_utf8(encoded).expect("hex digits are ASCII")
}

fn matches_filter(regex: Option<&Regex>, text: &str) -> bool {
    regex.map_or(true, |regex| regex.is_match(text))
}

fn detected_ip_match(text: &str) -> Option<(String, usize, usize)> {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let ipv4 = IPV4.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .unwrap()
    });
    if let Some(value) = ipv4
        .find_iter(text)
        .find(|matched| is_public_ipv4(matched.as_str()))
    {
        return Some((value.as_str().to_string(), value.start(), value.end()));
    }
    for token in text
        .split(|character: char| character.is_whitespace() || "\"'<>(),;[]{}".contains(character))
    {
        if token.parse::<std::net::Ipv6Addr>().is_ok() {
            if let Some(start) = text.find(token) {
                return Some((token.to_string(), start, start + token.len()));
            }
        }
    }
    None
}

fn detected_ip_value(text: &str) -> Option<String> {
    detected_ip_match(text).map(|(value, _, _)| value)
}

fn detected_url_match(text: &str) -> Option<(String, usize, usize)> {
    static URL: OnceLock<Regex> = OnceLock::new();
    let matched = URL
        .get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>]+"#).unwrap())
        .find(text)?;
    let raw = matched.as_str();
    let trimmed = raw.trim_end_matches(['.', ',', ';', ')', ']', '}']);
    Some((
        trimmed.to_string(),
        matched.start(),
        matched.start() + trimmed.len(),
    ))
}

fn detected_url_value(text: &str) -> Option<String> {
    detected_url_match(text).map(|(value, _, _)| value)
}

fn detected_domain_match(text: &str) -> Option<(String, usize, usize)> {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let matched = DOMAIN
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap()
        })
        .find(text)?;
    Some((matched.as_str().to_string(), matched.start(), matched.end()))
}

fn detected_domain_value(text: &str) -> Option<String> {
    detected_domain_match(text).map(|(value, _, _)| value)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if value.len() < 16 || value.len() % 4 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    for chunk in bytes.chunks_exact(4) {
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

fn detect_and_decode_base64_match(text: &str) -> Option<(String, usize, usize)> {
    static B64: OnceLock<Regex> = OnceLock::new();
    let regex = B64.get_or_init(|| {
        Regex::new(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap()
    });
    regex.find_iter(text).find_map(|matched| {
        let decoded = decode_base64(matched.as_str())?;
        let decoded = String::from_utf8(decoded).ok()?;
        if decoded
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
        {
            Some((decoded, matched.start(), matched.end()))
        } else {
            None
        }
    })
}

fn detect_and_decode_base64(text: &str) -> Option<String> {
    detect_and_decode_base64_match(text).map(|(value, _, _)| value)
}

fn apply_detectors(result: ExtractedString, detectors: &[Detector]) -> Vec<ExtractedString> {
    if detectors.is_empty() {
        return vec![result];
    }
    let mut out = Vec::with_capacity(detectors.len());
    for det in detectors {
        match det {
            Detector::Ip => {
                if let Some(v) = detected_ip_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Url => {
                if let Some(v) = detected_url_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Domain => {
                if let Some(v) = detected_domain_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Base64 => {
                if let Some(v) = detect_and_decode_base64(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Secret => {
                for m in bxmap::classifier::detect_secrets(&result.text) {
                    let mut r = result.clone();
                    r.text = m.value;
                    out.push(r);
                }
            }
        }
    }
    out
}

fn push_finding(
    out: &mut Vec<bxmap::classifier::DetectedFinding>,
    result: &ExtractedString,
    rule: &'static str,
    value: String,
    start: usize,
    end: usize,
) {
    out.push(bxmap::classifier::DetectedFinding {
        offset: result.offset,
        encoding: result.encoding,
        rule,
        value,
        text: result.text.clone(),
        context: bxmap::classifier::context_around(&result.text, start, end, 32),
        confidence: bxmap::classifier::confidence_for(rule),
        severity: bxmap::classifier::severity_for(rule),
    });
}

/// Structured detector output: keep the original string and annotate each match
/// with its rule, confidence, severity and surrounding context.
fn detect_findings(
    result: &ExtractedString,
    detectors: &[Detector],
) -> Vec<bxmap::classifier::DetectedFinding> {
    let mut out = Vec::new();
    for det in detectors {
        match det {
            Detector::Ip => {
                if let Some((value, start, end)) = detected_ip_match(&result.text) {
                    let rule = if value.contains(':') { "IPV6" } else { "IPV4" };
                    push_finding(&mut out, result, rule, value, start, end);
                }
            }
            Detector::Url => {
                if let Some((value, start, end)) = detected_url_match(&result.text) {
                    push_finding(&mut out, result, "URL", value, start, end);
                }
            }
            Detector::Domain => {
                if let Some((value, start, end)) = detected_domain_match(&result.text) {
                    push_finding(&mut out, result, "DOMAIN", value, start, end);
                }
            }
            Detector::Base64 => {
                if let Some((value, start, end)) = detect_and_decode_base64_match(&result.text) {
                    push_finding(&mut out, result, "BASE64_DECODED", value, start, end);
                }
            }
            Detector::Secret => {
                for finding in bxmap::classifier::detect_secrets_detailed(&result.text) {
                    out.push(bxmap::classifier::DetectedFinding {
                        offset: result.offset,
                        encoding: result.encoding,
                        rule: finding.rule,
                        value: finding.value,
                        text: result.text.clone(),
                        context: bxmap::classifier::context_around(
                            &result.text,
                            finding.start,
                            finding.end,
                            32,
                        ),
                        confidence: finding.confidence,
                        severity: finding.severity,
                    });
                }
            }
        }
    }
    out
}

#[derive(Clone)]
struct MagicMatch {
    offset: u64,
    kind: &'static str,
}

fn scan_magic_bytes(path: &str) -> io::Result<Vec<MagicMatch>> {
    let mut reader = BufReader::with_capacity(1 << 16, File::open(path)?);
    let signatures: &[(&[u8], &str)] = &[
        (b"MZ", "PE/DOS executable"),
        (b"\x7fELF", "ELF executable"),
        (b"PK\x03\x04", "ZIP/Office archive"),
        (b"%PDF-", "PDF document"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
    ];
    let mut matches = Vec::new();
    let mut buffer = Vec::with_capacity((1 << 16) + 16);
    let mut chunk = vec![0u8; 1 << 16];
    let mut offset = 0u64;
    loop {
        let previous = buffer.len().min(16);
        if buffer.len() > previous {
            buffer.drain(..buffer.len() - previous);
        }
        let start = offset.saturating_sub(previous as u64);
        let read = reader.read(&mut chunk)?;
        buffer.extend_from_slice(&chunk[..read]);
        for (signature, kind) in signatures {
            for (index, window) in buffer.windows(signature.len()).enumerate() {
                if index + signature.len() > previous && window == *signature {
                    matches.push(MagicMatch {
                        offset: start + index as u64,
                        kind,
                    });
                    if matches.len() >= 256 {
                        matches.sort_by_key(|item| item.offset);
                        return Ok(matches);
                    }
                }
            }
        }
        offset += read as u64;
        if read == 0 {
            break;
        }
    }
    matches.sort_by_key(|item| item.offset);
    Ok(matches)
}

fn write_entropy_json(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"Undefined\",\"offset\":{},\"length\":{},\"entropy\":{:.6},\"data_hex\":{}}}",
        region.offset,
        region.length,
        region.entropy,
        json_escape(&hex_encode(data))
    )?;
    *result_count += 1;
    Ok(())
}

fn write_entropy_text(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tUndefined\tlength={}\tentropy={:.6}\tdata_hex={}",
        region.offset,
        region.length,
        region.entropy,
        hex_encode(data)
    )
}

fn write_yara_text(rule: &bxmap::YaraMatch, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tYARA\t{}::{}",
        rule.offset, rule.namespace, rule.rule
    )
}

fn write_yara_json(
    rule: &bxmap::YaraMatch,
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"YARA\",\"offset\":{},\"namespace\":{},\"rule\":{}}}",
        rule.offset,
        json_escape(&rule.namespace),
        json_escape(&rule.rule)
    )?;
    *result_count += 1;
    Ok(())
}

fn write_magic_text(magic: &MagicMatch, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "{:#010x}\tMAGIC\t{}", magic.offset, magic.kind)
}

fn write_magic_json(
    magic: &MagicMatch,
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"MAGIC\",\"offset\":{},\"kind\":{}}}",
        magic.offset,
        json_escape(magic.kind)
    )?;
    *result_count += 1;
    Ok(())
}

#[derive(Clone)]
struct XorResult {
    offset: u64,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    score: f64,
}

fn refang_ioc_text(text: &str) -> String {
    static BRACKET_DOT: OnceLock<Regex> = OnceLock::new();
    static BRACKET_AT: OnceLock<Regex> = OnceLock::new();
    static WORD_DOT: OnceLock<Regex> = OnceLock::new();
    static WORD_AT: OnceLock<Regex> = OnceLock::new();
    let text = BRACKET_DOT
        .get_or_init(|| Regex::new(r"\s*[\[\(]\s*\.\s*[\]\)]\s*").unwrap())
        .replace_all(text, ".");
    let text = BRACKET_AT
        .get_or_init(|| Regex::new(r"(?i)\s*[\[\(]\s*at\s*[\]\)]\s*").unwrap())
        .replace_all(&text, "@");
    let text = WORD_DOT
        .get_or_init(|| Regex::new(r"(?i)\s+dot\s+").unwrap())
        .replace_all(&text, ".");
    WORD_AT
        .get_or_init(|| Regex::new(r"(?i)\s+at\s+").unwrap())
        .replace_all(&text, "@")
        .into_owned()
}

fn is_public_ipv4(value: &str) -> bool {
    let ip = value.split(':').next().unwrap_or(value);
    let Ok(address) = ip.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let octets = address.octets();
    let is_shared = octets[0] == 100 && (64..=127).contains(&octets[1]);
    let is_benchmark = octets[0] == 198 && (18..=19).contains(&octets[1]);
    let is_documentation = (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113);
    !address.is_private()
        && !address.is_loopback()
        && !address.is_link_local()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !address.is_broadcast()
        && !is_shared
        && !is_benchmark
        && !is_documentation
}

fn contains_public_ip(text: &str) -> bool {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let regex = IPV4.get_or_init(|| {
        Regex::new(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b",
        )
        .unwrap()
    });
    regex
        .find_iter(text)
        .any(|matched| is_public_ipv4(matched.as_str()))
}

fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[byte as usize] += 1;
    }
    let length = text.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn is_repetitive_noise(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 10 {
        return false;
    }
    let mut counts = [0usize; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let max_count = counts.iter().copied().max().unwrap_or(0);
    let distinct = counts.iter().filter(|&&count| count > 0).count();
    bytes.iter().filter(|&&byte| byte == b'?').count() * 5 >= bytes.len()
        || max_count * 100 >= bytes.len() * 65
        || distinct <= 3
}

fn contains_meaningful_base64(text: &str) -> bool {
    static BASE64: OnceLock<Regex> = OnceLock::new();
    let regex = BASE64.get_or_init(|| {
        Regex::new(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap()
    });
    let bytes = text.as_bytes();
    regex.find_iter(text).any(|matched| {
        let before_ok = matched.start() == 0
            || !bytes[matched.start() - 1].is_ascii_alphanumeric()
                && !matches!(bytes[matched.start() - 1], b'+' | b'/' | b'=');
        let after_ok = matched.end() == bytes.len()
            || !bytes[matched.end()].is_ascii_alphanumeric()
                && !matches!(bytes[matched.end()], b'+' | b'/' | b'=');
        let value = matched.as_str();
        before_ok
            && after_ok
            && shannon_entropy(value) >= 2.5
            && value.bytes().any(|byte| byte.is_ascii_digit())
    })
}

fn xor_printable_score(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let printable = data
        .iter()
        .filter(|&&byte| {
            (32..=126).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
        })
        .count();
    let alphanumeric = data
        .iter()
        .filter(|&&byte| byte.is_ascii_alphanumeric())
        .count();
    let question_marks = data.iter().filter(|&&byte| byte == b'?').count();
    if alphanumeric < MIN_XOR_ALNUM_CHARS
        || (alphanumeric as f64 / data.len() as f64) < 0.2
        || (question_marks as f64 / data.len() as f64) > 0.1
    {
        return 0.0;
    }
    let text = String::from_utf8_lossy(data).to_ascii_lowercase();
    let mut score = printable as f64 / data.len() as f64;
    if std::str::from_utf8(data).is_ok() {
        score += 0.15;
    }
    for keyword in ["http", "www", ".exe", ".dll", "virtual", "create", "thread"] {
        if text.contains(keyword) {
            score += 0.25;
        }
    }
    score
}

fn xor_top_results(candidate: &[u8], offset: u64, key_size: usize) -> Vec<XorResult> {
    let key_count = 1usize << (key_size * 8);
    let mut top = Vec::with_capacity(MAX_XOR_RESULTS_PER_CANDIDATE);
    for value in 0..key_count {
        let mut key = vec![0u8; key_size];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = ((value >> (index * 8)) & 0xff) as u8;
        }
        let plaintext: Vec<u8> = candidate
            .iter()
            .enumerate()
            .map(|(index, &byte)| byte ^ key[index % key_size])
            .collect();
        let result = XorResult {
            offset,
            key,
            score: xor_printable_score(&plaintext),
            plaintext,
        };
        if result.score == 0.0 {
            continue;
        }
        let position = top
            .iter()
            .position(|item: &XorResult| result.score > item.score)
            .unwrap_or(top.len());
        top.insert(position, result);
        if top.len() > MAX_XOR_RESULTS_PER_CANDIDATE {
            top.pop();
        }
    }
    top
}

fn collect_xor_candidates(path: &str) -> io::Result<Vec<(u64, Vec<u8>)>> {
    let mut reader = BufReader::with_capacity(1 << 16, File::open(path)?);
    let mut byte = [0u8; 1];
    let mut run = Vec::new();
    let mut run_offset = 0u64;
    let mut offset = 0u64;
    let mut candidates = Vec::new();
    loop {
        let read = reader.read(&mut byte)?;
        if read == 0 {
            break;
        }
        if byte[0] == 0 {
            append_xor_candidates(&mut candidates, run_offset, &run);
            run.clear();
        } else {
            if run.is_empty() {
                run_offset = offset;
            }
            run.push(byte[0]);
        }
        offset += 1;
        if candidates.len() >= MAX_XOR_CANDIDATES {
            break;
        }
    }
    if candidates.len() < MAX_XOR_CANDIDATES {
        append_xor_candidates(&mut candidates, run_offset, &run);
    }
    candidates.truncate(MAX_XOR_CANDIDATES);
    Ok(candidates)
}

fn append_xor_candidates(candidates: &mut Vec<(u64, Vec<u8>)>, offset: u64, data: &[u8]) {
    if data.len() < MIN_XOR_CANDIDATE_LEN {
        return;
    }
    for (index, chunk) in data.chunks(MAX_XOR_CANDIDATE_LEN).enumerate() {
        if chunk.len() >= MIN_XOR_CANDIDATE_LEN
            && !chunk.windows(2).all(|window| window[0] == window[1])
            && !chunk
                .windows(3)
                .all(|window| window[0] == window[2] && window[0] != window[1])
        {
            candidates.push((
                offset + (index * MAX_XOR_CANDIDATE_LEN) as u64,
                chunk.to_vec(),
            ));
            if candidates.len() >= MAX_XOR_CANDIDATES {
                return;
            }
        }
    }
}

fn write_xor_text(result: &XorResult, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tXOR\tkey={}\tscore={:.3}\t{}",
        result.offset,
        hex_encode(&result.key),
        result.score,
        String::from_utf8_lossy(&result.plaintext)
    )
}

fn write_xor_json(
    result: &XorResult,
    writer: &mut dyn Write,
    result_count: &mut usize,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"group\":\"XOR\",\"offset\":{},\"key\":{},\"score\":{:.6},\"plaintext\":{}}}",
        result.offset,
        json_escape(&hex_encode(&result.key)),
        result.score,
        json_escape(&String::from_utf8_lossy(&result.plaintext))
    )?;
    *result_count += 1;
    Ok(())
}

fn write_string_json(
    result: &ExtractedString,
    writer: &mut dyn Write,
    result_count: &mut usize,
    parse_pid: bool,
) -> io::Result<()> {
    if *result_count > 0 {
        write!(writer, ",\n")?;
    }
    write!(
        writer,
        "  {{\"offset\":{},\"encoding\":{},\"text\":{}",
        result.offset,
        json_escape(result.encoding),
        json_escape(&result.text)
    )?;
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

fn parse_pid_marker(text: &str) -> Option<u32> {
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

fn important_reason(text: &str) -> Option<&'static str> {
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

fn is_email_address(text: &str) -> bool {
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

fn contains_credential_marker(text: &str) -> bool {
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
fn has_c2_token(lower: &str) -> bool {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| token == "c2")
}

/// A JWT-shaped value: three dot-separated base64url segments starting with `eyJ`.
/// The bare word "jwt" next to random text is not a credential signal.
fn contains_jwt_shape(text: &str) -> bool {
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

fn contains_crypto_address(text: &str) -> bool {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(is_crypto_address)
}

fn is_crypto_address(token: &str) -> bool {
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
        let findings = super::detect_findings(&result, &[super::Detector::Secret]);
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
        let findings = super::detect_findings(&result, &[super::Detector::Ip]);
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

fn print_banner(path: &str, size: u64, format: Format) {
    if !io::stderr().is_terminal() {
        return;
    }
    let format = match format {
        Format::Text => "text",
        Format::Json => "json",
        Format::JsonTree => "json-tree",
    };
    eprintln!("\x1b[1;36m+------------------------------------------------------------+\x1b[0m");
    eprintln!(
        "\x1b[1;36m|  \x1b[1;37mBXMAP\x1b[1;36m  |  memory-dump string triage                  |\x1b[0m"
    );
    eprintln!("\x1b[1;36m+------------------------------------------------------------+\x1b[0m");
    eprintln!("  input      : {path}");
    eprintln!("  size/format: {size} bytes / {format}");
    eprintln!("  \x1b[1;34m[..] scanning\x1b[0m");
}

/// Print a truncation warning when the result limit stopped the scan early.
///
/// `last_absolute` is the absolute offset of the last emitted string and
/// `range_start`/`span` describe the scanned window (the whole file when no
/// `--start`/`--end` was given).
fn print_truncation_notice(max_strings: usize, last_absolute: u64, range_start: u64, span: u64) {
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
fn hit_result_limit(result_count: usize, max_strings: usize) -> bool {
    max_strings != usize::MAX && result_count > max_strings
}

fn print_report(
    result_count: usize,
    short: usize,
    medium: usize,
    long: usize,
    important: &[ExtractedString],
    entropy_regions: &[EntropyRegion],
    size: u64,
    elapsed: f64,
    threads: usize,
) {
    let color = io::stderr().is_terminal();
    if color {
        eprintln!("\x1b[1;32m  [OK] scan complete\x1b[0m");
        eprintln!("\x1b[1;36m+-------------------- summary -----------------------------+\x1b[0m");
    } else {
        eprintln!("  [OK] scan complete");
        eprintln!("+-------------------- summary -----------------------------+");
    }
    eprintln!("  results    : {result_count}");
    eprintln!("  length     : {short} short | {medium} medium | {long} long");
    eprintln!("  threads    : {threads}");
    eprintln!("  file size  : {size} bytes");
    eprintln!("  elapsed    : {:.3} ms", elapsed * 1000.0);
    eprintln!(
        "  throughput : {:.2} MiB/s",
        size as f64 / elapsed.max(f64::MIN_POSITIVE) / 1_048_576.0
    );
    eprintln!("+------------------------------------------------------------+");
    if !important.is_empty() {
        eprintln!("  [!] priority findings (up to 12)");
        for result in important {
            let reason = important_reason(&result.text).unwrap_or("interesting");
            eprintln!(
                "      - {:<12} | offset {:#010x} | {:<7} | {}",
                reason, result.offset, result.encoding, result.text
            );
        }
    }
    if !entropy_regions.is_empty() {
        eprintln!("  [!] high-entropy regions (showing up to 12)");
        for region in entropy_regions {
            eprintln!(
                "      offset {:#010x}  {:>6} bytes  entropy {:.3}/8.000",
                region.offset, region.length, region.entropy
            );
        }
    }
}

fn display_text(text: &str, max_str_len: usize) -> String {
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

fn update_stats(
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

fn record_result(
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
            if parse_pid {
                match parse_pid_marker(&result.text) {
                    Some(pid) => write!(writer, "\tpid={pid}")?,
                    None => write!(writer, "\tpid=-")?,
                }
            }
            writeln!(writer)?;
        }
        Format::Json => {
            write_string_json(&result, writer, result_count, parse_pid)?;
        }
        Format::JsonTree => {
            // handled separately in main(); no-op here
        }
    }
    *result_count += 1;
    update_stats(&result, short, medium, long, important);
    Ok(())
}

fn record_finding(
    finding: &bxmap::classifier::DetectedFinding,
    writer: &mut dyn Write,
    format: Format,
    result_count: &mut usize,
    max_str_len: usize,
) -> io::Result<()> {
    match format {
        Format::Text => {
            writeln!(
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
        }
        Format::Json => {
            if *result_count > 0 {
                write!(writer, ",\n")?;
            }
            write!(
                writer,
                "  {{\"offset\":{},\"encoding\":{},\"rule\":{},\"value\":{},\"confidence\":{:.4},\"severity\":{},\"context\":{},\"text\":{}}}",
                finding.offset,
                json_escape(finding.encoding),
                json_escape(finding.rule),
                json_escape(&finding.value),
                finding.confidence,
                json_escape(finding.severity),
                json_escape(&finding.context),
                json_escape(&finding.text)
            )?;
        }
        Format::JsonTree => {
            // rejected during argument validation
        }
    }
    *result_count += 1;
    Ok(())
}

fn write_results(
    results: &[ExtractedString],
    format: Format,
    writer: &mut dyn Write,
    parse_pid: bool,
    max_str_len: usize,
) -> io::Result<()> {
    match format {
        Format::Text => {
            for result in results {
                write!(
                    writer,
                    "{:#010x}\t{}\t{}",
                    result.offset,
                    result.encoding,
                    display_text(&result.text, max_str_len)
                )?;
                if parse_pid {
                    match parse_pid_marker(&result.text) {
                        Some(pid) => write!(writer, "\tpid={pid}")?,
                        None => write!(writer, "\tpid=-")?,
                    }
                }
                if DUMP_MAP.get().is_some() {
                    match va_annotation(result.offset) {
                        Some((va, label)) => write!(writer, "\tva={va:#x}\t{label}")?,
                        None => write!(writer, "\tva=-\t-")?,
                    }
                }
                writeln!(writer)?;
            }
        }
        Format::Json => {
            writeln!(writer, "[")?;
            let mut result_count = 0;
            for result in results {
                write_string_json(result, writer, &mut result_count, parse_pid)?;
            }
            writeln!(writer, "]")?;
        }
        Format::JsonTree => {}
    }
    Ok(())
}

#[cfg(test)]
mod extra_detector_tests {
    use super::*;

    #[test]
    fn detector_helpers_do_not_panic_on_random_input() {
        let mut state = 0xdeadbeefu64;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let mut s = String::new();
            for _ in 0..(state % 96) {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let c = (state & 0x7f) as u8;
                let c = if c < 0x20 {
                    (c + 0x20) as char
                } else {
                    c as char
                };
                s.push(c);
            }
            let _ = important_reason(&s);
            let _ = detected_ip_value(&s);
            let _ = detected_url_value(&s);
            let _ = detected_domain_value(&s);
            let _ = detect_and_decode_base64(&s);
            let _ = bxmap::classifier::detect_secrets(&s);
            let _ = bxmap::classifier::detect_secrets_detailed(&s);
            let result = ExtractedString {
                offset: 0,
                encoding: "ascii",
                text: s,
            };
            let _ = detect_findings(
                &result,
                &[
                    Detector::Ip,
                    Detector::Url,
                    Detector::Domain,
                    Detector::Base64,
                    Detector::Secret,
                ],
            );
        }
    }
}

fn main() -> Result<(), String> {
    let args = parse_args()?;
    if args.vmware_info {
        let state = bxmap::vmware::VmwareState::open(&args.path)
            .map_err(|e| format!("cannot parse VMware state '{}': {e}", args.path))?;
        print!("{}", state.render_info());
        return Ok(());
    }
    if args.tree {
        let dump = bxmap::minidump::Minidump::open(&args.path)
            .map_err(|e| format!("cannot parse minidump '{}': {e}", args.path))?;
        print!("{}", dump.render_tree(30));
        return Ok(());
    }
    if args.map_va
        || args.in_module.is_some()
        || args.rwx_only
        || args.heap_only
        || args.path.to_ascii_lowercase().ends_with(".mdmp")
        || args.path.to_ascii_lowercase().ends_with(".hdmp")
        || args.path.to_ascii_lowercase().ends_with(".dmp")
    {
        if let Ok(dump) = bxmap::minidump::Minidump::open(&args.path) {
            let _ = DUMP_MAP.set(dump);
        }
    }
    let filter_regex = args
        .filter_regex
        .as_deref()
        .map(Regex::new)
        .transpose()
        .map_err(|error| format!("invalid --filter-regex: {error}"))?;
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
    let file_size = std::fs::metadata(&args.path)
        .map_err(|e| format!("cannot inspect '{}': {e}", args.path))?
        .len();
    let range_active = args.start.is_some() || args.end.is_some();
    let range_start = args.start.unwrap_or(0);
    let range_end = args.end.unwrap_or(file_size);
    if range_active && range_start >= file_size {
        return Err(format!(
            "--start ({range_start:#x}) is beyond the end of the input ({file_size:#x})"
        ));
    }
    if range_start >= range_end {
        return Err(format!(
            "--start ({range_start:#x}) must be less than --end ({range_end:#x})"
        ));
    }
    let range_end = range_end.min(file_size);
    let scan_span = range_end.saturating_sub(range_start);
    let show_progress = args.progress.unwrap_or_else(|| {
        io::stderr().is_terminal() && (args.output.is_some() || !io::stdout().is_terminal())
    });
    // Ask the scanner for one extra result so we can tell "hit the cap" from
    // "finished the file at exactly the cap".
    let internal_limit = args.max_strings.saturating_add(1);
    print_banner(&args.path, file_size, args.format);
    let threads = if args.auto_tune {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if cpus <= 2 {
            1
        } else {
            std::cmp::max(1, std::cmp::min(cpus - 1, cpus * 3 / 4))
        }
    } else {
        args.threads
    };
    let noise = args
        .noise_threshold
        .map(NoiseConfig::from_threshold)
        .unwrap_or_default();
    let enc_filter = match args.encoding {
        Encoding::All => EncodingFilter::all(),
        Encoding::Ascii => EncodingFilter::ascii(),
        Encoding::Utf16 => EncodingFilter::utf16(),
        Encoding::Utf32 => EncodingFilter::utf32(),
    };
    let magic_matches = if args.magic_bytes {
        scan_magic_bytes(&args.path).map_err(|error| format!("magic-byte scan failed: {error}"))?
    } else {
        Vec::new()
    };
    let start = Instant::now();
    let mut entropy_regions = Vec::new();
    if args.entropy {
        scan_entropy_from_file_streaming_with_data(&args.path, ENTROPY_THRESHOLD, |region, _| {
            if entropy_regions.len() < MAX_ENTROPY_REPORTS {
                entropy_regions.push(region);
            }
        })
        .map_err(|e| format!("entropy scan failed: {e}"))?;
    }
    let mut yara_matches = Vec::new();
    if let Some(rules_path) = args.yar.as_ref() {
        scan_yara_from_file_streaming(&args.path, rules_path, |matched| {
            yara_matches.push(matched);
        })
        .map_err(|e| format!("YARA scan failed: {e}"))?;
    }
    let mut xor_results = Vec::new();
    if let Some(key_sizes) = args.brute_xor.as_ref() {
        let candidates = collect_xor_candidates(&args.path)
            .map_err(|e| format!("XOR candidate scan failed: {e}"))?;
        for (offset, candidate) in candidates {
            let mut candidate_results = Vec::new();
            for &key_size in key_sizes {
                candidate_results.extend(xor_top_results(&candidate, offset, key_size));
            }
            candidate_results.sort_by(|left, right| {
                right
                    .score
                    .partial_cmp(&left.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            candidate_results.truncate(MAX_XOR_RESULTS_PER_CANDIDATE);
            xor_results.extend(candidate_results);
        }
        xor_results.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }
    if (threads == 1 || range_active) && args.format != Format::JsonTree {
        let mut writer: Box<dyn Write> = match args.output.as_ref() {
            Some(path) => Box::new(BufWriter::new(
                File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?,
            )),
            None => Box::new(BufWriter::new(io::stdout().lock())),
        };
        if args.format == Format::Json {
            write!(writer, "[\n").map_err(|e| format!("write failed: {e}"))?;
        }
        let mut result_count = 0;
        let mut short = 0;
        let mut medium = 0;
        let mut long = 0;
        let mut important = Vec::new();
        let mut write_error = None;
        let mut last_offset = 0u64;
        let mut raw_count = 0usize;
        let mut truncated = false;
        let progress_results = std::cell::Cell::new(0usize);
        let mut handle = |result: ExtractedString| {
            if write_error.is_some() {
                return;
            }
            raw_count += 1;
            progress_results.set(raw_count);
            if raw_count > args.max_strings {
                truncated = true;
                return;
            }
            last_offset = last_offset.max(result.offset);
            if matches!(args.encoding, Encoding::All)
                || (args.encoding == Encoding::Ascii && result.encoding == "ascii")
                || (args.encoding == Encoding::Utf16
                    && (result.encoding == "utf16le" || result.encoding == "utf16be"))
                || (args.encoding == Encoding::Utf32
                    && (result.encoding == "utf32le" || result.encoding == "utf32be"))
            {
                if args.detect_format == DetectFormat::Rich {
                    let findings = detect_findings(&result, &args.detectors);
                    for finding in &findings {
                        if let Err(error) = record_finding(
                            finding,
                            &mut writer,
                            args.format,
                            &mut result_count,
                            args.max_str_len,
                        ) {
                            write_error = Some(error);
                        }
                    }
                    update_stats(&result, &mut short, &mut medium, &mut long, &mut important);
                } else {
                    for result in apply_detectors(result, &args.detectors) {
                        if matches_filter(filter_regex.as_ref(), &result.text) {
                            if let Err(error) = record_result(
                                result,
                                &mut writer,
                                args.format,
                                &mut result_count,
                                &mut short,
                                &mut medium,
                                &mut long,
                                &mut important,
                                args.parse_pid,
                                args.max_str_len,
                            ) {
                                write_error = Some(error);
                            }
                        }
                    }
                }
            }
        };
        let mut last_progress = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut progress = |scanned: u64| {
            if !show_progress {
                return;
            }
            let now = Instant::now();
            if now.duration_since(last_progress) < Duration::from_millis(200) {
                return;
            }
            last_progress = now;
            let relative = scanned.saturating_sub(range_start);
            let pct = if scan_span == 0 {
                100.0
            } else {
                relative as f64 * 100.0 / scan_span as f64
            };
            let secs = now.duration_since(start).as_secs_f64().max(1e-9);
            let mib_s = relative as f64 / secs / (1024.0 * 1024.0);
            eprint!(
                "\r  [..] {pct:>6.1}%  {mib_s:>7.1} MiB/s  scanned {scanned:#x}  results {}          ",
                progress_results.get()
            );
        };
        let scan_result = extract_strings_from_file_streaming_range_with_encodings_progress(
            &args.path,
            range_start,
            range_end,
            args.min_len,
            internal_limit,
            noise,
            enc_filter,
            &mut handle,
            &mut progress,
        );
        scan_result.map_err(|e| format!("scan failed: {e}"))?;
        if show_progress {
            eprintln!();
        }
        if let Some(error) = write_error {
            return Err(format!("write failed: {error}"));
        }
        if args.format == Format::Json {
            let mut json_count = result_count;
            for matched in &yara_matches {
                write_yara_json(matched, &mut writer, &mut json_count)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            for result in &xor_results {
                if filter_regex.as_ref().map_or(true, |regex| {
                    regex.is_match(&String::from_utf8_lossy(&result.plaintext))
                }) {
                    write_xor_json(result, &mut writer, &mut json_count)
                        .map_err(|e| format!("write failed: {e}"))?;
                }
            }
            for magic in &magic_matches {
                write_magic_json(magic, &mut writer, &mut json_count)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            if args.entropy {
                scan_entropy_from_file_streaming_with_data(
                    &args.path,
                    ENTROPY_THRESHOLD,
                    |region, data| {
                        if write_error.is_none() {
                            if let Err(error) =
                                write_entropy_json(region, data, &mut writer, &mut json_count)
                            {
                                write_error = Some(error);
                            }
                        }
                    },
                )
                .map_err(|e| format!("entropy scan failed: {e}"))?;
            }
            if let Some(error) = write_error {
                return Err(format!("write failed: {error}"));
            }
            write!(writer, "\n]\n").map_err(|e| format!("write failed: {e}"))?;
        } else {
            for matched in &yara_matches {
                write_yara_text(matched, &mut writer).map_err(|e| format!("write failed: {e}"))?;
            }
            for result in &xor_results {
                if filter_regex.as_ref().map_or(true, |regex| {
                    regex.is_match(&String::from_utf8_lossy(&result.plaintext))
                }) {
                    write_xor_text(result, &mut writer)
                        .map_err(|e| format!("write failed: {e}"))?;
                }
            }
            for magic in &magic_matches {
                write_magic_text(magic, &mut writer).map_err(|e| format!("write failed: {e}"))?;
            }
            if args.entropy {
                scan_entropy_from_file_streaming_with_data(
                    &args.path,
                    ENTROPY_THRESHOLD,
                    |region, data| {
                        if write_error.is_none() {
                            if let Err(error) = write_entropy_text(region, data, &mut writer) {
                                write_error = Some(error);
                            }
                        }
                    },
                )
                .map_err(|e| format!("entropy scan failed: {e}"))?;
                if let Some(error) = write_error {
                    return Err(format!("write failed: {error}"));
                }
            }
        }
        writer.flush().map_err(|e| format!("write failed: {e}"))?;
        if let Some(path) = args.output {
            eprintln!("wrote {result_count} results to '{path}'");
        }
        print_report(
            result_count,
            short,
            medium,
            long,
            &important,
            &entropy_regions,
            file_size,
            start.elapsed().as_secs_f64(),
            threads,
        );
        if truncated {
            print_truncation_notice(args.max_strings, last_offset, range_start, scan_span);
            std::process::exit(3);
        }
        return Ok(());
    }

    let mut results = if range_active {
        // Ranges always use the sequential range scanner; collect into a Vec
        // because the json-tree / buffered paths need the full result set.
        let mut collected: Vec<ExtractedString> = Vec::new();
        extract_strings_from_file_streaming_range_with_encodings(
            &args.path,
            range_start,
            range_end,
            args.min_len,
            internal_limit,
            noise,
            enc_filter,
            |result| collected.push(result),
        )
        .map(|_| collected)
    } else if threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| format!("cannot create worker pool: {e}"))?;
        pool.install(|| {
            extract_strings_from_file_parallel_with_encodings(
                &args.path,
                args.min_len,
                internal_limit,
                noise,
                enc_filter,
            )
        })
    } else {
        extract_strings_from_file_with_noise_config_and_encodings(
            &args.path,
            args.min_len,
            internal_limit,
            noise,
            enc_filter,
        )
    }
    .map_err(|e| format!("scan failed: {e}"))?;
    let truncated = hit_result_limit(results.len(), args.max_strings);
    if truncated {
        // Drop the probe result that told us the cap was hit.
        results.truncate(args.max_strings);
    }
    let raw_results: Vec<ExtractedString> = results
        .into_iter()
        .filter(|result| match args.encoding {
            Encoding::All => true,
            Encoding::Ascii => result.encoding == "ascii",
            Encoding::Utf16 => result.encoding == "utf16le" || result.encoding == "utf16be",
            Encoding::Utf32 => result.encoding == "utf32le" || result.encoding == "utf32be",
        })
        .filter(|result| {
            passes_region_filter(
                result.offset,
                &args.in_module,
                args.rwx_only,
                args.heap_only,
            )
        })
        .collect();

    if args.detect_format == DetectFormat::Rich {
        let findings: Vec<bxmap::classifier::DetectedFinding> = raw_results
            .iter()
            .flat_map(|result| detect_findings(result, &args.detectors))
            .collect();
        let mut writer: Box<dyn Write> = match args.output.as_ref() {
            Some(path) => Box::new(BufWriter::new(
                File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?,
            )),
            None => Box::new(BufWriter::new(io::stdout().lock())),
        };
        if args.format == Format::Json {
            write!(writer, "[\n").map_err(|e| format!("write failed: {e}"))?;
        }
        let mut result_count = 0;
        for finding in &findings {
            record_finding(
                finding,
                &mut writer,
                args.format,
                &mut result_count,
                args.max_str_len,
            )
            .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.format == Format::Json {
            write!(writer, "\n]\n").map_err(|e| format!("write failed: {e}"))?;
        }
        writer.flush().map_err(|e| format!("write failed: {e}"))?;
        if let Some(path) = args.output {
            eprintln!("wrote {result_count} findings to '{path}'");
        }
        let mut short = 0;
        let mut medium = 0;
        let mut long = 0;
        let mut important = Vec::new();
        for result in &raw_results {
            update_stats(result, &mut short, &mut medium, &mut long, &mut important);
        }
        print_report(
            result_count,
            short,
            medium,
            long,
            &important,
            &entropy_regions,
            file_size,
            start.elapsed().as_secs_f64(),
            threads,
        );
        if truncated {
            let last_offset = raw_results.iter().map(|r| r.offset).max().unwrap_or(0);
            print_truncation_notice(args.max_strings, last_offset, range_start, scan_span);
            std::process::exit(3);
        }
        return Ok(());
    }

    let results: Vec<ExtractedString> = raw_results
        .into_iter()
        .flat_map(|result| apply_detectors(result, &args.detectors))
        .filter(|result| {
            filter_regex
                .as_ref()
                .map_or(true, |regex| regex.is_match(&result.text))
        })
        .collect();

    let output_path = args.output.clone();
    let mut writer: Box<dyn Write> = match output_path.as_ref() {
        Some(path) => Box::new(BufWriter::new(
            File::create(path).map_err(|e| format!("cannot create '{path}': {e}"))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    if args.format == Format::JsonTree {
        use std::collections::BTreeMap;
        let mut groups: BTreeMap<(String, String), Vec<&ExtractedString>> = BTreeMap::new();
        for r in &results {
            let cls = bxmap::classifier::classify(&r.text);
            let (g, t) = match cls {
                Some(c) => (c.group.to_string(), c.typ.to_string()),
                None => ("STRING".to_string(), "GENERIC".to_string()),
            };
            groups.entry((g, t)).or_default().push(r);
        }
        let mut out = String::from("{\"groups\":[\n");
        let mut first_group = true;
        for ((g, t), items) in &groups {
            if !first_group {
                out.push_str(",\n");
            }
            first_group = false;
            out.push_str(&format!(
                "  {{\"group\":{},\"type\":{},\"items\":[\n",
                json_escape(g),
                json_escape(t)
            ));
            let mut first_item = true;
            for r in items {
                if !first_item {
                    out.push_str(",\n");
                }
                first_item = false;
                let ent = bxmap::classifier::entropy_of(&r.text);
                let ts_part = if let Some(dump) = DUMP_MAP.get() {
                    if let Some(va) = dump.offset_to_va(r.offset) {
                        if let Some(m) = dump.module_for_va(va) {
                            format!(",\"timestamp\":{}", m.timestamp)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                out.push_str(&format!(
                    "    {{\"text\":{},\"offset\":{},\"entropy\":{:.4}{}}}",
                    json_escape(&r.text),
                    r.offset,
                    ent,
                    ts_part
                ));
            }
            out.push_str("\n  ]}");
        }
        let last_offset = results.iter().map(|r| r.offset).max().unwrap_or(0);
        out.push_str(&format!(
            "\n],\"metadata\":{{\"total_strings\":{},\"truncated\":{},\"scanned_until\":{}}}\n}}\n",
            results.len(),
            truncated,
            last_offset
        ));
        write!(writer, "{}", out).map_err(|e| format!("write failed: {e}"))?;
        writer.flush().map_err(|e| format!("write failed: {e}"))?;
        if let Some(path) = output_path.clone() {
            eprintln!("wrote {} results to '{}'", results.len(), path);
        }
        let _ = args.stats;
        print_report(
            results.len(),
            0,
            0,
            0,
            &[],
            &entropy_regions,
            file_size,
            start.elapsed().as_secs_f64(),
            threads,
        );
        if truncated {
            print_truncation_notice(args.max_strings, last_offset, range_start, scan_span);
            std::process::exit(3);
        }
        return Ok(());
    }
    if args.format == Format::Json {
        write!(writer, "[\n").map_err(|e| format!("write failed: {e}"))?;
        let mut json_count = 0;
        for result in &results {
            write_string_json(result, &mut writer, &mut json_count, args.parse_pid)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for matched in &yara_matches {
            write_yara_json(matched, &mut writer, &mut json_count)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &xor_results {
            if filter_regex.as_ref().map_or(true, |regex| {
                regex.is_match(&String::from_utf8_lossy(&result.plaintext))
            }) {
                write_xor_json(result, &mut writer, &mut json_count)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &magic_matches {
            write_magic_json(magic, &mut writer, &mut json_count)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy {
            let mut entropy_write_error = None;
            scan_entropy_from_file_streaming_with_data(
                &args.path,
                ENTROPY_THRESHOLD,
                |region, data| {
                    if entropy_write_error.is_none() {
                        if let Err(error) =
                            write_entropy_json(region, data, &mut writer, &mut json_count)
                        {
                            entropy_write_error = Some(error);
                        }
                    }
                },
            )
            .map_err(|e| format!("entropy scan failed: {e}"))?;
            if let Some(error) = entropy_write_error {
                return Err(format!("write failed: {error}"));
            }
        }
        writeln!(writer, "\n]").map_err(|e| format!("write failed: {e}"))?;
    } else {
        write_results(
            &results,
            args.format,
            &mut writer,
            args.parse_pid,
            args.max_str_len,
        )
        .map_err(|e| format!("write failed: {e}"))?;
        for matched in &yara_matches {
            write_yara_text(matched, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &xor_results {
            if filter_regex.as_ref().map_or(true, |regex| {
                regex.is_match(&String::from_utf8_lossy(&result.plaintext))
            }) {
                write_xor_text(result, &mut writer).map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &magic_matches {
            write_magic_text(magic, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy && args.format == Format::Text {
            let mut entropy_write_error = None;
            scan_entropy_from_file_streaming_with_data(
                &args.path,
                ENTROPY_THRESHOLD,
                |region, data| {
                    if entropy_write_error.is_none() {
                        if let Err(error) = write_entropy_text(region, data, &mut writer) {
                            entropy_write_error = Some(error);
                        }
                    }
                },
            )
            .map_err(|e| format!("entropy scan failed: {e}"))?;
            if let Some(error) = entropy_write_error {
                return Err(format!("write failed: {error}"));
            }
        }
    }
    writer.flush().map_err(|e| format!("write failed: {e}"))?;
    if let Some(path) = output_path {
        eprintln!("wrote {} results to '{path}'", results.len());
    }
    let _ = args.stats;
    let mut short = 0;
    let mut medium = 0;
    let mut long = 0;
    let mut important = Vec::new();
    for result in &results {
        match result.text.chars().count() {
            0..=7 => short += 1,
            8..=31 => medium += 1,
            _ => long += 1,
        }
        if important.len() < 12 && important_reason(&result.text).is_some() {
            important.push(result.clone());
        }
    }
    print_report(
        results.len(),
        short,
        medium,
        long,
        &important,
        &entropy_regions,
        file_size,
        start.elapsed().as_secs_f64(),
        threads,
    );
    if truncated {
        let last_offset = results.iter().map(|r| r.offset).max().unwrap_or(0);
        print_truncation_notice(args.max_strings, last_offset, range_start, scan_span);
        std::process::exit(3);
    }
    Ok(())
}
