use super::*;
use bxmap::keys;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::sync::OnceLock;

pub fn write_entropy_json(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
    include_data: bool,
    data_truncated: bool,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("entropy"))?;
    write!(
        writer,
        "\"group\":\"Undefined\",\"offset\":{},\"length\":{},\"entropy\":{:.6}",
        region.offset, region.length, region.entropy
    )?;
    if include_data {
        write!(writer, ",\"data_hex\":{}", json_escape(&hex_encode(data)))?;
        if data_truncated {
            write!(writer, ",\"data_truncated\":true")?;
        }
    }
    write!(writer, "}}")?;
    *result_count += 1;
    Ok(())
}

pub fn write_entropy_text(
    region: EntropyRegion,
    data: &[u8],
    writer: &mut dyn Write,
    include_data: bool,
    data_truncated: bool,
) -> io::Result<()> {
    write!(
        writer,
        "{:#010x}\tUndefined\tlength={}\tentropy={:.6}",
        region.offset, region.length, region.entropy
    )?;
    if include_data {
        write!(writer, "\tdata_hex={}", hex_encode(data))?;
        if data_truncated {
            write!(writer, "\tdata_truncated=1")?;
        }
    }
    writeln!(writer)
}

pub fn write_yara_text(rule: &bxmap::YaraMatch, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(
        writer,
        "{:#010x}\tYARA\t{}::{}",
        rule.offset, rule.namespace, rule.rule
    )
}

pub fn write_yara_json(
    rule: &bxmap::YaraMatch,
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("yara"))?;
    write!(
        writer,
        "\"group\":\"YARA\",\"offset\":{},\"namespace\":{},\"rule\":{},\"matches\":[",
        rule.offset,
        json_escape(&rule.namespace),
        json_escape(&rule.rule)
    )?;
    for (i, hit) in rule.matches.iter().enumerate() {
        if i > 0 {
            write!(writer, ",")?;
        }
        write!(
            writer,
            "{{\"pattern\":{},\"offset\":{},\"length\":{}}}",
            json_escape(&hit.pattern),
            hit.offset,
            hit.length
        )?;
    }
    write!(writer, "]}}")?;
    *result_count += 1;
    Ok(())
}

pub fn write_magic_text(magic: &MagicMatch, writer: &mut dyn Write) -> io::Result<()> {
    writeln!(writer, "{:#010x}\tMAGIC\t{}", magic.offset, magic.kind)
}

pub fn write_magic_json(
    magic: &MagicMatch,
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("magic"))?;
    write!(
        writer,
        "\"group\":\"MAGIC\",\"offset\":{},\"kind\":{}}}",
        magic.offset,
        json_escape(magic.kind)
    )?;
    *result_count += 1;
    Ok(())
}

pub fn write_key_text(candidate: &keys::KeyCandidate, writer: &mut dyn Write) -> io::Result<()> {
    write!(
        writer,
        "{:#010x}\tKEY\t{}\talgorithm={}\tlength={}\tfingerprint={}",
        candidate.offset,
        candidate.kind,
        candidate.algorithm,
        candidate.length,
        candidate.fingerprint
    )?;
    if let Some(container) = candidate.container {
        write!(writer, "\tcontainer={container}")?;
    }
    writeln!(writer)
}

pub fn write_key_json(
    candidate: &keys::KeyCandidate,
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("key"))?;
    write!(
        writer,
        "\"group\":\"KEY\",\"offset\":{},\"kind\":{},\"algorithm\":{},\"length\":{},\"fingerprint\":{}}}",
        candidate.offset,
        json_escape(candidate.kind),
        json_escape(&candidate.algorithm),
        candidate.length,
        json_escape(&candidate.fingerprint)
    )?;
    if let Some(container) = candidate.container {
        write!(writer, ",\"container\":{}", json_escape(container))?;
    }
    write!(writer, "}}")?;
    *result_count += 1;
    Ok(())
}

/// Collect artifacts from an already-materialised result list.
pub fn collect_artifacts<'a, I>(kinds: ArtifactKinds, results: I) -> Vec<Artifact>
where
    I: IntoIterator<Item = &'a ExtractedString>,
{
    if kinds.is_empty() {
        return Vec::new();
    }
    let mut collector = ArtifactCollector::new(kinds, MAX_ARTIFACTS);
    for result in results {
        collector.observe(&result.text, result.offset);
    }
    collector.finish()
}

pub fn write_artifact_text(artifact: &Artifact, writer: &mut dyn Write) -> io::Result<()> {
    write!(
        writer,
        "{:#010x}\tARTIFACT\t{}\tcount={}\t{}",
        artifact.offset,
        artifact.kind.as_str(),
        artifact.count,
        artifact.value
    )?;
    if let Some(detail) = &artifact.detail {
        write!(writer, "\t{detail}")?;
    }
    writeln!(writer)
}

pub fn write_artifact_json(
    artifact: &Artifact,
    writer: &mut dyn Write,
    result_count: &mut usize,
    layout: JsonLayout,
) -> io::Result<()> {
    json_record_open(writer, result_count, layout, Some("artifact"))?;
    write!(
        writer,
        "\"group\":\"ARTIFACT\",\"kind\":{},\"value\":{},\"offset\":{},\"count\":{}",
        json_escape(artifact.kind.as_str()),
        json_escape(&artifact.value),
        artifact.offset,
        artifact.count
    )?;
    if let Some(detail) = &artifact.detail {
        write!(writer, ",\"detail\":{}", json_escape(detail))?;
    }
    write!(writer, "}}")?;
    *result_count += 1;
    Ok(())
}

/// Artifact rows reuse the fixed CSV header: `text` holds the artifact value,
/// `rule` the artifact kind and `context` the optional detail string.
pub fn write_artifact_csv_row(artifact: &Artifact, writer: &mut dyn Write) -> io::Result<()> {
    let offset = format!("{:#010x}", artifact.offset);
    let count = artifact.count.to_string();
    let detail = artifact.detail.as_deref().unwrap_or("");
    write_csv_row(
        writer,
        &[
            "artifact",
            &offset,
            "",
            &artifact.value,
            artifact.kind.as_str(),
            "",
            "",
            "",
            detail,
            &count,
            "",
        ],
    )
}

/// Append artifacts in the format-specific shape. JSON needs the shared record
/// counter so `total_records` in the trailing metadata stays accurate.
pub fn write_artifacts(
    artifacts: &[Artifact],
    writer: &mut dyn Write,
    format: Format,
    layout: JsonLayout,
    result_count: &mut usize,
) -> io::Result<()> {
    match format {
        Format::Json | Format::Ndjson => {
            for artifact in artifacts {
                write_artifact_json(artifact, writer, result_count, layout)?;
            }
        }
        Format::Csv => {
            for artifact in artifacts {
                write_artifact_csv_row(artifact, writer)?;
            }
        }
        Format::Text | Format::JsonTree => {
            for artifact in artifacts {
                write_artifact_text(artifact, writer)?;
            }
        }
        Format::Html | Format::Markdown => {
            // Handled in write_report_html_markdown
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct XorResult {
    pub offset: u64,
    pub key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub score: f64,
}

pub fn refang_ioc_text(text: &str) -> String {
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

pub fn is_public_ipv4(value: &str) -> bool {
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

pub fn contains_public_ip(text: &str) -> bool {
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

pub fn shannon_entropy(text: &str) -> f64 {
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

pub fn is_repetitive_noise(text: &str) -> bool {
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

pub fn contains_meaningful_base64(text: &str) -> bool {
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

pub fn xor_printable_score(data: &[u8]) -> f64 {
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

/// Known-plaintext cribs. A decrypted candidate containing one of these is
/// far more likely to be real code/text than random printable junk, so a hit
/// boosts the score and lets a wrong key be dropped early.
pub const XOR_CRIBS: [&[u8]; 8] = [
    b"MZ",
    b"This program cannot be run",
    b"http://",
    b"https://",
    b".dll",
    b"PK\x03\x04",
    b"<?xml",
    b"SELECT ",
];

/// How many of the most frequent ciphertext bytes per key position are tried
/// when the key space is too large to enumerate (key size >= 3), each XORed
/// with the plaintext bytes that usually dominate a column of real text.
pub const XOR_TOP_CIPHER_BYTES: usize = 3;
/// Plaintext bytes that tend to be the most common in a column of real text:
/// space, NUL (binary/UTF-16 padding), and the usual English letters.
pub const XOR_COMMON_PLAINTEXT: [u8; 6] = [b' ', 0x00, b'e', b't', b'a', b'o'];
/// How many keys a frequency-guided search may try per candidate.
pub const XOR_MAX_KEYS: usize = 65_536;
/// How many leading decrypted bytes the cheap rejection pass looks at.
pub const XOR_PREFILTER_BYTES: usize = 96;

pub fn xor_crib_score(data: &[u8]) -> f64 {
    XOR_CRIBS
        .iter()
        .filter(|crib| data.windows(crib.len()).any(|window| window == **crib))
        .count() as f64
        * 0.3
}

/// Cheap first pass: if the first `XOR_PREFILTER_BYTES` decrypted bytes are
/// mostly non-printable, the key is wrong -- skip decrypting the rest.
pub fn xor_prefilter_ok(candidate: &[u8], key: &[u8]) -> bool {
    let len = candidate.len().min(XOR_PREFILTER_BYTES);
    if len == 0 {
        return false;
    }
    let mut printable = 0usize;
    for (index, &byte) in candidate[..len].iter().enumerate() {
        let plain = byte ^ key[index % key.len()];
        if (32..=126).contains(&plain) || plain == b'\t' || plain == b'\n' || plain == b'\r' {
            printable += 1;
        }
    }
    printable * 100 >= len * 60
}

/// Score one key against a candidate, reusing `plain` as scratch space so the
/// hot loop allocates nothing.
pub fn xor_score_key(candidate: &[u8], key: &[u8], plain: &mut Vec<u8>) -> f64 {
    if !xor_prefilter_ok(candidate, key) {
        return 0.0;
    }
    plain.clear();
    plain.reserve(candidate.len());
    for (index, &byte) in candidate.iter().enumerate() {
        plain.push(byte ^ key[index % key.len()]);
    }
    let mut score = xor_printable_score(plain);
    if score > 0.0 {
        score += xor_crib_score(plain);
    }
    score
}

/// Per-thread accumulator: keeps the best `MAX_XOR_RESULTS_PER_CANDIDATE`
/// results plus a reusable plaintext buffer.
pub struct XorTop {
    top: Vec<XorResult>,
    plain: Vec<u8>,
}

impl XorTop {
    fn new(len: usize) -> Self {
        Self {
            top: Vec::with_capacity(MAX_XOR_RESULTS_PER_CANDIDATE + 1),
            plain: Vec::with_capacity(len),
        }
    }

    fn offer(&mut self, candidate: &[u8], offset: u64, key: &[u8]) {
        let score = xor_score_key(candidate, key, &mut self.plain);
        if score == 0.0 {
            return;
        }
        let position = self
            .top
            .iter()
            .position(|item| score > item.score)
            .unwrap_or(self.top.len());
        if position >= MAX_XOR_RESULTS_PER_CANDIDATE {
            return;
        }
        self.top.insert(
            position,
            XorResult {
                offset,
                key: key.to_vec(),
                plaintext: self.plain.clone(),
                score,
            },
        );
        self.top.truncate(MAX_XOR_RESULTS_PER_CANDIDATE);
    }

    fn merge(mut self, other: Self) -> Self {
        for item in other.top {
            let position = self
                .top
                .iter()
                .position(|existing| item.score > existing.score)
                .unwrap_or(self.top.len());
            if position >= MAX_XOR_RESULTS_PER_CANDIDATE {
                continue;
            }
            self.top.insert(position, item);
            self.top.truncate(MAX_XOR_RESULTS_PER_CANDIDATE);
        }
        self
    }
}

/// Frequency-guided key search for key spaces too large to enumerate.
///
/// A repeating XOR only shifts the plaintext byte distribution per key
/// position, so the most frequent ciphertext byte in a column is
/// `key_byte ^ (most frequent plaintext byte)`. For each position we take the
/// few most common ciphertext bytes, XOR them with the plaintext bytes that
/// usually dominate real text, and try every combination. A 3-byte key drops
/// from 16,777,216 keys to a few thousand, which stays interactive.
pub fn frequency_guided_keys(
    candidate: &[u8],
    key_size: usize,
    top_cipher_bytes: usize,
) -> Vec<Vec<u8>> {
    let mut columns: Vec<Vec<u8>> = Vec::with_capacity(key_size);
    for position in 0..key_size {
        let mut counts = [0usize; 256];
        for &byte in candidate.iter().skip(position).step_by(key_size) {
            counts[byte as usize] += 1;
        }
        let mut ranked: Vec<(u8, usize)> = counts
            .iter()
            .enumerate()
            .filter(|(_, &count)| count != 0)
            .map(|(byte, &count)| (byte as u8, count))
            .collect();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
        ranked.truncate(top_cipher_bytes);
        if ranked.is_empty() {
            ranked.push((0, 0));
        }
        let mut guesses: Vec<u8> = Vec::new();
        for &(cipher, _) in &ranked {
            for &plain in &XOR_COMMON_PLAINTEXT {
                let guess = cipher ^ plain;
                if !guesses.contains(&guess) {
                    guesses.push(guess);
                }
            }
        }
        columns.push(guesses);
    }

    let mut keys: Vec<Vec<u8>> = vec![Vec::with_capacity(key_size)];
    for column in &columns {
        let mut next = Vec::new();
        for prefix in &keys {
            for &byte in column {
                let mut key = prefix.clone();
                key.push(byte);
                next.push(key);
                if next.len() >= XOR_MAX_KEYS {
                    break;
                }
            }
            if next.len() >= XOR_MAX_KEYS {
                break;
            }
        }
        keys = next;
    }
    keys
}

/// Best `MAX_XOR_RESULTS_PER_CANDIDATE` keys for one candidate.
///
/// Keys are scored in parallel across the rayon pool. 1- and 2-byte keys are
/// enumerated exhaustively (256 / 65,536 keys); larger key spaces default to
/// the frequency-guided search unless `exhaustive` is set.
pub fn xor_top_results(
    candidate: &[u8],
    offset: u64,
    key_size: usize,
    exhaustive: bool,
) -> Vec<XorResult> {
    use rayon::prelude::*;

    let empty = || XorTop::new(candidate.len());
    if exhaustive || key_size <= 2 {
        let key_count = 1usize << (key_size * 8);
        (0..key_count)
            .into_par_iter()
            .fold(empty, |mut acc, value| {
                let mut key = [0u8; 3];
                for (index, byte) in key.iter_mut().enumerate().take(key_size) {
                    *byte = ((value >> (index * 8)) & 0xff) as u8;
                }
                acc.offer(candidate, offset, &key[..key_size]);
                acc
            })
            .reduce(empty, XorTop::merge)
            .top
    } else {
        frequency_guided_keys(candidate, key_size, XOR_TOP_CIPHER_BYTES)
            .par_iter()
            .fold(empty, |mut acc, key| {
                acc.offer(candidate, offset, key);
                acc
            })
            .reduce(empty, XorTop::merge)
            .top
    }
}

/// Split the file on NUL bytes and keep runs long enough to brute-force.
///
/// Reads in 1 MiB blocks and uses `memchr` to find separators; the previous
/// implementation called `read()` for a single byte at a time, which made
/// `--brute-xor` the slowest stage on a real dump.
pub fn collect_xor_candidates(path: &str) -> io::Result<Vec<(u64, Vec<u8>)>> {
    const BLOCK: usize = 1 << 20;
    let mut reader = BufReader::with_capacity(BLOCK, File::open(path)?);
    let mut buf = vec![0u8; BLOCK];
    let mut run: Vec<u8> = Vec::with_capacity(MAX_XOR_CANDIDATE_LEN);
    let mut run_offset = 0u64;
    let mut base = 0u64;
    let mut candidates = Vec::new();

    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        let mut pos = 0usize;
        while pos < read {
            match memchr::memchr(0, &buf[pos..read]) {
                Some(found) => {
                    let zero = pos + found;
                    if run.is_empty() {
                        run_offset = base + pos as u64;
                    }
                    push_xor_run(&mut candidates, &mut run_offset, &mut run, &buf[pos..zero]);
                    pos = zero + 1;
                }
                None => {
                    if run.is_empty() {
                        run_offset = base + pos as u64;
                    }
                    push_xor_run(&mut candidates, &mut run_offset, &mut run, &buf[pos..read]);
                    break;
                }
            }
            if candidates.len() >= MAX_XOR_CANDIDATES {
                return Ok(candidates);
            }
        }
        base += read as u64;
    }
    if !run.is_empty() {
        append_xor_candidates(&mut candidates, run_offset, &run);
    }
    candidates.truncate(MAX_XOR_CANDIDATES);
    Ok(candidates)
}

/// Append `data` to the current run, flushing it every
/// `MAX_XOR_CANDIDATE_LEN` bytes so a NUL-free file cannot grow `run` forever.
pub fn push_xor_run(
    candidates: &mut Vec<(u64, Vec<u8>)>,
    run_offset: &mut u64,
    run: &mut Vec<u8>,
    data: &[u8],
) {
    let mut rest = data;
    while !rest.is_empty() {
        let room = MAX_XOR_CANDIDATE_LEN - run.len();
        let take = room.min(rest.len());
        run.extend_from_slice(&rest[..take]);
        rest = &rest[take..];
        if run.len() >= MAX_XOR_CANDIDATE_LEN {
            append_xor_candidates(candidates, *run_offset, run);
            *run_offset += MAX_XOR_CANDIDATE_LEN as u64;
            run.clear();
        }
    }
}

/// Keep a run only if it is long enough and not trivially repetitive (all
/// one byte, or a two-byte cycle) -- those decrypt to junk for every key.
pub fn append_xor_candidates(candidates: &mut Vec<(u64, Vec<u8>)>, offset: u64, data: &[u8]) {
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

pub fn write_results(
    results: &[ExtractedString],
    format: Format,
    writer: &mut dyn Write,
    parse_pid: bool,
    max_str_len: usize,
    counts: Option<&std::collections::HashMap<String, usize>>,
    compact: bool,
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
                if let Some(count) = counts.and_then(|map| map.get(&result.text)) {
                    write!(writer, "\tcount={count}")?;
                }
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
        Format::Json | Format::Ndjson => {
            let layout = json_layout_for(format, compact);
            match layout {
                JsonLayout::Array => writeln!(writer, "[")?,
                JsonLayout::ArrayCompact => write!(writer, "[")?,
                JsonLayout::Lines => {}
            }
            let mut result_count = 0;
            for result in results {
                let count = counts.and_then(|map| map.get(&result.text).copied());
                write_string_json(result, writer, &mut result_count, parse_pid, count, layout)?;
            }
            match layout {
                JsonLayout::Array | JsonLayout::ArrayCompact => writeln!(writer, "]")?,
                JsonLayout::Lines => {}
            }
        }
        Format::JsonTree => {}
        Format::Csv => {
            write_csv_header(writer)?;
            for result in results {
                let count = counts.and_then(|map| map.get(&result.text).copied());
                write_csv_string_row(result, writer, parse_pid, max_str_len, count)?;
            }
        }
        Format::Html | Format::Markdown => {
            // Handled separately in write_report_html_markdown
        }
    }
    Ok(())
}
