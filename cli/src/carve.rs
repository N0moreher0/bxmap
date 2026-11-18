use super::*;
use std::fs::File;
use std::io::{self, BufWriter, Write};

/// JSON number for an optional offset, `null` when absent.
fn json_opt_u64(value: Option<u64>) -> String {
    match value {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    }
}

/// JSON string for an optional value, `null` when absent.
fn json_opt_str(value: Option<&str>) -> String {
    match value {
        Some(value) => json_escape(value),
        None => "null".to_string(),
    }
}

/// JSON number for an optional float, `null` when absent or non-finite.
fn json_opt_f64(value: Option<f64>) -> String {
    match value {
        Some(value) if value.is_finite() => format!("{value:.2}"),
        _ => "null".to_string(),
    }
}

/// `tracks_intact` array for the index, or `null` (ROADMAP 8.11.4): what
/// the NAL oracle learned about each video track of a rebuilt MP4.
fn json_tracks_intact(tracks: Option<&[bxmap::carve::TrackIntact]>) -> String {
    match tracks {
        Some(tracks) if !tracks.is_empty() => {
            let items = tracks
                .iter()
                .map(|track| {
                    format!(
                        "{{\"codec\":{},\"samples\":{},\"intact\":{},\"intact_ratio\":{:.4},\"broken_prefix_samples\":{},\"first_intact_sync_sample\":{},\"first_intact_sync_time\":{}}}",
                        json_escape(&track.codec),
                        track.samples,
                        track.intact,
                        track.intact_ratio,
                        track.broken_prefix,
                        json_opt_u64(track.first_intact_sync_sample),
                        json_opt_f64(track.first_intact_sync_time),
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        _ => "null".to_string(),
    }
}

/// `encrypted_ranges` array for the index, or `null` (ROADMAP 8.14.3):
/// absolute dump offsets `[start, end)` of high-entropy 4 KiB windows that
/// look like intermittently-encrypted blocks. `null` when the span was too
/// small to scan or nothing suspicious was found.
fn json_encrypted_ranges(ranges: Option<&[(u64, u64)]>) -> String {
    match ranges {
        Some(ranges) if !ranges.is_empty() => {
            let items = ranges
                .iter()
                .map(|(start, end)| format!("[{start},{end}]"))
                .collect::<Vec<_>>()
                .join(",");
            format!("[{items}]")
        }
        _ => "null".to_string(),
    }
}

/// `suspected-partial-encryption` object for the index, or `null`.
/// Heuristic only (ROADMAP 8.7.3): compressed data also scores high entropy.
fn json_partial_encryption(hint: Option<bxmap::carve::PartialEncryption>) -> String {
    match hint {
        Some(hint) => format!(
            "{{\"period\":{},\"duty\":{:.4},\"threshold\":{:.1}}}",
            hint.period, hint.duty, hint.threshold
        ),
        None => "null".to_string(),
    }
}

/// CSV carve index (RFC 4180, ROADMAP 8.14.3): one row per carved file.
fn write_carve_index_csv(report: &CarveReport, out: &mut BufWriter<File>) -> io::Result<()> {
    fn opt_u64(value: Option<u64>) -> String {
        value.map(|value| value.to_string()).unwrap_or_default()
    }
    writeln!(
        out,
        "offset,offset_hex,type,size,sha256,entropy,complete,corrupted_offset,entropy_spike_at,partial_encryption,trailer_offset,trailer_len,trailer_sha256,trailer_preview,role,tier,ext,ext_source,confidence,evidence,encrypted_ranges,notes,duplicates"
    )?;
    for file in &report.files {
        let partial_encryption = file
            .partial_encryption
            .map(|hint| {
                format!(
                    "period={},duty={:.4},threshold={:.1}",
                    hint.period, hint.duty, hint.threshold
                )
            })
            .unwrap_or_default();
        let encrypted_ranges = file
            .encrypted_ranges
            .as_deref()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(|(start, end)| format!("[{start},{end}]"))
                    .collect::<Vec<_>>()
                    .join(";")
            })
            .unwrap_or_default();
        let duplicates = file
            .duplicates
            .iter()
            .map(|offset| offset.to_string())
            .collect::<Vec<_>>()
            .join(";");
        let row = [
            file.offset.to_string(),
            format!("{:#x}", file.offset),
            file.kind.as_str().to_string(),
            file.size.to_string(),
            file.sha256.clone(),
            format!("{:.4}", file.entropy),
            file.complete.to_string(),
            opt_u64(file.corrupted_offset),
            opt_u64(file.entropy_spike_at),
            partial_encryption,
            opt_u64(file.trailer_offset),
            opt_u64(file.trailer_len),
            file.trailer_sha256.clone().unwrap_or_default(),
            file.trailer_preview.clone().unwrap_or_default(),
            file.role.as_str().to_string(),
            file.tier.to_string(),
            file.ext.clone(),
            file.ext_source.clone(),
            file.confidence.as_str().to_string(),
            file.evidence.join("|"),
            encrypted_ranges,
            file.notes.clone(),
            duplicates,
        ];
        writeln!(
            out,
            "{}",
            row.iter().map(csv_escape).collect::<Vec<_>>().join(",")
        )?;
    }
    out.flush()
}

/// RFC 4180 CSV field escaping.
fn csv_escape(field: &String) -> String {
    if field
        .chars()
        .any(|char| matches!(char, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.clone()
    }
}

/// `file_name` cho artifact/record: tên file carve đang nằm trên đĩa khi có,
/// nếu không thì tên mà writer sẽ dùng — cùng luật với index JSON.
fn carved_or_actual_name(file: &bxmap::carve::CarvedFile) -> String {
    match file.path.as_ref().and_then(|path| path.file_name()) {
        Some(name) => name.to_string_lossy().into_owned(),
        None => bxmap::carve::carved_file_name_with_ext(
            file.offset,
            file.kind,
            &file.ext,
            file.role,
            &file.sha256,
        ),
    }
}

/// ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`) cho một Unix timestamp (giây).
/// Viết tay để không phải thêm chrono/time chỉ cho một timestamp.
fn iso8601_from_unix(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = secs % 86_400;
    let (hour, minute, second) = (
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    );
    // Civil-from-days (Howard Hinnant). secs luôn >= 0 nên z > 0.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn iso8601_utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    iso8601_from_unix(secs)
}

/// Id dạng `<kind>--<uuid>` tất định cho đối tượng STIX (layout RFC 4122).
/// Suy ra từ SHA-256 của `kind|seed`, nên chạy lại trên cùng report luôn cho
/// ra id giống nhau (diff-friendly). Nibble version đặt 5 theo layout v5;
/// thay SHA-1 bằng SHA-256 chỉ có lợi cho độ duy nhất.
fn stix_id(kind: &str, seed: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"bxmap-stix|");
    hasher.update(kind.as_bytes());
    hasher.update(b"|");
    hasher.update(seed);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50; // v5 nibble (layout only)
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
    format!(
        "{kind}--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Escape `run` cho biểu thức `file:contents MATCHES '...'` trong STIX:
/// bước 1 escape ký tự regex (để khớp literal), bước 2 escape cho chuỗi
/// single-quoted của STIX (backslash gấp đôi, quote thành `\'`).
fn stix_matches_literal(run: &str) -> String {
    let mut re_escaped = String::with_capacity(run.len() * 2);
    for ch in run.chars() {
        if matches!(
            ch,
            '\\' | '.' | '^' | '$' | '*' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|'
        ) {
            re_escaped.push('\\');
        }
        re_escaped.push(ch);
    }
    let mut literal = String::with_capacity(re_escaped.len() * 2);
    for ch in re_escaped.chars() {
        match ch {
            '\\' => literal.push_str("\\\\"),
            '\'' => literal.push_str("\\'"),
            _ => literal.push(ch),
        }
    }
    literal
}

/// Đoạn printable dài nhất trong phần ASCII của trailer preview
/// (`hex | ascii`, byte non-printable ánh xạ thành `.`), chọn mảnh theo
/// đúng mẫu victim ID: chỉ `[A-Za-z0-9_-]`, tối thiểu 6 ký tự, có ít nhất
/// một chữ cái và một chữ số (bỏ binary junk đọc nhầm thành printable).
/// Heuristic tường minh: manh mối ransom-note, không phải verdict và
/// không bao giờ đủ một mình để kết luận — `indicator_types: ["unknown"]`.
/// `None` khi không có mảnh nào đủ tốt.
fn trailer_printable_run(preview: &str) -> Option<String> {
    let ascii = preview.split(" | ").nth(1)?;
    let mut best: Option<&str> = None;
    for piece in ascii.split('.') {
        let shaped = piece
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
            && piece.len() >= 6
            && piece.chars().any(|ch| ch.is_ascii_alphabetic())
            && piece.chars().any(|ch| ch.is_ascii_digit());
        if shaped {
            let better = best
                .map(|current| piece.len() > current.len())
                .unwrap_or(true);
            if better {
                best = Some(piece);
            }
        }
    }
    best.map(str::to_string)
}

fn summarize_kinds(report: &CarveReport) -> String {
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for file in &report.files {
        *counts.entry(file.kind.as_str()).or_default() += 1;
    }
    counts
        .iter()
        .map(|(kind, count)| format!("{kind}={count}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// STIX 2.1 bundle cho `--carve` (ROADMAP 8.14.7): nạp MISP/OpenCTI/
/// Velociraptor. Một `observed-data` gói mọi `file` SCO (hash/size/offset/
/// role/tier/evidence/encrypted_ranges); trailer đọc được (≥ 4 byte
/// printable) thành `indicator` với `[file:contents MATCHES '<run>']` — manh
/// mối, không phải kết luận; `report` + `relationship based-on` nối chúng lại.
pub fn write_carve_export_stix(
    report: &CarveReport,
    dump_name: &str,
    path: &str,
) -> io::Result<()> {
    let now = iso8601_utc_now();
    let file_name = std::path::Path::new(dump_name)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| dump_name.to_string());
    let kinds_summary = summarize_kinds(report);
    let duplicates: u64 = report
        .files
        .iter()
        .map(|file| file.duplicates.len() as u64)
        .sum();
    let description = format!(
        "bxmap carve of '{file_name}': {} file(s), {} byte(s) written, {duplicates} duplicate(s) skipped, truncated={}. Kinds: {kinds_summary}.",
        report.files.len(),
        report.bytes_written,
        report.truncated,
    );

    let mut objects: Vec<String> = Vec::with_capacity(report.files.len() * 2 + 8);

    let identity_id = stix_id("identity", b"bxmap-producer");
    objects.push(format!(
        "{{\"type\":\"identity\",\"id\":{id},\"created\":{now},\"modified\":{now},\"name\":\"bxmap\",\"description\":{desc},\"identity_class\":\"system\"}}",
        id = json_escape(&identity_id),
        now = json_escape(&now),
        desc = json_escape(&format!("bxmap memory-dump carver (carve export of '{file_name}')")),
    ));

    // One `file` SCO per carved record.
    let mut file_ids: Vec<String> = Vec::with_capacity(report.files.len());
    for file in &report.files {
        let name = carved_or_actual_name(file);
        let seed = format!("{}|{}", file.offset, file.sha256);
        let id = stix_id("file", seed.as_bytes());
        file_ids.push(id.clone());
        let evidence = file
            .evidence
            .iter()
            .map(|item| json_escape(item))
            .collect::<Vec<_>>()
            .join(",");
        objects.push(format!(
            "{{\"type\":\"file\",\"id\":{id},\"created\":{now},\"modified\":{now},\"name\":{name},\"size\":{size},\"hashes\":{{\"SHA-256\":{sha}}},\"x_bxmap_offset\":{offset},\"x_bxmap_offset_hex\":{offset_hex},\"x_bxmap_kind\":{kind},\"x_bxmap_role\":{role},\"x_bxmap_tier\":{tier},\"x_bxmap_complete\":{complete},\"x_bxmap_ext\":{ext},\"x_bxmap_confidence\":{confidence},\"x_bxmap_evidence\":[{evidence}],\"x_bxmap_encrypted_ranges\":{ranges},\"x_bxmap_trailer_sha256\":{trailer_sha},\"x_bxmap_trailer_preview\":{trailer_preview}}}",
            id = json_escape(&id),
            now = json_escape(&now),
            name = json_escape(&name),
            size = file.size,
            sha = json_escape(&file.sha256),
            offset = file.offset,
            offset_hex = json_escape(&format!("{:#x}", file.offset)),
            kind = json_escape(file.kind.as_str()),
            role = json_escape(file.role.as_str()),
            tier = file.tier,
            complete = file.complete,
            ext = json_escape(&file.ext),
            confidence = json_escape(file.confidence.as_str()),
            evidence = evidence,
            ranges = json_encrypted_ranges(file.encrypted_ranges.as_deref()),
            trailer_sha = json_opt_str(file.trailer_sha256.as_deref()),
            trailer_preview = json_opt_str(file.trailer_preview.as_deref()),
        ));
    }

    let observed_seed = format!("{dump_name}|{now}");
    let observed_data_id = stix_id("observed-data", observed_seed.as_bytes());
    objects.push(format!(
        "{{\"type\":\"observed-data\",\"id\":{id},\"created\":{now},\"modified\":{now},\"first_observed\":{now},\"last_observed\":{now},\"number_observed\":{count},\"object_refs\":[{refs}]}}",
        id = json_escape(&observed_data_id),
        now = json_escape(&now),
        count = report.files.len(),
        refs = file_ids
            .iter()
            .map(|id| json_escape(id))
            .collect::<Vec<_>>()
            .join(","),
    ));

    // One indicator per readable trailer — and at most one per trailer
    // content: identical trailer bytes (same SHA-256) at several offsets
    // yield the same deterministic id, so duplicates would break the
    // bundle's id uniqueness. First occurrence wins.
    let mut indicator_ids: Vec<String> = Vec::new();
    let mut relationships: Vec<String> = Vec::new();
    let mut seen_indicators: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for file in &report.files {
        let Some(preview) = file.trailer_preview.as_deref() else {
            continue;
        };
        let Some(run) = trailer_printable_run(preview) else {
            continue;
        };
        let pattern = format!("[file:contents MATCHES '{}']", stix_matches_literal(&run));
        let seed = format!(
            "trailer|{}",
            file.trailer_sha256.as_deref().unwrap_or(&file.sha256)
        );
        let indicator_id = stix_id("indicator", seed.as_bytes());
        if !seen_indicators.insert(indicator_id.clone()) {
            continue;
        }
        indicator_ids.push(indicator_id.clone());
        objects.push(format!(
            "{{\"type\":\"indicator\",\"id\":{id},\"created\":{now},\"modified\":{now},\"name\":\"Ransom-note trailer observed (bxmap, heuristic)\",\"description\":{desc},\"indicator_types\":[\"unknown\"],\"pattern\":{pattern},\"pattern_type\":\"stix\",\"valid_from\":{now},\"x_bxmap_offset\":{offset},\"x_bxmap_trailer_sha256\":{trailer_sha},\"x_bxmap_trailer_preview\":{preview}}}",
            id = json_escape(&indicator_id),
            now = json_escape(&now),
            desc = json_escape(&format!(
                "Printable trailer run '{run}' after {} file at {:#x} in '{file_name}'. A ransom-note hint recorded as evidence, not a verdict.",
                file.kind.as_str(),
                file.offset,
            )),            pattern = json_escape(&pattern),
            offset = file.offset,
            trailer_sha = json_opt_str(file.trailer_sha256.as_deref()),
            preview = json_escape(preview),
        ));
        relationships.push(format!(
            "{{\"type\":\"relationship\",\"id\":{id},\"created\":{now},\"modified\":{now},\"relationship_type\":\"based-on\",\"source_ref\":{source},\"target_ref\":{target}}}",
            id = json_escape(&stix_id("relationship", indicator_id.as_bytes())),
            now = json_escape(&now),
            source = json_escape(&indicator_id),
            target = json_escape(&observed_data_id),
        ));
    }
    objects.extend(relationships);

    let mut object_refs = vec![observed_data_id];
    object_refs.extend(indicator_ids);
    let report_id = stix_id("report", observed_seed.as_bytes());
    objects.push(format!(
        "{{\"type\":\"report\",\"id\":{id},\"created\":{now},\"modified\":{now},\"name\":{name},\"description\":{desc},\"published\":{now},\"report_types\":[\"threat-report\"],\"object_refs\":[{refs}]}}",
        id = json_escape(&report_id),
        now = json_escape(&now),
        name = json_escape(&format!("bxmap carve report — {file_name}")),
        desc = json_escape(&description),
        refs = object_refs
            .iter()
            .map(|id| json_escape(id))
            .collect::<Vec<_>>()
            .join(","),
    ));

    let bundle_seed = format!("bundle|{observed_seed}|{}", objects.len());
    let bundle_id = stix_id("bundle", bundle_seed.as_bytes());
    let mut out = BufWriter::new(File::create(path)?);
    writeln!(
        out,
        "{{\"type\":\"bundle\",\"id\":{},\"objects\":[{}]}}",
        json_escape(&bundle_id),
        objects.join(",")
    )?;
    out.flush()
}

/// SARIF 2.1.0 report cho `--carve` (ROADMAP 8.14.7): mỗi file carve là một
/// `result` (`note` khi complete, ngược lại `warning`), mỗi kind một
/// `rule`, mỗi file một `artifact` với `hashes["SHA-256"]`; `partialFingerprints`
/// mang SHA-256 để code-scanning UI dedupe qua các lần chạy.
pub fn write_carve_export_sarif(
    report: &CarveReport,
    dump_name: &str,
    path: &str,
) -> io::Result<()> {
    let now = iso8601_utc_now();
    let version = env!("CARGO_PKG_VERSION");
    let file_name_of_dump = std::path::Path::new(dump_name)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| dump_name.to_string());

    // One rule per carved kind, sorted for deterministic output.
    let mut kinds: Vec<String> = report
        .files
        .iter()
        .map(|file| file.kind.as_str().to_string())
        .collect();
    kinds.sort();
    kinds.dedup();
    let rules = kinds
        .iter()
        .map(|kind| {
            let mut cap = kind.chars();
            let name = match cap.next() {
                Some(first) => format!("Carve{}{}", first.to_ascii_uppercase(), cap.as_str()),
                None => "Carve".to_string(),
            };
            format!(
                "{{\"id\":\"carve/{kind}\",\"name\":\"{name}\",\"shortDescription\":{{\"text\":\"{kind} file recovered by carving\"}},\"fullDescription\":{{\"text\":\"bxmap validated and carved a {kind} file from '{file_name_of_dump}'.\"}},\"defaultConfiguration\":{{\"level\":\"note\"}},\"properties\":{{\"carveKind\":\"{kind}\"}}}}"
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    let mut results = Vec::with_capacity(report.files.len());
    let mut artifacts = Vec::with_capacity(report.files.len());
    for (index, file) in report.files.iter().enumerate() {
        let name = carved_or_actual_name(file);
        let level = if file.complete { "note" } else { "warning" };
        let message = if file.notes.is_empty() {
            format!(
                "{} file carved at {:#x} ({} bytes)",
                file.kind.as_str(),
                file.offset,
                file.size
            )
        } else {
            file.notes.clone()
        };
        let evidence = file
            .evidence
            .iter()
            .map(|item| json_escape(item))
            .collect::<Vec<_>>()
            .join(",");
        let duplicates = file
            .duplicates
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        results.push(format!(
            "{{\"ruleId\":\"carve/{kind}\",\"level\":\"{level}\",\"message\":{{\"text\":{message}}},\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{name},\"index\":{index}}},\"region\":{{\"byteOffset\":{offset},\"byteLength\":{size}}}}}}}],\"partialFingerprints\":{{\"bxmap.sha256/v1\":{sha}}},\"properties\":{{\"offset\":{offset},\"offsetHex\":{offset_hex},\"role\":{role},\"tier\":{tier},\"ext\":{ext},\"extSource\":{ext_source},\"confidence\":{confidence},\"complete\":{complete},\"evidence\":[{evidence}],\"encryptedRanges\":{ranges},\"trailerOffset\":{trailer_offset},\"trailerLength\":{trailer_length},\"trailerSha256\":{trailer_sha},\"trailerPreview\":{trailer_preview},\"duplicates\":[{duplicates}]}}}}",
            kind = file.kind.as_str(),
            level = level,
            message = json_escape(&message),
            name = json_escape(&name),
            index = index,
            offset = file.offset,
            size = file.size,
            sha = json_escape(&file.sha256),
            offset_hex = json_escape(&format!("{:#x}", file.offset)),
            role = json_escape(file.role.as_str()),
            tier = file.tier,
            ext = json_escape(&file.ext),
            ext_source = json_escape(&file.ext_source),
            confidence = json_escape(file.confidence.as_str()),
            complete = file.complete,
            evidence = evidence,
            ranges = json_encrypted_ranges(file.encrypted_ranges.as_deref()),
            trailer_offset = json_opt_u64(file.trailer_offset),
            trailer_length = json_opt_u64(file.trailer_len),
            trailer_sha = json_opt_str(file.trailer_sha256.as_deref()),
            trailer_preview = json_opt_str(file.trailer_preview.as_deref()),
            duplicates = duplicates,
        ));
        artifacts.push(format!(
            "{{\"location\":{{\"uri\":{name}}},\"length\":{size},\"hashes\":{{\"SHA-256\":{sha}}}}}",
            name = json_escape(&name),
            size = file.size,
            sha = json_escape(&file.sha256),
        ));
    }

    let mut out = BufWriter::new(File::create(path)?);
    writeln!(
        out,
        "{{\"$schema\":\"https://json.schemastore.org/sarif-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"bxmap\",\"version\":\"{version}\",\"informationUri\":\"https://github.com/N0moreher0/bxmap\",\"rules\":[{rules}]}}}},\"invocations\":[{{\"executionSuccessful\":true,\"startTimeUtc\":{now}}}],\"results\":[{results}],\"artifacts\":[{artifacts}]}}]}}",
        version = version,
        rules = rules,
        now = json_escape(&now),
        results = results.join(","),
        artifacts = artifacts.join(","),
    )?;
    out.flush()
}

/// Ghi kết quả carve ra `path` — định dạng chọn theo đuôi file, cùng một kênh
/// với index JSON/NDJSON/CSV (ROADMAP 8.14.7, không thêm cờ mới):
/// `.ndjson` = một record mỗi dòng · `.csv` = bảng RFC 4180 23 cột cố định ·
/// `.sarif` / `.sarif.json` = SARIF 2.1.0 (code-scanning) · `.stix` /
/// `.stix.json` = bundle STIX 2.1 (MISP/OpenCTI/Velociraptor) · đuôi khác =
/// JSON array. `dump_name` chỉ dùng để đặt tên report trong SARIF/STIX.
pub fn write_carve_index(report: &CarveReport, dump_name: &str, path: &str) -> io::Result<()> {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with(".sarif") || lower.ends_with(".sarif.json") {
        return write_carve_export_sarif(report, dump_name, path);
    }
    if lower.ends_with(".stix") || lower.ends_with(".stix.json") {
        return write_carve_export_stix(report, dump_name, path);
    }
    let ndjson = lower.ends_with(".ndjson");
    let csv = lower.ends_with(".csv");
    let mut out = BufWriter::new(File::create(path)?);
    if csv {
        return write_carve_index_csv(report, &mut out);
    }
    if !ndjson {
        writeln!(out, "[")?;
    }
    for (index, file) in report.files.iter().enumerate() {
        let duplicates = file
            .duplicates
            .iter()
            .map(|offset| offset.to_string())
            .collect::<Vec<_>>()
            .join(",");
        // The name on disk when the file was written; otherwise the name the
        // writer would have used, so the field is present either way.
        let file_name = match file.path.as_ref().and_then(|path| path.file_name()) {
            Some(name) => name.to_string_lossy().into_owned(),
            None => bxmap::carve::carved_file_name_with_ext(
                file.offset,
                file.kind,
                &file.ext,
                file.role,
                &file.sha256,
            ),
        };
        let evidence = file
            .evidence
            .iter()
            .map(|item| json_escape(item))
            .collect::<Vec<_>>()
            .join(",");
        let record = format!(
            "{{\"offset\":{},\"offset_hex\":\"{:#x}\",\"type\":\"{}\",\"size\":{},\"sha256\":\"{}\",\"entropy\":{:.4},\"complete\":{},\"corrupted_offset\":{},\"entropy_spike_at\":{},\"partial_encryption\":{},\"trailer_offset\":{},\"trailer_len\":{},\"trailer_sha256\":{},\"trailer_preview\":{},\"tracks_intact\":{},\"encrypted_ranges\":{},\"notes\":{},\"path\":{},\"duplicates\":[{}],\"file_name\":{},\"ext\":{},\"ext_source\":{},\"role\":\"{}\",\"tier\":{},\"evidence\":[{}],\"confidence\":\"{}\"}}",
            file.offset,
            file.offset,
            file.kind.as_str(),
            file.size,
            file.sha256,
            file.entropy,
            file.complete,
            json_opt_u64(file.corrupted_offset),
            json_opt_u64(file.entropy_spike_at),
            json_partial_encryption(file.partial_encryption),
            json_opt_u64(file.trailer_offset),
            json_opt_u64(file.trailer_len),
            json_opt_str(file.trailer_sha256.as_deref()),
            json_opt_str(file.trailer_preview.as_deref()),
            json_tracks_intact(file.tracks_intact.as_deref()),
            json_encrypted_ranges(file.encrypted_ranges.as_deref()),
            json_escape(&file.notes),
            match file.path.as_ref() {
                Some(path) => json_escape(&path.to_string_lossy()),
                None => "null".to_string(),
            },
            duplicates,
            json_escape(&file_name),
            json_escape(&file.ext),
            json_escape(&file.ext_source),
            file.role.as_str(),
            file.tier,
            evidence,
            file.confidence.as_str()
        );
        if ndjson {
            writeln!(out, "{record}")?;
        } else {
            let comma = if index + 1 == report.files.len() {
                ""
            } else {
                ","
            };
            writeln!(out, "  {record}{comma}")?;
        }
    }
    if !ndjson {
        writeln!(out, "]")?;
    }
    out.flush()
}
