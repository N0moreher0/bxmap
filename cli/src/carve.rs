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

pub fn write_carve_index(report: &CarveReport, path: &str) -> io::Result<()> {
    let ndjson = path.to_ascii_lowercase().ends_with(".ndjson");
    let csv = path.to_ascii_lowercase().ends_with(".csv");
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
