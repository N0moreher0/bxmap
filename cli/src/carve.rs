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

pub fn write_carve_index(report: &CarveReport, path: &str) -> io::Result<()> {
    let ndjson = path.to_ascii_lowercase().ends_with(".ndjson");
    let mut out = BufWriter::new(File::create(path)?);
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
            "{{\"offset\":{},\"offset_hex\":\"{:#x}\",\"type\":\"{}\",\"size\":{},\"sha256\":\"{}\",\"entropy\":{:.4},\"complete\":{},\"corrupted_offset\":{},\"entropy_spike_at\":{},\"partial_encryption\":{},\"trailer_offset\":{},\"trailer_len\":{},\"trailer_sha256\":{},\"trailer_preview\":{},\"tracks_intact\":{},\"notes\":{},\"path\":{},\"duplicates\":[{}],\"file_name\":{},\"ext\":{},\"ext_source\":{},\"role\":\"{}\",\"tier\":{},\"evidence\":[{}],\"confidence\":\"{}\"}}",
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
