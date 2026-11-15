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
            "{{\"offset\":{},\"offset_hex\":\"{:#x}\",\"type\":\"{}\",\"size\":{},\"sha256\":\"{}\",\"entropy\":{:.4},\"complete\":{},\"corrupted_offset\":{},\"entropy_spike_at\":{},\"notes\":{},\"path\":{},\"duplicates\":[{}],\"file_name\":{},\"ext\":{},\"ext_source\":{},\"role\":\"{}\",\"tier\":{},\"evidence\":[{}],\"confidence\":\"{}\"}}",
            file.offset,
            file.offset,
            file.kind.as_str(),
            file.size,
            file.sha256,
            file.entropy,
            file.complete,
            json_opt_u64(file.corrupted_offset),
            json_opt_u64(file.entropy_spike_at),
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
