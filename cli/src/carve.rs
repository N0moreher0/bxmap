use super::*;
use std::fs::File;
use std::io::{self, BufWriter, Write};

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
        let record = format!(
            "{{\"offset\":{},\"offset_hex\":\"{:#x}\",\"type\":\"{}\",\"size\":{},\"sha256\":\"{}\",\"entropy\":{:.4},\"complete\":{},\"notes\":{},\"path\":{},\"duplicates\":[{}]}}",
            file.offset,
            file.offset,
            file.kind.as_str(),
            file.size,
            file.sha256,
            file.entropy,
            file.complete,
            json_escape(&file.notes),
            match file.path.as_ref() {
                Some(path) => json_escape(&path.to_string_lossy()),
                None => "null".to_string(),
            },
            duplicates
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
