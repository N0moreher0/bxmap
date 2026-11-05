use bxmap::{scan_yara_from_file_streaming, YaraMatch};

/// Compile a YARA/YARA-X rules file and stream-scan `path`, returning every
/// match. A stub is used in lite builds (`--no-default-features`) where YARA
/// is not compiled in; callers should only invoke this when `--yar` is given.
pub fn scan_yara_rules(path: &str, rules_path: &str) -> Result<Vec<YaraMatch>, String> {
    let mut out = Vec::new();
    scan_yara_from_file_streaming(path, rules_path, |matched| {
        out.push(matched);
    })
    .map_err(|e| format!("YARA scan failed: {e}"))?;
    Ok(out)
}
