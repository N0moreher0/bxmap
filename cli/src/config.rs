//! Optional configuration file (`bxmap.toml`).
//!
//! A case directory usually runs the same scan over several dumps, and the
//! options that never change can live in `bxmap.toml` next to them. The
//! precedence is:
//!
//! 1. command line flags
//! 2. the configuration file
//! 3. the `--mode` / `--with` presets
//! 4. the built-in defaults
//!
//! ```toml
//! # bxmap.toml
//! min-len = 8
//! max-strings = 100000
//! encoding = "ascii,utf16le,utf16be"
//! threads = 4
//! format = "ndjson"
//! output = "case.ndjson"
//! report = "summary"
//! detectors = ["secret", "url"]
//! detect-format = "rich"
//! extract = "paths,env"
//! carve = "jpeg,png"
//! carve-out = "carved"
//! entropy = true
//! ```

use crate::args::{
    parse_detect_format, parse_detector, parse_encoding_spec, parse_format, parse_report_mode, Args,
};
use crate::helpers::ExplicitFlags;
use bxmap::artifacts::ArtifactKinds;
use std::path::Path;

/// File looked up in the current directory when `--config` is not given.
pub const DEFAULT_CONFIG_FILE: &str = "bxmap.toml";

/// Options read from the configuration file.
///
/// Every field is optional: a missing key leaves the built-in default alone.
#[derive(Debug, Default, Clone)]
pub struct FileConfig {
    pub min_len: Option<usize>,
    pub max_strings: Option<usize>,
    pub max_str_len: Option<usize>,
    pub encoding: Option<String>,
    pub noise_threshold: Option<usize>,
    pub threads: Option<usize>,
    pub auto_tune: Option<bool>,
    pub max_memory: Option<u64>,
    pub dedupe: Option<bool>,
    pub format: Option<String>,
    pub output: Option<String>,
    pub report: Option<String>,
    pub detectors: Option<Vec<String>>,
    pub detect_format: Option<String>,
    pub detect_strict: Option<bool>,
    pub extract: Option<String>,
    pub carve: Option<String>,
    pub carve_out: Option<String>,
    pub entropy: Option<bool>,
    pub signature: Option<String>,
    pub stats: Option<bool>,
}

/// Read and parse a configuration file.
pub fn load_config(path: &Path) -> Result<FileConfig, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read config file '{}': {e}", path.display()))?;
    let value: toml::Value = text
        .parse()
        .map_err(|e| format!("invalid config TOML '{}': {e}", path.display()))?;
    let table = value
        .as_table()
        .ok_or_else(|| format!("config '{}' is not a table", path.display()))?;
    Ok(FileConfig {
        min_len: get_int(table, "min-len")?.map(|v| v as usize),
        max_strings: get_int(table, "max-strings")?.map(|v| v as usize),
        max_str_len: get_int(table, "max-str-len")?.map(|v| v as usize),
        encoding: get_string(table, "encoding")?,
        noise_threshold: get_int(table, "noise-threshold")?.map(|v| v as usize),
        threads: get_int(table, "threads")?.map(|v| v as usize),
        auto_tune: get_bool(table, "auto-tune")?,
        max_memory: get_int(table, "max-memory")?.map(|v| v as u64),
        dedupe: get_bool(table, "dedupe")?,
        format: get_string(table, "format")?,
        output: get_string(table, "output")?,
        report: get_string(table, "report")?,
        detectors: get_string_array(table, "detectors")?,
        detect_format: get_string(table, "detect-format")?,
        detect_strict: get_bool(table, "detect-strict")?,
        extract: get_string(table, "extract")?,
        carve: get_string(table, "carve")?,
        carve_out: get_string(table, "carve-out")?,
        entropy: get_bool(table, "entropy")?,
        signature: get_string(table, "signature")?,
        stats: get_bool(table, "stats")?,
    })
}

/// Apply the configuration to the parsed arguments.
///
/// Options the user spelled out on the command line win; everything else is
/// taken from the file. The applied options are marked as explicit so the
/// `--mode` / `--with` presets do not overwrite them.
pub fn apply_config(
    args: &mut Args,
    explicit: &mut ExplicitFlags,
    config: &FileConfig,
) -> Result<(), String> {
    if let Some(value) = config.min_len {
        if value == 0 {
            return Err("config option 'min-len' must be at least 1".to_string());
        }
        if !explicit.min_len {
            args.min_len = value;
            explicit.min_len = true;
        }
    }
    if let Some(value) = config.max_strings {
        if !explicit.max_strings {
            args.max_strings = value;
            explicit.max_strings = true;
        }
    }
    if let Some(value) = config.max_str_len {
        args.max_str_len = value;
    }
    if let Some(value) = &config.encoding {
        if !explicit.encoding {
            args.encoding = parse_encoding_spec(value)?;
            explicit.encoding = true;
        }
    }
    if let Some(value) = config.noise_threshold {
        args.noise_threshold = Some(value);
    }
    if let Some(value) = config.threads {
        if value == 0 {
            return Err("config option 'threads' must be at least 1".to_string());
        }
        args.threads = value;
    }
    if let Some(true) = config.auto_tune {
        args.auto_tune = true;
    }
    if let Some(value) = config.max_memory {
        args.max_memory = value;
    }
    if let Some(true) = config.dedupe {
        if !explicit.dedupe {
            args.dedupe = true;
            explicit.dedupe = true;
        }
    }
    if let Some(value) = &config.format {
        args.format = parse_format(value)?;
    }
    if let Some(value) = &config.output {
        args.output = Some(value.clone());
    }
    if let Some(value) = &config.report {
        if !explicit.report {
            args.report_mode = parse_report_mode(value, "report")?;
            explicit.report = true;
        }
    }
    if let Some(values) = &config.detectors {
        if !explicit.detectors {
            let mut detectors = Vec::new();
            for value in values {
                let detector = parse_detector(value)?;
                if !detectors.contains(&detector) {
                    detectors.push(detector);
                }
            }
            args.detectors = detectors;
            explicit.detectors = true;
        }
    }
    if let Some(value) = &config.detect_format {
        args.detect_format = parse_detect_format(value)?;
    }
    if let Some(true) = config.detect_strict {
        args.detect_strict = true;
    }
    if let Some(value) = &config.extract {
        if !explicit.extract {
            args.extract = ArtifactKinds::from_list(value)?;
            explicit.extract = true;
        }
    }
    if let Some(value) = &config.carve {
        if !explicit.carve {
            args.carve = Some(value.clone());
            explicit.carve = true;
        }
    }
    if let Some(value) = &config.carve_out {
        if !explicit.carve_out {
            args.carve_out = Some(value.clone());
            explicit.carve_out = true;
        }
    }
    if let Some(true) = config.entropy {
        if !explicit.entropy {
            args.entropy = true;
            explicit.entropy = true;
        }
    }
    if let Some(value) = &config.signature {
        if !explicit.signature {
            args.signature = Some(value.clone());
            explicit.signature = true;
        }
    }
    if let Some(true) = config.stats {
        args.stats = true;
    }
    Ok(())
}

fn get_int(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<Option<i64>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_integer()
            .or_else(|| value.as_float().map(|f| f as i64))
            .map(Some)
            .ok_or_else(|| format!("config option '{key}' must be a number")),
    }
}

fn get_bool(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Option<bool>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("config option '{key}' must be true or false")),
    }
}

fn get_string(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Option<String>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|s| Some(s.to_string()))
            .ok_or_else(|| format!("config option '{key}' must be a string")),
    }
}

fn get_string_array(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Result<Option<Vec<String>>, String> {
    match table.get(key) {
        None => Ok(None),
        Some(value) => {
            let array = value
                .as_array()
                .ok_or_else(|| format!("config option '{key}' must be a list of strings"))?;
            let mut out = Vec::with_capacity(array.len());
            for item in array {
                let text = item
                    .as_str()
                    .ok_or_else(|| format!("config option '{key}' must be a list of strings"))?;
                out.push(text.to_string());
            }
            Ok(Some(out))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Format;

    fn write_config(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bxmap.toml");
        std::fs::write(&path, body).unwrap();
        (dir, path)
    }

    fn default_args() -> Args {
        crate::args::parse_args_from(vec!["dump.bin".to_string()])
            .expect("arguments should parse")
            .0
    }

    #[test]
    fn config_fills_the_options_the_command_line_did_not_set() {
        let (_dir, path) = write_config(
            "min-len = 8\nencoding = \"ascii,utf16le\"\nformat = \"ndjson\"\nreport = \"summary\"\n\
             detectors = [\"secret\", \"url\"]\nthreads = 3\n",
        );
        let config = load_config(&path).unwrap();
        assert_eq!(config.min_len, Some(8));
        assert_eq!(config.encoding.as_deref(), Some("ascii,utf16le"));
        assert_eq!(config.detectors.as_ref().unwrap().len(), 2);

        let mut args = default_args();
        let mut explicit = ExplicitFlags::default();
        apply_config(&mut args, &mut explicit, &config).unwrap();
        assert_eq!(args.min_len, 8);
        assert_eq!(args.threads, 3);
        assert!(matches!(args.format, Format::Ndjson));
        assert_eq!(args.detectors.len(), 2);
        // The config marks the options it filled in, so a preset does not
        // overwrite them.
        assert!(explicit.min_len);
        assert!(explicit.encoding);
    }

    #[test]
    fn the_command_line_wins_over_the_config_file() {
        let (_dir, path) = write_config("min-len = 8\n");
        let config = load_config(&path).unwrap();
        let mut args = default_args();
        let mut explicit = ExplicitFlags::default();
        explicit.min_len = true;
        args.min_len = 4;
        apply_config(&mut args, &mut explicit, &config).unwrap();
        assert_eq!(args.min_len, 4);
    }

    #[test]
    fn a_broken_config_file_is_reported() {
        let (_dir, path) = write_config("min-len = \"eight\"\n");
        let err = load_config(&path).unwrap_err();
        assert!(err.contains("min-len"), "{err}");

        let (_dir, path) = write_config("this is not toml =\n");
        assert!(load_config(&path).is_err());
    }
}
