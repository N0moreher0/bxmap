//! Custom detector rules loaded from a TOML file (`--detect-rules`).
//!
//! Example rules.toml:
//! ```toml
//! [[rules]]
//! id = "my_internal_key"
//! regex = '(?i)myapp_secret\\s*[:=]\\s*[A-Za-z0-9/+=]{16,}'
//! severity = "high"
//! confidence = 0.9
//! description = "Internal application secret"
//! keywords = ["myapp_secret"]
//!
//! [[rules]]
//! id = "corp_email_pattern"
//! regex = '\\b[a-z0-9._%+-]+@corp-example\\.com\\b'
//! severity = "low"
//! confidence = 0.7
//! description = "Corporate email address"
//! keywords = ["@corp-example.com"]
//! ```

use bxmap::classifier::{context_around, DetectedFinding};
use regex::Regex;
use std::path::Path;

/// Parsed representation of a single rule from the TOML file.
#[derive(Debug, Clone)]
pub struct CustomRule {
    pub id: String,
    pub regex: String,
    pub severity: String,
    pub confidence: f64,
    pub description: Option<String>,
    pub keywords: Vec<String>,
}

/// A compiled custom rule ready for matching.
#[derive(Debug)]
#[allow(dead_code)]
pub struct CompiledCustomRule {
    /// Leaked as `&'static str` so it fits into `DetectedFinding.rule` without
    /// changing the public API (rule stays `&'static str`).
    pub rule: &'static str,
    pub severity: &'static str,
    pub confidence: f64,
    pub description: Option<String>,
    pub regex: Regex,
    /// Lowercased keywords used as a cheap prefilter before running the regex.
    pub keywords: Vec<String>,
}

/// Maximum allowed pattern length to guard against pathological regexes.
const MAX_PATTERN_LEN: usize = 512;
/// Maximum number of alternation branches allowed.
const MAX_ALTERNATIONS: usize = 64;

impl CustomRule {
    /// Compile this rule, returning an error with line/column context when the
    /// regex is invalid or exceeds safety limits.
    pub fn compile(&self, _rule_index: usize) -> Result<CompiledCustomRule, String> {
        let pattern = &self.regex;
        if pattern.len() > MAX_PATTERN_LEN {
            return Err(format!(
                "rule {}: pattern too long ({} bytes, max {})",
                self.id,
                pattern.len(),
                MAX_PATTERN_LEN
            ));
        }
        // Count top-level alternation branches as a cheap ReDoS hint.
        let branch_count = count_top_level_alternations(pattern);
        if branch_count > MAX_ALTERNATIONS {
            return Err(format!(
                "rule {}: too many alternation branches ({}, max {})",
                self.id, branch_count, MAX_ALTERNATIONS
            ));
        }
        let regex = Regex::new(pattern)
            .map_err(|e| format!("rule {}: invalid regex '{}': {e}", self.id, pattern))?;
        let rule: &'static str = Box::leak(self.id.clone().into_boxed_str());
        let severity: &'static str = Box::leak(self.severity.clone().into_boxed_str());
        Ok(CompiledCustomRule {
            rule,
            severity,
            confidence: self.confidence,
            description: self.description.clone(),
            regex,
            keywords: self
                .keywords
                .iter()
                .map(|k| k.to_ascii_lowercase())
                .collect(),
        })
    }
}

/// Count top-level `|` alternation operators (naive, ignores brackets for speed).
fn count_top_level_alternations(pattern: &str) -> usize {
    let mut depth = 0usize;
    let mut count = 1usize;
    for ch in pattern.chars() {
        match ch {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            '|' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Load and compile custom rules from a TOML file.
pub fn load_custom_rules(_path: &Path) -> Result<Vec<CompiledCustomRule>, String> {
    let text = std::fs::read_to_string(_path)
        .map_err(|e| format!("cannot read --detect-rules file '{}': {e}", _path.display()))?;
    let value: toml::Value = text
        .parse()
        .map_err(|e| format!("invalid --detect-rules TOML '{}': {e}", _path.display()))?;
    let rules = value
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            format!(
                "--detect-rules '{}' is missing [[rules]] array",
                _path.display()
            )
        })?;
    let mut out = Vec::with_capacity(rules.len());
    for (index, rule_value) in rules.iter().enumerate() {
        let rule = parse_rule(rule_value)
            .map_err(|e| format!("rule #{index} in '{}': {e}", _path.display()))?;
        out.push(rule.compile(index)?);
    }
    Ok(out)
}

/// Parse a single rule from a `toml::Value`.
fn parse_rule(value: &toml::Value) -> Result<CustomRule, String> {
    let table = value
        .as_table()
        .ok_or_else(|| "rule is not a table".to_string())?;
    let id = get_string(table, "id")?;
    let regex = get_string(table, "regex")?;
    let severity = get_string_opt(table, "severity").unwrap_or_else(|| "medium".to_string());
    let confidence = get_float_opt(table, "confidence").unwrap_or(0.7);
    let description = get_string_opt(table, "description");
    let keywords = get_string_array_opt(table, "keywords").unwrap_or_default();
    Ok(CustomRule {
        id,
        regex,
        severity,
        confidence,
        description,
        keywords,
    })
}

fn get_string(table: &toml::map::Map<String, toml::Value>, key: &str) -> Result<String, String> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing or invalid '{key}' field"))
}

fn get_string_opt(table: &toml::map::Map<String, toml::Value>, key: &str) -> Option<String> {
    table
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_float_opt(table: &toml::map::Map<String, toml::Value>, key: &str) -> Option<f64> {
    table.get(key).and_then(|v| v.as_float()).or_else(|| {
        table
            .get(key)
            .and_then(|v| v.as_integer())
            .map(|n| n as f64)
    })
}

fn get_string_array_opt(
    table: &toml::map::Map<String, toml::Value>,
    key: &str,
) -> Option<Vec<String>> {
    table.get(key).and_then(|v| v.as_array()).map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect()
    })
}

/// Cheap prefilter: return true if any keyword appears (case-insensitive) in text.
fn keyword_prefilter(keywords: &[String], text: &str) -> bool {
    if keywords.is_empty() {
        return true;
    }
    let lower = text.to_ascii_lowercase();
    keywords.iter().any(|k| lower.contains(k.as_str()))
}

/// Match compiled custom rules against text, returning findings.
pub fn match_custom_rules(
    rules: &[CompiledCustomRule],
    result: &bxmap::ExtractedString,
) -> Vec<DetectedFinding> {
    let mut out = Vec::new();
    let text = &result.text;
    for rule in rules {
        if !keyword_prefilter(&rule.keywords, text) {
            continue;
        }
        for m in rule.regex.find_iter(text) {
            out.push(DetectedFinding {
                offset: result.offset,
                encoding: result.encoding,
                rule: rule.rule,
                value: m.as_str().to_string(),
                text: result.text.clone(),
                context: context_around(text, m.start(), m.end(), 32),
                confidence: rule.confidence,
                severity: rule.severity,
            });
        }
    }
    out
}

/// Return a deduplicated set of rule IDs present in `findings`.
#[allow(dead_code)]
pub fn custom_rule_ids(findings: &[DetectedFinding]) -> Vec<String> {
    let mut ids: Vec<String> = findings
        .iter()
        .filter(|f| f.rule.starts_with("custom::"))
        .map(|f| f.rule.to_string())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(id: &str, regex: &str) -> CustomRule {
        CustomRule {
            id: id.to_string(),
            regex: regex.to_string(),
            severity: "medium".to_string(),
            confidence: 0.7,
            description: None,
            keywords: Vec::new(),
        }
    }

    #[test]
    fn compile_valid_rule() {
        let rule = make_rule("test_rule", r"\b[A-Z]{3}\d{3}\b");
        let compiled = rule.compile(0).unwrap();
        assert_eq!(compiled.rule, "test_rule");
        assert!(compiled.regex.is_match("ABC123"));
        assert!(!compiled.regex.is_match("abc123"));
    }

    #[test]
    fn compile_invalid_rule_reports_error() {
        let rule = make_rule("bad_rule", r"[unclosed");
        let err = rule.compile(0).unwrap_err();
        assert!(err.contains("bad_rule"));
        assert!(err.contains("invalid regex"));
    }

    #[test]
    fn compile_pattern_too_long() {
        let rule = CustomRule {
            id: "long_rule".to_string(),
            regex: "a".repeat(MAX_PATTERN_LEN + 1),
            severity: "medium".to_string(),
            confidence: 0.7,
            description: None,
            keywords: Vec::new(),
        };
        let err = rule.compile(0).unwrap_err();
        assert!(err.contains("long_rule"));
        assert!(err.contains("too long"));
    }

    #[test]
    fn compile_too_many_alternations() {
        let pattern = (0..MAX_ALTERNATIONS + 1)
            .map(|_| "foo")
            .collect::<Vec<_>>()
            .join("|");
        let rule = make_rule("many_alt", &pattern);
        let err = rule.compile(0).unwrap_err();
        assert!(err.contains("many_alt"));
        assert!(err.contains("alternation"));
    }

    #[test]
    fn keyword_prefilter_skips_nonmatching() {
        let rule = make_rule("kw_rule", r"\bsecret\b");
        let mut compiled = rule.compile(0).unwrap();
        compiled.keywords = vec!["secret".to_string()];
        let result = bxmap::ExtractedString {
            offset: 0,
            encoding: "ascii",
            text: "nothing here".to_string(),
        };
        let findings = match_custom_rules(&[compiled], &result);
        assert!(findings.is_empty());
    }

    #[test]
    fn match_custom_rules_finds_value() {
        let rule = make_rule("my_key", r"mykey=([A-Za-z0-9]{8,})");
        let compiled = rule.compile(0).unwrap();
        let result = bxmap::ExtractedString {
            offset: 10,
            encoding: "ascii",
            text: "mykey=abcdefgh1234 trailing".to_string(),
        };
        let findings = match_custom_rules(&[compiled], &result);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "my_key");
        assert_eq!(findings[0].value, "mykey=abcdefgh1234");
        assert_eq!(findings[0].offset, 10);
    }

    #[test]
    fn load_custom_rules_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.toml");
        std::fs::write(
            &path,
            r#"[[rules]]
id = "my_secret"
regex = "(?i)my_secret\\s*[:=]\\s*[A-Za-z0-9/+=]{16,}"
severity = "high"
confidence = 0.9
description = "My app secret"
keywords = ["my_secret"]
"#,
        )
        .unwrap();
        let rules = load_custom_rules(&path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].rule, "my_secret");
        assert_eq!(rules[0].severity, "high");
        assert!((rules[0].confidence - 0.9).abs() < 1e-6);
    }

    #[test]
    fn load_custom_rules_missing_array() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.toml");
        std::fs::write(&path, "# empty\n").unwrap();
        let err = load_custom_rules(&path).unwrap_err();
        assert!(err.contains("missing [[rules]]"));
    }
}
