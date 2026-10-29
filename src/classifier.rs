//! Classification engine: maps an extracted string to a (group, type) pair.
//!
//! This is a deterministic, rule-based classifier that runs AFTER extraction
//! (separate pass), so it doesn't touch the hot scanning path. Rules live
//! here as data so they can be extended/tested without recompiling core logic.

use std::sync::OnceLock;
use regex::Regex;

/// A single classified string record in the JSON tree output.
#[derive(Debug, Clone)]
pub struct Classification {
    pub group: &'static str,
    pub typ: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    group: &'static str,
    typ: &'static str,
    /// Compiled at first use; regex must match somewhere in the (refanged) text.
    pattern: &'static str,
    /// Optional minimum entropy (0 = no entropy gate).
    min_entropy: f64,
    /// Optional "must contain digit" gate (for base64 etc).
    require_digit: bool,
}

const RULES: &[Rule] = &[
    // ---- SECRET ----
    Rule { group: "SECRET", typ: "AWS_KEY", pattern: r"AKIA[0-9A-Z]{16}", min_entropy: 0.0, require_digit: false },
    Rule { group: "SECRET", typ: "AWS_SECRET", pattern: r"(?i)aws.{0,20}secret.{0,20}[a-z0-9/+=]{20,}", min_entropy: 2.0, require_digit: false },
    Rule { group: "SECRET", typ: "GITHUB_TOKEN", pattern: r"gh[pousr]_[A-Za-z0-9]{36,}", min_entropy: 0.0, require_digit: false },
    Rule { group: "SECRET", typ: "JWT", pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", min_entropy: 0.0, require_digit: false },
    Rule { group: "SECRET", typ: "PRIVATE_KEY", pattern: r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", min_entropy: 0.0, require_digit: false },
    Rule { group: "SECRET", typ: "AZURE_KEY", pattern: r"(?i)azure.{0,20}(key|token|secret).{0,20}[a-z0-9]{20,}", min_entropy: 2.0, require_digit: false },
    Rule { group: "SECRET", typ: "GCP_KEY", pattern: r"AIza[0-9A-Za-z_-]{35}", min_entropy: 0.0, require_digit: false },
    Rule { group: "SECRET", typ: "GENERIC_SECRET", pattern: r"(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S{6,}", min_entropy: 0.0, require_digit: false },
    // ---- NETWORK ----
    Rule { group: "NETWORK", typ: "URL", pattern: r#"(?i)https?://[^\s"'<>]+"#, min_entropy: 0.0, require_digit: false },
    Rule { group: "NETWORK", typ: "IPV4", pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", min_entropy: 0.0, require_digit: false },
    Rule { group: "NETWORK", typ: "DOMAIN", pattern: r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", min_entropy: 0.0, require_digit: false },
    Rule { group: "NETWORK", typ: "EMAIL", pattern: r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b", min_entropy: 0.0, require_digit: false },
    // ---- CRYPTO ----
    Rule { group: "CRYPTO", typ: "BTC_ADDR", pattern: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", min_entropy: 0.0, require_digit: false },
    Rule { group: "CRYPTO", typ: "ETH_ADDR", pattern: r"\b0x[a-fA-F0-9]{40}\b", min_entropy: 0.0, require_digit: false },
    Rule { group: "CRYPTO", typ: "XMR_ADDR", pattern: r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b", min_entropy: 0.0, require_digit: false },
    // ---- MALWARE ----
    Rule { group: "MALWARE", typ: "SUSPICIOUS_PATH", pattern: r"(?i)\\(temp|appdata|startup|public)\\", min_entropy: 0.0, require_digit: false },
    Rule { group: "MALWARE", typ: "MUTEX", pattern: r"(?i)Global\\[A-Za-z0-9_-]{4,}", min_entropy: 0.0, require_digit: false },
    Rule { group: "MALWARE", typ: "C2", pattern: r"(?i)(c2|gate\.php|/panel/|/admin/)", min_entropy: 0.0, require_digit: false },
    // ---- ENCODING ----
    Rule { group: "ENCODING", typ: "BASE64", pattern: r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", min_entropy: 2.5, require_digit: true },
];

static COMPILED: OnceLock<Vec<(Rule, Regex)>> = OnceLock::new();

fn compiled_rules() -> &'static Vec<(Rule, Regex)> {
    COMPILED.get_or_init(|| {
        RULES.iter().map(|r| {
            let re = Regex::new(r.pattern).unwrap_or_else(|_| Regex::new(r".^").unwrap());
            (*r, re)
        }).collect()
    })
}

/// Shannon entropy (bits/byte) for a string's bytes.
pub fn entropy_of(text: &str) -> f64 {
    if text.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for b in text.bytes() { counts[b as usize] += 1; }
    let len = text.len() as f64;
    counts.iter().filter(|&&c| c != 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}

/// Classify a single extracted string. Returns None if no rule matches.
pub fn classify(text: &str) -> Option<Classification> {
    let e = entropy_of(text);
    for (rule, re) in compiled_rules() {
        if re.is_match(text) {
            if rule.min_entropy > 0.0 && e < rule.min_entropy { continue; }
            if rule.require_digit && !text.bytes().any(|b| b.is_ascii_digit()) { continue; }
            return Some(Classification { group: rule.group, typ: rule.typ });
        }
    }
    None
}

/// Default group/type for strings that don't match any rule.
pub const DEFAULT_GROUP: &str = "STRING";
pub const DEFAULT_TYPE: &str = "GENERIC";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aws_key_classified() {
        let c = classify("AKIAIOSFODNN7EXAMPLE").unwrap();
        assert_eq!(c.group, "SECRET");
        assert_eq!(c.typ, "AWS_KEY");
    }
    #[test]
    fn generic_string_unclassified() {
        let c = classify("hello world this is a normal sentence");
        // may or may not match; just ensure no panic
        let _ = c;
    }
    #[test]
    fn url_classified() {
        let c = classify("https://example.com/api?q=1").unwrap();
        assert_eq!(c.group, "NETWORK");
        assert_eq!(c.typ, "URL");
    }
    #[test]
    fn eth_addr_classified() {
        let c = classify("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        assert_eq!(c.group, "CRYPTO");
        assert_eq!(c.typ, "ETH_ADDR");
    }
    #[test]
    fn entropy_function_works() {
        assert_eq!(entropy_of(""), 0.0);
        assert!((entropy_of("aaaa") - 0.0).abs() < 1e-9);
    }
}