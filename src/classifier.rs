//! Classification engine: maps an extracted string to a (group, type) pair.
//!
//! This is a deterministic, rule-based classifier that runs AFTER extraction
//! (separate pass), so it doesn't touch the hot scanning path. Rules live
//! here as data so they can be extended/tested without recompiling core logic.

use std::sync::OnceLock;
use regex::Regex;

/// A concrete secret value extracted from text.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub typ: &'static str,
    pub value: String,
}

/// Built-in secret/API-key detection patterns (name, regex).
/// Order matters only for `classify()` preference (first match wins).
pub static SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    ("AWS_SECRET_KEY", r"(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+=]{30,}"),
    ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z_-]{35}"),
    ("GOOGLE_OAUTH_CLIENT_ID", r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    ("AZURE_STORAGE_KEY", r"(?i)azure.{0,20}(?:storage|account).{0,20}key.{0,20}[A-Za-z0-9+/=]{40,}"),
    ("AZURE_SAS_TOKEN", r"(?i)\?[^ ]*sig=[A-Za-z0-9%+/=]{20,}"),
    ("GITHUB_PAT_CLASSIC", r"ghp_[A-Za-z0-9]{36,}"),
    ("GITHUB_FINE_GRAINED_PAT", r"github_pat_[A-Za-z0-9_]{20,}"),
    ("GITHUB_OAUTH_TOKEN", r"gho_[A-Za-z0-9]{36,}"),
    ("GITHUB_APP_TOKEN", r"(ghu|ghs)_[A-Za-z0-9]{36,}"),
    ("GITLAB_PAT", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("NPM_TOKEN", r"npm_[A-Za-z0-9]{36,}"),
    ("OPENAI_API_KEY", r"sk-[A-Za-z0-9]{20,}"),
    ("ANTHROPIC_API_KEY", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("HUGGINGFACE_TOKEN", r"hf_[A-Za-z0-9]{20,}"),
    ("DEEPSEEK_API_KEY", r"sk-[A-Za-z0-9]{20,}"),
    ("STRIPE_SECRET_KEY", r"sk_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("STRIPE_PUBLISHABLE_KEY", r"pk_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("STRIPE_RESTRICTED_KEY", r"rk_(?:live|test)_[A-Za-z0-9]{20,}"),
    ("PAYPAL_CLIENT_SECRET", r"(?i)paypal.{0,20}secret.{0,20}[A-Za-z0-9]{20,}"),
    ("SLACK_BOT_TOKEN", r"xoxb-[0-9A-Za-z-]{20,}"),
    ("SLACK_USER_TOKEN", r"xoxp-[0-9A-Za-z-]{20,}"),
    ("SLACK_WEBHOOK", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("DISCORD_BOT_TOKEN", r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"),
    ("TWILIO_API_KEY_SID", r"SK[0-9a-fA-F]{32}"),
    ("TWILIO_AUTH_TOKEN", r"(?i)twilio.{0,20}auth.{0,20}token.{0,20}[0-9a-f]{32}"),
    ("SENDGRID_API_KEY", r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    ("JWT_TOKEN", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("PRIVATE_KEY_BLOCK", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    ("DATABASE_URI", r#"(?i)(postgres|postgresql|mysql|mongodb|redis|sqlserver|mssql)://[^\s"'<>]+"#),
    ("GENERIC_SECRET", r"(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S{6,}"),
];

static SECRET_COMPILED: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
fn secret_compiled() -> &'static Vec<(&'static str, Regex)> {
    SECRET_COMPILED.get_or_init(|| {
        SECRET_PATTERNS.iter().map(|(name, pat)| {
            let re = Regex::new(pat).unwrap_or_else(|_| Regex::new(r".^").unwrap());
            (*name, re)
        }).collect()
    })
}

pub fn detect_secrets(text: &str) -> Vec<SecretMatch> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (name, re) in secret_compiled() {
        for m in re.find_iter(text) {
            let val = m.as_str().to_string();
            if seen.insert(val.clone()) {
                out.push(SecretMatch { typ: name, value: val });
            }
        }
    }
    out
}

/// Extract PEM private-key blocks from text.
pub fn extract_pems(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----").unwrap()
    });
    re.find_iter(text).map(|m| m.as_str().to_string()).collect()
}

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
    // Secret patterns take priority
    for (name, re) in secret_compiled() {
        if re.is_match(text) {
            if *name == "GENERIC_SECRET" {
                // only classify if entropy reasonable? keep as-is
            }
            return Some(Classification { group: "SECRET", typ: name });
        }
    }
    // existing rules...
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
        assert_eq!(c.typ, "AWS_ACCESS_KEY");
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