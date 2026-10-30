//! Classification engine: maps an extracted string to a (group, type) pair.
//!
//! This is a deterministic, rule-based classifier that runs AFTER extraction
//! (separate pass), so it doesn't touch the hot scanning path. Rules live
//! here as data so they can be extended/tested without recompiling core logic.

use aho_corasick::AhoCorasick;
use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// A concrete secret value extracted from text.
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub typ: &'static str,
    pub value: String,
}

/// A secret match with provenance: byte span, confidence and severity.
///
/// This is the structured counterpart of [`SecretMatch`]; `detect_secrets`
/// keeps its original shape for backward compatibility.
#[derive(Debug, Clone, PartialEq)]
pub struct SecretFinding {
    pub rule: &'static str,
    pub value: String,
    /// Byte offset of the match inside the scanned string.
    pub start: usize,
    /// Byte offset just past the match inside the scanned string.
    pub end: usize,
    pub confidence: f64,
    pub severity: &'static str,
}

/// A structured detector finding ready for JSON/text output.
///
/// Unlike the flat detector output (which replaces the original string with the
/// matched token), a finding keeps the source `text` plus a `context` snippet so
/// an analyst can see where the match came from.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DetectedFinding {
    pub offset: u64,
    pub encoding: &'static str,
    pub rule: &'static str,
    pub value: String,
    pub text: String,
    pub context: String,
    pub confidence: f64,
    pub severity: &'static str,
}

/// Severity bucket for a rule name.
pub fn severity_for(rule: &str) -> &'static str {
    match rule {
        "GENERIC_SECRET" | "DOMAIN" | "BASE64_DECODED" => "low",
        "AWS_SECRET_KEY"
        | "AZURE_SAS_TOKEN"
        | "PAYPAL_CLIENT_SECRET"
        | "TWILIO_AUTH_TOKEN"
        | "URL"
        | "IPV4"
        | "IPV6" => "medium",
        _ => "high",
    }
}

/// Baseline confidence for a rule. Values are intentionally coarse: detectors
/// are triage hints, not proof.
pub fn confidence_for(rule: &str) -> f64 {
    match rule {
        "GENERIC_SECRET" => 0.40,
        "DOMAIN" => 0.60,
        "BASE64_DECODED" => 0.50,
        "URL" => 0.85,
        "IPV4" | "IPV6" => 0.90,
        "AWS_SECRET_KEY" | "AZURE_SAS_TOKEN" | "PAYPAL_CLIENT_SECRET" | "TWILIO_AUTH_TOKEN" => 0.75,
        _ => 0.95,
    }
}

fn char_floor(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn char_ceil(text: &str, mut index: usize) -> usize {
    index = index.min(text.len());
    while index < text.len() && !text.is_char_boundary(index) {
        index += 1;
    }
    index
}

/// Return a short snippet around `[start, end)` with `...` markers when the
/// context was clipped. Offsets are byte offsets and are snapped to UTF-8
/// boundaries, so this never panics on multibyte text.
pub fn context_around(text: &str, start: usize, end: usize, radius: usize) -> String {
    let start = char_floor(text, start);
    let end = char_ceil(text, end.max(start));
    let left = char_floor(text, start.saturating_sub(radius));
    let right = char_ceil(text, end.saturating_add(radius));
    let mut out = String::with_capacity(right - left + 8);
    if left > 0 {
        out.push_str("...");
    }
    out.push_str(&text[left..right]);
    if right < text.len() {
        out.push_str("...");
    }
    out
}

/// Built-in secret/API-key detection patterns (name, regex).
/// Order matters only for `classify()` preference (first match wins).
pub static SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS_ACCESS_KEY", r"AKIA[0-9A-Z]{16}"),
    (
        "AWS_SECRET_KEY",
        r"(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+=]{30,}",
    ),
    ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z_-]{35}"),
    (
        "GOOGLE_OAUTH_CLIENT_ID",
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    ),
    (
        "AZURE_STORAGE_KEY",
        r"(?i)azure.{0,20}(?:storage|account).{0,20}key.{0,20}[A-Za-z0-9+/=]{40,}",
    ),
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
    (
        "STRIPE_PUBLISHABLE_KEY",
        r"pk_(?:live|test)_[A-Za-z0-9]{20,}",
    ),
    (
        "STRIPE_RESTRICTED_KEY",
        r"rk_(?:live|test)_[A-Za-z0-9]{20,}",
    ),
    (
        "PAYPAL_CLIENT_SECRET",
        r"(?i)paypal.{0,20}secret.{0,20}[A-Za-z0-9]{20,}",
    ),
    ("SLACK_BOT_TOKEN", r"xoxb-[0-9A-Za-z-]{20,}"),
    ("SLACK_USER_TOKEN", r"xoxp-[0-9A-Za-z-]{20,}"),
    (
        "SLACK_WEBHOOK",
        r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    ),
    (
        "DISCORD_BOT_TOKEN",
        r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}",
    ),
    ("TWILIO_API_KEY_SID", r"SK[0-9a-fA-F]{32}"),
    (
        "TWILIO_AUTH_TOKEN",
        r"(?i)twilio.{0,20}auth.{0,20}token.{0,20}[0-9a-f]{32}",
    ),
    (
        "SENDGRID_API_KEY",
        r"SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
    ),
    (
        "JWT_TOKEN",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    ),
    (
        "PRIVATE_KEY_BLOCK",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    ),
    (
        "DATABASE_URI",
        r#"(?i)(postgres|postgresql|mysql|mongodb|redis|sqlserver|mssql)://[^\s"'<>]+"#,
    ),
    (
        "GENERIC_SECRET",
        r"(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S{6,}",
    ),
];

static SECRET_COMPILED: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
fn secret_compiled() -> &'static Vec<(&'static str, Regex)> {
    SECRET_COMPILED.get_or_init(|| {
        SECRET_PATTERNS
            .iter()
            .map(|(name, pat)| {
                let re = Regex::new(pat).unwrap_or_else(|_| Regex::new(r".^").unwrap());
                (*name, re)
            })
            .collect()
    })
}

/// Literal anchors for `SECRET_PATTERNS`: every match of the named pattern MUST
/// contain at least one of these substrings (compared ASCII case-insensitively,
/// which only ever over-selects). A single Aho-Corasick pass over the text then
/// tells us which of the regexes can possibly match, instead of running all of
/// them on every string. A pattern missing from this table is simply always run,
/// so forgetting an entry costs speed, never correctness.
const SECRET_ANCHORS: &[(&str, &[&str])] = &[
    ("AWS_ACCESS_KEY", &["AKIA"]),
    ("AWS_SECRET_KEY", &["aws"]),
    ("GOOGLE_API_KEY", &["AIza"]),
    ("GOOGLE_OAUTH_CLIENT_ID", &[".apps.googleusercontent.com"]),
    ("AZURE_STORAGE_KEY", &["azure"]),
    ("AZURE_SAS_TOKEN", &["sig="]),
    ("GITHUB_PAT_CLASSIC", &["ghp_"]),
    ("GITHUB_FINE_GRAINED_PAT", &["github_pat_"]),
    ("GITHUB_OAUTH_TOKEN", &["gho_"]),
    ("GITHUB_APP_TOKEN", &["ghu_", "ghs_"]),
    ("GITLAB_PAT", &["glpat-"]),
    ("NPM_TOKEN", &["npm_"]),
    ("OPENAI_API_KEY", &["sk-"]),
    ("ANTHROPIC_API_KEY", &["sk-ant-"]),
    ("HUGGINGFACE_TOKEN", &["hf_"]),
    ("DEEPSEEK_API_KEY", &["sk-"]),
    ("STRIPE_SECRET_KEY", &["sk_live_", "sk_test_"]),
    ("STRIPE_PUBLISHABLE_KEY", &["pk_live_", "pk_test_"]),
    ("STRIPE_RESTRICTED_KEY", &["rk_live_", "rk_test_"]),
    ("PAYPAL_CLIENT_SECRET", &["paypal"]),
    ("SLACK_BOT_TOKEN", &["xoxb-"]),
    ("SLACK_USER_TOKEN", &["xoxp-"]),
    ("SLACK_WEBHOOK", &["https://hooks.slack.com/services/"]),
    ("TWILIO_API_KEY_SID", &["SK"]),
    ("TWILIO_AUTH_TOKEN", &["twilio"]),
    ("SENDGRID_API_KEY", &["SG."]),
    ("JWT_TOKEN", &["eyJ"]),
    ("PRIVATE_KEY_BLOCK", &["-----BEGIN "]),
    (
        "DATABASE_URI",
        &[
            "postgres",
            "mysql",
            "mongodb",
            "redis",
            "sqlserver",
            "mssql",
        ],
    ),
    (
        "GENERIC_SECRET",
        &["password", "passwd", "secret", "token", "apikey", "api_key"],
    ),
];

/// Minimum byte length of any possible match, per pattern (derived from the regex).
/// Lets us skip patterns that have no literal anchor (Discord) on short strings.
const SECRET_MIN_LEN: &[(&str, usize)] = &[
    ("DISCORD_BOT_TOKEN", 59),  // 24 + '.' + 6 + '.' + 27+
    ("TWILIO_API_KEY_SID", 34), // "SK" + 32 hex
];

struct SecretPrefilter {
    ac: AhoCorasick,
    /// Aho-Corasick pattern id -> bitmask of `SECRET_PATTERNS` indices it enables.
    anchor_masks: Vec<u64>,
    /// Patterns without anchors: candidates for every string.
    always: u64,
    /// Every pattern (used for non-ASCII text, see `secret_candidates`).
    all: u64,
    /// (pattern index, min byte length) gates.
    gates: Vec<(usize, usize)>,
}

fn secret_prefilter() -> &'static SecretPrefilter {
    static PREFILTER: OnceLock<SecretPrefilter> = OnceLock::new();
    PREFILTER.get_or_init(|| {
        let count = SECRET_PATTERNS.len();
        assert!(count <= 64, "secret prefilter uses a u64 bitmask");
        let all = if count == 64 {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };
        let mut anchors: Vec<&str> = Vec::new();
        let mut anchor_masks: Vec<u64> = Vec::new();
        let mut anchored = 0u64;
        let mut gates = Vec::new();
        for (idx, (name, _)) in SECRET_PATTERNS.iter().enumerate() {
            if let Some((_, lits)) = SECRET_ANCHORS.iter().find(|(n, _)| n == name) {
                for lit in lits.iter() {
                    match anchors.iter().position(|a| a.eq_ignore_ascii_case(lit)) {
                        Some(pos) => anchor_masks[pos] |= 1u64 << idx,
                        None => {
                            anchors.push(lit);
                            anchor_masks.push(1u64 << idx);
                        }
                    }
                }
                anchored |= 1u64 << idx;
            }
            if let Some((_, min)) = SECRET_MIN_LEN.iter().find(|(n, _)| n == name) {
                gates.push((idx, *min));
            }
        }
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&anchors)
            .expect("secret anchors form a valid automaton");
        SecretPrefilter {
            ac,
            anchor_masks,
            always: all & !anchored,
            all,
            gates,
        }
    })
}

/// Bitmask over `SECRET_PATTERNS` of the patterns that can possibly match `text`.
fn secret_candidates(text: &str) -> u64 {
    let pf = secret_prefilter();
    // `(?i)` in the regexes is Unicode-aware (e.g. U+017F folds to 's', U+212A to
    // 'k') while the automaton only folds ASCII, so for non-ASCII text we keep the
    // exact old behaviour and try every pattern.
    if !text.is_ascii() {
        return pf.all;
    }
    let mut mask = pf.always;
    for m in pf.ac.find_overlapping_iter(text) {
        mask |= pf.anchor_masks[m.pattern().as_usize()];
    }
    for &(idx, min) in &pf.gates {
        if text.len() < min {
            mask &= !(1u64 << idx);
        }
    }
    mask
}

pub fn detect_secrets(text: &str) -> Vec<SecretMatch> {
    detect_secrets_detailed(text)
        .into_iter()
        .map(|finding| SecretMatch {
            typ: finding.rule,
            value: finding.value,
        })
        .collect()
}

/// Structured secret detection: same rules and de-duplication as
/// [`detect_secrets`], but each match also carries its byte span, confidence and
/// severity.
pub fn detect_secrets_detailed(text: &str) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let candidates = secret_candidates(text);
    for (idx, (name, re)) in secret_compiled().iter().enumerate() {
        if candidates & (1u64 << idx) == 0 {
            continue;
        }
        for m in re.find_iter(text) {
            let val = m.as_str().to_string();
            if seen.insert(val.clone()) {
                out.push(SecretFinding {
                    rule: name,
                    value: val,
                    start: m.start(),
                    end: m.end(),
                    confidence: confidence_for(name),
                    severity: severity_for(name),
                });
            }
        }
    }
    out
}

/// Extract PEM private-key blocks from text.
pub fn extract_pems(text: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")
            .unwrap()
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
    Rule {
        group: "SECRET",
        typ: "AWS_KEY",
        pattern: r"AKIA[0-9A-Z]{16}",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "AWS_SECRET",
        pattern: r"(?i)aws.{0,20}secret.{0,20}[a-z0-9/+=]{20,}",
        min_entropy: 2.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "GITHUB_TOKEN",
        pattern: r"gh[pousr]_[A-Za-z0-9]{36,}",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "JWT",
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "PRIVATE_KEY",
        pattern: r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "AZURE_KEY",
        pattern: r"(?i)azure.{0,20}(key|token|secret).{0,20}[a-z0-9]{20,}",
        min_entropy: 2.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "GCP_KEY",
        pattern: r"AIza[0-9A-Za-z_-]{35}",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "SECRET",
        typ: "GENERIC_SECRET",
        pattern: r"(?i)(password|passwd|secret|token|apikey|api_key)\s*[=:]\s*\S{6,}",
        min_entropy: 0.0,
        require_digit: false,
    },
    // ---- NETWORK ----
    Rule {
        group: "NETWORK",
        typ: "URL",
        pattern: r#"(?i)https?://[^\s"'<>]+"#,
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "NETWORK",
        typ: "IPV4",
        pattern: r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "NETWORK",
        typ: "DOMAIN",
        pattern: r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "NETWORK",
        typ: "EMAIL",
        pattern: r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    // ---- CRYPTO ----
    Rule {
        group: "CRYPTO",
        typ: "BTC_ADDR",
        pattern: r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "CRYPTO",
        typ: "ETH_ADDR",
        pattern: r"\b0x[a-fA-F0-9]{40}\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "CRYPTO",
        typ: "XMR_ADDR",
        pattern: r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    // ---- MALWARE ----
    Rule {
        group: "MALWARE",
        typ: "SUSPICIOUS_PATH",
        pattern: r"(?i)\\(temp|appdata|startup|public)\\",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "MALWARE",
        typ: "MUTEX",
        pattern: r"(?i)Global\\[A-Za-z0-9_-]{4,}",
        min_entropy: 0.0,
        require_digit: false,
    },
    Rule {
        group: "MALWARE",
        typ: "C2",
        pattern: r"(?i)(c2|gate\.php|/panel/|/admin/)",
        min_entropy: 0.0,
        require_digit: false,
    },
    // ---- ENCODING ----
    Rule {
        group: "ENCODING",
        typ: "BASE64",
        pattern: r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        min_entropy: 2.5,
        require_digit: true,
    },
];

static COMPILED: OnceLock<Vec<(Rule, Regex)>> = OnceLock::new();

fn compiled_rules() -> &'static Vec<(Rule, Regex)> {
    COMPILED.get_or_init(|| {
        RULES
            .iter()
            .map(|r| {
                let re = Regex::new(r.pattern).unwrap_or_else(|_| Regex::new(r".^").unwrap());
                (*r, re)
            })
            .collect()
    })
}

/// Shannon entropy (bits/byte) for a string's bytes.
pub fn entropy_of(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in text.bytes() {
        counts[b as usize] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|&&c| c != 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Classify a single extracted string. Returns None if no rule matches.
pub fn classify(text: &str) -> Option<Classification> {
    let e = entropy_of(text);
    // Secret patterns take priority
    let candidates = secret_candidates(text);
    for (idx, (name, re)) in secret_compiled().iter().enumerate() {
        if candidates & (1u64 << idx) == 0 {
            continue;
        }
        if re.is_match(text) {
            if *name == "GENERIC_SECRET" {
                // only classify if entropy reasonable? keep as-is
            }
            return Some(Classification {
                group: "SECRET",
                typ: name,
            });
        }
    }
    // existing rules...
    for (rule, re) in compiled_rules() {
        if re.is_match(text) {
            if rule.min_entropy > 0.0 && e < rule.min_entropy {
                continue;
            }
            if rule.require_digit && !text.bytes().any(|b| b.is_ascii_digit()) {
                continue;
            }
            return Some(Classification {
                group: rule.group,
                typ: rule.typ,
            });
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
    /// The pre-prefilter implementation, kept as the reference for equivalence tests.
    fn detect_secrets_reference(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (name, re) in secret_compiled() {
            for m in re.find_iter(text) {
                let val = m.as_str().to_string();
                if seen.insert(val.clone()) {
                    out.push((name.to_string(), val));
                }
            }
        }
        out
    }

    fn detect_pairs(text: &str) -> Vec<(String, String)> {
        detect_secrets(text)
            .into_iter()
            .map(|m| (m.typ.to_string(), m.value))
            .collect()
    }

    #[test]
    fn prefilter_is_equivalent_to_running_every_regex() {
        let samples = [
            "AKIAIOSFODNN7EXAMPLE",
            "akiaiosfodnn7example",
            "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
            "github_pat_11ABCDEFG0123456789_abcdefghij",
            "sk-abcdefghijklmnopqrstuvwxyz012345",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "SK0123456789abcdef0123456789abcde",
            "sk_live_abcdefghijklmnopqrstuv",
            "xoxb-123456789012-abcdefghij",
            "https://hooks.slack.com/services/T000/B000/XXXX",
            "SG.abcdefghijklmnopqrstu.abcdefghijklmnopqrstu",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "postgres://user:pw@db.example.com:5432/app",
            "MONGODB://u:p@host/db",
            "PASSWORD=hunter2hunter2",
            "Api_Key: abcdef123456",
            "token=abc",
            "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "AZURE storage account key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "https://example.com/x?foo=1&sig=abcdefghijklmnopqrstuvwx",
            "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM.abcdef.abcdefghijklmnopqrstuvwxyz0",
            "hello world this is a plain sentence",
            "",
            "SK",
            // non-ASCII: (?i) is Unicode-aware, the automaton is not
            "\u{17F}ecret=abcdefgh1234",
            "to\u{212A}en=abcdefgh1234",
            "pa\u{17F}\u{17F}word=abcdefgh1234",
        ];
        for text in samples {
            assert_eq!(
                detect_pairs(text),
                detect_secrets_reference(text),
                "text: {text:?}"
            );
        }
        // pseudo-random mixes of anchors and noise
        let atoms = [
            "AKIA",
            "ghp_",
            "sk-",
            "SK",
            "eyJ",
            ".",
            "=",
            ":",
            "token",
            "SECRET",
            "passwd",
            "redis",
            "://",
            "SG.",
            "aws",
            "xoxb-",
            "Azure",
            "key",
            "ABCDEFGHIJKLMNOPQRST",
            "0123456789abcdef0123456789abcdef",
            "-----BEGIN ",
            "PRIVATE KEY-----",
            " ",
            "x",
        ];
        let mut state = 0x2545F4914F6CDD1Du64;
        for _ in 0..4000 {
            let mut text = String::new();
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let parts = 1 + (state % 7) as usize;
            for _ in 0..parts {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                text.push_str(atoms[(state % atoms.len() as u64) as usize]);
            }
            assert_eq!(
                detect_pairs(&text),
                detect_secrets_reference(&text),
                "text: {text:?}"
            );
        }
    }

    #[test]
    fn every_secret_pattern_has_an_anchor_entry() {
        // Not required for correctness (missing entries are always run) but it is
        // what makes the prefilter effective, so keep the tables in sync.
        for (name, _) in SECRET_PATTERNS {
            let anchored = SECRET_ANCHORS.iter().any(|(n, _)| n == name);
            let gated = SECRET_MIN_LEN.iter().any(|(n, _)| n == name);
            assert!(
                anchored || gated,
                "{name} has neither anchors nor a length gate"
            );
        }
        for (name, _) in SECRET_ANCHORS {
            assert!(
                SECRET_PATTERNS.iter().any(|(n, _)| n == name),
                "stale anchor entry {name}"
            );
        }
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

    #[test]
    fn detailed_secret_findings_carry_span_and_scores() {
        let text = "config: AKIAIOSFODNN7EXAMPLE trailing";
        let findings = detect_secrets_detailed(text);
        let aws = findings
            .iter()
            .find(|f| f.rule == "AWS_ACCESS_KEY")
            .expect("AWS key should be detected");
        assert_eq!(aws.value, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(&text[aws.start..aws.end], aws.value);
        assert!(aws.confidence >= 0.9);
        assert_eq!(aws.severity, "high");
    }

    #[test]
    fn detect_secrets_matches_detailed_rules() {
        let text = "password=hunter2hunter2 and AKIAIOSFODNN7EXAMPLE";
        let flat: Vec<(&str, String)> = detect_secrets(text)
            .into_iter()
            .map(|m| (m.typ, m.value))
            .collect();
        let rich: Vec<(&str, String)> = detect_secrets_detailed(text)
            .into_iter()
            .map(|f| (f.rule, f.value))
            .collect();
        assert_eq!(flat, rich);
    }

    #[test]
    fn context_around_clips_and_handles_multibyte() {
        let text = "αβγδε hello world ζηθικλ";
        let start = text.find("hello").unwrap();
        let context = context_around(text, start, start + 5, 4);
        assert!(context.contains("hello"));
        assert!(context.starts_with("..."));
        assert!(context.ends_with("..."));

        let all = context_around(text, 0, text.len(), 64);
        assert_eq!(all, text);
    }

    #[test]
    fn generic_secret_is_low_confidence() {
        let findings = detect_secrets_detailed("password=hunter2hunter2");
        let generic = findings
            .iter()
            .find(|f| f.rule == "GENERIC_SECRET")
            .expect("generic secret should be detected");
        assert_eq!(generic.severity, "low");
        assert!(generic.confidence < 0.5);
    }
}
