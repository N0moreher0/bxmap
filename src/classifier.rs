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
        "GENERIC_SECRET"
        | "DOMAIN"
        | "BASE64_DECODED"
        | "PUBLIC_CLIENT_KEY"
        | "GOOGLE_OAUTH_CLIENT_ID" => "low",
        "AWS_SECRET_KEY"
        | "AZURE_SAS_TOKEN"
        | "PAYPAL_CLIENT_SECRET"
        | "TWILIO_AUTH_TOKEN"
        | "GOOGLE_API_KEY"
        | "CREDIT_CARD"
        | "BTC_SEGWIT"
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
        // A name=value hit is a triage hint, not proof: keep it low enough
        // that strict mode and confidence filters discard it by default.
        "GENERIC_SECRET" => 0.20,
        "DOMAIN" => 0.60,
        "BASE64_DECODED" => 0.50,
        "PUBLIC_CLIENT_KEY" => 0.30,
        // A Google OAuth client id is a public identifier, never a secret.
        "GOOGLE_OAUTH_CLIENT_ID" => 0.20,
        // AIza keys are usually browser-embedded public client keys; a
        // server-side key can be escalated by the analyst after review.
        "GOOGLE_API_KEY" => 0.50,
        "URL" => 0.85,
        "IPV4" | "IPV6" => 0.90,
        "AWS_SECRET_KEY" | "AZURE_SAS_TOKEN" | "PAYPAL_CLIENT_SECRET" | "TWILIO_AUTH_TOKEN" => 0.75,
        // Checksum-verified, but a card number in a dump may still be a test
        // value, so do not claim the same certainty as a cloud credential.
        "CREDIT_CARD" => 0.90,
        "BTC_SEGWIT" => 0.90,
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
    ("AWS_ACCESS_KEY", r"\bAKIA[0-9A-Z]{16}\b"),
    (
        "AWS_SECRET_KEY",
        r"(?i)aws.{0,20}secret.{0,20}[A-Za-z0-9/+=]{30,}",
    ),
    ("GOOGLE_API_KEY", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    (
        "GOOGLE_OAUTH_CLIENT_ID",
        r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    ),
    (
        "AZURE_STORAGE_KEY",
        r"(?i)azure.{0,20}(?:storage|account).{0,20}key.{0,20}[A-Za-z0-9+/=]{40,}",
    ),
    (
        "AZURE_SAS_TOKEN",
        r#"(?i)https?://[a-z0-9.-]+\.(?:blob|queue|table|file)\.core\.windows\.net/[^\s"'<>]*[?&]sig=[A-Za-z0-9%+/=_-]{20,}"#,
    ),
    ("GITHUB_PAT_CLASSIC", r"\bghp_[A-Za-z0-9]{36,}\b"),
    (
        "GITHUB_FINE_GRAINED_PAT",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    ),
    ("GITHUB_OAUTH_TOKEN", r"\bgho_[A-Za-z0-9]{36,}\b"),
    ("GITHUB_APP_TOKEN", r"\b(?:ghu|ghs)_[A-Za-z0-9]{36,}\b"),
    ("GITLAB_PAT", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    ("NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{36,}\b"),
    ("OPENAI_API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b"),
    ("ANTHROPIC_API_KEY", r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    ("HUGGINGFACE_TOKEN", r"\bhf_[A-Za-z0-9]{20,}\b"),
    ("DEEPSEEK_API_KEY", r"\bsk-[A-Za-z0-9]{20,}\b"),
    (
        "STRIPE_SECRET_KEY",
        r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b",
    ),
    (
        "STRIPE_PUBLISHABLE_KEY",
        r"\bpk_(?:live|test)_[A-Za-z0-9]{20,}\b",
    ),
    (
        "STRIPE_RESTRICTED_KEY",
        r"\brk_(?:live|test)_[A-Za-z0-9]{20,}\b",
    ),
    (
        "PAYPAL_CLIENT_SECRET",
        r"(?i)paypal.{0,20}secret.{0,20}[A-Za-z0-9]{20,}",
    ),
    ("SLACK_BOT_TOKEN", r"\bxoxb-[0-9A-Za-z-]{20,}\b"),
    ("SLACK_USER_TOKEN", r"\bxoxp-[0-9A-Za-z-]{20,}\b"),
    (
        "SLACK_WEBHOOK",
        r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    ),
    (
        "DISCORD_BOT_TOKEN",
        r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
    ),
    ("TWILIO_API_KEY_SID", r"\bSK[0-9a-fA-F]{32}\b"),
    (
        "TWILIO_AUTH_TOKEN",
        r"(?i)twilio.{0,20}auth.{0,20}token.{0,20}[0-9a-f]{32}",
    ),
    (
        "SENDGRID_API_KEY",
        r"\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
    ),
    (
        "JWT_TOKEN",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
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
                let re =
                    Regex::new(pat).unwrap_or_else(|_| panic!("invalid regex for rule {name}"));
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

/// Values that show up next to `token=`/`password=` in manifests, JavaScript
/// and Windows API names but are not credentials.
const NON_SECRET_VALUES: &[&str] = &[
    "true",
    "false",
    "null",
    "none",
    "nil",
    "undefined",
    "function",
    "password",
    "passwd",
    "token",
    "secret",
    "apikey",
    "api_key",
    // Strong-name public key tokens from .NET manifests.
    "6595b64144ccf1df",
    "31bf3856ad364e35",
    "1122334455667788",
    "b77a5c561934e089",
    "cc7b13ffcd2ddd51",
];

/// Domains that indicate a Google API key (`AIza...`) is embedded in a
/// browser/mobile client request rather than being a server-side secret.
/// When an `AIza` key appears near one of these domains, it is labeled
/// `public-client-key` with low confidence.
const PUBLIC_CLIENT_KEY_DOMAINS: &[&str] = &[
    "clients1.google.com",
    "clients2.google.com",
    "clients3.google.com",
    "clients4.google.com",
    "clients5.google.com",
    "clients6.google.com",
    "clients7.google.com",
    "clients8.google.com",
    "clients9.google.com",
];

/// Check if a match at `[start, end)` in `text` appears in a public-client
/// context (near a Google client domain within ~200 bytes). If so, an
/// `AIza...` key is likely embedded in a client-side request and should be
/// labeled `public-client-key` with low confidence instead of `GOOGLE_API_KEY`.
fn is_public_client_key_context(text: &str, start: usize, end: usize) -> bool {
    let radius = 200usize;
    let left = start.saturating_sub(radius);
    let right = text.len().min(end + radius);
    if !text.is_char_boundary(left) || !text.is_char_boundary(right) {
        return false;
    }
    let context = &text[left..right];
    let lower = context.to_ascii_lowercase();
    PUBLIC_CLIENT_KEY_DOMAINS
        .iter()
        .any(|domain| lower.contains(domain))
}

/// Decide whether the value after a generic `password=`/`token:` prefix looks
/// like a credential instead of an identifier, keyword or JavaScript snippet.
fn generic_secret_plausible(full_match: &str) -> bool {
    let value = match full_match.find(['=', ':']) {
        Some(index) => full_match[index + 1..].trim(),
        None => full_match.trim(),
    };
    let value = value
        .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | ']' | '}' | '>' | '<'));
    // Real credentials are compact tokens. Prose, short counters and single
    // query parameters all fail this length gate before anything else.
    if value.len() < 12 {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if NON_SECRET_VALUES.contains(&lower.as_str()) {
        return false;
    }
    // Structural characters mean we caught a query string, path, JSON/XML
    // fragment or code snippet instead of one credential value.
    if value.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\''
                    | ','
                    | ';'
                    | '&'
                    | '\\'
                    | '%'
                    | '{'
                    | '}'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '<'
                    | '>'
                    | '|'
            )
    }) {
        return false;
    }
    // A UUID is an identifier, not a credential.
    if value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return false;
    }
    // JavaScript / code fragments.
    if lower.starts_with("function") || value.contains("=>") {
        return false;
    }
    // CamelCase identifiers such as GetTokenInformation2 are API names.
    let has_underscore = value.contains('_');
    let camel_case = value
        .as_bytes()
        .windows(2)
        .any(|w| w[0].is_ascii_lowercase() && w[1].is_ascii_uppercase());
    if camel_case && !has_underscore {
        return false;
    }
    // Short all-hex values are GUID/CLSID halves and .NET assembly public
    // key tokens (b77a5c561934e089), not credentials. Real hex keys (MD5,
    // SHA-1/256, HMAC) are 32+ characters.
    if value.len() < 24 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let has_digit = value.bytes().any(|b| b.is_ascii_digit());
    let has_symbol = value
        .bytes()
        .any(|b| !b.is_ascii_alphanumeric() && b != b'_');
    let identifier = value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    // Identifier-shaped words like GetTokenInformation, Malloc, DigiCert.
    if identifier && !has_digit && value.len() < 24 {
        return false;
    }
    // Short alphabetic words are natural language, not keys.
    if !has_digit && !has_symbol && value.len() < 20 {
        return false;
    }
    // Low-entropy values (repeated words, counters) are not credentials.
    if entropy_of(value) < 2.5 {
        return false;
    }
    true
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
            if *name == "GENERIC_SECRET" && !generic_secret_plausible(&val) {
                continue;
            }
            // An `AIza...` key appearing near a Google client domain (e.g.
            // clients6.google.com) is a public client key, not a server secret.
            if *name == "GOOGLE_API_KEY" && is_public_client_key_context(text, m.start(), m.end()) {
                if seen.insert(val.clone()) {
                    out.push(SecretFinding {
                        rule: "PUBLIC_CLIENT_KEY",
                        value: val,
                        start: m.start(),
                        end: m.end(),
                        confidence: confidence_for("PUBLIC_CLIENT_KEY"),
                        severity: severity_for("PUBLIC_CLIENT_KEY"),
                    });
                }
                continue;
            }
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
            .expect("invalid regex for rule PRIVATE_KEY_BLOCK")
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
    Rule {
        group: "CRYPTO",
        typ: "BTC_SEGWIT",
        // bech32/bech32m addresses: `bc1` + data part (charset excludes 1, b, i, o)
        pattern: r"(?i)\bbc1[023456789acdefghjklmnpqrstuvwxyz]{11,71}\b",
        min_entropy: 0.0,
        require_digit: false,
    },
    // ---- FINANCE ----
    Rule {
        group: "FINANCE",
        typ: "CREDIT_CARD",
        // 13-19 digits, optionally grouped with spaces or dashes. A plain digit
        // run of another length is not matched, so long ids/timestamps stay out.
        pattern: r"\b(?:\d[ -]?){12,18}\d\b",
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
                let re = Regex::new(r.pattern)
                    .unwrap_or_else(|_| panic!("invalid regex for rule {}", r.typ));
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

/// Literal anchors for the `RULES` table: every match of the named rule MUST
/// contain at least one of these substrings (compared ASCII case-insensitively,
/// which only ever over-selects). A single Aho-Corasick pass over the text then
/// tells us which rules can possibly match, instead of running all of them on
/// every extracted string. A rule with no anchor entry is simply always run, so
/// forgetting an entry costs speed, never correctness.
const RULE_ANCHORS: &[(&str, &[&str])] = &[
    ("AWS_KEY", &["AKIA"]),
    ("AWS_SECRET", &["aws", "secret"]),
    ("GITHUB_TOKEN", &["gh"]),
    ("JWT", &["eyJ"]),
    ("PRIVATE_KEY", &["-----BEGIN"]),
    ("AZURE_KEY", &["azure"]),
    ("GCP_KEY", &["AIza"]),
    // The generic rule matches `password|passwd|secret|token|apikey|api_key`
    // followed by `=` or `:`; these four literals cover all six alternatives.
    ("GENERIC_SECRET", &["pass", "secret", "token", "api"]),
    ("URL", &["://"]),
    ("IPV4", &["."]),
    ("DOMAIN", &["."]),
    ("EMAIL", &["@"]),
    ("ETH_ADDR", &["0x"]),
    ("BTC_SEGWIT", &["bc1"]),
    (
        "SUSPICIOUS_PATH",
        &["\\temp", "\\appdata", "\\startup", "\\public"],
    ),
    ("MUTEX", &["global"]),
    ("C2", &["c2", "gate.php", "/panel/", "/admin/"]),
];

/// Minimum byte length of any possible match, per rule (derived from the
/// regex). Lets us skip rules that cannot match a short string.
const RULE_MIN_LEN: &[(&str, usize)] = &[
    ("BTC_ADDR", 26),    // '1'/'3' + 25..34 base58 characters
    ("XMR_ADDR", 95),    // '4' + 1 + 93 base58 characters
    ("CREDIT_CARD", 13), // 13 digits
    ("BASE64", 16),      // 4 groups of 4
];

/// Prefilter for the `RULES` table, same idea as [`SecretPrefilter`] but for
/// the second (non-secret) rule set.
struct RulePrefilter {
    ac: AhoCorasick,
    /// Aho-Corasick pattern id -> bitmask of `RULES` indices it enables.
    anchor_masks: Vec<u64>,
    /// Rules without anchors: candidates for every string.
    always: u64,
    /// Every rule (used for non-ASCII text, see `rule_candidates`).
    all: u64,
    /// (rule index, min byte length) gates.
    gates: Vec<(usize, usize)>,
}

fn rule_prefilter() -> &'static RulePrefilter {
    static PREFILTER: OnceLock<RulePrefilter> = OnceLock::new();
    PREFILTER.get_or_init(|| {
        let count = RULES.len();
        assert!(count <= 64, "rule prefilter uses a u64 bitmask");
        let all = if count == 64 {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };
        let mut anchors: Vec<&str> = Vec::new();
        let mut anchor_masks: Vec<u64> = Vec::new();
        let mut anchored = 0u64;
        let mut gates = Vec::new();
        for (idx, rule) in RULES.iter().enumerate() {
            if let Some((_, lits)) = RULE_ANCHORS.iter().find(|(n, _)| n == &rule.typ) {
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
            if let Some((_, min)) = RULE_MIN_LEN.iter().find(|(n, _)| n == &rule.typ) {
                gates.push((idx, *min));
            }
        }
        let ac = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&anchors)
            .expect("rule anchors form a valid automaton");
        RulePrefilter {
            ac,
            anchor_masks,
            always: all & !anchored,
            all,
            gates,
        }
    })
}

/// Bitmask over `RULES` of the rules that can possibly match `text`.
fn rule_candidates(text: &str) -> u64 {
    let pf = rule_prefilter();
    // `(?i)` in the regexes is Unicode-aware (e.g. U+017F folds to 's') while
    // the automaton only folds ASCII, so for non-ASCII text we keep every rule
    // as a candidate.
    let mut mask = if text.is_ascii() {
        let mut mask = pf.always;
        for m in pf.ac.find_overlapping_iter(text) {
            mask |= pf.anchor_masks[m.pattern().as_usize()];
        }
        mask
    } else {
        pf.all
    };
    for &(idx, min) in &pf.gates {
        if text.len() < min {
            mask &= !(1u64 << idx);
        }
    }
    mask
}

/// Rules whose validation is a checksum or issuer check.
///
/// When such a check fails the value is definitely not of that type, so
/// classification moves on to the next rule instead of labelling it. Structural
/// checks (JWT shape, signed URLs) are deliberately *not* listed: they also
/// reject genuine secrets that were truncated in the dump, so they only lower
/// the reported confidence.
const CHECKSUM_RULES: &[&str] = &["BTC_ADDR", "BTC_SEGWIT", "CREDIT_CARD"];

fn checksum_ok(rule: &str, value: &str) -> bool {
    if !CHECKSUM_RULES.contains(&rule) {
        return true;
    }
    validate_finding(rule, value) != ValidationResult::Invalid
}

/// Run the non-secret rule set over `text` and return `(group, type)` of the
/// first rule that matches.
///
/// With `prefilter` enabled, rules whose literal anchors are absent from the
/// text (or whose minimum match length exceeds it) are skipped. The prefilter
/// only ever removes rules that cannot match, so the outcome is identical to
/// running every rule.
fn classify_rules(text: &str, prefilter: bool) -> Option<(&'static str, &'static str)> {
    let e = entropy_of(text);
    let candidates = if prefilter {
        rule_candidates(text)
    } else {
        u64::MAX
    };
    for (idx, (rule, re)) in compiled_rules().iter().enumerate() {
        if candidates & (1u64 << idx) == 0 {
            continue;
        }
        if let Some(matched) = re.find(text) {
            if rule.typ == "GENERIC_SECRET" && !generic_secret_plausible(matched.as_str()) {
                continue;
            }
            if rule.min_entropy > 0.0 && e < rule.min_entropy {
                continue;
            }
            if rule.require_digit && !text.bytes().any(|b| b.is_ascii_digit()) {
                continue;
            }
            // A checksum or issuer check that fails means this is not the
            // type the pattern suggests: keep looking instead of labelling it.
            if !checksum_ok(rule.typ, matched.as_str()) {
                continue;
            }
            return Some((rule.group, rule.typ));
        }
    }
    None
}

/// Classify a single extracted string. Returns None if no rule matches.
pub fn classify(text: &str) -> Option<Classification> {
    let candidates = secret_candidates(text);
    for (idx, (name, re)) in secret_compiled().iter().enumerate() {
        if candidates & (1u64 << idx) == 0 {
            continue;
        }
        if let Some(matched) = re.find(text) {
            if *name == "GENERIC_SECRET" && !generic_secret_plausible(matched.as_str()) {
                continue;
            }
            if !checksum_ok(name, matched.as_str()) {
                continue;
            }
            // An `AIza...` key near a Google client domain is a public client key.
            if *name == "GOOGLE_API_KEY"
                && is_public_client_key_context(text, matched.start(), matched.end())
            {
                return Some(Classification {
                    group: "SECRET",
                    typ: "PUBLIC_CLIENT_KEY",
                });
            }
            return Some(Classification {
                group: "SECRET",
                typ: name,
            });
        }
    }
    // existing rules...
    let (group, typ) = classify_rules(text, true)?;
    Some(Classification { group, typ })
}

/// Default group/type for strings that don't match any rule.
pub const DEFAULT_GROUP: &str = "STRING";
pub const DEFAULT_TYPE: &str = "GENERIC";

/// Validation result for a detected secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    /// The value passed validation (checksum, structure, etc.)
    Valid,
    /// The value failed validation (e.g., invalid checksum)
    Invalid,
    /// Validation not applicable or not implemented for this type
    NotApplicable,
}

/// Validate Base58Check encoding (used in Bitcoin addresses, etc.)
/// Returns true if the checksum is valid.
pub fn validate_base58check(encoded: &str) -> ValidationResult {
    use sha2::{Digest, Sha256};

    // Base58 alphabet
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Count leading '1's (which are value 0 in base58)
    let leading_ones = encoded.chars().take_while(|&c| c == '1').count();

    // Decode the rest
    let mut num = Vec::new();
    for ch in encoded[leading_ones..].chars() {
        match ALPHABET.iter().position(|&b| b as char == ch) {
            Some(p) => num.push(p as u32),
            None => return ValidationResult::Invalid,
        }
    }

    // Convert from base-58 to base-256 (big-endian)
    let mut bytes = Vec::new();
    for &digit in &num {
        let mut carry = digit;
        for byte in bytes.iter_mut().rev() {
            let val = (*byte as u32) * 58 + carry;
            *byte = (val & 0xFF) as u8;
            carry = val >> 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    bytes.reverse();

    // Add leading zero bytes for each leading '1'
    let mut result = vec![0u8; leading_ones];
    result.extend(bytes);

    if result.len() < 4 {
        return ValidationResult::Invalid;
    }

    // Verify checksum: last 4 bytes = first 4 bytes of SHA256(SHA256(payload))
    let (payload, checksum) = result.split_at(result.len() - 4);
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);

    if &hash2[0..4] == checksum {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate Bech32 encoding (used in Bitcoin SegWit, etc.)
/// Returns true if the checksum is valid.
pub fn validate_bech32(encoded: &str) -> ValidationResult {
    // Bech32 charset (BIP-173)
    const CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    // Bech32 generator polynomial
    const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    let encoded = encoded.to_lowercase();

    // Find the separator (last '1')
    let sep_pos = match encoded.rfind('1') {
        Some(pos) if pos < encoded.len() - 1 => pos,
        _ => return ValidationResult::Invalid,
    };

    // HRP (human-readable part) - not used in checksum but must be valid ASCII
    let _hrp = &encoded[..sep_pos];
    let data_part = &encoded[sep_pos + 1..];

    if data_part.len() < 6 {
        return ValidationResult::Invalid;
    }

    // Expand HRP for checksum
    let mut values = Vec::with_capacity(data_part.len() + _hrp.len() + 1);

    // Add HRP (lowercase, high bits then low bits)
    for ch in _hrp.chars() {
        if ch as u32 > 127 {
            return ValidationResult::Invalid;
        }
        values.push((ch as u32) >> 5);
    }
    values.push(0); // separator
    for ch in _hrp.chars() {
        values.push((ch as u32) & 0x1f);
    }

    // Add data part
    for ch in data_part.chars() {
        match CHARSET.find(ch) {
            Some(idx) => values.push(idx as u32),
            None => return ValidationResult::Invalid,
        }
    }

    // Verify checksum using Bech32 polynomial
    let mut chk = 1u32;
    for &v in &values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        #[allow(clippy::needless_range_loop)]
        for i in 0..5 {
            if (top >> i) & 1 == 1 {
                chk ^= GENERATOR[i];
            }
        }
    }

    if chk == 1 {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate using Luhn algorithm (credit card numbers, IMEI, etc.)
/// Returns true if the checksum is valid.
pub fn validate_luhn(number: &str) -> ValidationResult {
    let digits: Vec<u32> = number
        .bytes()
        .filter_map(|b| {
            if b.is_ascii_digit() {
                Some((b - b'0') as u32)
            } else {
                None
            }
        })
        .collect();

    if digits.len() < 2 {
        return ValidationResult::Invalid;
    }

    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut val = if double { d * 2 } else { d };
        if val > 9 {
            val -= 9;
        }
        sum += val;
        double = !double;
    }

    if sum % 10 == 0 {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate a payment card number.
///
/// A random 16-digit string is not a card number: it must also carry a known
/// issuer prefix. The check is therefore length + issuer + Luhn checksum.
pub fn validate_credit_card(value: &str) -> ValidationResult {
    let card_chars = value
        .chars()
        .all(|c| c.is_ascii_digit() || c == ' ' || c == '-');
    if value.is_empty() || !card_chars {
        return ValidationResult::Invalid;
    }
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if !(13..=19).contains(&digits.len()) {
        return ValidationResult::Invalid;
    }
    if !card_issuer_prefix_ok(&digits) {
        return ValidationResult::Invalid;
    }
    validate_luhn(&digits)
}

/// Known card issuer prefixes (IIN ranges).
///
/// Only used to separate real card numbers from arbitrary digit strings; the
/// checksum does the rest.
fn card_issuer_prefix_ok(digits: &str) -> bool {
    let b = digits.as_bytes();
    if b.len() < 2 {
        return false;
    }
    let starts2 = |a: u8, c: u8| b.len() >= 2 && b[0] == a && b[1] == c;
    let num = |from: usize, len: usize| -> Option<u32> {
        if b.len() < from + len {
            return None;
        }
        digits.get(from..from + len)?.parse::<u32>().ok()
    };

    // Visa
    if b[0] == b'4' {
        return true;
    }
    // Mastercard: 51-55 and 2221-2720
    if matches!(num(0, 2), Some(51..=55)) {
        return true;
    }
    if matches!(num(0, 4), Some(2221..=2720)) {
        return true;
    }
    // American Express: 34, 37
    if starts2(b'3', b'4') || starts2(b'3', b'7') {
        return true;
    }
    // Discover: 6011 and 65
    if num(0, 4) == Some(6011) || starts2(b'6', b'5') {
        return true;
    }
    // Discover: 644-649
    if matches!(num(0, 3), Some(644..=649)) {
        return true;
    }
    // Discover: 622126-622925
    if matches!(num(0, 6), Some(622126..=622925)) {
        return true;
    }
    // JCB: 3528-3589
    if matches!(num(0, 4), Some(3528..=3589)) {
        return true;
    }
    // Diners Club: 300-305
    if matches!(num(0, 3), Some(300..=305)) {
        return true;
    }
    // Diners Club: 36 and 38
    if starts2(b'3', b'6') || starts2(b'3', b'8') {
        return true;
    }
    // UnionPay: 62
    if starts2(b'6', b'2') {
        return true;
    }
    false
}

/// Validate JWT structure (decode header/payload, basic checks)
/// Returns ValidationResult::Valid if structure is valid and not expired (if exp present)
pub fn validate_jwt(token: &str) -> ValidationResult {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return ValidationResult::Invalid;
    }

    // Decode header
    let header_bytes = match URL_SAFE_NO_PAD.decode(parts[0]) {
        Ok(b) => b,
        Err(_) => return ValidationResult::Invalid,
    };

    // Decode payload
    let payload_bytes = match URL_SAFE_NO_PAD.decode(parts[1]) {
        Ok(b) => b,
        Err(_) => return ValidationResult::Invalid,
    };

    // Parse header as JSON
    let header: serde_json::Value = match serde_json::from_slice(&header_bytes) {
        Ok(v) => v,
        Err(_) => return ValidationResult::Invalid,
    };

    // Parse payload as JSON
    let payload: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return ValidationResult::Invalid,
    };

    // `alg` is mandatory (RFC 7519), `typ` is optional -- plenty of issuers
    // omit it, so requiring it would reject real tokens.
    let Some(alg) = header.get("alg").and_then(|v| v.as_str()) else {
        return ValidationResult::Invalid;
    };
    if alg.is_empty() {
        return ValidationResult::Invalid;
    }

    // The signature segment must be base64url. An empty signature is only
    // allowed for the unsecured `alg: none`.
    if parts[2].is_empty() {
        if alg != "none" {
            return ValidationResult::Invalid;
        }
    } else if URL_SAFE_NO_PAD.decode(parts[2]).is_err() {
        return ValidationResult::Invalid;
    }

    // Check if expired (exp claim)
    if let Some(exp) = payload.get("exp") {
        if let Some(exp_ts) = exp.as_u64() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if exp_ts < now {
                return ValidationResult::Invalid; // Expired
            }
        }
    }

    ValidationResult::Valid
}

/// Validate an Azure SAS token: the URL must point at an Azure storage host
/// and carry a non-trivial `sig=`. YouTube and other signed URLs use the same
/// query parameter name, so the host check is what separates them.
fn validate_azure_sas(value: &str) -> ValidationResult {
    let lower = value.to_ascii_lowercase();
    let azure_host = [
        ".blob.core.windows.net",
        ".queue.core.windows.net",
        ".table.core.windows.net",
        ".file.core.windows.net",
    ]
    .iter()
    .any(|host| lower.contains(host));
    let has_sig = lower.contains("sig=") && value.len() >= 40;
    if azure_host && has_sig {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate an AWS access key ID: starts with `AKIA` or `ASIA` and is exactly
/// 20 characters. No checksum exists for AWS keys, so prefix + length is the
/// only structural check available.
fn validate_aws_key(value: &str) -> ValidationResult {
    let len = value.len();
    if (value.starts_with("AKIA") || value.starts_with("ASIA")) && len == 20 {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate a GitHub token: known prefixes with a minimum total length.
fn validate_github_token(value: &str) -> ValidationResult {
    let ok = (value.starts_with("ghp_")
        || value.starts_with("gho_")
        || value.starts_with("ghu_")
        || value.starts_with("ghs_")
        || value.starts_with("github_pat_"))
        && value.len() >= 40;
    if ok {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Validate a Slack token: `xoxb-`, `xoxp-`, `xoxo-`, or `xoxr-` prefix with
/// a minimum total length. Slack webhook URLs (`https://hooks.slack.com/...`)
/// are also accepted.
fn validate_slack_token(value: &str) -> ValidationResult {
    if value.starts_with("https://hooks.slack.com/services/") && value.len() >= 40 {
        return ValidationResult::Valid;
    }
    let ok = (value.starts_with("xoxb-")
        || value.starts_with("xoxp-")
        || value.starts_with("xoxo-")
        || value.starts_with("xoxr-"))
        && value.len() >= 25;
    if ok {
        ValidationResult::Valid
    } else {
        ValidationResult::Invalid
    }
}

/// Run validation checks based on the rule type.
///
/// `ETH_ADDR` intentionally returns [`ValidationResult::NotApplicable`]: EIP-55
/// checksum validation requires a keccak256 dependency which is not in the lite
/// dependency set. Bech32 is *not* used for Ethereum addresses.
pub fn validate_finding(rule: &str, value: &str) -> ValidationResult {
    match rule {
        "BTC_ADDR" => validate_base58check(value),
        "BTC_SEGWIT" => validate_bech32(value),
        "ETH_ADDR" => ValidationResult::NotApplicable,
        "AWS_ACCESS_KEY" => validate_aws_key(value),
        "AZURE_SAS_TOKEN" => validate_azure_sas(value),
        "GENERIC_SECRET" => {
            if generic_secret_plausible(value) {
                ValidationResult::Valid
            } else {
                ValidationResult::Invalid
            }
        }
        "GITHUB_PAT_CLASSIC"
        | "GITHUB_FINE_GRAINED_PAT"
        | "GITHUB_OAUTH_TOKEN"
        | "GITHUB_APP_TOKEN" => validate_github_token(value),
        "SLACK_BOT_TOKEN" | "SLACK_USER_TOKEN" | "SLACK_WEBHOOK" => validate_slack_token(value),
        "JWT" | "JWT_TOKEN" => validate_jwt(value),
        "CREDIT_CARD" => validate_credit_card(value),
        _ => ValidationResult::NotApplicable,
    }
}

/// Enumeration of detected encryption containers (Phase 8.4).
///
/// Represents well-known encrypted container formats that can be identified
/// by their magic bytes without attempting decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptedContainer {
    /// BitLocker Drive Encryption (Windows)
    /// Signature: -FVE-FS- in volume information
    BitLocker,
    /// LUKS (Linux Unified Key Setup)
    /// Magic bytes: 0x43 0x4C 0x55 0x53 0x00 0x61
    LUKS,
    /// OpenSSL Encrypted Data
    /// Signature: "Salted__" (8 bytes)
    OpenSSL,
    /// PGP (Pretty Good Privacy) container
    /// "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    PGP,
    /// VeraCrypt/TrueCrypt containers
    /// UUID magic (first 16 bytes)
    VeraCrypt,
    /// Encrypted archive (ZIP, 7z, RAR)
    EncryptedArchive,
}

/// Detect if binary data contains a known encryption shell/container signature.
///
/// This is a **read-only detection** (Phase 8.4): checks for known magic bytes
/// and signatures without attempting decryption.
///
/// # Arguments
/// * `input` - Raw bytes to scan
///
/// # Returns
/// * Some(EncryptedContainer) - type of detected container
/// * None - no known container signature found
pub fn detect_encryption_shell(input: &[u8]) -> Option<EncryptedContainer> {
    if input.len() < 12 {
        return None;
    }

    // 1. Detect BitLocker: "-FVE-FS-" signature (ASCII, 8 bytes)
    if input.len() >= 8 {
        let view = std::str::from_utf8(&input[..8]).ok()?;
        if view.contains("-FVE-FS-") {
            return Some(EncryptedContainer::BitLocker);
        }
        if view == "Salted__" {
            return Some(EncryptedContainer::OpenSSL);
        }
    }

    // 2. Detect LUKS: magic bytes "LUKS\x00\x61"
    if input.len() >= 6
        && input[0] == 0x43
        && input[1] == 0x4C
        && input[2] == 0x55
        && input[3] == 0x53
        && input[4] == 0x00
        && input[5] == 0x61
    {
        return Some(EncryptedContainer::LUKS);
    }

    // 3. Detect PGP entry marker
    let pgp_marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    if input.len() >= pgp_marker.len() {
        let view = std::str::from_utf8(&input[..pgp_marker.len()]).ok()?;
        if view.starts_with(pgp_marker) {
            return Some(EncryptedContainer::PGP);
        }
    }

    // 4. Detect VeraCrypt/TrueCrypt: UUID magic (first 12 bytes)
    if input.len() >= 12
        && input[6] == 0x56
        && input[7] == 0x45
        && input[8] == 0x52
        && input[9] == 0x41
    {
        return Some(EncryptedContainer::VeraCrypt);
    }

    None
}

/// Detect BitLocker-specific header within the data.
pub fn detect_bitlocker_header(input: &[u8]) -> bool {
    if input.len() < 8 {
        return false;
    }
    std::str::from_utf8(&input[..8])
        .unwrap_or("")
        .contains("-FVE-FS-")
}

/// Detect LUKS header magic bytes.
pub fn detect_luks_header(input: &[u8]) -> bool {
    input.len() >= 6
        && input[0] == 0x43
        && input[1] == 0x4C
        && input[2] == 0x55
        && input[3] == 0x53
        && input[4] == 0x00
        && input[5] == 0x61
}

/// Detect OpenSSL encrypted format signature.
pub fn detect_openssl_encrypted(input: &[u8]) -> bool {
    if input.len() < 8 {
        return false;
    }
    std::str::from_utf8(&input[..8]) == Ok("Salted__")
}

/// Detect PGP container marker.
pub fn detect_pgp_container(input: &[u8]) -> bool {
    let pgp_marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
    input.len() >= pgp_marker.len()
        && std::str::from_utf8(&input[..pgp_marker.len()])
            .unwrap_or("")
            .starts_with(pgp_marker)
}

/// Detect VeraCrypt/TrueCrypt header (UUID magic pattern).
pub fn detect_veracrypt_header(input: &[u8]) -> bool {
    input.len() >= 12
        && input[6] == 0x56
        && input[7] == 0x45
        && input[8] == 0x52
        && input[9] == 0x41
}

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
                if *name == "GENERIC_SECRET" && !generic_secret_plausible(&val) {
                    continue;
                }
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
            "ghp-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST",
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
    fn every_rule_anchor_entry_points_at_a_real_rule() {
        for (name, _) in RULE_ANCHORS {
            assert!(
                RULES.iter().any(|r| *name == r.typ),
                "stale anchor entry {name}"
            );
        }
        for (name, _) in RULE_MIN_LEN {
            assert!(
                RULES.iter().any(|r| *name == r.typ),
                "stale length gate {name}"
            );
        }
    }

    #[test]
    fn rule_prefilter_skips_rules_whose_anchors_are_absent() {
        let mask = rule_candidates("hello world");
        for (idx, rule) in RULES.iter().enumerate() {
            let anchored = RULE_ANCHORS.iter().any(|(n, _)| n == &rule.typ);
            if anchored {
                assert_eq!(
                    mask & (1u64 << idx),
                    0,
                    "{} should have been skipped",
                    rule.typ
                );
            }
        }
    }

    #[test]
    fn rule_prefilter_is_equivalent_to_running_every_regex() {
        // One representative string per rule plus edge cases: the anchor
        // prefilter must never change which rule matches.
        let samples = [
            "",
            "hello world this is a plain sentence",
            "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_access_key = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            "ghp_012345678901234567890123456789012345",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
            "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
            "azure storage key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
            "PASSWORD=hunter2hunter2",
            "https://example.com/api?q=1",
            "192.168.1.10",
            "example.com",
            "user@example.com",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
            "0x52908400098527886E0F7030069857D2E4169EE7",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "4532015112830366",
            "C:\\temp\\evil",
            "Global\\SomeMutex123",
            "/admin/index",
            "0123456789abcdef0123456789abcdef",
            "\u{17F}ecret=abcdefgh1234",
        ];
        for text in samples {
            assert_eq!(
                classify_rules(text, true),
                classify_rules(text, false),
                "text: {text:?}"
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

    #[test]
    fn generic_secret_rejects_common_false_positives() {
        let samples = [
            "Token: GetTokenInformation",
            "Token: Malloc",
            "Token:DigiCert",
            "Password: false,",
            "ApiKey=function(a){return a}",
            "publicKeyToken=\"6595b64144ccf1df\"",
            "publicKeyToken=\"31bf3856ad364e35\"",
            "token=undefined",
        ];
        for text in samples {
            let found = detect_secrets(text);
            assert!(
                !found.iter().any(|m| m.typ == "GENERIC_SECRET"),
                "false positive for {text:?}: {found:?}"
            );
            assert!(
                classify(text).map_or(true, |c| c.typ != "GENERIC_SECRET"),
                "classify false positive for {text:?}"
            );
        }
    }

    #[test]
    fn generic_secret_keeps_real_looking_values() {
        for text in [
            "password=hunter2hunter2",
            "api_key=abc123def456ghi789",
            "token=sk-live-abc123def456",
            "password=0123456789abcdef0123456789abcdef",
            "Password: correcthorsebatterystaple",
        ] {
            let found = detect_secrets(text);
            assert!(
                found.iter().any(|m| m.typ == "GENERIC_SECRET"),
                "missed plausible secret {text:?}: {found:?}"
            );
        }
    }

    #[test]
    fn azure_sas_requires_azure_host() {
        // YouTube signed URLs use the same ?...&sig= shape and used to be
        // reported as Azure SAS tokens at confidence 0.75.
        let youtube = "https://r1---sn-abc.googlevideo.com/videoplayback?expire=1566225713&ip=137.97.68.29&id=o-abc&sig=ALgxI2wwABCDEFGHIJKLMNOP";
        let found = detect_secrets(youtube);
        assert!(
            !found.iter().any(|m| m.typ == "AZURE_SAS_TOKEN"),
            "YouTube signed URL misreported as Azure SAS: {found:?}"
        );

        let azure = "https://acct.blob.core.windows.net/container/blob?sv=2019-02-02&ss=b&srt=sco&sp=rl&se=2026-01-01T00:00:00Z&sig=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789%2Babc%3D";
        let found = detect_secrets(azure);
        assert!(
            found.iter().any(|m| m.typ == "AZURE_SAS_TOKEN"),
            "real Azure SAS not detected: {found:?}"
        );
        assert_eq!(
            validate_finding("AZURE_SAS_TOKEN", azure),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("AZURE_SAS_TOKEN", youtube),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn fixed_prefix_rules_are_case_sensitive_and_bounded() {
        // Lowercase "akia" appears inside base64 blobs in real memory dumps.
        let found = detect_secrets("lNHAAYGAIAABA8uvE+UbrR4T5tmKAAAAKIAAAAAACAAAAAAAAAAAAwDAAAAAAAFApBwYAQHA1BgcAUGAzBAAAAEAzBAaAUGAsBAbAMDAyAgLAQGAsBAbAwCAtAgMAEDA3AwNAkDAAAAGAAAAyBAAAwBAAAwAAAAAcAAAA0CAAAAOAAAAgBAAAEBAAAwAAAAAsQcNkBBAAAAADpDXVNXZyNHXAAAKAAAACAAAAQBAAAAAAAAAAAgAAwFXT1UQSRlTFRVLQNEXVNXZyNHAT1WYyRnTlRHXQl2Y0VnclNHAQAAAAUAAAA6JAAAA1FAAAwBAAAwCAAAowEo4z4hT2Z0gahZOctzw7WXAAAQmAAAAJAAAg2IAAAQMTB1UirIWGxLT4M0u8PxkmgZbOHHAAAABAAAAA8BAAAwLAAAATBQLAEDAtAQNA0CAyAQMA0CAzAAMAcDAzAQNAcDAwAgNAQDA4AQLAMDAxAANAkDAzAQOAcDA1AANAADAtAgMAIDA2AQOAYDA0AAOAMDAzAgMA0CAxAAMAADAxAAAAAAAAAAAAAAAAAAYAAAADAAAgiFAAAAAAAAAz1WYyRnblRXLwNGAAAAAAgKc1TyfF7gROyteDxqb6wYkiCAhJch6RIopIAwJGjlmoCX9k8XxOYkjcr3Qs6mOMGpoAQYCXoeECaKCAcixYpJAAAAA");
        assert!(
            !found.iter().any(|m| m.typ == "AWS_ACCESS_KEY"),
            "lowercase akia inside base64 matched AWS_ACCESS_KEY: {found:?}"
        );
        // The real uppercase key is still found and passes validation.
        let found = detect_secrets("AKIAIOSFODNN7EXAMPLE");
        assert!(
            found.iter().any(|m| m.typ == "AWS_ACCESS_KEY"),
            "uppercase AWS key missed: {found:?}"
        );
    }

    #[test]
    fn lab6_generic_secret_false_positives_are_rejected() {
        for text in [
            "GetSidFromToken: GetTokenInformation2 failed with %d",
            "Token: GetTokenInformation2",
            "token=470026429&forcesecure=1",
            "Token=\"6595b64144ccf1df\",type=\"win32\",version=\"1.0.7600.16385\"",
            "Secret: status:",
            "publicKeyToken=\"6595b64144ccf1df\"",
            "Token=b03f5f7f11d50a3",
            "Token=b77a5c561934e089",
            "Token=b77a5c561934e08",
            "API_KEY: \"7e40f68c-7938-4c5d-9f95-e61647c213eb\",",
        ] {
            let found = detect_secrets(text);
            assert!(
                !found.iter().any(|m| m.typ == "GENERIC_SECRET"),
                "generic false positive for {text:?}: {found:?}"
            );
            assert_eq!(
                validate_finding("GENERIC_SECRET", text),
                ValidationResult::Invalid,
                "validator accepted false positive {text:?}"
            );
        }
    }

    #[test]
    fn public_rules_are_calibrated_low() {
        assert!(confidence_for("GENERIC_SECRET") <= 0.20);
        assert!(confidence_for("GOOGLE_OAUTH_CLIENT_ID") <= 0.20);
        assert!(confidence_for("GOOGLE_API_KEY") <= 0.50);
        assert_eq!(severity_for("GOOGLE_OAUTH_CLIENT_ID"), "low");
        assert_eq!(severity_for("GOOGLE_API_KEY"), "medium");
        // High-signal, structurally validated rules stay high.
        assert!(confidence_for("AWS_ACCESS_KEY") >= 0.75);
    }

    #[test]
    fn validate_base58check_works() {
        let _ = validate_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let _ = validate_base58check("msf4WtN1YQKXvNtvdFYt7hhTVjF1zKuHkX");
        assert_eq!(
            validate_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
            ValidationResult::Invalid
        );
        assert_eq!(validate_base58check("1A1"), ValidationResult::Invalid);
        assert_eq!(
            validate_base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0"),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn validate_bech32_works() {
        let _ = validate_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        let _ = validate_bech32("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        assert_eq!(
            validate_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
            ValidationResult::Invalid
        );
        assert_eq!(validate_bech32("bc1abc"), ValidationResult::Invalid);
        assert_eq!(
            validate_bech32("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t!"),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn validate_luhn_works() {
        assert_eq!(validate_luhn("4532015112830366"), ValidationResult::Valid);
        assert_eq!(validate_luhn("5555555555554444"), ValidationResult::Valid);
        assert_eq!(validate_luhn("378282246310005"), ValidationResult::Valid);
        assert_eq!(validate_luhn("4532015112830367"), ValidationResult::Invalid);
        assert_eq!(validate_luhn("1"), ValidationResult::Invalid);
        assert_eq!(
            validate_luhn("4532 0151 1283 0366"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_luhn("5555-5555-5555-4444"),
            ValidationResult::Valid
        );
    }

    #[test]
    fn validate_credit_card_checks_length_issuer_and_luhn() {
        // Real test numbers: Visa, Mastercard, Amex.
        assert_eq!(
            validate_credit_card("4532015112830366"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_credit_card("4532 0151 1283 0366"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_credit_card("5555-5555-5555-4444"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_credit_card("378282246310005"),
            ValidationResult::Valid
        );
        // Known issuer, broken checksum.
        assert_eq!(
            validate_credit_card("4532015112830367"),
            ValidationResult::Invalid
        );
        // Valid checksum, but the prefix belongs to no known issuer.
        assert_eq!(
            validate_credit_card("1234567890123452"),
            ValidationResult::Invalid
        );
        // Wrong length and non-digit content.
        assert_eq!(
            validate_credit_card("453201511283036"),
            ValidationResult::Invalid
        );
        assert_eq!(
            validate_credit_card("45320151128303661234"),
            ValidationResult::Invalid
        );
        assert_eq!(
            validate_credit_card("not-a-card-number"),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn credit_card_is_classified_when_checksum_and_issuer_match() {
        let c = classify("4532015112830366").unwrap();
        assert_eq!(c.group, "FINANCE");
        assert_eq!(c.typ, "CREDIT_CARD");
    }

    #[test]
    fn digit_runs_are_not_classified_as_cards() {
        for (text, why) in [
            ("4532015112830367", "Visa prefix, broken checksum"),
            ("1234567890123452", "valid checksum, unknown issuer"),
            ("453201511283036", "too short"),
            ("202411091233445566", "timestamp-like, no issuer prefix"),
        ] {
            assert!(
                classify(text).map_or(true, |c| c.typ != "CREDIT_CARD"),
                "{text:?} ({why}) was classified as a credit card"
            );
        }
    }

    #[test]
    fn segwit_address_is_classified_when_the_bech32_checksum_matches() {
        let c = classify("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
        assert_eq!(c.group, "CRYPTO");
        assert_eq!(c.typ, "BTC_SEGWIT");
    }

    #[test]
    fn addresses_with_a_broken_checksum_are_not_classified_as_crypto() {
        for (text, why) in [
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                "broken bech32",
            ),
            ("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "broken base58check"),
        ] {
            let c = classify(text);
            assert!(
                c.map_or(true, |c| c.typ != "BTC_SEGWIT" && c.typ != "BTC_ADDR"),
                "{text:?} ({why}) was classified as a crypto address"
            );
        }
    }

    #[test]
    fn validate_jwt_requires_alg_but_not_typ() {
        // `typ` is optional in RFC 7519, so this token is structurally fine.
        assert_eq!(
            validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"),
            ValidationResult::Valid
        );
        // `alg` is mandatory.
        assert_eq!(
            validate_jwt("eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxIn0.c2ln"),
            ValidationResult::Invalid
        );
        // An unsecured token (`alg: none`) may carry an empty signature.
        assert_eq!(
            validate_jwt("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0."),
            ValidationResult::Valid
        );
        // An empty signature is only allowed for `alg: none`.
        assert_eq!(
            validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0."),
            ValidationResult::Invalid
        );
        // A signature that is not base64url is invalid.
        assert_eq!(
            validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.si!"),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn validate_jwt_works() {
        let valid_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assert_eq!(validate_jwt(valid_jwt), ValidationResult::Valid);
        assert_eq!(validate_jwt("invalid.token"), ValidationResult::Invalid);
        assert_eq!(validate_jwt("a.b.c.d"), ValidationResult::Invalid);
        assert_eq!(validate_jwt("invalid..token"), ValidationResult::Invalid);
        let bad_header = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid";
        assert_eq!(validate_jwt(bad_header), ValidationResult::Invalid);
    }

    #[test]
    fn validate_finding_routes_correctly() {
        // BTC_ADDR routes to validate_base58check - returns Valid or Invalid (not NotApplicable)
        let btc_result = validate_finding("BTC_ADDR", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert!(btc_result == ValidationResult::Valid || btc_result == ValidationResult::Invalid);
        let btc_result2 = validate_finding("BTC_ADDR", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb");
        assert!(btc_result2 == ValidationResult::Valid || btc_result2 == ValidationResult::Invalid);
        // JWT_TOKEN routes to validate_jwt - use a JWT with wrong number of parts
        assert_eq!(
            validate_finding("JWT_TOKEN", "invalid.token"),
            ValidationResult::Invalid
        );
        // CREDIT_CARD routes to validate_credit_card (length + issuer + Luhn)
        assert_eq!(
            validate_finding("CREDIT_CARD", "4532015112830366"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("CREDIT_CARD", "4532015112830367"),
            ValidationResult::Invalid
        );
        // BTC_SEGWIT routes to validate_bech32
        assert_eq!(
            validate_finding("BTC_SEGWIT", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("BTC_SEGWIT", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
            ValidationResult::Invalid
        );
        // The classify() rule name for a JWT is "JWT"; both spellings work.
        assert_eq!(
            validate_finding("JWT", "invalid.token"),
            ValidationResult::Invalid
        );
        // UNKNOWN_RULE routes to NotApplicable
        assert_eq!(
            validate_finding("UNKNOWN_RULE", "something"),
            ValidationResult::NotApplicable
        );
    }

    #[test]
    fn validate_aws_key_works() {
        assert_eq!(
            validate_finding("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("AWS_ACCESS_KEY", "ASIAIOSFODNN7EXAMPLE"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAM"),
            ValidationResult::Invalid
        );
        assert_eq!(
            validate_finding("AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLEEXTRA"),
            ValidationResult::Invalid
        );
        assert_eq!(
            validate_finding("AWS_ACCESS_KEY", "XYZIAIOSFODNN7EXAMPLE"),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn validate_github_token_works() {
        assert_eq!(
            validate_finding(
                "GITHUB_PAT_CLASSIC",
                "ghp_TEST_TEST_TEST_TEST_TEST_TEST_TEST_TEST",
            ),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding(
                "GITHUB_OAUTH_TOKEN",
                "gho_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
            ),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding(
                "GITHUB_APP_TOKEN",
                "ghu_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
            ),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding(
                "GITHUB_FINE_GRAINED_PAT",
                "github_pat_11ABCDEFG0123456789_abcdefghij"
            ),
            ValidationResult::Valid
        );
        // Too short
        assert_eq!(
            validate_finding("GITHUB_PAT_CLASSIC", "ghp_abc"),
            ValidationResult::Invalid
        );
        // Unknown prefix
        assert_eq!(
            validate_finding(
                "GITHUB_PAT_CLASSIC",
                "xyz_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
            ),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn validate_slack_token_works() {
        assert_eq!(
            validate_finding("SLACK_BOT_TOKEN", "xoxb-TEST-SLACK-TOKEN-FOR-TESTING-ONLY"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding("SLACK_USER_TOKEN", "xoxp-TEST-SLACK-TOKEN-FOR-TESTING-ONLY"),
            ValidationResult::Valid
        );
        assert_eq!(
            validate_finding(
                "SLACK_WEBHOOK",
                "https://hooks.slack.com/services/T000/B000/XXXX"
            ),
            ValidationResult::Valid
        );
        // Too short
        assert_eq!(
            validate_finding("SLACK_BOT_TOKEN", "xoxb-abc"),
            ValidationResult::Invalid
        );
        // Unknown prefix
        assert_eq!(
            validate_finding(
                "SLACK_BOT_TOKEN",
                "xyz-123456789012-abcdefghijklmnopqrstuvwxyz"
            ),
            ValidationResult::Invalid
        );
    }

    #[test]
    fn eth_addr_classified_and_validated() {
        let c = classify("0x52908400098527886E0F7030069857D2E4169EE7").unwrap();
        assert_eq!(c.group, "CRYPTO");
        assert_eq!(c.typ, "ETH_ADDR");
        // ETH_ADDR returns NotApplicable: EIP-55 needs keccak256, not in lite deps.
        assert_eq!(
            validate_finding("ETH_ADDR", "0x52908400098527886E0F7030069857D2E4169EE7"),
            ValidationResult::NotApplicable
        );
    }

    #[test]
    fn public_client_key_context() {
        // AIza near clients6.google.com -> public-client-key, low confidence
        let findings = detect_secrets_detailed(
            "fetch('https://clients6.google.com/?key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567')",
        );
        let pck = findings
            .iter()
            .find(|f| f.rule == "PUBLIC_CLIENT_KEY")
            .expect("should be public-client-key near clients6 domain");
        assert_eq!(pck.value, "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567");
        assert!(pck.confidence < 0.5);
        assert_eq!(pck.severity, "low");

        // Same key WITHOUT google domain context -> GOOGLE_API_KEY
        let findings2 = detect_secrets_detailed("key AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567");
        let gapi = findings2
            .iter()
            .find(|f| f.rule == "GOOGLE_API_KEY")
            .expect("should be GOOGLE_API_KEY without domain context");
        assert_eq!(gapi.value, "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567");
        // Server-side-looking Google keys are medium signal, not proof.
        assert!((0.5..0.75).contains(&gapi.confidence));
        assert_eq!(gapi.severity, "medium");
    }

    #[test]
    fn classify_public_client_key() {
        let c =
            classify("https://clients6.google.com/?key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567")
                .unwrap();
        assert_eq!(c.group, "SECRET");
        assert_eq!(c.typ, "PUBLIC_CLIENT_KEY");

        let c2 = classify("key AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567").unwrap();
        assert_eq!(c2.group, "SECRET");
        assert_eq!(c2.typ, "GOOGLE_API_KEY");
    }

    #[test]
    fn every_static_regex_compiles() {
        // An invalid pattern panics with "invalid regex for rule <NAME>", so a
        // failure here points straight at the broken rule.
        let secrets = secret_compiled();
        assert_eq!(secrets.len(), SECRET_PATTERNS.len());
        for (name, regex) in secrets {
            assert!(!name.is_empty());
            assert!(!regex.as_str().is_empty(), "{name}");
        }

        let rules = compiled_rules();
        assert_eq!(rules.len(), RULES.len());
        for (rule, regex) in rules {
            assert!(!regex.as_str().is_empty(), "{}", rule.typ);
        }

        // Also forces the PRIVATE_KEY_BLOCK OnceLock to build.
        assert!(extract_pems("nothing to see").is_empty());
        // And the Aho-Corasick anchor automaton.
        assert_ne!(secret_prefilter().all, 0);
    }
}
