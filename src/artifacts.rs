//! Structured artifact extraction.
//!
//! The string extractor intentionally returns everything; this module turns
//! that string sea into a small, deduped artifact list: file paths, environment
//! assignments, URLs, e-mail addresses and registry keys. Each artifact keeps
//! the first offset where it was seen plus an occurrence count, and the final
//! list is sorted rarest-first so unusual evidence floats to the top.

use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Artifact families the collector understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Path,
    Env,
    Url,
    Email,
    Registry,
}

impl ArtifactKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ArtifactKind::Path => "path",
            ArtifactKind::Env => "env",
            ArtifactKind::Url => "url",
            ArtifactKind::Email => "email",
            ArtifactKind::Registry => "registry",
        }
    }

    fn bit(self) -> u8 {
        match self {
            ArtifactKind::Path => 1 << 0,
            ArtifactKind::Env => 1 << 1,
            ArtifactKind::Url => 1 << 2,
            ArtifactKind::Email => 1 << 3,
            ArtifactKind::Registry => 1 << 4,
        }
    }
}

/// A small bitset of [`ArtifactKind`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArtifactKinds(u8);

impl std::ops::BitOr for ArtifactKinds {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl ArtifactKinds {
    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(0b1_1111);

    pub const fn paths() -> Self {
        Self(1 << 0)
    }

    pub const fn env() -> Self {
        Self(1 << 1)
    }

    pub const fn urls() -> Self {
        Self(1 << 2)
    }

    pub const fn emails() -> Self {
        Self(1 << 3)
    }

    pub const fn registry() -> Self {
        Self(1 << 4)
    }

    pub fn insert(&mut self, kind: ArtifactKind) {
        self.0 |= kind.bit();
    }

    pub fn contains(self, kind: ArtifactKind) -> bool {
        self.0 & kind.bit() != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Parse a comma/semicolon separated list such as `paths,env,urls`.
    /// `all` selects every family.
    pub fn from_list(list: &str) -> Result<Self, String> {
        let mut kinds = Self::NONE;
        for part in list.split([',', ';']) {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            match part.to_ascii_lowercase().as_str() {
                "all" => return Ok(Self::ALL),
                "path" | "paths" => kinds.insert(ArtifactKind::Path),
                "env" | "environment" => kinds.insert(ArtifactKind::Env),
                "url" | "urls" => kinds.insert(ArtifactKind::Url),
                "email" | "emails" => kinds.insert(ArtifactKind::Email),
                "registry" | "reg" => kinds.insert(ArtifactKind::Registry),
                other => {
                    return Err(format!(
                        "invalid --extract value '{other}' (expected paths, env, urls, emails, \
                         registry or all)"
                    ))
                }
            }
        }
        if kinds.is_empty() {
            return Err("--extract needs at least one artifact kind".to_string());
        }
        Ok(kinds)
    }
}

/// One deduped artifact occurrence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Artifact {
    pub kind: ArtifactKind,
    /// First spelling seen. Paths/registry keys are compared case-insensitively
    /// but displayed as originally extracted.
    pub value: String,
    /// Offset of the string that produced the first occurrence.
    pub offset: u64,
    /// Number of occurrences across the scan.
    pub count: usize,
    /// Extra context: `user=...;category=...` for paths, `name=...` for env.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Incremental artifact collector: feed it every extracted string, then call
/// [`finish`](Self::finish) to get a rarest-first, deduped list.
pub struct ArtifactCollector {
    kinds: ArtifactKinds,
    max: usize,
    artifacts: HashMap<(ArtifactKind, String), Artifact>,
}

impl ArtifactCollector {
    pub fn new(kinds: ArtifactKinds, max: usize) -> Self {
        Self {
            kinds,
            max,
            artifacts: HashMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Extract artifacts from one string.
    pub fn observe(&mut self, text: &str, offset: u64) {
        if self.kinds.is_empty() || text.is_empty() {
            return;
        }
        if self.kinds.contains(ArtifactKind::Path) {
            for (start, path) in extract_paths(text) {
                let windows = is_windows_path(path);
                let key = if windows {
                    path.to_ascii_lowercase().replace('/', "\\")
                } else {
                    path.to_string()
                };
                self.record(
                    ArtifactKind::Path,
                    path,
                    key,
                    offset + start as u64,
                    path_detail(path),
                );
            }
        }
        if self.kinds.contains(ArtifactKind::Env) {
            for pair in extract_env(text) {
                if let Some((name, _value)) = pair.split_once('=') {
                    let detail = if is_sensitive_name(name) {
                        format!("name={};sensitive=true", name.trim())
                    } else {
                        format!("name={}", name.trim())
                    };
                    self.record(
                        ArtifactKind::Env,
                        pair,
                        pair.to_string(),
                        offset,
                        Some(detail),
                    );
                }
            }
        }
        if self.kinds.contains(ArtifactKind::Url) {
            for (start, url) in extract_matches(text, url_regex()) {
                self.record(
                    ArtifactKind::Url,
                    url,
                    url.to_ascii_lowercase(),
                    offset + start as u64,
                    None,
                );
            }
        }
        if self.kinds.contains(ArtifactKind::Email) {
            for (start, email) in extract_matches(text, email_regex()) {
                self.record(
                    ArtifactKind::Email,
                    email,
                    email.to_ascii_lowercase(),
                    offset + start as u64,
                    None,
                );
            }
        }
        if self.kinds.contains(ArtifactKind::Registry) {
            for (start, key) in extract_matches(text, registry_regex()) {
                self.record(
                    ArtifactKind::Registry,
                    key,
                    key.to_ascii_lowercase().replace('/', "\\"),
                    offset + start as u64,
                    None,
                );
            }
        }
    }

    fn record(
        &mut self,
        kind: ArtifactKind,
        value: &str,
        key: String,
        offset: u64,
        detail: Option<String>,
    ) {
        if let Some(existing) = self.artifacts.get_mut(&(kind, key.clone())) {
            existing.count += 1;
            if existing.detail.is_none() {
                existing.detail = detail;
            }
            return;
        }
        if self.artifacts.len() >= self.max {
            return;
        }
        self.artifacts.insert(
            (kind, key),
            Artifact {
                kind,
                value: value.to_string(),
                offset,
                count: 1,
                detail,
            },
        );
    }

    /// Consume the collector and return artifacts sorted rarest-first.
    pub fn finish(self) -> Vec<Artifact> {
        let mut artifacts: Vec<Artifact> = self.artifacts.into_values().collect();
        artifacts.sort_by(|left, right| {
            left.count
                .cmp(&right.count)
                .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
                .then_with(|| left.value.cmp(&right.value))
        });
        artifacts
    }
}

fn url_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\b(?:https?|ftp)://[^\s"'<>\\]{4,2048}"#).unwrap())
}

fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b").unwrap()
    })
}

fn registry_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s'"<>|]{2,1024}"#,
        )
        .unwrap()
    })
}

fn env_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<name>[A-Za-z_][A-Za-z0-9_ ().\-]{0,63})=(?P<value>.{3,512})$").unwrap()
    })
}

/// Regex matches with trailing punctuation trimmed.
fn extract_matches<'a>(text: &'a str, regex: &Regex) -> Vec<(usize, &'a str)> {
    regex
        .find_iter(text)
        .filter_map(|matched| {
            let trimmed = trim_trailing_punctuation(matched.as_str());
            if trimmed.is_empty() {
                None
            } else {
                Some((matched.start(), trimmed))
            }
        })
        .collect()
}

fn trim_trailing_punctuation(text: &str) -> &str {
    let mut end = text.len();
    while let Some(ch) = text[..end].chars().next_back() {
        let trim = match ch {
            ' ' | '\t' | '\r' | '\n' | '.' | ',' | ';' | ':' | '\'' | '"' => true,
            ')' | ']' | '}' => closer_unbalanced(&text[..end], ch),
            _ => false,
        };
        if !trim {
            break;
        }
        end -= ch.len_utf8();
    }
    &text[..end]
}

fn closer_unbalanced(text: &str, closer: char) -> bool {
    let opener = match closer {
        ')' => '(',
        ']' => '[',
        '}' => '{',
        _ => return false,
    };
    let opens = text.chars().filter(|&ch| ch == opener).count();
    let closes = text.chars().filter(|&ch| ch == closer).count();
    opens < closes
}

fn is_windows_path(path: &str) -> bool {
    path.contains('\\') || path.as_bytes().get(1) == Some(&b':')
}

/// Path candidates inside `text`, with the byte index where each starts.
fn extract_paths(text: &str) -> Vec<(usize, &str)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(end) = path_end_at(text, index) {
            let candidate = &text[index..end];
            let trimmed = trim_trailing_punctuation(candidate);
            if looks_like_path(trimmed) {
                spans.push((index, trimmed));
            }
            index = end.max(index + 1);
        } else {
            index += 1;
        }
    }
    spans
}

fn path_end_at(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let first = *bytes.get(start)?;
    let drive = first.is_ascii_alphabetic()
        && bytes.get(start + 1) == Some(&b':')
        && matches!(bytes.get(start + 2), Some(&b'\\') | Some(&b'/'));
    let windows_prefix = text[start..].starts_with("\\\\?\\")
        || text[start..].starts_with("\\\\.\\")
        || text[start..].starts_with("\\Device\\")
        || text[start..].starts_with("\\??\\");
    let unc = first == b'\\' && bytes.get(start + 1) == Some(&b'\\');
    if drive || windows_prefix || unc {
        return Some(consume_windows_path(text, start));
    }
    // Unix path: starts with '/', not '//', not right after ':' (URL) and not
    // embedded in a longer word.
    if first == b'/' && bytes.get(start + 1).copied() != Some(b'/') {
        let previous = if start == 0 {
            None
        } else {
            text[..start].chars().next_back()
        };
        if matches!(previous, Some(':') | Some('/') | Some('\\') | Some('.')) {
            return None;
        }
        let end = consume_unix_path(text, start);
        if text[start..end].matches('/').count() >= 2 {
            return Some(end);
        }
    }
    None
}

fn consume_windows_path(text: &str, start: usize) -> usize {
    let allow_question = text[start..].starts_with("\\\\?\\");
    let mut end = start;
    let mut opens = 0i32;
    let mut closes = 0i32;
    let mut iter = text[start..].char_indices().peekable();
    while let Some((offset, ch)) = iter.next() {
        let absolute = start + offset;
        let stop = match ch {
            '\0' | '\n' | '\r' | '\t' | '"' | '<' | '>' | '|' | '*' => true,
            '?' if !allow_question => true,
            ',' | ';' => true,
            '(' | '[' | '{' => {
                opens += 1;
                false
            }
            ')' | ']' | '}' => {
                closes += 1;
                closes > opens
            }
            c if c.is_whitespace() => {
                // `cmd.exe /c ...` and `path -flag` are separate tokens, and a
                // lowercase English word (`... and ...`) is prose rather than a
                // path segment. `Program Files (x86)` must stay intact.
                let mut look = iter.clone();
                let mut token = String::new();
                for (_, next) in look.by_ref() {
                    if next.is_whitespace()
                        || matches!(next, '"' | '<' | '>' | '|' | '*' | ',' | ';')
                    {
                        break;
                    }
                    token.push(next);
                    if token.len() >= 64 {
                        break;
                    }
                }
                let segment_like = token.chars().any(|next| {
                    next.is_ascii_uppercase()
                        || next.is_ascii_digit()
                        || matches!(next, '.' | '_' | '(' | ')')
                });
                token.is_empty()
                    || token.starts_with('/')
                    || token.starts_with('\\')
                    || token.starts_with('-')
                    || !segment_like
            }
            _ => false,
        };
        if stop {
            break;
        }
        end = absolute + ch.len_utf8();
    }
    end
}

fn consume_unix_path(text: &str, start: usize) -> usize {
    let mut end = start;
    for (offset, ch) in text[start..].char_indices() {
        let allowed = ch.is_ascii_alphanumeric()
            || matches!(ch, '/' | '.' | '_' | '-' | '+' | '~' | '@' | '%');
        if !allowed {
            break;
        }
        end = start + offset + ch.len_utf8();
    }
    end
}

fn looks_like_path(path: &str) -> bool {
    if path.len() < 4 {
        return false;
    }
    if path.contains("://") {
        return false;
    }
    let separators = path.matches(['\\', '/']).count();
    if is_windows_path(path) {
        return separators >= 1 && !path.ends_with('\\') && !path.ends_with('/');
    }
    separators >= 2
}

/// Environment assignment candidates (`NAME=value`) inside one string.
fn extract_env(text: &str) -> Vec<&str> {
    let trimmed = text.trim_matches(|ch: char| ch == '\0' || ch.is_whitespace());
    if trimmed.len() < 5 {
        return Vec::new();
    }
    let Some(captures) = env_regex().captures(trimmed) else {
        return Vec::new();
    };
    let name = captures.name("name").map(|m| m.as_str()).unwrap_or("");
    let value = captures.name("value").map(|m| m.as_str()).unwrap_or("");
    if !env_name_plausible(name) || !env_value_plausible(value) {
        return Vec::new();
    }
    vec![trimmed]
}

fn env_name_plausible(name: &str) -> bool {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    let env_style = name
        .chars()
        .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
    env_style || is_sensitive_name(name)
}

fn is_sensitive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api key",
        "credential",
        "access_key",
        "auth",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn env_value_plausible(value: &str) -> bool {
    let value = value.trim();
    if value.len() < 3 || value.len() > 512 {
        return false;
    }
    // Reject source code / HTML fragments that commonly contain `=`.
    let lower = value.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "false" | "true" | "null" | "none" | "nil" | "undefined" | "yes" | "no" | "0" | "1"
    ) {
        return false;
    }
    if value.starts_with('(')
        || value.starts_with('{')
        || value.starts_with('[')
        || lower.contains("function(")
        || lower.contains("=>")
        || lower.contains("</")
        || lower.ends_with(';')
    {
        return false;
    }
    // A value made only of punctuation is noise.
    value.chars().any(|ch| ch.is_ascii_alphanumeric())
}

/// `user=<profile>;category=<desktop|documents|downloads|appdata|other>` for
/// paths that live under a user profile.
fn path_detail(path: &str) -> Option<String> {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    let user = user_from_path(&lower);
    let category = if lower.contains("\\desktop\\") {
        "desktop"
    } else if lower.contains("\\documents\\") {
        "documents"
    } else if lower.contains("\\downloads\\") {
        "downloads"
    } else if lower.contains("\\appdata\\") {
        "appdata"
    } else if lower.contains("\\temp\\") {
        "temp"
    } else {
        "other"
    };
    match (user, category) {
        (Some(user), category) => Some(format!("user={user};category={category}")),
        (None, "other") => None,
        (None, category) => Some(format!("category={category}")),
    }
}

fn user_from_path(lower: &str) -> Option<&str> {
    for marker in ["\\users\\", "\\home\\"] {
        if let Some(rest) = lower.split_once(marker).map(|(_, rest)| rest) {
            let user = rest.split('\\').next().unwrap_or("");
            if !user.is_empty() && !user.contains(':') {
                return Some(user);
            }
        }
    }
    if lower.starts_with("\\root\\") {
        return Some("root");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(kinds: ArtifactKinds, text: &str) -> Vec<Artifact> {
        let mut collector = ArtifactCollector::new(kinds, 1000);
        collector.observe(text, 0x1000);
        collector.finish()
    }

    #[test]
    fn extracts_windows_and_unix_paths() {
        let artifacts = collect(
            ArtifactKinds::paths(),
            r#"C:\Users\eminem\Desktop\secrets.txt and /home/eminem/docs/galf.jpeg"#,
        );
        assert_eq!(artifacts.len(), 2, "{artifacts:?}");
        let values: Vec<&str> = artifacts.iter().map(|a| a.value.as_str()).collect();
        assert!(values.contains(&r"C:\Users\eminem\Desktop\secrets.txt"));
        assert!(values.contains(&"/home/eminem/docs/galf.jpeg"));
    }

    #[test]
    fn keeps_paths_with_spaces_and_device_prefixes() {
        let artifacts = collect(
            ArtifactKinds::paths(),
            r#"C:\Program Files (x86)\DumpIt\DumpIt.exe \Device\HarddiskVolume2\Windows\System32\cmd.exe"#,
        );
        assert_eq!(artifacts.len(), 2, "{artifacts:?}");
        let values: Vec<&str> = artifacts.iter().map(|a| a.value.as_str()).collect();
        assert!(values.contains(&r"C:\Program Files (x86)\DumpIt\DumpIt.exe"));
        assert!(values.contains(&r"\Device\HarddiskVolume2\Windows\System32\cmd.exe"));
    }

    #[test]
    fn dedupes_paths_case_insensitively_and_counts() {
        let mut collector = ArtifactCollector::new(ArtifactKinds::paths(), 1000);
        collector.observe(r"C:\Users\eminem\Desktop\a.txt", 10);
        collector.observe(r"c:\users\EMINEM\desktop\A.TXT", 20);
        let artifacts = collector.finish();
        assert_eq!(artifacts.len(), 1, "{artifacts:?}");
        assert_eq!(artifacts[0].count, 2);
        assert_eq!(artifacts[0].offset, 10);
        assert_eq!(
            artifacts[0].detail.as_deref(),
            Some("user=eminem;category=desktop")
        );
    }

    #[test]
    fn sorts_rarest_first() {
        let mut collector = ArtifactCollector::new(ArtifactKinds::urls(), 1000);
        for _ in 0..3 {
            collector.observe("https://common.example/a", 0);
        }
        collector.observe("https://rare.example/b", 0);
        let artifacts = collector.finish();
        assert_eq!(artifacts[0].value, "https://rare.example/b");
        assert_eq!(artifacts[0].count, 1);
        assert_eq!(artifacts[1].count, 3);
    }

    #[test]
    fn extracts_env_assignments_but_rejects_code() {
        let artifacts = collect(ArtifactKinds::env(), "RAR password=easypeasyvirus");
        assert_eq!(artifacts.len(), 1, "{artifacts:?}");
        assert_eq!(artifacts[0].value, "RAR password=easypeasyvirus");
        assert_eq!(
            artifacts[0].detail.as_deref(),
            Some("name=RAR password;sensitive=true")
        );

        assert!(collect(ArtifactKinds::env(), "ApiKey=function(a){return a}").is_empty());
        assert!(collect(ArtifactKinds::env(), "Token: GetTokenInformation").is_empty());
        assert!(collect(ArtifactKinds::env(), "password=false").is_empty());
    }

    #[test]
    fn extracts_urls_emails_and_registry() {
        let text = "see https://example.com/a?b=1, mail admin@example.org \
                    HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
        let artifacts = collect(
            ArtifactKinds::urls() | ArtifactKinds::emails() | ArtifactKinds::registry(),
            text,
        );
        assert_eq!(artifacts.len(), 3, "{artifacts:?}");
        let values: Vec<&str> = artifacts.iter().map(|a| a.value.as_str()).collect();
        assert!(values.contains(&"https://example.com/a?b=1"));
        assert!(values.contains(&"admin@example.org"));
        assert!(values.contains(&r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion"));
    }

    #[test]
    fn rejects_url_fragments_as_paths() {
        let artifacts = collect(ArtifactKinds::paths(), "https://example.com/a/b/c");
        assert!(artifacts.is_empty(), "{artifacts:?}");
    }

    #[test]
    fn parses_kind_lists() {
        let kinds = ArtifactKinds::from_list("paths, env").unwrap();
        assert!(kinds.contains(ArtifactKind::Path));
        assert!(kinds.contains(ArtifactKind::Env));
        assert!(!kinds.contains(ArtifactKind::Url));
        assert_eq!(ArtifactKinds::from_list("all").unwrap(), ArtifactKinds::ALL);
        assert!(ArtifactKinds::from_list("bogus").is_err());
    }
}
