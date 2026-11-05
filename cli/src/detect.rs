use super::*;
use std::sync::OnceLock;

pub fn detected_ip_match(text: &str) -> Option<(String, usize, usize)> {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    let ipv4 = IPV4.get_or_init(|| {
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .unwrap()
    });
    if let Some(value) = ipv4
        .find_iter(text)
        .find(|matched| is_public_ipv4(matched.as_str()))
    {
        return Some((value.as_str().to_string(), value.start(), value.end()));
    }
    for token in text
        .split(|character: char| character.is_whitespace() || "\"'<>(),;[]{}".contains(character))
    {
        if token.parse::<std::net::Ipv6Addr>().is_ok() {
            if let Some(start) = text.find(token) {
                return Some((token.to_string(), start, start + token.len()));
            }
        }
    }
    None
}

pub fn detected_ip_value(text: &str) -> Option<String> {
    detected_ip_match(text).map(|(value, _, _)| value)
}

pub fn detected_url_match(text: &str) -> Option<(String, usize, usize)> {
    static URL: OnceLock<Regex> = OnceLock::new();
    let matched = URL
        .get_or_init(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>]+"#).unwrap())
        .find(text)?;
    let raw = matched.as_str();
    let trimmed = raw.trim_end_matches(['.', ',', ';', ')', ']', '}']);
    Some((
        trimmed.to_string(),
        matched.start(),
        matched.start() + trimmed.len(),
    ))
}

pub fn detected_url_value(text: &str) -> Option<String> {
    detected_url_match(text).map(|(value, _, _)| value)
}

pub fn detected_domain_match(text: &str) -> Option<(String, usize, usize)> {
    static DOMAIN: OnceLock<Regex> = OnceLock::new();
    let matched = DOMAIN
        .get_or_init(|| {
            Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b").unwrap()
        })
        .find(text)?;
    Some((matched.as_str().to_string(), matched.start(), matched.end()))
}

pub fn detected_domain_value(text: &str) -> Option<String> {
    detected_domain_match(text).map(|(value, _, _)| value)
}

pub fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

pub fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if value.len() < 16 || value.len() % 4 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    for chunk in bytes.chunks_exact(4) {
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    Some(output)
}

pub fn detect_and_decode_base64_match(text: &str) -> Option<(String, usize, usize)> {
    static B64: OnceLock<Regex> = OnceLock::new();
    let regex = B64.get_or_init(|| {
        Regex::new(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?").unwrap()
    });
    regex.find_iter(text).find_map(|matched| {
        let decoded = decode_base64(matched.as_str())?;
        let decoded = String::from_utf8(decoded).ok()?;
        if decoded
            .chars()
            .any(|character| character.is_ascii_alphanumeric())
        {
            Some((decoded, matched.start(), matched.end()))
        } else {
            None
        }
    })
}

pub fn detect_and_decode_base64(text: &str) -> Option<String> {
    detect_and_decode_base64_match(text).map(|(value, _, _)| value)
}

pub fn apply_detectors(result: ExtractedString, detectors: &[Detector]) -> Vec<ExtractedString> {
    if detectors.is_empty() {
        return vec![result];
    }
    let mut out = Vec::with_capacity(detectors.len());
    for det in detectors {
        match det {
            Detector::Ip => {
                if let Some(v) = detected_ip_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Url => {
                if let Some(v) = detected_url_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Domain => {
                if let Some(v) = detected_domain_value(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Base64 => {
                if let Some(v) = detect_and_decode_base64(&result.text) {
                    let mut r = result.clone();
                    r.text = v;
                    out.push(r);
                }
            }
            Detector::Secret => {
                for m in bxmap::classifier::detect_secrets(&result.text) {
                    let mut r = result.clone();
                    r.text = m.value;
                    out.push(r);
                }
            }
        }
    }
    out
}

pub fn push_finding(
    out: &mut Vec<bxmap::classifier::DetectedFinding>,
    result: &ExtractedString,
    rule: &'static str,
    value: String,
    start: usize,
    end: usize,
) {
    out.push(bxmap::classifier::DetectedFinding {
        offset: result.offset,
        encoding: result.encoding,
        rule,
        value,
        text: result.text.clone(),
        context: bxmap::classifier::context_around(&result.text, start, end, 32),
        confidence: bxmap::classifier::confidence_for(rule),
        severity: bxmap::classifier::severity_for(rule),
    });
}

/// Structured detector output: keep the original string and annotate each match
/// with its rule, confidence, severity and surrounding context.
pub fn detect_findings(
    result: &ExtractedString,
    detectors: &[Detector],
    strict: bool,
) -> Vec<bxmap::classifier::DetectedFinding> {
    let mut out = Vec::new();
    for det in detectors {
        match det {
            Detector::Ip => {
                if let Some((value, start, end)) = detected_ip_match(&result.text) {
                    let rule = if value.contains(':') { "IPV6" } else { "IPV4" };
                    push_finding(&mut out, result, rule, value, start, end);
                }
            }
            Detector::Url => {
                if let Some((value, start, end)) = detected_url_match(&result.text) {
                    push_finding(&mut out, result, "URL", value, start, end);
                }
            }
            Detector::Domain => {
                if let Some((value, start, end)) = detected_domain_match(&result.text) {
                    push_finding(&mut out, result, "DOMAIN", value, start, end);
                }
            }
            Detector::Base64 => {
                if let Some((value, start, end)) = detect_and_decode_base64_match(&result.text) {
                    push_finding(&mut out, result, "BASE64_DECODED", value, start, end);
                }
            }
            Detector::Secret => {
                for finding in bxmap::classifier::detect_secrets_detailed(&result.text) {
                    let validation =
                        bxmap::classifier::validate_finding(finding.rule, &finding.value);
                    match validation {
                        bxmap::classifier::ValidationResult::Invalid if strict => {
                            // Drop invalid findings in strict mode.
                            continue;
                        }
                        bxmap::classifier::ValidationResult::Invalid => {
                            // Lower confidence but keep the finding (default).
                            // Evidence is never silently dropped.
                            let mut adjusted = finding.confidence * 0.5;
                            if adjusted < 0.05 {
                                adjusted = 0.05;
                            }
                            out.push(bxmap::classifier::DetectedFinding {
                                offset: result.offset,
                                encoding: result.encoding,
                                rule: finding.rule,
                                value: finding.value,
                                text: result.text.clone(),
                                context: bxmap::classifier::context_around(
                                    &result.text,
                                    finding.start,
                                    finding.end,
                                    32,
                                ),
                                confidence: adjusted,
                                severity: finding.severity,
                            });
                        }
                        bxmap::classifier::ValidationResult::Valid
                        | bxmap::classifier::ValidationResult::NotApplicable => {
                            out.push(bxmap::classifier::DetectedFinding {
                                offset: result.offset,
                                encoding: result.encoding,
                                rule: finding.rule,
                                value: finding.value,
                                text: result.text.clone(),
                                context: bxmap::classifier::context_around(
                                    &result.text,
                                    finding.start,
                                    finding.end,
                                    32,
                                ),
                                confidence: finding.confidence,
                                severity: finding.severity,
                            });
                        }
                    }
                }
            }
        }
    }
    out
}

#[derive(Clone)]
pub struct MagicMatch {
    pub offset: u64,
    pub kind: &'static str,
}

/// Cap on reported magic-byte hits; dumps can contain millions of `MZ` bytes.
pub const MAX_MAGIC_MATCHES: usize = 256;
