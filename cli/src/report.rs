use super::*;
use std::io::{self, Write};

#[allow(clippy::too_many_arguments)]
pub fn write_report_html_markdown(
    results: &[bxmap::ExtractedString],
    yara_matches: &[bxmap::YaraMatch],
    xor_results: &[XorResult],
    magic_matches: &[MagicMatch],
    entropy_regions: &[bxmap::EntropyRegion],
    artifacts: &[Artifact],
    format: Format,
    _parse_pid: bool,
    _max_str_len: usize,
    file_size: u64,
    range_start: u64,
    range_end: u64,
    elapsed: f64,
    threads: usize,
    truncated: bool,
    _max_strings: u64,
    _scanned_until: u64,
    report_mode: ReportMode,
    filter_appdata: bool,
    min_files_in_user: usize,
    carve_report: Option<&CarveReport>,
    writer: &mut dyn Write,
) -> io::Result<()> {
    let is_html = matches!(format, Format::Html);
    let nl = "\n";

    // Collect stats
    let total_strings = results.len();
    let (short, medium, long) = {
        let mut s = 0;
        let mut m = 0;
        let mut l = 0;
        for r in results {
            match r.text.chars().count() {
                0..=7 => s += 1,
                8..=31 => m += 1,
                _ => l += 1,
            }
        }
        (s, m, l)
    };
    let encodings = count_encodings(results);

    // Important findings
    let mut important = Vec::new();
    for r in results {
        if important.len() < 12 && important_reason(&r.text).is_some() {
            important.push(r.clone());
        }
    }

    // User stats
    let user_stats = build_user_stats(artifacts, filter_appdata);

    // Carve summary
    let carve_summary = carve_report.map(|c| c.summary_line());

    let mut out = String::new();

    if is_html {
        out.push_str("<!DOCTYPE html>");
        out.push_str("<html lang=\"en\"><head>");
        out.push_str("<meta charset=\"utf-8\">");
        out.push_str("<title>bxmap Analysis Report</title>");
        out.push_str("<style>");
        out.push_str(include_str!("report_style.css"));
        out.push_str("</style></head><body>");
        out.push_str("<div class=\"container\">");
    } else {
        out.push_str("# bxmap Analysis Report\n\n");
    }

    // Header
    if is_html {
        out.push_str("<h1>bxmap Analysis Report</h1>");
        out.push_str("<table class=\"info\">");
    } else {
        out.push_str("## File Information\n\n");
    }
    out.push_str(&format!("{}File: {}{}", nl, "input dump", nl));
    out.push_str(&format!(
        "{}Size: {} bytes ({:.2} MiB){}",
        nl,
        file_size,
        file_size as f64 / 1_048_576.0,
        nl
    ));
    out.push_str(&format!(
        "{}Range: 0x{:x} - 0x{:x}{}",
        nl, range_start, range_end, nl
    ));
    out.push_str(&format!("{}Elapsed: {:.2}s{}", nl, elapsed, nl));
    out.push_str(&format!("{}Threads: {}{}", nl, threads, nl));
    out.push_str(&format!(
        "{}Truncated: {}{}",
        nl,
        if truncated {
            "YES (results incomplete)"
        } else {
            "No"
        },
        nl
    ));
    if is_html {
        out.push_str("</table>");
    }

    // Summary
    if is_html {
        out.push_str("<h2>Summary</h2><table class=\"summary\">");
    } else {
        out.push_str("## Summary\n\n");
    }
    out.push_str(&format!("{}Total strings: {}{}", nl, total_strings, nl));
    out.push_str(&format!("{}  Short (≤7): {}{}", nl, short, nl));
    out.push_str(&format!("{}  Medium (8-31): {}{}", nl, medium, nl));
    out.push_str(&format!("{}  Long (≥32): {}{}", nl, long, nl));
    out.push_str(&format!(
        "{}Encodings: {}{}",
        nl,
        format_encodings(&encodings),
        nl
    ));
    if is_html {
        out.push_str("</table>");
    }

    // Artifacts
    if !artifacts.is_empty() {
        if is_html {
            out.push_str("<h2>Artifacts</h2><table class=\"artifacts\"><thead><tr><th>Type</th><th>Count</th><th>Offset</th><th>Value</th><th>Detail</th></tr></thead><tbody>");
        } else {
            out.push_str("## Artifacts\n\n");
        }
        for a in artifacts {
            let detail = a.detail.as_deref().unwrap_or("");
            if is_html {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{:#010x}</td><td>{}</td><td>{}</td></tr>",
                    a.kind.as_str(),
                    a.count,
                    a.offset,
                    html_escape(&a.value),
                    html_escape(detail)
                ));
            } else {
                out.push_str(&format!(
                    "- **{}** (count={}) @ {:#010x}: {}  \n  Detail: {}\n",
                    a.kind.as_str(),
                    a.count,
                    a.offset,
                    a.value,
                    detail
                ));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // Priority findings: strings flagged by important_reason, plus sensitive
    // env artifacts (password=..., token=..., etc.) collected via --extract env.
    let mut sensitive_env: Vec<&Artifact> = Vec::new();
    let mut slots_left = 12usize.saturating_sub(important.len());
    for a in artifacts {
        if slots_left == 0 {
            break;
        }
        if a.kind == ArtifactKind::Env
            && a.detail
                .as_deref()
                .is_some_and(|d| d.contains("sensitive=true"))
        {
            sensitive_env.push(a);
            slots_left -= 1;
        }
    }
    let has_priority = !important.is_empty() || !sensitive_env.is_empty();
    if has_priority {
        if is_html {
            out.push_str("<h2>Priority Findings</h2><table class=\"findings\"><thead><tr><th>Type</th><th>Offset</th><th>Encoding</th><th>Text</th></tr></thead><tbody>");
        } else {
            out.push_str("## Priority Findings\n\n");
        }
        for r in important {
            if let Some(reason) = important_reason(&r.text) {
                if is_html {
                    out.push_str(&format!(
                        "<tr><td>{}</td><td>{:#010x}</td><td>{}</td><td>{}</td></tr>",
                        reason,
                        r.offset,
                        r.encoding,
                        html_escape(&r.text)
                    ));
                } else {
                    out.push_str(&format!(
                        "- **{}** @ {:#010x} ({}) : {}\n",
                        reason, r.offset, r.encoding, r.text
                    ));
                }
            }
        }
        for a in &sensitive_env {
            if is_html {
                out.push_str(&format!(
                    "<tr><td>env-sensitive</td><td>{:#010x}</td><td>env</td><td>{}</td></tr>",
                    a.offset,
                    html_escape(&a.value)
                ));
            } else {
                out.push_str(&format!(
                    "- **env-sensitive** @ {:#010x} (env) : {}\n",
                    a.offset, a.value
                ));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // YARA matches
    if !yara_matches.is_empty() {
        if is_html {
            out.push_str("<h2>YARA Matches</h2><table class=\"yara\"><thead><tr><th>Rule</th><th>Offset</th><th>Tags</th></tr></thead><tbody>");
        } else {
            out.push_str("## YARA Matches\n\n");
        }
        for m in yara_matches {
            if is_html {
                out.push_str(&format!(
                    "<tr><td>{}</td><td>{:#010x}</td><td>{}</td></tr>",
                    html_escape(&m.rule),
                    m.offset,
                    html_escape(&m.namespace)
                ));
            } else {
                out.push_str(&format!(
                    "- Rule: {} @ {:#010x} [{}]\n",
                    m.rule, m.offset, m.namespace
                ));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // XOR results
    if !xor_results.is_empty() {
        if is_html {
            out.push_str("<h2>XOR Candidates</h2><table class=\"xor\"><thead><tr><th>Offset</th><th>Key</th><th>Score</th><th>Preview</th></tr></thead><tbody>");
        } else {
            out.push_str("## XOR Candidates\n\n");
        }
        for x in xor_results.iter().take(10) {
            let preview = String::from_utf8_lossy(&x.plaintext)
                .chars()
                .take(60)
                .collect::<String>();
            if is_html {
                out.push_str(&format!(
                    "<tr><td>{:#010x}</td><td>{}</td><td>{:.3}</td><td>{}</td></tr>",
                    x.offset,
                    hex_encode(&x.key),
                    x.score,
                    html_escape(&preview)
                ));
            } else {
                out.push_str(&format!(
                    "- Offset {:#010x}: key={} score={:.3} preview={}\n",
                    x.offset,
                    hex_encode(&x.key),
                    x.score,
                    preview
                ));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // Magic bytes
    if !magic_matches.is_empty() {
        if is_html {
            out.push_str("<h2>Magic Byte Signatures</h2><table class=\"magic\"><thead><tr><th>Offset</th><th>Type</th></tr></thead><tbody>");
        } else {
            out.push_str("## Magic Byte Signatures\n\n");
        }
        for m in magic_matches {
            if is_html {
                out.push_str(&format!(
                    "<tr><td>{:#010x}</td><td>{}</td></tr>",
                    m.offset,
                    html_escape(m.kind)
                ));
            } else {
                out.push_str(&format!("- {:#010x}: {}\n", m.offset, m.kind));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // Entropy regions
    if !entropy_regions.is_empty() {
        if is_html {
            out.push_str("<h2>High-Entropy Regions</h2><table class=\"entropy\"><thead><tr><th>Offset</th><th>Length</th><th>Entropy</th></tr></thead><tbody>");
        } else {
            out.push_str("## High-Entropy Regions\n\n");
        }
        for e in entropy_regions.iter().take(20) {
            if is_html {
                out.push_str(&format!(
                    "<tr><td>{:#010x}</td><td>{}</td><td>{:.3}/8.0</td></tr>",
                    e.offset, e.length, e.entropy
                ));
            } else {
                out.push_str(&format!(
                    "- {:#010x}: {} bytes, entropy {:.3}/8.0\n",
                    e.offset, e.length, e.entropy
                ));
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    // Carve report
    if let Some(summary) = carve_summary {
        if is_html {
            out.push_str("<h2>Carved Files</h2><p>");
            out.push_str(&html_escape(&summary));
            out.push_str("</p>");
        } else {
            out.push_str(&format!("## Carved Files\n\n{}\n", summary));
        }
    }

    // User report
    if (report_mode == ReportMode::User || report_mode == ReportMode::All) && !user_stats.is_empty()
    {
        if is_html {
            out.push_str("<h2>Per-User File Summary</h2><table class=\"users\"><thead><tr><th>User</th><th>Files</th><th>AppData</th><th>AppData%</th></tr></thead><tbody>");
        } else {
            out.push_str("## Per-User File Summary\n\n");
        }
        for u in user_stats {
            if u.file_count >= min_files_in_user {
                if is_html {
                    out.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td></tr>",
                        html_escape(&u.name),
                        u.file_count,
                        u.appdata_file_count,
                        u.pct_appdata
                    ));
                } else {
                    out.push_str(&format!(
                        "- {}: {} files ({} AppData, {:.1}%)\n",
                        u.name, u.file_count, u.appdata_file_count, u.pct_appdata
                    ));
                }
            }
        }
        if is_html {
            out.push_str("</tbody></table>");
        }
    }

    writer.write_all(out.as_bytes())
}

pub fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for ch in value.chars() {
        match ch {
            '&' => out.push('&'),
            '<' => out.push('<'),
            '>' => out.push('>'),
            '"' => out.push('"'),
            '\'' => out.push('\''),
            c => out.push(c),
        }
    }
    out
}
