//! The two scan execution paths (streaming and buffered), extracted from
//! `main.rs` so that `main.rs` stays a thin orchestrator. Behaviour is
//! intentionally unchanged -- these functions are called by `run()` after the
//! shared setup (args, validation, carve, yara, xor, magic) is done.

use super::*;
use std::io::{self, IsTerminal, Write};

use bxmap::EncodingFilter;
use regex::Regex;
use std::time::Duration;

/// Shared inputs for both scan paths.
pub struct ScanContext<'a> {
    pub args: &'a Args,
    pub file_size: u64,
    pub range_start: u64,
    pub range_end: u64,
    pub scan_span: u64,
    pub range_active: bool,
    pub internal_limit: usize,
    pub noise: NoiseConfig,
    pub enc_filter: EncodingFilter,
    pub filter_regex: Option<Regex>,
    pub threads: usize,
    pub entropy_options: EntropyScanOptions,
    pub entropy_include_data: bool,
    pub entropy_regions: Vec<EntropyRegion>,
    pub yara_matches: Vec<bxmap::YaraMatch>,
    pub xor_results: Vec<XorResult>,
    pub magic_matches: Vec<MagicMatch>,
    pub key_candidates: Vec<bxmap::keys::KeyCandidate>,
    pub carve_report: Option<CarveReport>,
    pub custom_rules: Option<Vec<CompiledCustomRule>>,
}

/// Multi-threaded streaming scan: results are written as they are produced,
/// RAM does not grow with the number of matches.
pub fn run_streaming(ctx: &ScanContext<'_>) -> Result<(), String> {
    let args = ctx.args;
    let output_is_file = args.output.is_some();
    let show_progress = args.progress.unwrap_or_else(|| {
        io::stderr().is_terminal() && (args.output.is_some() || !io::stdout().is_terminal())
    });
    let start = Instant::now();
    let mut writer = Sink::open(args.output.as_deref())?;
    let json_layout = json_layout_for(args.format, args.compact);
    if args.format == Format::Json {
        match json_layout {
            JsonLayout::Array => {
                writeln!(writer, "[").map_err(|e| format!("write failed: {e}"))?;
            }
            _ => write!(writer, "[").map_err(|e| format!("write failed: {e}"))?,
        }
    }
    if args.format == Format::Csv {
        write_csv_header(&mut writer).map_err(|e| format!("write failed: {e}"))?;
    }
    let mut result_count = 0;
    let mut short = 0;
    let mut medium = 0;
    let mut long = 0;
    let mut important = Vec::new();
    let mut write_error = None;
    let mut last_offset = 0u64;
    let mut raw_count = 0usize;
    let mut truncated = false;
    let mut artifacts = ArtifactCollector::new(args.extract, MAX_ARTIFACTS);
    let mut encoding_counts = [0usize; ENCODING_LABELS.len()];
    let progress_results = std::cell::Cell::new(0usize);
    let mut handle = |result: ExtractedString| {
        if write_error.is_some() {
            return;
        }
        raw_count += 1;
        progress_results.set(raw_count);
        if raw_count > args.max_strings {
            truncated = true;
            return;
        }
        last_offset = last_offset.max(result.offset);
        if !passes_region_filter(
            result.offset,
            &args.in_module,
            args.rwx_only,
            args.heap_only,
        ) {
            return;
        }
        if encoding_accepts(args.encoding, result.encoding) {
            if let Some(slot) = ENCODING_LABELS
                .iter()
                .position(|label| *label == result.encoding)
            {
                encoding_counts[slot] += 1;
            }
            artifacts.observe(&result.text, result.offset);
            if args.detect_format == DetectFormat::Rich {
                let findings = detect_findings(&result, &args.detectors, args.detect_strict);
                for finding in &findings {
                    if let Err(error) = record_finding(
                        finding,
                        &mut writer,
                        args.format,
                        &mut result_count,
                        args.max_str_len,
                        None,
                        None,
                        false,
                        args.compact,
                    ) {
                        write_error = Some(error);
                    }
                }
                // Custom detector rules (--detect-rules)
                if let Some(rules) = &ctx.custom_rules {
                    for finding in match_custom_rules(rules, &result) {
                        if let Err(error) = record_finding(
                            &finding,
                            &mut writer,
                            args.format,
                            &mut result_count,
                            args.max_str_len,
                            None,
                            None,
                            false,
                            args.compact,
                        ) {
                            write_error = Some(error);
                        }
                    }
                }
                update_stats(&result, &mut short, &mut medium, &mut long, &mut important);
            } else {
                for result in apply_detectors(result, &args.detectors) {
                    if matches_filter(ctx.filter_regex.as_ref(), &result.text) {
                        if let Err(error) = record_result(
                            result,
                            &mut writer,
                            args.format,
                            &mut result_count,
                            &mut short,
                            &mut medium,
                            &mut long,
                            &mut important,
                            args.parse_pid,
                            args.max_str_len,
                            None,
                            args.compact,
                        ) {
                            write_error = Some(error);
                        }
                    }
                }
            }
        }
    };
    let mut last_progress = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    let mut progress = |scanned: u64| {
        if !show_progress {
            return;
        }
        let now = Instant::now();
        if now.duration_since(last_progress) < Duration::from_millis(200) {
            return;
        }
        last_progress = now;
        let relative = scanned.saturating_sub(ctx.range_start);
        let pct = if ctx.scan_span == 0 {
            100.0
        } else {
            relative as f64 * 100.0 / ctx.scan_span as f64
        };
        let secs = now.duration_since(start).as_secs_f64().max(1e-9);
        let mib_s = relative as f64 / secs / (1024.0 * 1024.0);
        eprint!(
            "\r  [..] {pct:>6.1}%  {mib_s:>7.1} MiB/s  scanned {scanned:#x}  results {}          ",
            progress_results.get()
        );
    };
    let scan_result = if ctx.threads > 1 && !ctx.range_active {
        extract_strings_from_file_parallel_streaming_with_encodings_progress(
            &args.path,
            args.min_len,
            ctx.internal_limit,
            ctx.noise,
            ctx.enc_filter,
            ctx.threads,
            &mut handle,
            &mut progress,
        )
    } else {
        extract_strings_from_file_streaming_range_with_encodings_progress(
            &args.path,
            ctx.range_start,
            ctx.range_end,
            args.min_len,
            ctx.internal_limit,
            ctx.noise,
            ctx.enc_filter,
            &mut handle,
            &mut progress,
        )
    };
    scan_result.map_err(|e| format!("scan failed: {e}"))?;
    if show_progress {
        eprintln!();
    }
    let artifacts = artifacts.finish();
    if let Some(error) = write_error {
        return Err(format!("write failed: {error}"));
    }
    if args.format == Format::Json || args.format == Format::Ndjson {
        let mut json_count = result_count;
        for matched in &ctx.yara_matches {
            write_yara_json(matched, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &ctx.xor_results {
            if ctx
                .filter_regex
                .as_ref()
                .is_none_or(|regex| regex.is_match(&String::from_utf8_lossy(&result.plaintext)))
            {
                write_xor_json(result, &mut writer, &mut json_count, json_layout)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &ctx.magic_matches {
            write_magic_json(magic, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for candidate in &ctx.key_candidates {
            write_key_json(candidate, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy {
            if let Ok(regions) = collect_entropy_regions(
                &args.path,
                ctx.entropy_options,
                ctx.range_active,
                ctx.range_start,
                ctx.range_end,
            ) {
                for (region, data, data_truncated) in regions {
                    if let Err(error) = write_entropy_json(
                        region,
                        &data,
                        &mut writer,
                        &mut json_count,
                        json_layout,
                        ctx.entropy_include_data,
                        data_truncated,
                    ) {
                        return Err(format!("write failed: {error}"));
                    }
                }
            }
        }
        write_artifacts(
            &artifacts,
            &mut writer,
            args.format,
            json_layout,
            &mut json_count,
        )
        .map_err(|e| format!("write failed: {e}"))?;
        match json_layout {
            JsonLayout::Lines => {
                write_ndjson_metadata(&mut writer, json_count, truncated, last_offset)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::Array => {
                writeln!(writer, "\n]").map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::ArrayCompact => {
                writeln!(writer, "]").map_err(|e| format!("write failed: {e}"))?;
            }
        }
    } else {
        for matched in &ctx.yara_matches {
            write_yara_text(matched, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &ctx.xor_results {
            if ctx
                .filter_regex
                .as_ref()
                .is_none_or(|regex| regex.is_match(&String::from_utf8_lossy(&result.plaintext)))
            {
                write_xor_text(result, &mut writer).map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &ctx.magic_matches {
            write_magic_text(magic, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        for candidate in &ctx.key_candidates {
            write_key_text(candidate, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy {
            if let Ok(regions) = collect_entropy_regions(
                &args.path,
                ctx.entropy_options,
                ctx.range_active,
                ctx.range_start,
                ctx.range_end,
            ) {
                for (region, data, data_truncated) in regions {
                    if let Err(error) = write_entropy_text(
                        region,
                        &data,
                        &mut writer,
                        ctx.entropy_include_data,
                        data_truncated,
                    ) {
                        return Err(format!("write failed: {error}"));
                    }
                }
            }
        }
        write_artifacts(
            &artifacts,
            &mut writer,
            args.format,
            json_layout,
            &mut result_count,
        )
        .map_err(|e| format!("write failed: {e}"))?;
    }
    if let Some(path) = args.output.as_ref() {
        eprintln!("wrote {result_count} results to '{path}'");
    }
    print_report(&ReportData {
        result_count,
        short,
        medium,
        long,
        important: &important,
        entropy_regions: &ctx.entropy_regions,
        artifacts: &artifacts,
        encodings: encoding_counts,
        file_size: ctx.file_size,
        range_start: ctx.range_start,
        range_end: ctx.range_end,
        elapsed: start.elapsed().as_secs_f64(),
        threads: ctx.threads,
        truncated,
        max_strings: args.max_strings,
        scanned_until: last_offset,
        detailed: args.report_mode == ReportMode::Summary || args.report_mode == ReportMode::All,
        output_is_file,
        carve: ctx.carve_report.as_ref(),
    });
    if args.report_mode == ReportMode::User || args.report_mode == ReportMode::All {
        let stats = build_user_stats(&artifacts, args.filter_appdata);
        print_user_report(&stats, args.min_files_in_user, args.filter_appdata);
    }
    if truncated {
        print_truncation_notice(
            args.max_strings,
            last_offset,
            ctx.range_start,
            ctx.scan_span,
        );
        writer.finish().ok();
        std::process::exit(3);
    }
    exit_if_carve_truncated(&ctx.carve_report);
    Ok(())
}

/// Buffered scan: collect every result into a Vec, then write. Used for
/// json-tree / dedupe / range requests that need the full result set.
pub fn run_buffered(ctx: &ScanContext<'_>) -> Result<(), String> {
    let args = ctx.args;
    let mut results = if ctx.range_active {
        let mut collected: Vec<ExtractedString> = Vec::new();
        extract_strings_from_file_streaming_range_with_encodings(
            &args.path,
            ctx.range_start,
            ctx.range_end,
            args.min_len,
            ctx.internal_limit,
            ctx.noise,
            ctx.enc_filter,
            |result| collected.push(result),
        )
        .map(|_| collected)
    } else if ctx.threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(ctx.threads)
            .build()
            .map_err(|e| format!("cannot create worker pool: {e}"))?;
        pool.install(|| {
            extract_strings_from_file_parallel_with_encodings(
                &args.path,
                args.min_len,
                ctx.internal_limit,
                ctx.noise,
                ctx.enc_filter,
            )
        })
    } else {
        extract_strings_from_file_with_noise_config_and_encodings(
            &args.path,
            args.min_len,
            ctx.internal_limit,
            ctx.noise,
            ctx.enc_filter,
        )
    }
    .map_err(|e| format!("scan failed: {e}"))?;
    let truncated = hit_result_limit(results.len(), args.max_strings);
    if truncated {
        results.truncate(args.max_strings);
    }
    let raw_results: Vec<ExtractedString> = results
        .into_iter()
        .filter(|result| encoding_accepts(args.encoding, result.encoding))
        .filter(|result| {
            passes_region_filter(
                result.offset,
                &args.in_module,
                args.rwx_only,
                args.heap_only,
            )
        })
        .collect();

    let start = Instant::now();
    if args.detect_format == DetectFormat::Rich {
        let artifacts = collect_artifacts(args.extract, raw_results.iter());
        let findings: Vec<bxmap::classifier::DetectedFinding> = raw_results
            .iter()
            .flat_map(|result| detect_findings(result, &args.detectors, args.detect_strict))
            .collect();
        let findings: Vec<DedupedFinding> = if args.dedupe {
            dedupe_findings(findings)
        } else {
            findings
                .into_iter()
                .map(|finding| {
                    let offset = finding.offset;
                    DedupedFinding {
                        finding,
                        count: 1,
                        offsets: vec![offset],
                        offsets_truncated: false,
                    }
                })
                .collect()
        };
        let mut writer = Sink::open(args.output.as_deref())?;
        let json_layout = json_layout_for(args.format, args.compact);
        if args.format == Format::Json {
            match json_layout {
                JsonLayout::Array => {
                    writeln!(writer, "[").map_err(|e| format!("write failed: {e}"))?;
                }
                _ => write!(writer, "[").map_err(|e| format!("write failed: {e}"))?,
            }
        }
        if args.format == Format::Csv {
            write_csv_header(&mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        let mut result_count = 0;
        for deduped in &findings {
            record_finding(
                &deduped.finding,
                &mut writer,
                args.format,
                &mut result_count,
                args.max_str_len,
                if args.dedupe {
                    Some(deduped.count)
                } else {
                    None
                },
                if args.dedupe {
                    Some(&deduped.offsets)
                } else {
                    None
                },
                deduped.offsets_truncated,
                args.compact,
            )
            .map_err(|e| format!("write failed: {e}"))?;
        }
        // Custom detector rules (--detect-rules)
        if let Some(rules) = &ctx.custom_rules {
            for result in raw_results.iter() {
                for finding in match_custom_rules(rules, result) {
                    record_finding(
                        &finding,
                        &mut writer,
                        args.format,
                        &mut result_count,
                        args.max_str_len,
                        None,
                        None,
                        false,
                        args.compact,
                    )
                    .map_err(|e| format!("write failed: {e}"))?;
                }
            }
        }
        write_artifacts(
            &artifacts,
            &mut writer,
            args.format,
            json_layout,
            &mut result_count,
        )
        .map_err(|e| format!("write failed: {e}"))?;
        match json_layout {
            JsonLayout::Lines => {
                let last_offset = raw_results.iter().map(|r| r.offset).max().unwrap_or(0);
                write_ndjson_metadata(&mut writer, result_count, truncated, last_offset)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::Array => {
                writeln!(writer, "\n]").map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::ArrayCompact => {
                writeln!(writer, "]").map_err(|e| format!("write failed: {e}"))?;
            }
        }
        if let Some(path) = args.output.as_ref() {
            eprintln!("wrote {result_count} findings to '{path}'");
        }
        let mut short = 0;
        let mut medium = 0;
        let mut long = 0;
        let mut important = Vec::new();
        for result in &raw_results {
            update_stats(result, &mut short, &mut medium, &mut long, &mut important);
        }
        print_report(&ReportData {
            result_count,
            short,
            medium,
            long,
            important: &important,
            entropy_regions: &ctx.entropy_regions, // placeholder
            artifacts: &artifacts,
            encodings: count_encodings(&raw_results),
            file_size: ctx.file_size,
            range_start: ctx.range_start,
            range_end: ctx.range_end,
            elapsed: start.elapsed().as_secs_f64(),
            threads: ctx.threads,
            truncated,
            max_strings: args.max_strings,
            scanned_until: raw_results.iter().map(|r| r.offset).max().unwrap_or(0),
            detailed: args.report_mode == ReportMode::Summary
                || args.report_mode == ReportMode::All,
            output_is_file: args.output.is_some(),
            carve: ctx.carve_report.as_ref(),
        });
        if args.report_mode == ReportMode::User || args.report_mode == ReportMode::All {
            let stats = build_user_stats(&artifacts, args.filter_appdata);
            print_user_report(&stats, args.min_files_in_user, args.filter_appdata);
        }
        if truncated {
            let last_offset = raw_results.iter().map(|r| r.offset).max().unwrap_or(0);
            print_truncation_notice(
                args.max_strings,
                last_offset,
                ctx.range_start,
                ctx.scan_span,
            );
            std::process::exit(3);
        }
        exit_if_carve_truncated(&ctx.carve_report);
        return Ok(());
    }

    let artifacts = collect_artifacts(args.extract, raw_results.iter());
    let mut results: Vec<ExtractedString> = raw_results
        .into_iter()
        .flat_map(|result| apply_detectors(result, &args.detectors))
        .filter(|result| {
            ctx.filter_regex
                .as_ref()
                .is_none_or(|regex| regex.is_match(&result.text))
        })
        .collect();
    let counts = if args.dedupe {
        let (unique, counts) = dedupe_strings(results);
        results = unique;
        Some(counts)
    } else {
        None
    };

    let output_path = args.output.clone();
    let mut writer = Sink::open(output_path.as_deref())?;
    if args.format == Format::JsonTree {
        use std::collections::BTreeMap;
        let mut groups: BTreeMap<(String, String), Vec<&ExtractedString>> = BTreeMap::new();
        for r in &results {
            let cls = bxmap::classifier::classify(&r.text);
            let (g, t) = match cls {
                Some(c) => (c.group.to_string(), c.typ.to_string()),
                None => ("STRING".to_string(), "GENERIC".to_string()),
            };
            groups.entry((g, t)).or_default().push(r);
        }
        let (sep, item_indent, group_indent, nl) = if args.compact {
            (",", "", "", "")
        } else {
            (",\n", "    ", "  ", "\n")
        };
        let mut out = format!("{{\"groups\":[{nl}");
        let mut first_group = true;
        for ((g, t), items) in &groups {
            if !first_group {
                out.push_str(sep);
            }
            first_group = false;
            out.push_str(&format!(
                "{group_indent}{{\"group\":{},\"type\":{},\"items\":[{nl}",
                json_escape(g),
                json_escape(t)
            ));
            let mut first_item = true;
            for r in items {
                if !first_item {
                    out.push_str(sep);
                }
                first_item = false;
                let ent = bxmap::classifier::entropy_of(&r.text);
                let ts_part = if let Some(dump) = DUMP_MAP.get() {
                    if let Some(va) = dump.offset_to_va(r.offset) {
                        if let Some(m) = dump.module_for_va(va) {
                            format!(",\"timestamp\":{}", m.timestamp)
                        } else {
                            String::new()
                        }
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                let count_part = counts
                    .as_ref()
                    .and_then(|map| map.get(&r.text))
                    .map(|count| format!(",\"count\":{count}"))
                    .unwrap_or_default();
                out.push_str(&format!(
                    "{item_indent}{{\"text\":{},\"offset\":{},\"entropy\":{:.4}{}{}}}",
                    json_escape(&r.text),
                    r.offset,
                    ent,
                    ts_part,
                    count_part
                ));
            }
            out.push_str(&format!("{nl}{group_indent}]}}"));
        }
        let last_offset = results.iter().map(|r| r.offset).max().unwrap_or(0);
        out.push_str(&format!(
            "{nl}],\"metadata\":{{\"total_strings\":{},\"truncated\":{},\"scanned_until\":{}}}{nl}}}{nl}",
            results.len(),
            truncated,
            last_offset
        ));
        if args.compact {
            out.push('\n');
        }
        write!(writer, "{}", out).map_err(|e| format!("write failed: {e}"))?;
        if let Some(path) = output_path.clone() {
            eprintln!("wrote {} results to '{}'", results.len(), path);
        }
    } else if args.format == Format::Json || args.format == Format::Ndjson {
        let json_layout = json_layout_for(args.format, args.compact);
        match json_layout {
            JsonLayout::Array => writeln!(writer, "[").map_err(|e| format!("write failed: {e}"))?,
            JsonLayout::ArrayCompact => {
                write!(writer, "[").map_err(|e| format!("write failed: {e}"))?
            }
            JsonLayout::Lines => {}
        }
        let mut json_count = 0;
        for result in &results {
            let count = counts
                .as_ref()
                .and_then(|map| map.get(&result.text).copied());
            write_string_json(
                result,
                &mut writer,
                &mut json_count,
                args.parse_pid,
                count,
                json_layout,
            )
            .map_err(|e| format!("write failed: {e}"))?;
        }
        for matched in &ctx.yara_matches {
            write_yara_json(matched, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &ctx.xor_results {
            if ctx
                .filter_regex
                .as_ref()
                .is_none_or(|regex| regex.is_match(&String::from_utf8_lossy(&result.plaintext)))
            {
                write_xor_json(result, &mut writer, &mut json_count, json_layout)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &ctx.magic_matches {
            write_magic_json(magic, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        for candidate in &ctx.key_candidates {
            write_key_json(candidate, &mut writer, &mut json_count, json_layout)
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy {
            if let Ok(regions) = collect_entropy_regions(
                &args.path,
                ctx.entropy_options,
                ctx.range_active,
                ctx.range_start,
                ctx.range_end,
            ) {
                for (region, data, data_truncated) in regions {
                    if let Err(error) = write_entropy_json(
                        region,
                        &data,
                        &mut writer,
                        &mut json_count,
                        json_layout,
                        ctx.entropy_include_data,
                        data_truncated,
                    ) {
                        return Err(format!("write failed: {error}"));
                    }
                }
            }
        }
        write_artifacts(
            &artifacts,
            &mut writer,
            args.format,
            json_layout,
            &mut json_count,
        )
        .map_err(|e| format!("write failed: {e}"))?;
        match json_layout {
            JsonLayout::Lines => {
                let last_offset = results.iter().map(|r| r.offset).max().unwrap_or(0);
                write_ndjson_metadata(&mut writer, json_count, truncated, last_offset)
                    .map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::Array => {
                writeln!(writer, "\n]").map_err(|e| format!("write failed: {e}"))?;
            }
            JsonLayout::ArrayCompact => {
                writeln!(writer, "]").map_err(|e| format!("write failed: {e}"))?;
            }
        }
    } else if args.format == Format::Html || args.format == Format::Markdown {
        write_report_html_markdown(
            &results[..],
            &ctx.yara_matches[..],
            &ctx.xor_results[..],
            &ctx.magic_matches[..],
            &[], // entropy_regions placeholder
            &artifacts[..],
            args.format,
            args.parse_pid,
            args.max_str_len,
            ctx.file_size,
            ctx.range_start,
            ctx.range_end,
            start.elapsed().as_secs_f64(),
            ctx.threads,
            truncated,
            args.max_strings as u64,
            results.iter().map(|r| r.offset).max().unwrap_or(0),
            args.report_mode,
            args.filter_appdata,
            args.min_files_in_user,
            ctx.carve_report.as_ref(),
            &mut writer,
        )
        .map_err(|e| format!("write failed: {e}"))?;
    } else {
        write_results(
            &results,
            args.format,
            &mut writer,
            args.parse_pid,
            args.max_str_len,
            counts.as_ref(),
            args.compact,
        )
        .map_err(|e| format!("write failed: {e}"))?;
        for matched in &ctx.yara_matches {
            write_yara_text(matched, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        for result in &ctx.xor_results {
            if ctx
                .filter_regex
                .as_ref()
                .is_none_or(|regex| regex.is_match(&String::from_utf8_lossy(&result.plaintext)))
            {
                write_xor_text(result, &mut writer).map_err(|e| format!("write failed: {e}"))?;
            }
        }
        for magic in &ctx.magic_matches {
            write_magic_text(magic, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        for candidate in &ctx.key_candidates {
            write_key_text(candidate, &mut writer).map_err(|e| format!("write failed: {e}"))?;
        }
        if args.entropy && args.format == Format::Text {
            if let Ok(regions) = collect_entropy_regions(
                &args.path,
                ctx.entropy_options,
                ctx.range_active,
                ctx.range_start,
                ctx.range_end,
            ) {
                for (region, data, data_truncated) in regions {
                    if let Err(error) = write_entropy_text(
                        region,
                        &data,
                        &mut writer,
                        ctx.entropy_include_data,
                        data_truncated,
                    ) {
                        return Err(format!("write failed: {error}"));
                    }
                }
            }
        }
        let mut written = 0usize;
        write_artifacts(
            &artifacts,
            &mut writer,
            args.format,
            json_layout_for(args.format, args.compact),
            &mut written,
        )
        .map_err(|e| format!("write failed: {e}"))?;
    }
    let output_path_for_message = output_path.as_ref();
    if let Some(path) = output_path_for_message {
        eprintln!("wrote {} results to '{}'", results.len(), path);
    }
    let mut short = 0;
    let mut medium = 0;
    let mut long = 0;
    let mut important = Vec::new();
    for result in &results {
        match result.text.chars().count() {
            0..=7 => short += 1,
            8..=31 => medium += 1,
            _ => long += 1,
        }
        if important.len() < 12 && important_reason(&result.text).is_some() {
            important.push(result.clone());
        }
    }
    print_report(&ReportData {
        result_count: results.len(),
        short,
        medium,
        long,
        important: &important,
        entropy_regions: &ctx.entropy_regions, // placeholder
        artifacts: &artifacts,
        encodings: count_encodings(&results),
        file_size: ctx.file_size,
        range_start: ctx.range_start,
        range_end: ctx.range_end,
        elapsed: start.elapsed().as_secs_f64(),
        threads: ctx.threads,
        truncated,
        max_strings: args.max_strings,
        scanned_until: results.iter().map(|r| r.offset).max().unwrap_or(0),
        detailed: args.report_mode == ReportMode::Summary || args.report_mode == ReportMode::All,
        output_is_file: args.output.is_some(),
        carve: ctx.carve_report.as_ref(),
    });
    if args.report_mode == ReportMode::User || args.report_mode == ReportMode::All {
        let stats = build_user_stats(&artifacts, args.filter_appdata);
        print_user_report(&stats, args.min_files_in_user, args.filter_appdata);
    }
    if truncated {
        let last_offset = results.iter().map(|r| r.offset).max().unwrap_or(0);
        print_truncation_notice(
            args.max_strings,
            last_offset,
            ctx.range_start,
            ctx.scan_span,
        );
        writer.finish().ok();
        std::process::exit(3);
    }
    exit_if_carve_truncated(&ctx.carve_report);
    writer.finish().map_err(|e| format!("write failed: {e}"))?;
    let output_path_for_message = args.output.as_ref();
    if let Some(path) = output_path_for_message {
        eprintln!("wrote {} results to '{}'", results.len(), path);
    }
    Ok(())
}
