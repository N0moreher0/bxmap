mod helpers;
use helpers::*;

mod output;
use output::*;

mod carve;
use carve::*;

mod xor;
use xor::*;

mod detect;
use detect::*;

mod report;
use report::*;

mod args;
use args::*;

mod entropy;
use entropy::{
    collect_entropy_regions, entropy_region_in_range, stream_entropy_regions, ENTROPY_MAX_DATA,
    ENTROPY_THRESHOLD, MAX_ENTROPY_REPORTS,
};

mod scan;
use scan::{run_buffered, run_streaming, ScanContext};

mod yara;
use yara::scan_yara_rules;

mod custom_rules;
use custom_rules::{load_custom_rules, match_custom_rules, CompiledCustomRule};

mod config;

use bxmap::{
    artifacts::{Artifact, ArtifactCollector, ArtifactKind, ArtifactKinds},
    carve::{reassemble_fragments, CarveKind, CarveOptions, CarveReport, Carver, ReassemblyReport},
    extract_strings_from_file_parallel_streaming_with_encodings_progress,
    extract_strings_from_file_parallel_with_encodings,
    extract_strings_from_file_streaming_range_with_encodings,
    extract_strings_from_file_streaming_range_with_encodings_progress,
    extract_strings_from_file_with_noise_config_and_encodings, EntropyRegion, EntropyScanOptions,
    ExtractedString, NoiseConfig, MAX_STRINGS,
};
use regex::Regex;
use std::path::Path;
use std::time::Instant;

// --- user report types ---
/// One user and how many files belong to it.
#[derive(Clone, Debug)]
struct UserStat {
    name: String,
    file_count: usize,         // all path artifacts, including AppData
    appdata_file_count: usize, // paths where category=appdata
    pct_appdata: f64,          // percentage of files that are AppData
}

/// Mode for the optional stderr report.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ReportMode {
    None,
    Summary,
    User,
    All,
}

/// Parse artifact detail string like "user=alice;category=desktop".
/// Build per-user file statistics from collected artifacts.
/// Only considers artifacts of kind `Path`. Category-only paths (no user) are skipped.
#[allow(clippy::items_after_test_module)]
#[cfg(test)]
mod extra_detector_tests {
    use super::*;

    #[test]
    fn detector_helpers_do_not_panic_on_random_input() {
        let mut state = 0xdeadbeefu64;
        for _ in 0..2000 {
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let mut s = String::new();
            for _ in 0..(state % 96) {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let c = (state & 0x7f) as u8;
                let c = if c < 0x20 {
                    (c + 0x20) as char
                } else {
                    c as char
                };
                s.push(c);
            }
            let _ = important_reason(&s);
            let _ = detected_ip_value(&s);
            let _ = detected_url_value(&s);
            let _ = detected_domain_value(&s);
            let _ = detect_and_decode_base64(&s);
            let _ = bxmap::classifier::detect_secrets(&s);
            let _ = bxmap::classifier::detect_secrets_detailed(&s);
            let result = ExtractedString {
                offset: 0,
                encoding: "ascii",
                text: s,
            };
            let _ = detect_findings(
                &result,
                &[
                    Detector::Ip,
                    Detector::Url,
                    Detector::Domain,
                    Detector::Base64,
                    Detector::Secret,
                ],
                false,
            );
        }
    }
}

/// Sniff the input so the common forensic formats do not need a flag.
///
/// * `MDMP` magic: Windows minidump -> `--tree` + `--map-va`.
/// * `.vmss`/`.vmsn`: VMware snapshot -> `--vmware-info` (`.vmem` is scanned
///   like any other memory image).
///
/// Everything detected here can be turned off again with `--no-tree`,
/// `--no-map-va` or `--no-vmware-info`.
fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}

/// Centralised conflict / validity checks for a parsed `Args`. Keeping them in
/// one place makes the error messages consistent and gives a single target for
/// the conflict-matrix tests.
fn run() -> Result<(), String> {
    let mut args = parse_args()?;
    apply_input_autodetect(&mut args);
    if args.vmware_info {
        let state = bxmap::vmware::VmwareState::open(&args.path)
            .map_err(|e| format!("cannot parse VMware state '{}': {e}", args.path))?;
        print!("{}", state.render_info());
        return Ok(());
    }
    if args.tree {
        let dump = bxmap::minidump::Minidump::open(&args.path)
            .map_err(|e| format!("cannot parse minidump '{}': {e}", args.path))?;
        print!("{}", dump.render_tree(30));
        return Ok(());
    }
    if args.map_va
        || args.in_module.is_some()
        || args.rwx_only
        || args.heap_only
        || args.path.to_ascii_lowercase().ends_with(".mdmp")
        || args.path.to_ascii_lowercase().ends_with(".hdmp")
        || args.path.to_ascii_lowercase().ends_with(".dmp")
    {
        if let Ok(dump) = bxmap::minidump::Minidump::open(&args.path) {
            let _ = DUMP_MAP.set(dump);
        }
    }
    let filter_regex = args
        .filter_regex
        .as_deref()
        .map(Regex::new)
        .transpose()
        .map_err(|error| format!("invalid --filter-regex: {error}"))?;
    validate(&args, filter_regex.as_ref())?;
    let file_size = std::fs::metadata(&args.path)
        .map_err(|e| format!("cannot inspect '{}': {e}", args.path))?
        .len();
    let range_active = args.start.is_some() || args.end.is_some();
    let range_start = args.start.unwrap_or(0);
    let range_end = args.end.unwrap_or(file_size);
    if range_active && range_start >= file_size {
        return Err(format!(
            "--start ({range_start:#x}) is beyond the end of the input ({file_size:#x})"
        ));
    }
    if range_start >= range_end {
        return Err(format!(
            "--start ({range_start:#x}) must be less than --end ({range_end:#x})"
        ));
    }
    let range_end = range_end.min(file_size);
    let scan_span = range_end.saturating_sub(range_start);
    // Ask the scanner for one extra result so we can tell "hit the cap" from
    let internal_limit = args.max_strings.saturating_add(1);
    print_banner(&args.path, file_size, args.format);
    if args.report_mode == ReportMode::Summary || args.report_mode == ReportMode::All {
        print_summary_header(
            range_start,
            range_end,
            file_size,
            args.encoding,
            args.extract,
        );
    }
    let threads = if args.auto_tune {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        if cpus <= 2 {
            1
        } else {
            std::cmp::max(1, std::cmp::min(cpus - 1, cpus * 3 / 4))
        }
    } else {
        args.threads
    };
    // A memory budget may force fewer workers than requested.
    let threads = apply_memory_budget(threads, args.max_memory)?;
    let noise = args
        .noise_threshold
        .map(NoiseConfig::from_threshold)
        .unwrap_or_default();
    let enc_filter = encoding_filter_for(args.encoding);
    let entropy_options = EntropyScanOptions {
        window: args.entropy_window.unwrap_or(bxmap::ENTROPY_BLOCK_SIZE),
        threshold: args.entropy_threshold.unwrap_or(ENTROPY_THRESHOLD),
        merge: args.entropy_merge,
        max_data: if args.entropy_no_data {
            0
        } else {
            args.entropy_max_data.unwrap_or(ENTROPY_MAX_DATA)
        },
    };
    let entropy_include_data = !args.entropy_no_data && entropy_options.max_data != 0;
    let Ok((want_magic, want_keys)) = parse_signature(&args.signature) else {
        // Should not happen: validation already runs before this point.
        return Err("invalid --signature".to_string());
    };
    let mut magic_matches = if want_magic {
        scan_magic_bytes(&args.path).map_err(|error| format!("magic-byte scan failed: {error}"))?
    } else {
        Vec::new()
    };
    let mut key_candidates: Vec<bxmap::keys::KeyCandidate> = Vec::new();
    if want_keys {
        let count = bxmap::keys::scan_key_candidates_from_file_streaming(&args.path, |candidate| {
            key_candidates.push(candidate);
            true
        })
        .map_err(|error| format!("key scan failed: {error}"))?;
        if count > 0 {
            eprintln!("  [i] --signature keys: {count} key candidate(s) found");
        }
    }
    let mut entropy_regions = Vec::new();
    if args.entropy {
        stream_entropy_regions(&args.path, entropy_options, |region, _data, _truncated| {
            if entropy_regions.len() < MAX_ENTROPY_REPORTS {
                entropy_regions.push(region);
            }
        })
        .map_err(|e| format!("entropy scan failed: {e}"))?;
    }
    // --- --carve stage -----------------------------------------------------
    // Carving is an independent pass: it needs byte ranges, not strings, so it
    // does not reuse the string scan's callback. It runs before the scan so a
    // huge carve cap fails fast.
    let mut carve_report: Option<CarveReport> = None;
    if let Some(types) = args.carve.as_deref() {
        let kinds = CarveKind::from_list(types).map_err(|error| format!("--carve: {error}"))?;
        let out_dir = args
            .carve_out
            .as_deref()
            .ok_or_else(|| "--carve requires --carve-out <dir>".to_string())?;
        let options = CarveOptions {
            kinds,
            min_size: args.carve_min_size,
            max_size: args.carve_max_size,
            max_total: args.carve_max_total,
            max_files: args.carve_max_files,
        };
        if args.reassemble {
            // Page-order reassembly requires a minidump to map file offsets
            // back to virtual addresses.
            let dump = bxmap::minidump::Minidump::open(&args.path)
                .map_err(|e| format!("--reassemble requires a minidump input: {e}"))?;
            let carver = Carver::new(options);
            let fragments = carver
                .collect_fragments(&args.path, Some(&dump))
                .map_err(|error| format!("collect fragments failed: {error}"))?;
            let report = reassemble_fragments(&fragments, &args.path, Path::new(out_dir))
                .map_err(|error| format!("reassemble failed: {error}"))?;
            print_reassembly_summary(&report);
        } else {
            let report = Carver::new(options)
                .carve_to_dir(&args.path, Path::new(out_dir))
                .map_err(|error| format!("carve failed: {error}"))?;
            if let Some(index_path) = args.carve_index.as_deref() {
                write_carve_index(&report, index_path)
                    .map_err(|error| format!("cannot write carve index: {error}"))?;
            }
            print_carve_summary(&report);
            carve_report = Some(report);
        }
    }

    let mut yara_matches: Vec<bxmap::YaraMatch> = Vec::new();
    if let Some(rules_path) = args.yar.as_ref() {
        yara_matches = scan_yara_rules(&args.path, rules_path)?;
    }
    let mut xor_results = Vec::new();
    if let Some(key_sizes) = args.brute_xor.as_ref() {
        let candidates = collect_xor_candidates(&args.path)
            .map_err(|e| format!("XOR candidate scan failed: {e}"))?;
        let big_keys = key_sizes.iter().copied().filter(|&size| size >= 3).max();
        if let Some(size) = big_keys {
            if args.xor_exhaustive {
                let keys = 1u64 << (size * 8);
                let ops = keys
                    .saturating_mul(candidates.len() as u64)
                    .saturating_mul(MAX_XOR_CANDIDATE_LEN as u64);
                eprintln!(
                    "  [i] --xor-exhaustive: {} candidate(s) x {keys} {size}-byte keys (~{:.1} G byte-ops); expect minutes on a large dump",
                    candidates.len(),
                    ops as f64 / 1e9
                );
            } else {
                eprintln!(
                    "  [i] --brute-xor: {size}-byte keys use a frequency-guided search ({} keys instead of {}); pass --xor-exhaustive to enumerate the full space",
                    (XOR_TOP_CIPHER_BYTES * XOR_COMMON_PLAINTEXT.len()).pow(size as u32),
                    1u64 << (size * 8)
                );
            }
        }
        for (offset, candidate) in candidates {
            let mut candidate_results = Vec::new();
            for &key_size in key_sizes {
                candidate_results.extend(xor_top_results(
                    &candidate,
                    offset,
                    key_size,
                    args.xor_exhaustive,
                ));
            }
            candidate_results.sort_by(|left, right| {
                right
                    .score
                    .partial_cmp(&left.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            candidate_results.truncate(MAX_XOR_RESULTS_PER_CANDIDATE);
            xor_results.extend(candidate_results);
        }
        xor_results.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    // Load custom detector rules (--detect-rules), if any.
    let custom_rules = if let Some(path) = &args.custom_rules {
        Some(load_custom_rules(Path::new(path)).map_err(|e| e.to_string())?)
    } else {
        None
    };

    if range_active {
        // Auxiliary stages still read the whole file (their APIs are not
        // range-aware yet), but only report hits inside the requested window.
        magic_matches.retain(|matched| matched.offset >= range_start && matched.offset < range_end);
        key_candidates
            .retain(|candidate| candidate.offset >= range_start && candidate.offset < range_end);
        yara_matches.retain(|matched| matched.offset >= range_start && matched.offset < range_end);
        xor_results.retain(|result| result.offset >= range_start && result.offset < range_end);
        entropy_regions
            .retain(|region| entropy_region_in_range(region, range_active, range_start, range_end));
    }

    let ctx = ScanContext {
        args: &args,
        file_size,
        range_start,
        range_end,
        scan_span,
        range_active,
        internal_limit,
        noise,
        enc_filter,
        filter_regex,
        threads,
        entropy_options,
        entropy_include_data,
        entropy_regions,
        yara_matches,
        xor_results,
        magic_matches,
        key_candidates,
        carve_report,
        custom_rules,
    };
    if args.format != Format::JsonTree
        && !matches!(args.format, Format::Html | Format::Markdown)
        && !args.dedupe
    {
        run_streaming(&ctx)?;
    } else {
        run_buffered(&ctx)?;
    }
    Ok(())
}
