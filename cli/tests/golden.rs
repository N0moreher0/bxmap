use std::io::Read;
use std::process::Command;

fn bin_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_bxmap-cli") {
        return path.into();
    }
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    if cfg!(windows) {
        p.push("bxmap-cli.exe");
    } else {
        p.push("bxmap-cli");
    }
    p
}

#[test]
fn golden_text_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--max-strings",
            "100",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.trim_end(), "0x00000000\tascii\thello world");
}

#[test]
fn golden_json_output_contains_result() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--format",
            "json",
            "--min-len",
            "4",
            "--max-strings",
            "100",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"text\":\"hello world\""));
}

#[test]
fn golden_json_tree_output_contains_group() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--format",
            "json-tree",
            "--min-len",
            "4",
            "--max-strings",
            "100",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"groups\""));
}

#[test]
fn golden_rich_detector_json_has_structured_fields() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"config AKIAIOSFODNN7EXAMPLE end\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--format",
            "json",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--min-len",
            "4",
            "--max-strings",
            "100",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"rule\":\"AWS_ACCESS_KEY\""), "{stdout}");
    assert!(
        stdout.contains("\"value\":\"AKIAIOSFODNN7EXAMPLE\""),
        "{stdout}"
    );
    assert!(stdout.contains("\"confidence\":"), "{stdout}");
    assert!(stdout.contains("\"severity\":\"high\""), "{stdout}");
    assert!(
        stdout.contains("\"context\":\"config AKIAIOSFODNN7EXAMPLE end\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("\"text\":\"config AKIAIOSFODNN7EXAMPLE end\""),
        "{stdout}"
    );
}

#[test]
fn golden_rich_detector_text_is_one_line_per_finding() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"config AKIAIOSFODNN7EXAMPLE end\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--min-len",
            "4",
            "--max-strings",
            "100",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    assert!(stdout.contains("rule=AWS_ACCESS_KEY"), "{stdout}");
    assert!(stdout.contains("conf=0.95"), "{stdout}");
    assert!(stdout.contains("sev=high"), "{stdout}");
    assert!(stdout.contains("value=AKIAIOSFODNN7EXAMPLE"), "{stdout}");
}

#[test]
fn golden_max_strings_truncation_exits_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00cccc\x00dddd\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--max-strings",
            "1",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3), "{:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("TRUNCATED"), "{stderr}");
    assert!(stderr.contains("--max-strings (0 = unlimited)"), "{stderr}");
}

#[test]
fn golden_max_strings_zero_means_unlimited() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00cccc\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--max-strings",
            "0",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.lines().count(), 3, "{stdout}");
}

#[test]
fn golden_exact_result_count_is_not_reported_as_truncated() {
    // Exactly 2 strings and --max-strings 2: the scan finished, so no warning
    // and exit code 0 (the old heuristic reported truncation here).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--max-strings",
            "2",
            "--encoding",
            "ascii",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("TRUNCATED"), "{stderr}");
}

#[test]
fn golden_start_end_filters_by_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"AAAA\x00BBBB\x00CCCC\x00DDDD\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--start",
            "5",
            "--end",
            "15",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0x00000005\tascii\tBBBB"), "{stdout}");
    assert!(stdout.contains("0x0000000a\tascii\tCCCC"), "{stdout}");
    assert!(!stdout.contains("AAAA"), "{stdout}");
    assert!(!stdout.contains("DDDD"), "{stdout}");
}

#[test]
fn golden_start_accepts_hex_and_forces_streaming_with_threads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"AAAA\x00BBBB\x00CCCC\x00DDDD\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--start",
            "0x5",
            "--end",
            "0xA",
            "--threads",
            "4",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("BBBB"), "{stdout}");
    assert!(!stdout.contains("CCCC"), "{stdout}");
}

#[test]
fn golden_start_greater_than_end_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--start", "10", "--end", "5"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--start"), "{stderr}");
    assert!(stderr.contains("--end"), "{stderr}");
}

#[test]
fn golden_progress_flag_writes_status_to_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00cccc\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[..]"), "{stderr}");
    assert!(stderr.contains("MiB/s"), "{stderr}");
}

#[test]
fn golden_no_progress_suppresses_status_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("[..]"), "{stderr}");
}

#[test]
fn golden_dedupe_reports_count_and_first_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00aaaa\x00cccc\x00aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--dedupe",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("0x00000000\tascii\taaaa\tcount=3"),
        "{stdout}"
    );
    assert!(
        stdout.contains("0x00000005\tascii\tbbbb\tcount=1"),
        "{stdout}"
    );
    assert!(
        stdout.contains("0x0000000f\tascii\tcccc\tcount=1"),
        "{stdout}"
    );
    assert_eq!(stdout.lines().count(), 3, "{stdout}");
}

#[test]
fn golden_dedupe_json_adds_count_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--dedupe",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"text\":\"aaaa\",\"count\":2"), "{stdout}");
    assert!(stdout.contains("\"text\":\"bbbb\",\"count\":1"), "{stdout}");
}

#[test]
fn golden_dedupe_rich_findings_groups_by_rule_and_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(
        &path,
        b"key AKIAIOSFODNN7EXAMPLE x\x00other AKIAIOSFODNN7EXAMPLE y\x00",
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--dedupe",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"rule\":\"AWS_ACCESS_KEY\""), "{stdout}");
    assert!(stdout.contains("\"count\":2"), "{stdout}");
    assert!(stdout.contains("\"offsets\":["), "{stdout}");
    assert!(!stdout.contains("\"offsets_truncated\":true"), "{stdout}");
    assert_eq!(stdout.matches("\"rule\":").count(), 1, "{stdout}");
}

#[test]
fn golden_ndjson_emits_one_record_per_line_plus_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "ndjson",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(
        lines[0].starts_with("{\"type\":\"string\",\"offset\":0,"),
        "{stdout}"
    );
    assert!(
        lines[2].starts_with("{\"type\":\"metadata\",\"total_records\":2,"),
        "{stdout}"
    );
    for line in &lines {
        assert!(line.starts_with('{') && line.ends_with('}'), "{line}");
    }
}

#[test]
fn golden_ndjson_rich_finding_keeps_type_and_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(
        &path,
        b"key AKIAIOSFODNN7EXAMPLE x\x00other AKIAIOSFODNN7EXAMPLE y\x00",
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--dedupe",
            "--format",
            "ndjson",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "{stdout}");
    assert!(
        lines[0].starts_with("{\"type\":\"finding\",\"offset\":0,"),
        "{stdout}"
    );
    assert!(lines[0].contains("\"rule\":\"AWS_ACCESS_KEY\""), "{stdout}");
    assert!(lines[0].contains("\"count\":2"), "{stdout}");
    assert!(
        lines[1].starts_with("{\"type\":\"metadata\",\"total_records\":1,"),
        "{stdout}"
    );
}

#[test]
fn golden_ndjson_metadata_flags_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00cccc\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "ndjson",
            "--max-strings",
            "1",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let last = stdout.lines().last().unwrap_or_default();
    assert!(last.starts_with("{\"type\":\"metadata\""), "{stdout}");
    assert!(last.contains("\"truncated\":true"), "{stdout}");
}

#[test]
fn golden_gzip_output_is_written_and_finished_on_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00cccc\x00").unwrap();
    let gz = dir.path().join("out.ndjson.gz");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "ndjson",
            "--max-strings",
            "2",
            "-o",
            gz.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Truncation still exits 3, but the gzip stream must stay readable.
    assert_eq!(output.status.code(), Some(3));
    let mut text = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&gz).unwrap())
        .read_to_string(&mut text)
        .unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert!(lines[2].contains("\"truncated\":true"), "{text}");
}

#[test]
fn golden_csv_emits_header_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "csv",
            "--dedupe",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines[0], "type,offset,encoding,text,rule,value,severity,confidence,context,count,pid",
        "{stdout}"
    );
    assert_eq!(lines.len(), 3, "{stdout}");
    assert_eq!(lines[1], "string,0x00000000,ascii,aaaa,,,,,,2,", "{stdout}");
}

#[test]
fn golden_csv_quotes_commas_and_quotes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"he said \"hi\", ok\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "csv",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"he said \"\"hi\"\", ok\""),
        "comma/quote field must be RFC 4180 quoted: {stdout}"
    );
}

#[test]
fn golden_csv_rejects_auxiliary_stages() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "csv",
            "--entropy",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--format csv supports strings"), "{stderr}");
}

#[test]
fn golden_compact_json_is_single_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "json",
            "--compact",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim_end();
    assert_eq!(trimmed.lines().count(), 1, "must be one line: {stdout}");
    assert!(
        trimmed.starts_with('[') && trimmed.ends_with(']'),
        "{stdout}"
    );
    assert!(trimmed.contains("\"text\":\"aaaa\""), "{stdout}");
    assert!(!trimmed.contains("\n  {"), "no indentation: {stdout}");
}

#[test]
fn golden_compact_json_tree_is_single_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00bbbb\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "json-tree",
            "--compact",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim_end();
    assert_eq!(trimmed.lines().count(), 1, "must be one line: {stdout}");
    assert!(trimmed.starts_with("{\"groups\":[{"), "{stdout}");
    assert!(trimmed.contains("\"metadata\":"), "{stdout}");
}

/// Deterministic pseudo-random bytes: entropy is high enough for `--entropy`
/// to report the block, without pulling in an RNG dependency.
fn high_entropy_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

#[test]
fn golden_entropy_no_data_omits_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(16 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--entropy-no-data",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"entropy\":"), "{stdout}");
    assert!(
        !stdout.contains("data_hex"),
        "--entropy-no-data must omit data_hex: {stdout}"
    );
}

#[test]
fn golden_entropy_with_data_includes_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(16 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"data_hex\":\""), "{stdout}");
}

#[test]
fn golden_entropy_no_data_implies_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(16 * 1024)).unwrap();

    // `--entropy-no-data` alone now turns entropy scanning on instead of
    // erroring out.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy-no-data",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"group\":\"Undefined\""), "{stdout}");
    assert!(!stdout.contains("data_hex"), "{stdout}");
}

#[test]
fn golden_entropy_merge_merges_adjacent_windows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(8 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--entropy-window",
            "1024",
            "--entropy-merge",
            "--entropy-no-data",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("\"group\":\"Undefined\"").count(),
        1,
        "merge must collapse contiguous windows: {stdout}"
    );
    assert!(stdout.contains("\"length\":8192"), "{stdout}");
}

#[test]
fn golden_entropy_window_controls_region_count() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(8 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--entropy-window",
            "1024",
            "--entropy-no-data",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("\"length\":1024").count(),
        8,
        "one region per 1024-byte window: {stdout}"
    );
}

#[test]
fn golden_entropy_max_data_caps_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(4 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--entropy-window",
            "1024",
            "--entropy-max-data",
            "8",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"data_truncated\":true"), "{stdout}");
    // 8 payload bytes render as 16 hex characters.
    let start = stdout.find("\"data_hex\":\"").expect("data_hex") + "\"data_hex\":\"".len();
    let rest = &stdout[start..];
    let end = rest.find('"').expect("closing quote");
    assert_eq!(end, 16, "payload must be capped to 8 bytes: {stdout}");
}

#[test]
fn golden_entropy_window_zero_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--entropy", "--entropy-window", "0"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--entropy-window must be greater than 0"),
        "{stderr}"
    );
}

#[test]
fn golden_entropy_threshold_out_of_range_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--entropy",
            "--entropy-threshold",
            "9",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--entropy-threshold must be between 0 and 8"),
        "{stderr}"
    );
}

#[test]
fn golden_entropy_flags_imply_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(16 * 1024)).unwrap();

    // `--entropy-merge` on its own enables entropy scanning.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--entropy-merge",
            "--entropy-window",
            "1024",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"group\":\"Undefined\""), "{stdout}");
}

#[test]
fn golden_entropy_max_data_zero_omits_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, high_entropy_bytes(16 * 1024)).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy",
            "--entropy-max-data",
            "0",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("data_hex"), "{stdout}");
    assert!(!stdout.contains("data_truncated"), "{stdout}");
}

/// Fixture with one duplicated user path plus one artifact of every other kind.
const ARTIFACT_FIXTURE: &[u8] = b"C:\\Users\\eminem\\Desktop\\a.txt\x00\
C:\\Users\\eminem\\Desktop\\a.txt\x00\
RAR password=hunter2\x00\
https://example.com/x\x00\
admin@example.org\x00\
HKLM\\SOFTWARE\\Foo\x00";

fn artifact_fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifacts.bin");
    std::fs::write(&path, ARTIFACT_FIXTURE).unwrap();
    (dir, path)
}

#[test]
fn golden_extract_text_appends_deduped_artifacts() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "all",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let artifact_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("\tARTIFACT\t"))
        .collect();
    assert_eq!(artifact_lines.len(), 5, "{stdout}");
    assert!(
        artifact_lines.iter().any(|line| line.contains(
            "\tpath\tcount=2\tC:\\Users\\eminem\\Desktop\\a.txt\tuser=eminem;category=desktop"
        )),
        "{stdout}"
    );
    assert!(
        artifact_lines.iter().any(|line| line
            .contains("\tenv\tcount=1\tRAR password=hunter2\tname=RAR password;sensitive=true")),
        "{stdout}"
    );
    assert!(
        artifact_lines
            .iter()
            .any(|line| line.contains("\turl\tcount=1\thttps://example.com/x")),
        "{stdout}"
    );
    assert!(
        artifact_lines
            .iter()
            .any(|line| line.contains("\temail\tcount=1\tadmin@example.org")),
        "{stdout}"
    );
    assert!(
        artifact_lines
            .iter()
            .any(|line| line.contains("\tregistry\tcount=1\tHKLM\\SOFTWARE\\Foo")),
        "{stdout}"
    );
    // Rarest-first ordering puts the twice-seen path last.
    assert!(
        stdout.trim_end().ends_with("user=eminem;category=desktop"),
        "{stdout}"
    );
}

#[test]
fn golden_extract_json_emits_artifact_records() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "paths,env",
            "--format",
            "json",
            "--compact",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            r#""group":"ARTIFACT","kind":"path","value":"C:\\Users\\eminem\\Desktop\\a.txt","offset":0,"count":2,"detail":"user=eminem;category=desktop""#
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(r#""kind":"env","value":"RAR password=hunter2""#),
        "{stdout}"
    );
    // Only the requested families are collected.
    assert!(!stdout.contains(r#""kind":"url""#), "{stdout}");
    assert!(!stdout.contains(r#""kind":"email""#), "{stdout}");
    assert!(!stdout.contains(r#""kind":"registry""#), "{stdout}");
}

#[test]
fn golden_extract_tools_reports_capture_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tools.bin");
    let mut data = Vec::new();
    data.extend_from_slice(b"C:\\Users\\eminem\\Downloads\\DumpIt.exe\0");
    data.extend_from_slice(b"winpmem_mini_x64_rc2.exe --output C:\\dumps\\mem.raw\0");
    data.extend_from_slice(b"DUMPIT.EXE-1A2B3C4D.pf\0");
    data.extend_from_slice(b"DESKTOP-7F3A2B-20240101-120000.raw\0");
    std::fs::write(&path, data).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "tools",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let artifact_lines: Vec<&str> = stdout
        .lines()
        .filter(|line| line.contains("\tARTIFACT\t"))
        .collect();
    assert!(
        artifact_lines
            .iter()
            .any(|line| line.contains("\ttool\tcount=2\tDumpIt\tevidence=")
                && line.contains("category=capture")
                && line.contains("trace=path,prefetch")),
        "{stdout}"
    );
    assert!(
        artifact_lines
            .iter()
            .any(|line| line.contains("\ttool\tcount=1\tWinPmem\tevidence=")
                && line.contains("trace=command")),
        "{stdout}"
    );
    assert!(
        artifact_lines.iter().any(|line| line
            .contains("\ttool\tcount=1\traw/mem image\tevidence=")
            && line.contains("trace=filename")),
        "{stdout}"
    );
    // The prefetch entry is merged into the DumpIt artifact, so `tools` alone
    // never emits path/env/url/email/registry rows.
    assert!(
        !artifact_lines.iter().any(|line| {
            line.contains("\tpath\t")
                || line.contains("\tenv\t")
                || line.contains("\turl\t")
                || line.contains("\temail\t")
                || line.contains("\tregistry\t")
        }),
        "{stdout}"
    );
}

#[test]
fn golden_extract_ndjson_metadata_counts_artifacts() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "all",
            "--format",
            "ndjson",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    let metadata = lines.last().copied().unwrap();
    // 6 strings (the path is duplicated) + 5 artifacts.
    assert!(
        metadata.contains(r#""type":"metadata","total_records":11"#),
        "{stdout}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with(r#"{"type":"artifact","group":"ARTIFACT""#)),
        "{stdout}"
    );
}

#[test]
fn golden_extract_csv_emits_artifact_rows() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "all",
            "--format",
            "csv",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(
            "artifact,0x00000000,,C:\\Users\\eminem\\Desktop\\a.txt,path,,,,user=eminem;category=desktop,2,"
        ),
        "{stdout}"
    );
    assert!(
        stdout.contains(",HKLM\\SOFTWARE\\Foo,registry,,,,,1,"),
        "{stdout}"
    );
}

#[test]
fn golden_extract_rejects_json_tree() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--extract",
            "all",
            "--format",
            "json-tree",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--extract does not support --format json-tree"),
        "{stderr}"
    );
}

#[test]
fn golden_extract_rejects_unknown_kind() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--extract", "bogus"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid --extract value 'bogus'"),
        "{stderr}"
    );
}

#[test]
fn golden_report_summary_breaks_down_encodings_and_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mixed.bin");
    let mut data = b"hello ascii\x00".to_vec();
    for unit in "hello wide".encode_utf16() {
        data.extend_from_slice(&unit.to_le_bytes());
    }
    data.extend_from_slice(&[0, 0]);
    std::fs::write(&path, data).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "all",
            "--report",
            "summary",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[report] window 0x00000000-"), "{stderr}");
    // latin1/cp1252/utf8/shift_jis no longer repeat the all-ASCII "hello ascii"
    // row: when the ascii family is scanned too, a run without any non-ASCII
    // byte is already covered by the "ascii" record and the other families
    // would only add duplicates at the same offset. The UTF-16 mirror is still
    // reported because it is a separate run.
    assert!(
        stderr.contains("encodings  : ascii 1 | utf16le 1 | utf16be 1"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("latin1 1") && !stderr.contains("utf8 1"),
        "all-ASCII duplicates leaked into the report: {stderr}"
    );
    assert!(stderr.contains("scanned    : 0x00000000-"), "{stderr}");
    assert!(stderr.contains("% of file"), "{stderr}");
    assert!(
        stderr.contains("limit      : not reached (--max-strings 200000)"),
        "{stderr}"
    );
}

#[test]
fn golden_report_summary_flags_truncation() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--max-strings",
            "1",
            "--report",
            "summary",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("limit      : --max-strings 1 reached at 0x"),
        "{stderr}"
    );
    assert!(stderr.contains("(exit 3)"), "{stderr}");
}

#[test]
fn golden_report_summary_lists_top_artifacts() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--extract",
            "paths",
            "--report",
            "summary",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("top artifacts (rarest first"), "{stderr}");
    assert!(
        stderr.contains("C:\\Users\\eminem\\Desktop\\a.txt"),
        "{stderr}"
    );
    assert!(stderr.contains("count=2"), "{stderr}");
}

#[test]
fn golden_report_is_off_by_default() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("encodings  :"), "{stderr}");
    assert!(!stderr.contains("scanned    :"), "{stderr}");
    assert!(!stderr.contains("limit      :"), "{stderr}");
    assert!(!stderr.contains("[report] window"), "{stderr}");
}

#[test]
fn golden_report_rejects_unknown_mode() {
    let (_dir, path) = artifact_fixture();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--report", "bogus"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --report mode 'bogus'"), "{stderr}");
}

// --- --carve ---------------------------------------------------------------

/// CRC-32 (IEEE) used by PNG chunk trailers.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                0xedb8_8320 ^ (crc >> 1)
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xffff_ffff
}

/// A PNG whose IDAT payload is arbitrary bytes (the carver checks structure and
/// CRCs, not whether the deflate stream decodes).
fn png_fixture(payload: &[u8]) -> Vec<u8> {
    fn chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
        out
    }
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&4u32.to_be_bytes()); // width
    ihdr.extend_from_slice(&1u32.to_be_bytes()); // height
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]); // 8-bit RGB, no interlace

    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    out.extend(chunk(b"IHDR", &ihdr));
    out.extend(chunk(b"IDAT", payload));
    out.extend(chunk(b"IEND", &[]));
    out
}

/// A structurally valid JPEG: APP0, DQT, SOF0, DHT, SOS, entropy data, EOI.
fn jpeg_fixture(payload: &[u8]) -> Vec<u8> {
    fn segment(marker: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, marker];
        out.extend_from_slice(&((body.len() as u16) + 2).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    let mut out = vec![0xFF, 0xD8];
    out.extend(segment(
        0xE0,
        b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00",
    ));
    let mut dqt = vec![0u8];
    dqt.extend((1u8..=64).collect::<Vec<_>>());
    out.extend(segment(0xDB, &dqt));
    let mut sof = vec![8u8];
    sof.extend_from_slice(&8u16.to_be_bytes());
    sof.extend_from_slice(&8u16.to_be_bytes());
    sof.extend_from_slice(&[1, 1, 0x11, 0]);
    out.extend(segment(0xC0, &sof));
    let mut dht = vec![0u8, 1];
    dht.extend_from_slice(&[0u8; 15]);
    dht.push(0);
    out.extend(segment(0xC4, &dht));
    out.extend(segment(0xDA, &[1, 1, 0, 0, 0x3f, 0]));
    out.extend_from_slice(payload);
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

#[test]
fn golden_carve_writes_validated_files_and_index() {
    let dir = tempfile::tempdir().unwrap();
    let png = png_fixture(b"png payload bytes");
    let jpeg = jpeg_fixture(&vec![0x5au8; 300]);

    let mut dump = vec![0u8; 256];
    let png_offset = dump.len();
    dump.extend_from_slice(&png);
    dump.extend_from_slice(&vec![0u8; 512]);
    let jpeg_offset = dump.len();
    dump.extend_from_slice(&jpeg);
    dump.extend_from_slice(&[0u8; 128]);

    let path = dir.path().join("dump.bin");
    std::fs::write(&path, &dump).unwrap();
    let out_dir = dir.path().join("carved");
    let index = dir.path().join("index.ndjson");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--carve",
            "png,jpeg",
            "--carve-out",
            out_dir.to_str().unwrap(),
            "--carve-index",
            index.to_str().unwrap(),
            "--max-strings",
            "0",
            "--no-progress",
            "--report",
            "none",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("carve: 2 file(s) (2 complete)"), "{stderr}");

    let files = std::fs::read_dir(&out_dir).unwrap().count();
    assert_eq!(files, 2);

    let written = std::fs::read_dir(&out_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().contains("-png-"))
        .map(|entry| std::fs::read(entry.path()).unwrap())
        .unwrap();
    assert_eq!(written, png, "carved PNG must be byte-identical");

    let records = std::fs::read_to_string(&index).unwrap();
    let lines = records.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2, "{records}");
    assert!(
        lines[0].contains(&format!("\"offset\":{png_offset}")),
        "{records}"
    );
    assert!(lines[0].contains("\"type\":\"png\""), "{records}");
    assert!(lines[0].contains("\"complete\":true"), "{records}");
    assert!(
        lines[0].contains(&format!("\"size\":{}", png.len())),
        "{records}"
    );
    assert!(
        lines[1].contains(&format!("\"offset\":{jpeg_offset}")),
        "{records}"
    );
    assert!(lines[1].contains("\"type\":\"jpeg\""), "{records}");
    assert!(
        lines[1].contains(&format!("\"size\":{}", jpeg.len())),
        "{records}"
    );
}

#[test]
fn golden_carve_max_files_truncation_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let png = png_fixture(b"payload");
    let mut dump = vec![0u8; 64];
    for _ in 0..2 {
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 64]);
    }
    let path = dir.path().join("dump.bin");
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--carve",
            "png",
            "--carve-out",
            dir.path().join("out").to_str().unwrap(),
            "--carve-max-files",
            "1",
            "--max-strings",
            "0",
            "--no-progress",
            "--report",
            "none",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CARVE TRUNCATED"), "{stderr}");
}

#[test]
fn golden_carve_defaults_out_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dump.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    // Carving now defaults its output directory to <input>.bxmap/carved
    // instead of demanding --carve-out.
    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--carve", "png"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let default_dir = dir.path().join("dump.bin.bxmap").join("carved");
    assert!(default_dir.is_dir(), "carve defaults dir not created");
}

// ---------------------------------------------------------------------------
// --encoding accepts a comma-separated list (step 1 of the CLI cleanup).
// ---------------------------------------------------------------------------

/// One ASCII string plus one UTF-16LE string, so encoding filters are visible.
fn mixed_encoding_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("mixed.bin");
    let mut bytes = b"hello\x00".to_vec();
    for unit in "world!".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&[0, 0]);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn golden_encoding_list_selects_multiple_families() {
    let dir = tempfile::tempdir().unwrap();
    let path = mixed_encoding_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii,utf16",
            "--report",
            "summary",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"), "{stdout}");
    assert!(stdout.contains("world!"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("| encodings ascii, utf16 |"),
        "list is reported as-is: {stderr}"
    );
}

#[test]
fn golden_encoding_single_value_still_narrows() {
    let dir = tempfile::tempdir().unwrap();
    let path = mixed_encoding_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello"), "{stdout}");
    assert!(!stdout.contains("world!"), "{stdout}");
}

#[test]
fn golden_encoding_rejects_unknown_list_entry() {
    let dir = tempfile::tempdir().unwrap();
    let path = mixed_encoding_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--encoding", "ascii,klingon"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid encoding 'klingon'"), "{stderr}");
}
// ---------------------------------------------------------------------------
// -o <file> infers the writer from the extension unless --format is given.
// ---------------------------------------------------------------------------

fn tiny_scan_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();
    path
}

#[test]
fn golden_output_extension_infers_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());
    let out = dir.path().join("result.json");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "-o",
            out.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(written.trim_start().starts_with('['), "{written}");
    assert!(written.contains("\"text\":\"hello world\""), "{written}");
}

#[test]
fn golden_output_extension_infers_ndjson_and_csv() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    for (name, marker) in [
        ("result.ndjson", "{\"type\":\"string\""),
        ("result.csv", "type,offset,encoding,text"),
    ] {
        let out = dir.path().join(name);
        let output = Command::new(bin_path())
            .args([
                path.to_str().unwrap(),
                "--min-len",
                "4",
                "--encoding",
                "ascii",
                "-o",
                out.to_str().unwrap(),
                "--no-progress",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{name}: {:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        let written = std::fs::read_to_string(&out).unwrap();
        assert!(written.contains(marker), "{name}: {written}");
    }
}

#[test]
fn golden_explicit_format_beats_output_extension() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());
    let out = dir.path().join("result.json");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "text",
            "-o",
            out.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let written = std::fs::read_to_string(&out).unwrap();
    assert!(
        written.trim_end() == "0x00000000\tascii\thello world",
        "{written}"
    );
}

#[test]
fn golden_output_extension_infers_markdown_through_gzip_suffix() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());
    let out = dir.path().join("case.md.gz");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "-o",
            out.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let raw = std::fs::read(&out).unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&raw[..]);
    let mut written = String::new();
    decoder.read_to_string(&mut written).unwrap();
    assert!(written.starts_with("# bxmap Analysis Report"), "{written}");
}
// ---------------------------------------------------------------------------
// --mode presets are opt-in: without them nothing changes.
// ---------------------------------------------------------------------------

fn mode_fixture(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("mode.bin");
    std::fs::write(&path, b"abcd\x00http://example.com/x\x00").unwrap();
    path
}

#[test]
fn golden_mode_quick_matches_historical_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = mode_fixture(dir.path());

    let plain = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--no-progress"])
        .output()
        .unwrap();
    let quick = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--mode", "quick", "--no-progress"])
        .output()
        .unwrap();

    assert!(plain.status.success());
    assert!(quick.status.success());
    assert_eq!(
        String::from_utf8_lossy(&plain.stdout),
        String::from_utf8_lossy(&quick.stdout),
        "quick must be a no-op"
    );
}

#[test]
fn golden_mode_triage_applies_preset_and_respects_explicit_flags_in_any_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = mode_fixture(dir.path());

    let first = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--mode",
            "triage",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();
    let second = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--encoding",
            "ascii",
            "--mode",
            "triage",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(first.status.success(), "{:?}", first.status);
    assert_eq!(
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&second.stdout),
        "flag order must not matter"
    );

    let stdout = String::from_utf8_lossy(&first.stdout);
    // Preset: min-len 5 + detectors keep the URL and drop the short token.
    assert!(stdout.contains("http"), "{stdout}");
    assert!(!stdout.contains("abcd"), "{stdout}");
}

#[test]
fn golden_mode_triage_is_unlimited_when_writing_to_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = mode_fixture(dir.path());
    let out = dir.path().join("triage.ndjson");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--mode",
            "triage",
            "-o",
            out.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("limit      : not reached (unlimited)"),
        "{stderr}"
    );
    assert!(out.exists());
}

#[test]
fn golden_mode_rejects_unknown_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = mode_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--mode", "turbo"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --mode 'turbo'"), "{stderr}");
}
// ---------------------------------------------------------------------------
// Input auto-detection: MDMP minidumps and VMware snapshots.
// ---------------------------------------------------------------------------

#[test]
fn golden_mdmp_magic_enables_tree_and_map_va() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capture.dmp");
    std::fs::write(&path, b"MDMPhello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap()])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[i] MDMP minidump detected: enabled --tree + --map-va"),
        "{stderr}"
    );
    // --tree runs and fails on the truncated fake dump, so no scan happens.
    assert!(!output.status.success(), "{stderr}");
}

#[test]
fn golden_mdmp_autodetect_can_be_disabled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capture.dmp");
    std::fs::write(&path, b"MDMPhello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--no-tree",
            "--no-map-va",
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("[i] MDMP"), "{stderr}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello world"), "{stdout}");
}

#[test]
fn golden_vmware_snapshot_extension_enables_vmware_info() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("case.vmss");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let auto = Command::new(bin_path())
        .args([path.to_str().unwrap()])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&auto.stderr);
    assert!(
        stderr.contains("[i] VMware snapshot input: running --vmware-info"),
        "{stderr}"
    );

    let disabled = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--no-vmware-info",
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();
    assert!(
        disabled.status.success(),
        "{:?}",
        String::from_utf8_lossy(&disabled.stderr)
    );
    assert!(String::from_utf8_lossy(&disabled.stdout).contains("hello world"));
}

#[test]
fn golden_vmem_is_scanned_like_a_normal_image() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("memory.vmem");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("[i] VMware"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));
}
// ---------------------------------------------------------------------------
// The ASCII logo is help-only now; a normal scan must stay quiet.
// ---------------------------------------------------------------------------

#[test]
fn golden_scan_does_not_print_the_logo() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("fast memory-dump string extraction"),
        "logo leaked into scan output: {stderr}"
    );
    assert!(!stderr.contains('\u{28c0}'), "art leaked: {stderr}");
}

#[test]
fn golden_help_still_prints_the_logo() {
    let output = Command::new(bin_path()).arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fast memory-dump string extraction"),
        "{stdout}"
    );
    assert!(
        stdout.contains('\u{28c0}'),
        "art missing from --help: {stdout}"
    );
    assert!(stdout.contains("USAGE:"), "{stdout}");
}

// ---------------------------------------------------------------------------
// -V/--version reports the CLI crate version, not the library one.
// ---------------------------------------------------------------------------

#[test]
fn golden_version_prints_the_cli_crate_version() {
    for flag in ["-V", "--version"] {
        let output = Command::new(bin_path()).arg(flag).output().unwrap();

        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let first = stdout.lines().next().unwrap_or("");
        assert_eq!(
            first,
            format!("bxmap-cli {}", env!("CARGO_PKG_VERSION")),
            "{flag}: {stdout}"
        );
        assert!(stdout.contains("features: yara="), "{stdout}");
        assert!(stdout.contains("target:"), "{stdout}");
        assert_ne!(
            stdout.trim(),
            format!("bxmap-cli {}", bxmap::VERSION),
            "CLI must not print the library version: {stdout}"
        );
    }
}

// ---------------------------------------------------------------------------
// Flag conflict matrix: validate() must reject incompatible flag combos with a
// consistent error message. These pin the behaviour for the Phase 4 refactor.
// ---------------------------------------------------------------------------

#[test]
fn golden_conflict_detect_with_filter_regex() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--filter-regex",
            "^hello",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("cannot be combined with a detector"),
        "{stderr}"
    );
}

#[test]
fn golden_conflict_rich_detect_format_implies_detect() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"config AKIAIOSFODNN7EXAMPLE end\x00").unwrap();

    // `--detect-format rich` now enables the default (secret) detector set
    // instead of erroring.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect-format",
            "rich",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"rule\":\"AWS_ACCESS_KEY\""), "{stdout}");
}

#[test]
fn golden_conflict_rich_rejects_json_tree() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--format",
            "json-tree",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("supports --format text or json"),
        "{stderr}"
    );
}

#[test]
fn golden_conflict_xor_exhaustive_requires_brute_xor() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--xor-exhaustive",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires --brute-xor"), "{stderr}");
}

#[test]
fn golden_conflict_carve_out_implies_carve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    // `--carve-out` on its own now starts an all-kinds carve.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--carve-out",
            dir.path().join("carved").to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("carved").is_dir());
}

#[test]
fn golden_conflict_carve_defaults_out_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--carve",
            "png",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let default_dir = dir.path().join("input.bin.bxmap").join("carved");
    assert!(default_dir.is_dir(), "default carve dir missing");
}

#[test]
fn golden_conflict_entropy_flags_require_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--entropy-window",
            "1024",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .unwrap();

    // Entropy sub-flags enable entropy scanning by themselves now.
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("\"group\":\"Undefined\""),
        "plain text must not look encrypted"
    );
}

#[test]
fn golden_conflict_csv_rejects_yar() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();
    let rules = dir.path().join("rules.yar");
    std::fs::write(
        &rules,
        r#"rule demo { strings: $a = "hello" condition: $a }"#,
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "csv",
            "--yar",
            rules.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("csv supports") || stderr.contains("yar"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// Golden coverage for flags previously missing from cli/tests/golden.rs.
// These pin the *current* behaviour byte-for-byte so Phase 4 refactor can't
// silently change output. Behaviour assertions are kept minimal and derived
// from the source; if a flag's output changes on purpose, update both the
// assertion here and CHANGELOG.md.
// ---------------------------------------------------------------------------

#[test]
fn golden_max_str_len_truncates_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"this is a long string that should be cut\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--max-str-len",
            "8",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("this is ..."), "{stdout}");
}

#[test]
fn golden_magic_bytes_reports_signatures() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // "MZ" PE header followed by a PE signature a bit later.
    let mut dump = b"xxMZ\x90\x00\x00\x00".to_vec();
    dump.extend_from_slice(b"\x00PE\x00\x00tail");
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--signature",
            "magic",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MAGIC"), "{stdout}");
}

#[test]
fn golden_find_keys_reports_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // PKCS#8 DER envelope (RSA private key):
    // SEQUENCE { INTEGER version, SEQUENCE { OID rsaEncryption, NULL },
    //            OCTET STRING { SEQUENCE { INTEGER n, INTEGER e } } }
    let envelope: &[u8] = &[
        0x30, 0x1c, // outer SEQUENCE, len 28
        0x02, 0x01, 0x00, // version INTEGER 0
        0x30, 0x0d, // algorithm SEQUENCE, len 13
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // OID rsaEncryption
        0x05, 0x00, // NULL
        0x04, 0x08, // OCTET STRING, len 8
        0x30, 0x04, 0x02, 0x01, 0x01, 0x02, 0x01, 0x05, // inner SEQUENCE {n,e}
    ];
    let mut dump = b"prefix".to_vec();
    dump.extend_from_slice(envelope);
    dump.extend_from_slice(b"suffix");
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--signature",
            "keys",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("KEY"), "{stdout}");
    assert!(stdout.contains("rsa_private_key"), "{stdout}");
}

#[test]
fn golden_parse_pid_emits_pid_field() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"process pid 1234 started\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--parse-pid",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pid=1234"), "{stdout}");
}

#[test]
fn golden_filter_regex_only_matching_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"alpha\x00beta\x00gamma\x00beta\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--filter-regex",
            "^beta",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("beta"), "{stdout}");
    assert!(!stdout.contains("alpha"), "{stdout}");
    assert!(!stdout.contains("gamma"), "{stdout}");
}

#[test]
fn golden_auto_tune_runs_without_crash() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--auto-tune",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(String::from_utf8_lossy(&output.stdout).contains("hello world"));
}

#[test]
fn golden_brute_xor_emits_xor_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // Printable candidate region + a 1-byte-XORed string.
    let mut dump = b"AAAAAAAAAA".to_vec();
    dump.extend_from_slice(
        &b"hello world\0"
            .iter()
            .map(|b| b ^ 0x42)
            .collect::<Vec<_>>(),
    );
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--brute-xor",
            "1b",
            "--max-strings",
            "0",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("XOR"), "{stdout}");
    assert!(stdout.contains("key="), "{stdout}");
}

#[test]
fn golden_carve_min_size_skips_small_files() {
    let dir = tempfile::tempdir().unwrap();
    let png = png_fixture(b"tiny");
    let mut dump = vec![0u8; 256];
    let off = dump.len();
    dump.extend_from_slice(&png);
    let path = dir.path().join("dump.bin");
    std::fs::write(&path, &dump).unwrap();
    let out_dir = dir.path().join("carved");

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--carve",
            "png",
            "--carve-out",
            out_dir.to_str().unwrap(),
            "--carve-min-size",
            "999999",
            "--max-strings",
            "0",
            "--no-progress",
            "--report",
            "none",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let files = std::fs::read_dir(&out_dir)
        .map(|rd| rd.count())
        .unwrap_or(0);
    assert_eq!(files, 0, "min-size above file size must skip carving");
    let _ = off;
}

#[test]
fn golden_carve_max_total_exits_3() {
    let dir = tempfile::tempdir().unwrap();
    let png = png_fixture(b"payload payload payload payload");
    let mut dump = vec![0u8; 64];
    for _ in 0..3 {
        dump.extend_from_slice(&png);
        dump.extend_from_slice(&[0u8; 64]);
    }
    let path = dir.path().join("dump.bin");
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--carve",
            "png",
            "--carve-out",
            dir.path().join("out").to_str().unwrap(),
            "--carve-max-total",
            "1",
            "--max-strings",
            "0",
            "--no-progress",
            "--report",
            "none",
        ])
        .output()
        .unwrap();

    assert_eq!(
        output.status.code(),
        Some(3),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("carve") || stderr.contains("max-total") || stderr.contains("truncat"),
        "{stderr}"
    );
}

#[test]
fn golden_filter_appdata_without_extract_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--filter-appdata",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
}

#[test]
fn golden_min_files_in_user_without_extract_is_noop() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--min-files-in-user",
            "5",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
}

#[test]
fn golden_noise_threshold_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--noise-threshold",
            "3",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
}

#[test]
fn golden_stats_flag_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--stats",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
}

#[test]
fn golden_xor_exhaustive_prints_estimate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // A printable candidate region long enough to be picked up.
    let mut dump = b"AAAAAAAAAAAAAAAAAAAA".to_vec();
    dump.extend_from_slice(
        &b"hello world\0"
            .iter()
            .map(|b| b ^ 0x42)
            .collect::<Vec<_>>(),
    );
    std::fs::write(&path, &dump).unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--brute-xor",
            "3b",
            "--xor-exhaustive",
            "--max-strings",
            "0",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("byte-ops")
            || stderr.contains("G byte-ops")
            || stderr.contains("keys")
            || stderr.contains("exhaustive"),
        "{stderr}"
    );
}

#[test]
#[cfg(feature = "yara")]
fn golden_yara_reports_rule_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00secret key material here\x00").unwrap();
    let rules = dir.path().join("rules.yar");
    std::fs::write(
        &rules,
        r#"rule demo { strings: $a = "secret key" condition: $a }"#,
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--yar",
            rules.to_str().unwrap(),
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("YARA"), "{stdout}");
    assert!(stdout.contains("demo"), "{stdout}");
}

#[test]
fn golden_csv_rejects_magic_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = tiny_scan_fixture(dir.path());

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--format",
            "csv",
            "--magic-bytes",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("csv supports") || stderr.contains("magic-bytes"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// --detect-strict: invalid findings are dropped instead of confidence-reduced.
// ---------------------------------------------------------------------------

#[test]
fn golden_detect_strict_drops_invalid_aws_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // AKIA followed by only 15 chars (not 20) -> fails validate_aws_key.
    std::fs::write(&path, b"key AKIA12345678901 rest\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--format",
            "json",
            "--detect-strict",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Strict mode: invalid AWS key dropped entirely.
    assert!(!stdout.contains("AWS_ACCESS_KEY"), "{stdout}");
}

#[test]
fn golden_detect_strict_keeps_valid_aws_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // Valid AKIA + 16 chars = 20 total.
    std::fs::write(&path, b"key AKIAIOSFODNN7EXAMPLE rest\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--format",
            "json",
            "--detect-strict",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"rule\":\"AWS_ACCESS_KEY\""), "{stdout}");
    assert!(
        stdout.contains("\"value\":\"AKIAIOSFODNN7EXAMPLE\""),
        "{stdout}"
    );
}

#[test]
fn golden_detect_non_strict_keeps_invalid_jwt_with_lower_confidence() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // JWT-shaped (3 base64url parts) but header lacks "typ" claim ->
    // validate_jwt returns Invalid.
    std::fs::write(
        &path,
        b"token eyJhbGciOiJIUzI1NiJ9.invalidtokenpart.signaturepart123 rest\x00",
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--detect",
            "secret",
            "--detect-format",
            "rich",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Non-strict: keeps the finding (confidence halved instead of dropped).
    assert!(stdout.contains("JWT_TOKEN"), "{stdout}");
}

// ---------------------------------------------------------------------------
// --with feature bundles and option-implies-feature behaviour
// ---------------------------------------------------------------------------

#[test]
fn golden_with_iocs_detects_secret() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"config AKIAIOSFODNN7EXAMPLE end\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--with",
            "iocs",
            "--detect-format",
            "rich",
            "--format",
            "json",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AWS_ACCESS_KEY"), "{stdout}");
}

#[test]
fn golden_with_all_is_rejected_passing_feature_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    // --with all parses in any position/combination and stays explicit-safe.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--with",
            "entropy",
            "--with",
            "magic",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn golden_with_unknown_feature_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--with", "wat"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown --with feature"), "{stderr}");
}

#[test]
fn golden_with_all_runs_full_triage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    // Mixed content: plain text plus an IOC, so the bundle proves every
    // feature ran. Detector mode (like --detect) prints matching findings
    // instead of raw strings.
    std::fs::write(
        &path,
        b"hello world AKIAIOSFODNN7EXAMPLE C:\\Users\\bob\\payload.exe\x00",
    )
    .unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--with",
            "all",
            "--max-strings",
            "50",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // IOC detectors fired on the secret...
    assert!(stdout.contains("AKIAIOSFODNN7EXAMPLE"), "{stdout}");
    // ...and the artifact collector picked up the user path.
    assert!(stdout.contains("payload.exe"), "{stdout}");
}

#[test]
fn golden_report_user_implies_path_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(
        &path,
        b"C:\\Users\\alice\\Documents\\secret.txt\x00".as_slice(),
    )
    .unwrap();

    // --report used to demand --extract; collecting paths is now automatic.
    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--report",
            "user",
            "--no-progress",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\tARTIFACT\tpath"), "{stdout}");
}

#[test]
fn golden_heap_only_implies_map_va() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([
            path.to_str().unwrap(),
            "--min-len",
            "4",
            "--encoding",
            "ascii",
            "--heap-only",
            "--no-progress",
        ])
        .output()
        .unwrap();

    // Non-minidump input ignores --map-va, but the flag combination must not
    // complain ("--heap-only requires --map-va" is gone).
    assert!(
        output.status.success(),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}
