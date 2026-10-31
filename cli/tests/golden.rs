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
fn golden_entropy_no_data_requires_entropy() {
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
            "--entropy-no-data",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--entropy-no-data requires --entropy"),
        "{stderr}"
    );
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
fn golden_entropy_flags_require_entropy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, b"aaaa\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--entropy-merge"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--entropy-merge requires --entropy"),
        "{stderr}"
    );
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
    assert!(
        stderr.contains("encodings  : ascii 1 | utf16le 1"),
        "{stderr}"
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
    dump.extend_from_slice(&vec![0u8; 128]);

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
        dump.extend_from_slice(&vec![0u8; 64]);
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
fn golden_carve_requires_out_dir() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dump.bin");
    std::fs::write(&path, b"hello world\x00").unwrap();

    let output = Command::new(bin_path())
        .args([path.to_str().unwrap(), "--carve", "png"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--carve requires --carve-out"), "{stderr}");
}
