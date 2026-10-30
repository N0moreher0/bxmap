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
