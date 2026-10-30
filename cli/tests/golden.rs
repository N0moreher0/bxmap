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
