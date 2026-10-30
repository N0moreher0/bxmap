use std::process::Command;

fn bin_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop(); // deps
    if cfg!(windows) {
        p.push("bxmap.exe");
    } else {
        p.push("bxmap");
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

    assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
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

    assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
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

    assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"groups\""));
}
