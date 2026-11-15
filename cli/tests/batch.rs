use std::process::Command;

fn bin_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_bxmap") {
        return path.into();
    }
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // deps
    if cfg!(windows) {
        path.push("bxmap.exe");
    } else {
        path.push("bxmap");
    }
    path
}

fn batch_command(output_dir: &std::path::Path, inputs: &[&std::path::Path]) -> Command {
    let mut command = Command::new(bin_path());
    command.arg("--parallel-files").arg("2");
    command.arg("--output-dir").arg(output_dir);
    command.args(inputs);
    command.args(["--min-len", "4", "--encoding", "ascii"]);
    command
}

fn le32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn le64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn synthetic_minidump(module_name: &str, timestamp: u32, text: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"MDMP");
    le32(&mut bytes, 0xa793);
    le32(&mut bytes, 2); // module list + memory64 list
    le32(&mut bytes, 32); // directory RVA
    le32(&mut bytes, 0); // checksum
    le32(&mut bytes, 1); // header timestamp
    le64(&mut bytes, 0); // flags
    let directory = bytes.len();
    bytes.resize(directory + 24, 0);

    let name_rva = bytes.len();
    let name: Vec<u16> = module_name.encode_utf16().collect();
    le32(&mut bytes, (name.len() * 2) as u32);
    for unit in name {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    let module_rva = bytes.len();
    le32(&mut bytes, 1); // module count
    le64(&mut bytes, 0x1000); // base
    le32(&mut bytes, 0x2000); // image size
    le32(&mut bytes, 0); // checksum
    le32(&mut bytes, timestamp);
    le32(&mut bytes, name_rva as u32);
    bytes.resize(module_rva + 112, 0); // count + MINIDUMP_MODULE

    let memory64_rva = bytes.len();
    le64(&mut bytes, 1); // one memory range
    le64(&mut bytes, (memory64_rva + 32) as u64); // memory base RVA
    le64(&mut bytes, 0x1000); // memory base VA
    le64(&mut bytes, 16); // memory size
    let mut memory = [0u8; 16];
    let text = text.as_bytes();
    assert!(text.len() < memory.len());
    memory[..text.len()].copy_from_slice(text);
    bytes.extend_from_slice(&memory);

    for (index, (stream_type, size, rva)) in [(4u32, 112u32, module_rva), (9, 32, memory64_rva)]
        .into_iter()
        .enumerate()
    {
        let entry = directory + index * 12;
        bytes[entry..entry + 4].copy_from_slice(&stream_type.to_le_bytes());
        bytes[entry + 4..entry + 8].copy_from_slice(&size.to_le_bytes());
        bytes[entry + 8..entry + 12].copy_from_slice(&(rva as u32).to_le_bytes());
    }
    bytes
}

#[test]
fn batch_writes_independent_outputs_and_publishes_only_final_names() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("alpha.raw");
    let second = dir.path().join("beta.raw");
    let output_dir = dir.path().join("results");
    std::fs::write(&first, b"alpha string\0").unwrap();
    std::fs::write(&second, b"beta string\0").unwrap();

    let output = batch_command(&output_dir, &[&first, &second])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let first_result = std::fs::read_to_string(output_dir.join("0001_alpha.txt")).unwrap();
    let second_result = std::fs::read_to_string(output_dir.join("0002_beta.txt")).unwrap();
    assert!(first_result.contains("alpha string"));
    assert!(!first_result.contains("beta string"));
    assert!(second_result.contains("beta string"));
    assert!(!second_result.contains("alpha string"));
    assert!(!output_dir.join("0001_alpha.txt.partial").exists());
    assert!(!output_dir.join("0002_beta.txt.partial").exists());

    for (input, batch_result, baseline_name) in [
        (
            &first,
            output_dir.join("0001_alpha.txt"),
            "single-alpha.txt",
        ),
        (&second, output_dir.join("0002_beta.txt"), "single-beta.txt"),
    ] {
        let baseline = dir.path().join(baseline_name);
        let single = Command::new(bin_path())
            .arg(input)
            .args(["--min-len", "4", "--encoding", "ascii"])
            .arg("-o")
            .arg(&baseline)
            .output()
            .unwrap();
        assert!(
            single.status.success(),
            "{}",
            String::from_utf8_lossy(&single.stderr)
        );
        assert_eq!(
            std::fs::read(batch_result).unwrap(),
            std::fs::read(baseline).unwrap()
        );
    }
}

#[test]
fn batch_disambiguates_identical_basenames_from_different_directories() {
    let dir = tempfile::tempdir().unwrap();
    let first_dir = dir.path().join("first");
    let second_dir = dir.path().join("second");
    std::fs::create_dir_all(&first_dir).unwrap();
    std::fs::create_dir_all(&second_dir).unwrap();
    let first = first_dir.join("same.raw");
    let second = second_dir.join("same.raw");
    let output_dir = dir.path().join("results");
    std::fs::write(&first, b"first dump\0").unwrap();
    std::fs::write(&second, b"second dump\0").unwrap();

    let output = batch_command(&output_dir, &[&first, &second])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first_result = std::fs::read_to_string(output_dir.join("0001_same.txt")).unwrap();
    let second_result = std::fs::read_to_string(output_dir.join("0002_same.txt")).unwrap();
    assert!(first_result.contains("first dump"));
    assert!(second_result.contains("second dump"));
}

#[test]
fn batch_maps_each_minidump_to_its_own_va_and_module_timestamp() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("alpha.mdmp");
    let second = dir.path().join("beta.mdmp");
    let output_dir = dir.path().join("results");
    std::fs::write(
        &first,
        synthetic_minidump("alpha.exe", 1111, "alpha mapped"),
    )
    .unwrap();
    std::fs::write(&second, synthetic_minidump("beta.exe", 2222, "beta mapped")).unwrap();

    let mut command = batch_command(&output_dir, &[&first, &second]);
    command.args(["--no-tree", "--format", "json-tree", "--min-len", "8"]);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let first_result = std::fs::read_to_string(output_dir.join("0001_alpha.json")).unwrap();
    let second_result = std::fs::read_to_string(output_dir.join("0002_beta.json")).unwrap();
    assert!(first_result.contains("alpha mapped"));
    assert!(first_result.contains("\"timestamp\":1111"));
    assert!(!first_result.contains("beta mapped"));
    assert!(!first_result.contains("\"timestamp\":2222"));
    assert!(second_result.contains("beta mapped"));
    assert!(second_result.contains("\"timestamp\":2222"));
    assert!(!second_result.contains("alpha mapped"));
    assert!(!second_result.contains("\"timestamp\":1111"));

    let json_dir = dir.path().join("json-results");
    let mut command = batch_command(&json_dir, &[&first, &second]);
    command.args(["--no-tree", "--format", "json", "--min-len", "8"]);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let first_json = std::fs::read_to_string(json_dir.join("0001_alpha.json")).unwrap();
    let second_json = std::fs::read_to_string(json_dir.join("0002_beta.json")).unwrap();
    assert!(first_json.contains("\"va\":\"0x1000\""));
    assert!(first_json.contains("\"module\":\"alpha.exe\""));
    assert!(!first_json.contains("beta.exe"));
    assert!(second_json.contains("\"va\":\"0x1000\""));
    assert!(second_json.contains("\"module\":\"beta.exe\""));
    assert!(!second_json.contains("alpha.exe"));
}

#[test]
fn batch_continues_after_one_input_fails_and_keeps_successful_result() {
    let dir = tempfile::tempdir().unwrap();
    let valid = dir.path().join("valid.raw");
    let missing = dir.path().join("missing.raw");
    let output_dir = dir.path().join("results");
    std::fs::write(&valid, b"valid string\0").unwrap();

    let output = batch_command(&output_dir, &[&valid, &missing])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("completed 1/2 input(s)"), "{stderr}");
    assert!(output_dir.join("0001_valid.txt").is_file());
    assert!(!output_dir.join("0002_missing.txt").exists());
    assert!(!output_dir.join("0002_missing.txt.partial").exists());
}

#[test]
fn batch_refuses_existing_output_without_changing_it() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("alpha.raw");
    let second = dir.path().join("beta.raw");
    let output_dir = dir.path().join("results");
    std::fs::write(&input, b"alpha string\0").unwrap();
    std::fs::write(&second, b"beta string\0").unwrap();
    std::fs::create_dir_all(&output_dir).unwrap();
    let existing = output_dir.join("0001_alpha.txt");
    std::fs::write(&existing, b"keep this result").unwrap();

    let output = batch_command(&output_dir, &[&input, &second])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already exists"));
    assert_eq!(std::fs::read(existing).unwrap(), b"keep this result");
}

#[test]
fn batch_rejects_interleaved_reports_before_creating_output_dir() {
    let dir = tempfile::tempdir().unwrap();
    let first = dir.path().join("alpha.raw");
    let second = dir.path().join("beta.raw");
    let output_dir = dir.path().join("results");
    std::fs::write(&first, b"alpha string\0").unwrap();
    std::fs::write(&second, b"beta string\0").unwrap();

    let mut command = batch_command(&output_dir, &[&first, &second]);
    command.arg("--report").arg("summary");
    let output = command.output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--report is not supported"));
    assert!(!output_dir.exists());
}
