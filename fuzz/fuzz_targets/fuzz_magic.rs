#![no_main]
use bxmap::magic::scan_file;
use libfuzzer_sys::fuzz_target;
use std::fs::File;
use std::io::Cursor;
use std::io::Write;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    // scan_file takes a path, so write to temp file
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(data).unwrap();
    temp.flush().unwrap();
    let _ = scan_file(temp.path().to_str().unwrap(), 100);
});
