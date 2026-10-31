#![no_main]
use bxmap::{scan_entropy_from_file_with_options, EntropyScanOptions};
use libfuzzer_sys::fuzz_target;
use std::fs::File;
use std::io::Cursor;
use std::io::Write;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let mut temp = NamedTempFile::new().unwrap();
    temp.write_all(data).unwrap();
    temp.flush().unwrap();
    let options = EntropyScanOptions {
        window: 4096,
        threshold: 7.0,
        merge: true,
        max_data: 1024,
    };
    let _ = scan_entropy_from_file_with_options(
        temp.path().to_str().unwrap(),
        options,
        |_region, _data, _truncated| {},
    );
});
