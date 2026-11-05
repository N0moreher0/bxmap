#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // magic scan reads from a file path; stage the bytes in a temp file.
    let path = std::env::temp_dir().join("bxmap-fuzz-magic.bin");
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(data);
        let _ = f.flush();
        let _ = bxmap::magic::scan_file(path.to_str().unwrap(), 100);
    }
    let _ = std::fs::remove_file(&path);
});