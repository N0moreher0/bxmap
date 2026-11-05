#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join("bxmap-fuzz-entropy.bin");
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(data);
        let _ = f.flush();
        let _ = bxmap::scan_entropy_from_file_streaming(path.to_str().unwrap(), 7.0, |r| {
            let _ = r;
        });
    }
    let _ = std::fs::remove_file(&path);
});