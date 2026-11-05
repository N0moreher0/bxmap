#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    // Carving must never panic on arbitrary bytes; scan_from_reader stages
    // the corpus into a temp file the carver can open.
    let path = std::env::temp_dir().join("bxmap-fuzz-carve.bin");
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(data);
        let _ = f.flush();
        let _ = bxmap::carve::Carver::new(bxmap::carve::CarveOptions::default())
            .scan_from_reader(&data[..]);
    }
    let _ = std::fs::remove_file(&path);
});
