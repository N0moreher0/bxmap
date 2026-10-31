#![no_main]
use bxmap::carve::{CarveKind, CarveOptions, Carver};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let cursor = Cursor::new(data);
    let options = CarveOptions {
        kinds: CarveKind::ALL.to_vec(),
        min_size: 0,
        max_size: 64 * 1024 * 1024,
        max_total: 0,
        max_files: 10,
    };
    let _ = Carver::new(options).scan_from_reader(cursor);
});
