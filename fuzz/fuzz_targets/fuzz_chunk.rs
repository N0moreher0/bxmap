#![no_main]
use bxmap::chunk::{for_each_chunk_reader, CHUNK_SIZE};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let mut cursor = Cursor::new(data);
    let _ = for_each_chunk_reader(&mut cursor, CHUNK_SIZE, 64, |_chunk| true);
});
