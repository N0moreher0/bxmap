#![no_main]
use libfuzzer_sys::fuzz_target;
use bxmap::minidump::Minidump;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = Minidump::from_reader(Cursor::new(data));
});