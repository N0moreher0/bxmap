#![no_main]
use bxmap::minidump::Minidump;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = Minidump::from_reader(Cursor::new(data));
});
