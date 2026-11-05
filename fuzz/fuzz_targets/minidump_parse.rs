#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    // Must never panic or OOM on hostile input.
    if let Ok(md) = bxmap::minidump::Minidump::from_reader(Cursor::new(data)) {
        let _ = md.render_tree(20);
        let _ = md.rwx_regions();
        let _ = md.va_to_offset(0);
        let _ = md.offset_to_va(0);
    }
});