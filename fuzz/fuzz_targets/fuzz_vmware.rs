#![no_main]
use bxmap::vmware::VmwareState;
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
    let _ = VmwareState::open(temp.path());
});
