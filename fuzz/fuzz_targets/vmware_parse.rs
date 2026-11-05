#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let path = std::env::temp_dir().join("bxmap-fuzz-vmware.bin");
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(data);
        let _ = f.flush();
        if let Ok(st) = bxmap::vmware::VmwareState::open(path.to_str().unwrap()) {
            let _ = st.render_info();
        }
    }
    let _ = std::fs::remove_file(&path);
});