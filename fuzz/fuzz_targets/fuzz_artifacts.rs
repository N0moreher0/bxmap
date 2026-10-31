#![no_main]
use bxmap::artifacts::{ArtifactCollector, ArtifactKinds};
use bxmap::{extract_strings, NoiseConfig};
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    let results = extract_strings(data, 4, 1000);
    let mut collector = ArtifactCollector::new(ArtifactKinds::ALL, 1000);
    for result in &results {
        collector.observe(&result.text, result.offset);
    }
    let _ = collector.finish();
});
