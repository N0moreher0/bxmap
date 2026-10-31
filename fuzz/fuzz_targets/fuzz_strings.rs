#![no_main]
use bxmap::{extract_strings, NoiseConfig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = extract_strings(data, 4, 1000);
    let _ = bxmap::extract_strings_with_noise_config(data, 4, 1000, NoiseConfig::default());
});
