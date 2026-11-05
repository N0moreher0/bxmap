#![no_main]

use libfuzzer_sys::fuzz_target;
use bxmap::{extract_strings, EncodingFilter};

fuzz_target!(|data: &[u8]| {
    // Must never panic on arbitrary bytes.
    let _ = extract_strings(data, 4, 1000);
    let _ = extract_strings(data, 1, 1000);
    let _ = extract_strings(data, 0, 1000);
    let _ = bxmap::extract_strings_with_encodings(data, 4, 1000, EncodingFilter::all());
    let _ = bxmap::extract_strings_with_encodings(data, 4, 1000, EncodingFilter::ascii());
});