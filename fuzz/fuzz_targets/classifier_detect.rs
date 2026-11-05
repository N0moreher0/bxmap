#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = bxmap::classifier::classify(s);
        let _ = bxmap::classifier::detect_secrets(s);
        let _ = bxmap::classifier::detect_secrets_detailed(s);
        let _ = bxmap::classifier::extract_pems(s);
        let _ = bxmap::classifier::context_around(s, 0, s.len().min(8), 8);
    }
    // Also exercise byte-oriented helpers.
    let _ = bxmap::classifier::detect_encryption_shell(data);
    let _ = bxmap::classifier::detect_bitlocker_header(data);
    let _ = bxmap::classifier::detect_luks_header(data);
    let _ = bxmap::classifier::detect_openssl_encrypted(data);
    let _ = bxmap::classifier::detect_pgp_container(data);
    let _ = bxmap::classifier::detect_veracrypt_header(data);
});