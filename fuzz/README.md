# Fuzzing

This directory is intentionally outside the workspace. Use `cargo-fuzz`
(nightly required):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run fuzz_minidump
cargo +nightly fuzz run fuzz_strings
```
PY