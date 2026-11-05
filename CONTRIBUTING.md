# Contributing

Thanks for considering a contribution to `bxmap`.

## Development setup

```bash
git clone https://github.com/N0moreher0/bxmap.git
cd bxmap
cargo build --no-default-features
cargo test --no-default-features
cargo test
```

Full builds need the YARA feature (`default`); they can take a while and
require a 64-bit toolchain.

## Running checks before a PR

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings   # may need -D denied adjustments
cargo test
```

## Coding guidelines
- Keep the scanning hot path allocations bounded; prefer reusing buffers.
- Library API must remain backward compatible unless a breaking change is
  approved and marked in the changelog.
- New detectors / patterns should come with regression tests.
- Encoding detection lives in `src/lib.rs`; keep single-pass semantics.

## Pull requests
- One logical change per PR.
- Add / update tests for behavior changes.
- Update `CHANGELOG.md` when user-visible behavior changes.
