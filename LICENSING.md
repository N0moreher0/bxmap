# Licensing

This repository contains two packages with different licenses. There is no
single "repository license": pick the package you are using.

| Package | Path | License | Text |
|---------|------|---------|------|
| `bxmap` (library) | repo root | `MIT OR Apache-2.0` | [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE) |
| `bxmap-cli` (frontend) | [`cli/`](cli) | `AGPL-3.0-only` | [cli/LICENSE-AGPL](cli/LICENSE-AGPL) |

Both choices are recorded in the `license` field of each `Cargo.toml`, so the
published crates (`bxmap`, `bxmap-cli`) carry the correct metadata.

## Why the split

The library is meant to be embedded — in other tools, in services, in a
notebook via a future binding — so it stays on the usual permissive Rust dual
license. The CLI is the end-user product and is AGPL-3.0-only.

## Rules of thumb

- **Linking `bxmap` as a dependency** (any project, including proprietary) →
  MIT OR Apache-2.0, at your option.
- **Using, modifying or redistributing `bxmap-cli`, or offering it as a
  network service** → AGPL-3.0-only applies to the CLI and to modifications of
  it. Running the CLI on a dump does not make your dump or your analysis
  output AGPL.
- Copying code from `cli/` into the library would relicense that code as
  AGPL, so keep the two trees separate.

Note: this file is a summary to make the split obvious on GitHub. The license
texts above are authoritative.
