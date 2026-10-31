# bxmap

```text
+-----------------------------------------+
|  BBBB    X   X   MMM MMM    AAA    PPPP |
|  B   B    X X    M M M M   A   A   P   P|
|  BBBB      X     M  M  M   AAAAA   PPPP |
|  B   B    X X    M     M   A   A   P    |
|  BBBB    X   X   M     M   A   A   P    |
+-----------------------------------------+
             Fast, composable memory-dump extraction
```

> **A fast Rust core library plus a ready-to-use CLI for DFIR and
> malware-analysis workflows.**

[![Crates.io](https://img.shields.io/crates/v/bxmap?logo=rust)](https://crates.io/crates/bxmap)
[![Documentation](https://img.shields.io/docsrs/bxmap?logo=docs.rs)](https://docs.rs/bxmap)
[![License](https://img.shields.io/crates/l/bxmap)](https://github.com/N0moreher0/bxmap)

This repository contains two layers:

- **`bxmap`** — the library crate published on
  [crates.io](https://crates.io/crates/bxmap), containing the extraction
  engine, noise filtering, bounded parallel scanning, and serializable
  results.
- **`bxmap-cli`** — the optional command-line frontend in [`cli/`](./cli/),
  published separately with a BXMAP banner, automatic reports, JSON/text
  output, encoding filters, credential/IP/crypto-wallet triage signals, and
  hardware-aware scanning.

Use the Rust API directly for custom applications, or install the finished
CLI when you want an immediate command-line workflow.

## Install the CLI and use it

For the fastest setup, download a prebuilt binary from the
[latest automated GitHub Release](https://github.com/N0moreher0/bxmap/releases)
and put `bxmap` on your `PATH`. Tag-based releases (`v*`) publish platform
archives with `SHA256SUMS`; verify downloads before DFIR use.

If you use [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall),
it downloads the matching release binary instead of compiling from source:

```powershell
cargo binstall bxmap-cli
```

The normal Cargo command remains available, but it compiles locally:

```powershell
cargo install bxmap-cli
```

Then scan immediately:

```powershell
bxmap memory.dmp --auto-tune
bxmap memory.dmp --entropy --format json -o triage.json
bxmap memory.dmp --yar rules.yar --format json -o yara.json
bxmap memory.dmp --brute-xor "1b;2b" --format json -o xor.json

# Malware dump: single-pass IOC + private-key triage
bxmap suspicious.dmp --encoding all --format json-tree --detect --map-va --heap-only -o triage.json
```

Update an existing installation:

```powershell
cargo install bxmap-cli --force
```

See all available options:

```powershell
bxmap --help
```

## Static builds for any machine (routers, embedded, old distros)

One file cannot run on every CPU architecture, so every release ships one
self-contained `bxmap-<target>.bin` per architecture. The Linux ones are fully
static (musl): no libc, no dependencies, copy and run.

| Target | Typical hardware | Build |
| --- | --- | --- |
| `x86_64-unknown-linux-musl` | PCs, servers | full (YARA) |
| `aarch64-unknown-linux-musl` | ARM64 boards, phones, newer routers | full (YARA) |
| `i686-unknown-linux-musl` | old 32-bit x86 | lite |
| `armv7-unknown-linux-musleabihf` | Raspberry Pi, ARM routers | lite |
| `arm-unknown-linux-musleabi` | older ARM (ARMv6) | lite |
| `mipsel-unknown-linux-musl` | many OpenWrt routers (MediaTek, Atheros) | lite |
| `mips-unknown-linux-musl` | big-endian MIPS routers | lite |

The **lite** build is the same tool without YARA (`--yar` reports that it is not
compiled in). It is a few MB and has no heavy dependencies, because YARA-X only
supports 64-bit CPUs. Build it yourself with:

```bash
cargo build --release -p bxmap-cli --no-default-features
# binary: target/release/bxmap
```

On a router: `chmod +x bxmap-mipsel-unknown-linux-musl.bin && ./bxmap-mipsel-unknown-linux-musl.bin dump.bin`.
If you are not sure which one you need, run `uname -m` (or `cat /proc/cpuinfo`)
on the device; for MIPS check endianness with `lscpu | grep -i endian`.

## Why bxmap?

Memory dumps are large, noisy, and full of useful evidence hidden among
padding bytes. `bxmap` gives applications a predictable core:

- **Streaming by default**: scan multi-gigabyte files without loading them
  completely into RAM.
- **Multi-encoding support**: detect ASCII, UTF-16LE, UTF-16BE, UTF-32LE, and UTF-32BE in the same pass.
- **Conservative noise filtering**: suppress clear period-1 and period-2
  fill patterns while preserving short evidence.
- **Entropy hints**: identify fixed-size regions with high byte-distribution
  entropy as possible compressed, encrypted, or packed data; no decryption is
  attempted.
- In CLI JSON output, matching regions are emitted as `group: "Undefined"`
  records with `offset`, `length`, `entropy`, and `data_hex` (capped by
  `--entropy-max-data`; capped records add `data_truncated: true`).
- Text output emits the same `Undefined` records in tab-separated form.
- Entropy scanning is opt-in with `--entropy` so the default scan keeps its
  original throughput. The window size (`--entropy-window`), threshold
  (`--entropy-threshold`) and merging of contiguous windows
  (`--entropy-merge`) are configurable; library users can call
  `scan_entropy_from_file_with_options` with `EntropyScanOptions`.
- **Configurable behavior**: control minimum length, result limits, and noise
  thresholds from Rust.
- **Parallel when useful**: opt into bounded region-based scanning with Rayon.
- **Composable output**: receive sorted `ExtractedString` values and decide
  how your application classifies, displays, or stores them.
- **Separate frontend**: the core stays composable while `bxmap-cli` offers
  a complete terminal workflow for users who want one.

## Installation

```toml
[dependencies]
bxmap = "1.0.4"
```

Or:

```bash
cargo add bxmap
```

The crate exposes a Rust API (including the `bxmap::minidump` module for
MDMP parsing). Build your own CLI, service, desktop application, forensic
pipeline, or scripting integration around it.

For the ready-made frontend, inspect [`cli/src/main.rs`](./cli/src/main.rs)
or install it with `cargo install bxmap-cli`.

## Quick start

```rust
use bxmap::extract_strings_from_file;

fn main() -> std::io::Result<()> {
    let strings = extract_strings_from_file(
        "memory.dmp",
        4,       // minimum string length
        200_000, // maximum results
    )?;

    for result in strings {
        println!(
            "{:#010x}\t{}\t{}",
            result.offset, result.encoding, result.text
        );
    }
    Ok(())
}
```

## API surface

| API | Use case |
| --- | --- |
| `extract_strings` | Scan bytes already held in memory |
| `extract_strings_with_noise_config` | In-memory scan with custom filtering |
| `extract_strings_from_reader` | Stream from any `std::io::Read` |
| `extract_strings_from_reader_with_noise_config` | Stream with custom filtering |
| `extract_strings_from_file` | Scan a file with bounded memory |
| `extract_strings_from_file_with_noise_config` | File scan with custom filtering |
| `extract_strings_from_file_parallel` | Opt-in parallel file scan |
| `scan_yara_from_reader_streaming` | Stream bytes through compiled YARA rules |
| `scan_yara_from_file_streaming` | Compile a rule file and scan a dump |
| `magic::scan_file` | Find file-header signatures (`SIGNATURES`) with a bounded result |
| `chunk::for_each_chunk` | Stream any file in overlapping windows with absolute offsets |
| `artifacts::ArtifactCollector` | Turn extracted strings into deduped path/env/URL/e-mail/registry/tool artifacts |
| `NoiseConfig` | Configure or disable repeat-pattern filtering |

Every result is an `ExtractedString`:

```rust
pub struct ExtractedString {
    pub offset: u64,
    pub encoding: &'static str, // "ascii", "utf16le", "utf16be",
                               // "utf32le", or "utf32be"
    pub text: String,
}
```

Results are sorted by ascending offset. `ExtractedString` derives
`serde::Serialize`, so applications can emit JSON, NDJSON, database records,
or any custom protocol without pulling a serializer into this crate.

## Filtering and evidence policy

The default filter targets two high-confidence low-information shapes:

- period-1 repeats: `AAAAAAAAAAAA`
- period-2 repeats: `ABABABABABAB`

Short repeats remain available because values such as `0000` can be meaningful
evidence. Use `NoiseConfig` when your workload needs a different trade-off:

```rust
use bxmap::{
    extract_strings_from_file_with_noise_config,
    NoiseConfig,
};

let config = NoiseConfig::from_threshold(16);
let strings = extract_strings_from_file_with_noise_config(
    "memory.dmp",
    6,
    500_000,
    config,
)?;
```

To preserve all repeat patterns:

```rust
let config = NoiseConfig::disabled();
```

The library does not classify IOC content, apply vendor-specific rules, or
decide what is malicious. That is intentional: downstream applications can
layer their own regexes, YARA rules, enrichment, confidence scoring, privacy
handling, and reporting without fighting a bundled CLI policy.

## CLI frontend in this repository

The GitHub repository includes the complete CLI source under [`cli/`](./cli/).
It is a separate package so the core library remains reusable:

```text
bxmap/
├── src/lib.rs          # bxmap core library
├── cli/
│   ├── Cargo.toml      # bxmap-cli package
│   └── src/main.rs     # bxmap executable
├── Cargo.toml          # bxmap core package
└── README.md           # repository guide
```

The CLI adds:

- `--format text|json`
- `--encoding all|ascii|utf16`
- `--min-len` and `--max-strings`
- `--noise-threshold`
- `--threads` and `--auto-tune`
- `--format`, `--encoding`, `--min-len`, and `--max-strings` are echoed to
  `stderr` in a selected-options block before scanning.
- `--entropy` to export high-entropy memory regions
- `--yar <PATH>` to compile and match a YARA rule file during bounded
  streaming scan (matched rules are emitted as `group: "YARA"` records)
- `--brute-xor <1b;2b;3b>` to opt into bounded candidate collection and
  printable/UTF-8 scored XOR brute-forcing in the CLI only
- `--filter-regex <RE>` to keep extracted strings and XOR plaintext matching a
  Rust regular expression
- `--detect <ip|url|domain|b64|secret|all>` unified IOC/secret triage in one pass (replaces individual detector flags). `secret` runs a full sweep for 30+ token types: AWS, Google, Azure, GitHub, GitLab, npm, OpenAI, Anthropic, Hugging Face, DeepSeek, Stripe, PayPal, Slack, Discord, Twilio, SendGrid, JWT, PEM private keys, DB connection URIs, and generic secrets. Detected IOCs replace the string value in output.
- `--format json-tree` grouped output (`group`/`type`/`items`) with entropy, offset, and PE timestamp when a minidump is loaded.
- `--heap-only` keeps only MEM_PRIVATE (heap) regions for minidumps.
- `--encoding all|ascii|utf16|utf32` — utf-16/utf-32 cover both LE and BE in one pass.
- `--map-va`, `--in-module`, `--rwx-only` for minidump-aware filtering.
- `--magic-bytes` reports PE/ELF/ZIP-Office/PDF/PNG signatures.
- `--extract <paths|env|urls|emails|registry|tools|all>` appends deduped
  artifacts (paths with `user=`/`category=` detail, environment assignments,
  URLs, e-mails, registry keys, capture-tool traces) sorted rarest-first; works
  with `text`, `json`, `ndjson` and `csv`.
- `--extract tools` names the capture/analysis tooling in the dump (DumpIt,
  WinPmem, FTK Imager, Volatility, ...) and default `.raw`/`.mem` image names,
  with `trace=path|command|prefetch|filename` evidence.
- `--report <mode>` adds encoding counts, scanned-range coverage, limit status
  and top artifacts to the stderr summary; modes: `none`, `summary`, `user`, `all`.
- IOC triage refangs `[.]`/`[at]`, validates public IPv4, drops private IP noise, uses entropy to reject base64 filler.
- `--parse-pid` to map common PID markers in extracted strings
- `-o/--output`
- automatic scan reports and priority triage signals on `stderr`
- IPv4/IPv6 and common crypto-wallet address hints

Results stay clean on `stdout`, so the CLI works both interactively and in
shell pipelines. The priority signals are practical investigation hints for
common credential, token, secret, URL, network, and email patterns; they are
not a verdict that a value is valid, active, or malicious.

Detector modes are mutually exclusive and intentionally replace the normal
string value with the detected token. They cannot be combined with
`--filter-regex`; omit all detector flags for the default full extraction.

Entropy scanning is opt-in so the default scan keeps its original throughput.
When enabled, fixed-size high-entropy regions are exported as `Undefined`
records in both text and JSON output. Each record includes its offset, length,
measured entropy, and original bytes encoded as hexadecimal; bxmap does not
decrypt or identify the underlying compression/encryption format.

### Optional XOR brute-force triage

`--brute-xor` is deliberately implemented in `bxmap-cli`, not in the Core
library. It collects up to 256 non-zero byte candidates, each between 10 and
100 bytes, then tries the requested repeating-key XOR sizes:

```powershell
bxmap memory.dmp --brute-xor "1b"
bxmap memory.dmp --brute-xor "1b;2b" --format json -o xor.json
```

Candidates are ranked by printable ASCII/whitespace ratio, valid UTF-8, and
bonus terms such as `http`, `www`, `.exe`, `.dll`, `Virtual`, `Create`, and
`Thread`. The CLI retains the top five results per candidate after combining
the selected key sizes. One-byte XOR is cheap; two-byte XOR is substantially
more expensive, and three-byte XOR is exhaustive over 16,777,216 keys per
candidate. `--auto-tune` currently tunes string-extraction workers; it does
not parallelize the XOR brute-force loop.

### YARA streaming

The Core exposes `scan_yara_from_reader_streaming` and
`scan_yara_from_file_streaming`. The CLI's `--yar <PATH>` compiles the rule
file and scans bounded chunks with overlap, so rules crossing an I/O boundary
remain visible without loading the complete dump into memory.

### File carving (`--carve`)

Recover structured files directly from a raw dump. The carver:

- Uses the same signature table as `--magic-bytes` (one source of truth).
- Validates every candidate against its format's internal structure before
  writing: JPEG marker walk + EOI, PNG chunk walk + CRC32, ZIP local-header + EOCD,
  RAR4/5 block walks, 7-Zip next-header offset, PDF `%%EOF`, GZIP deflate walk +
  trailer, BMP header consistency, SQLite page size × page count.
- Deduplicates by SHA-256; identical files found at multiple offsets are recorded
  once with `duplicates: [offsets]` in the index.
- Writes files with a neutral `.carved` extension (`<offset:08x>-<kind>-<sha8>.carved`)
  so nothing auto-executes or auto-opens.
- Refuses to overwrite existing files: re-running into the same `--carve-out`
  directory is an error.
- Produces a separate `--carve-index` (JSON array or NDJSON) so carving never
  reshapes the string output. Each record has `offset`, `type`, `size`, `sha256`,
  `entropy`, `complete`, `notes`, `path`, and `duplicates`.
- Runs before the string scan so a huge cap (`--carve-max-total`, `--carve-max-files`)
  fails fast with exit code 3.

```powershell
# Carve everything, write index, don't scan strings
bxmap dump.bin --carve all --carve-out carved --carve-index idx.ndjson --max-strings 0 --report none

# Only JPEG and PNG, limit total output to 100 MiB
bxmap dump.bin --carve jpeg,png --carve-out carved --carve-max-total 104857600

# JSON array index instead of NDJSON
bxmap dump.bin --carve all --carve-out carved --carve-index idx.json
```

⚠️ **Malware handling warning**: Carved files are raw bytes from the dump.
They may contain malicious code, exploits, or encrypted payloads. Treat every
`.carved` file as untrusted: inspect in a sandbox/VM, never open on a host
machine, and do not execute them.

## Streaming and parallel scanning

The normal file and reader APIs use bounded streaming memory. They are a good
default for very large dumps, slow disks, and memory-constrained systems.
The CLI's default single-worker mode streams each result directly to its
output instead of retaining the complete result set in memory.

For fast storage and CPU-heavy workloads, use the parallel API inside your own
controlled worker pool:

```rust
use bxmap::{
    extract_strings_from_file_parallel,
    NoiseConfig,
};

let strings = extract_strings_from_file_parallel(
    "memory.dmp",
    4,
    500_000,
    NoiseConfig::default(),
)?;
```

The parallel API divides the input into fixed regions, preserves offsets, and
returns results in sorted order. Configure Rayon's thread pool in your
application when you need an explicit CPU/RAM policy.

## Building an application around the core

The crate deliberately leaves these product decisions to you:

- CLI arguments and terminal UI
- IOC and credential detection
- JSON, CSV, NDJSON, or database output
- progress bars and cancellation
- case management and evidence provenance
- redaction, access control, and retention
- YARA, regex, entropy, or threat-intelligence enrichment

This makes the core suitable for both the included CLI and a custom
`strings`-style utility or full forensic pipeline.

## Performance characteristics

- Single-pass ASCII/UTF-16LE extraction.
- Constant-memory streaming path with respect to file size.
- Parallel path bounded by active worker regions, not total file size.
- Result collection is capped by `max_strings`.
- Core extractor treats input as raw bytes by default; optional
  `bxmap::minidump` parses Windows minidumps (MDMP) for VA mapping,
  process/module/thread timeline, and region filters.

### Measured numbers

Two benchmarks are checked in, so the numbers below can be reproduced rather
than taken on faith:

- `cargo bench --no-default-features` — CPU-only scanner throughput
  (criterion, `benches/extract.rs`, no disk I/O).
- `python bench/bench.py --with-strings` — end-to-end wall time and peak RSS
  on a generated 256 MiB corpus (mixed ASCII + UTF-16LE strings separated by
  binary junk).

In-memory scanner, 8 MiB corpus, release build, 6-core x86-64 VM:

| Encodings scanned | Throughput |
|---|---|
| ASCII only | ~125 MiB/s |
| ASCII + UTF-16LE/BE + UTF-32LE/BE | ~80 MiB/s |
| UTF-16 only | ~53 MiB/s |

End-to-end on a 256 MiB corpus (best of 3; the VM was busy, so ±30% between
runs is normal):

| Command | Time | Peak RSS | Output |
|---|---|---|---|
| `bxmap --threads 1` | 10.6 s | 81 MB | 190 MB |
| `bxmap --auto-tune` (6 threads) | 5.8 s | 142 MB | 190 MB |
| `bxmap --extract all --report summary` | 15.7 s | 150 MB | 190 MB |
| `strings -a -el -n 4` (same corpus) | 11.9 s | 4 MB | 43 MB |

Read that comparison honestly:

- `strings` wins on RAM (it streams line by line and writes far less), and it
  only scans ASCII + UTF-16LE. bxmap scans five encodings in one pass, which is
  why its output is ~4x larger on this corpus (every UTF-16LE string also has
  a UTF-16BE mirror).
- bxmap wins on wall time once the scan is parallel, and it emits offsets and
  encodings per record instead of bare text.
- `--extract` costs roughly 2-3x the plain scan because every string is tested
  for paths, URLs, e-mails, registry keys and env assignments.

Your storage, CPU and result density will dominate; measure your own dump with
`bench/bench.py` before quoting any number.

## Minimum supported Rust version

Rust 1.70.

## License

The `bxmap` library is dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

The `bxmap-cli` frontend in [`cli/`](./cli) is licensed separately under the
GNU Affero General Public License v3.0 only — see
[`cli/LICENSE-AGPL`](./cli/LICENSE-AGPL).

## Minidump process tree

```rust
use bxmap::minidump::Minidump;
let md = Minidump::open("chrome.DMP")?;
print!("{}", md.render_tree(20));
let off = md.va_to_offset(0x7ff731340000); // VA -> file offset
```

From the CLI: `bxmap chrome.DMP --tree` prints modules, threads, memory-region
summary and committed RWX regions for a Windows minidump, then exits.
Add `--map-va` to annotate every extracted string with its virtual address and module:

```powershell
bxmap chrome.DMP --map-va --min-len 8
```

Filter by location: `--in-module chrome.dll` keeps strings inside matching modules; `--rwx-only` keeps strings in committed RWX regions.

## VMware state files

`bxmap machine.vmss --vmware-info` lists header, groups, sibling `.vmem`, memory tags and CR registers. The `.vmem` is a flat RAM image: run the normal scanner on it directly.
