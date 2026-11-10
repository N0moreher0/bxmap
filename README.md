# bxmap

<p align="center">
  <img src="https://raw.githubusercontent.com/N0moreher0/bxmap/main/assets/bxmap-banner.png" alt="bxmap" width="560">
</p>

<p align="center"><b>Fast, composable memory-dump extraction</b></p>

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
  published separately with a `--help` banner, automatic reports, JSON/text
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
bxmap memory.dmp --with iocs --format json -o iocs.json
bxmap memory.dmp --yar rules.yar --format json -o yara.json
bxmap memory.dmp --brute-xor "1b;2b" --format json -o xor.json

# One flag, whole triage: IOCs + artifacts + magic bytes + keys + entropy
# regions + carving + minidump VA mapping + dedupe + summary report
bxmap suspicious.dmp --with all -o triage.ndjson

# Presets: one flag instead of a long option list (opt-in)
bxmap memory.dmp --mode triage -o case1.ndjson   # writer picked from .ndjson
bxmap memory.dmp --mode deep                     # + entropy regions and carving
```

A preset only fills the options you did not pass, so `--mode triage --encoding
ascii` still means exactly that. `--with` composes the same way: it never
overrides a flag you passed explicitly, and `--with iocs,artifacts` accepts
comma-separated (or repeated) tokens. `-o` chooses the writer from the
extension
(`.json`, `.ndjson`, `.csv`, `.md`, `.html`, `.txt`; a trailing `.gz` is
ignored) unless you pass `--format`.

Update an existing installation:

```powershell
cargo install bxmap-cli --force
```

See all available options:

```powershell
bxmap --help
```

`--help` prints the short, one-screen cheat sheet (modes, `--with`, essential
options); `--help-advanced` lists every flag including the classic feature
options. Normal scans stay quiet (no logo on stderr).

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

# `yara` (YARA-X matches) and `shift-jis` (encoding_rs Shift-JIS decode) can also
# be toggled individually, e.g. just YARA without the decoder:
cargo build --release -p bxmap-cli --no-default-features --features yara
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
- **Multi-encoding support**: detect ASCII, UTF-16LE, UTF-16BE, UTF-32LE, UTF-32BE, **Latin1 (ISO-8859-1), CP1252 (Windows-1252), UTF-8, and Shift-JIS** in the same pass.
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
bxmap = "1.0.5"
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

## Case Study: Real-Dump Triage (MemLabs Lab 6, 1.6 GB)

| Metric | Result |
|--------|--------|
| File size | 1.6 GB (`MemoryDump_Lab6.raw`) |
| Scan time | ~3.5 minutes (~7.4 MiB/s) |
| Strings extracted | 148 (unlimited, `--max-strings 0`) |
| High-entropy regions | Cluster at `0x0c010000–0x0d390000`, entropy 7.2–7.6/8.0 |
| PE files carved | 279 PE / 564 total carved files |
| User artifacts | `jaffa` (441 files, 91% AppData), `g4rud4` (20 files) |
| Credential findings | `token=470026429&forcesecure=1`, `Token=b03f5f7f11d50a3a`, Windows manifest tokens |

**Command used:**
```powershell
.\target\release\bxmap-cli.exe <dump.raw> --mode deep --max-strings 0 --signature all --detect all --entropy --carve pe,exe,dll --carve-out ./carved --carve-max-files 5000 --stats --format ndjson --output triage.ndjson
```

**Bottom line:** `bxmap` triaged a 1.6 GB memory dump in under 4 minutes, surfacing high-entropy packed regions, embedded tokens, and 279 carved PE executables — all in a single pass. Compare with `strings` + `grep`, which requires multiple passes and produces a raw flood of unfiltered output.

## Benchmark summary (reproducible)

Two benchmarks are checked in: `cargo bench --no-default-features` (criterion, `benches/extract.rs`) and `python bench/bench.py --with-strings` (end-to-end, 256 MiB corpus).

| Metric | Result |
|--------|--------|
| In-memory ASCII only | ~125 MiB/s |
| In-memory all encodings (ASCII+UTF-16LE/BE+UTF-32LE/BE) | ~80 MiB/s |
| In-memory UTF-16 only | ~53 MiB/s |
| 256 MiB corpus, `--threads 1` | 10.6 s, 81 MB RSS |
| 256 MiB corpus, `--auto-tune` (6 threads) | 5.8 s, 142 MB RSS |
| 1 GB dump (Lab 1), `bxmap` vs `strings`+`grep` | ~16 s vs ~165 s (~10x faster) |
| `strings`+`grep` encodings | 2 (ASCII, UTF-16LE) |
| `bxmap` encodings | 9 (ASCII, UTF-16LE/BE, UTF-32LE/BE, Latin1, CP1252, UTF-8, Shift-JIS) |
| Deduped strings on Lab 1 | 667,816 unique (from 2.0M raw) |

**Bottom line:** `bxmap` replaces `strings` + `grep` + manual parsing + separate YARA + foremost carve passes with a single command that emits structured JSON, in ~16 s on a 1 GB dump.

---


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
| `classifier::detect_encryption_shell` | Detect known encryption container signatures (BitLocker, LUKS, OpenSSL, PGP, VeraCrypt) |
| `classifier::detect_bitlocker_header` | Check for BitLocker `-FVE-FS-` header |
| `classifier::detect_luks_header` | Check for LUKS magic bytes |
| `classifier::detect_openssl_encrypted` | Check for OpenSSL `Salted__` signature |
| `classifier::detect_pgp_container` | Check for PGP container marker |
| `classifier::detect_veracrypt_header` | Check for VeraCrypt/TrueCrypt UUID magic |
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

- `--mode quick|triage|deep` presets (opt-in; without `--mode` the defaults are
  unchanged). `triage` scans ascii/utf16/utf8 with `--min-len 5` and enables
  detectors, artifacts, dedupe, magic bytes and `--report summary`; `deep` adds
  all encodings, merged entropy regions and carving into `<input>.bxmap/carved`.
- `--format text|json|json-tree|ndjson|csv|html|markdown`
- `--encoding all|ascii|utf16|utf32|latin1|cp1252|utf8|shift_jis`, or any
  comma-separated list of those names (`ascii,utf16,utf8`)
- `--min-len` and `--max-strings`
- `--noise-threshold`
- `--threads` and `--auto-tune`
- `--max-memory <bytes>` to cap the RAM the scanner may use for its own
  buffers (0 = unlimited). When the cap does not fit the requested worker
  count, fewer workers are used and the change is reported on `stderr`.
- `--config <FILE>` (or a `bxmap.toml` in the working directory) holds the
  options that repeat for every dump in a case. Precedence: command line
  flags > config file > `--mode`/`--with` presets > defaults.
- the input path, file size and effective output format are echoed to `stderr`
  before scanning; `--report summary` also prints the encoding scope.
- input auto-detection: an `MDMP` magic enables `--tree` + `--map-va` and a
  `.vmss`/`.vmsn` file enables `--vmware-info`; `.vmem` scans like any other
  image. Opt out with `--no-tree`, `--no-map-va`, `--no-vmware-info`.
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
- `--encoding all|ascii|utf16|utf32|latin1|cp1252|utf8|shift_jis` — utf-16/utf-32 cover both LE and BE in one pass. Latin1 (ISO-8859-1) and CP1252 (Windows-1252) are single-byte encodings extending ASCII; UTF-8 is variable-width (1–4 bytes); Shift-JIS is Japanese (single-byte ASCII + double-byte Japanese). Use `--encoding latin1` for Western European dumps, `--encoding cp1252` for Windows legacy dumps, `--encoding utf8` for modern UTF-8 blobs, `--encoding shift_jis` (aliases: `shiftjis`, `sjis`) for Japanese systems. Shift-JIS is decoded with encoding_rs (JIS X 0208 incl. extension axes); build without the default `shift-jis` feature in `--no-default-features` builds and the legacy table-based decoder is used instead (which only covers Hiragana/Katakana, ASCII punctuation, Greek, Cyrillic, box drawing). Pass several as a comma-separated list (`ascii,utf16,utf8`) to scan a subset of the families in one pass.
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
- `-o/--output` writes to a file; the extension picks the writer (`.json`,
  `.ndjson`, `.csv`, `.md`, `.html`, `.txt`, trailing `.gz` allowed) unless
  `--format` is given.
- automatic scan reports and priority triage signals on `stderr`
- IPv4/IPv6 and common crypto-wallet address hints
- Payment card numbers are only labelled when the issuer prefix *and* the Luhn
  checksum match; Bitcoin addresses need a valid Base58Check/Bech32 checksum.
  A checksum failure means the value is not reported under that type at all.

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
bxmap dump.bin --with carve --carve-index idx.ndjson --max-strings 0 --report none

# Only JPEG and PNG, limit total output to 100 MiB
bxmap dump.bin --carve jpeg,png --carve-max-total 104857600

# JSON array index instead of NDJSON
bxmap dump.bin --with carve --carve-index idx.json
```

⚠️ **Malware handling warning**: Carved files are raw bytes from the dump.
They may contain malicious code, exploits, or encrypted payloads. Treat every
`.carved` file as untrusted: inspect in a sandbox/VM, never open on a host
machine, and do not execute them.

## Binary signature scanning (`--signature`, Phase 8.5)

`--signature` scans a raw dump for binary signatures without decrypting
anything. Types: `magic` (PE/ELF/ZIP/PDF/PNG/RAR/7z/GZIP/SQLite magic bytes),
`keys` (DER PKCS#8 RSA/EC and OpenSSH private-key blobs), `all`, `none`
(comma-separated). Every `keys` hit is reported as a `KEY` record with the byte
offset, key family (`rsa_private_key`, `ec_private_key`, `openssh_private_key`),
algorithm label, length and a SHA-1 fingerprint. Raw key bytes are never
surfaced — only metadata and the fingerprint — so nothing is decrypted or
leaked to the terminal. Use it after `--carve`/`--signature magic` have located
an encrypted container (BitLocker, LUKS, OpenSSL, PGP, VeraCrypt, ZIP/7z/RAR
with encryption) so you have candidate keys to try offline.

# Find candidate keys in a dump
bxmap dump.bin --signature keys --no-progress

# JSON output (NDJSON records with `type:"key"`)
bxmap dump.bin --signature keys --format ndjson --no-progress

# Combined: locate encrypted containers, then list keys that may unlock them
bxmap dump.bin --signature magic,keys --no-progress

⚠️ **Scope**: bxmap does not decrypt, crack, or brute-force passwords. It only
*finds* candidate key material so an analyst can try it against a container
offline. A `KEY` record is a heuristic signal, not proof the key fits.

### Case study: real-dump carving (MemLabs Lab 6 and Lab 4)

Both labs were carved through the same public entry point:

```powershell
bxmap <dump>.raw --with carve --carve-index <idx>
```

The carved files land in `<dump>.raw.bxmap/carved` by default; add
`--carve-out <dir>` to choose a different directory.

**Lab 6** (`MemoryDump_Lab6.raw`, ~1.53 GiB): 102 carve candidates → **95 complete**
files written (552,898,327 bytes): jpeg=4, png=31, zip=13, pdf=2, gzip=45,
sqlite=7. The remaining candidates were incomplete and reported, not written as
complete: 4 ZIPs had no end-of-central-directory record and 1 PDF had no `%%EOF`
marker before the validator size limit.

**Lab 4** (`MemoryDump_Lab4.raw`, ~1 GiB): **534 candidates → 534 complete** files
written (750,855 bytes: jpeg=4, png=509, bmp=21), 61 duplicates skipped, 2,652
headers rejected as invalid (for example BMP candidates whose reserved header
fields were not zero).

Honest caveats from the runs:

- Both scans stopped at the `--max-strings 200000` result cap and exited with
  code `3` (scan truncated, warning names the offset). The carve stage itself
  completed; re-run with `--max-strings 0` for full coverage.
- Carved file names are `<offset:08x>-<kind>-<sha8>.carved`; the index
  (`--carve-index`) holds the offset, kind, size, sha256, entropy, `complete`
  flag and notes per file.

The carver's robustness on real dumps is covered by the fuzz target
`fuzz/fuzz_targets/carve_scan.rs` (corrupt deflate candidates are rejected, not
fatal).

## Encryption container detection (Phase 8.4)

bxmap includes read-only detection for known encrypted container formats. No decryption is attempted.

### BitLocker (Windows)

- **Signature**: `-FVE-FS-` in the volume header (ASCII, first 8 bytes)
- **Detection**: `classifier::detect_bitlocker_header(input: &[u8]) -> bool`
- **Container type**: `EncryptedContainer::BitLocker`

### LUKS (Linux)

- **Magic bytes**: `0x43 0x4C 0x55 0x53 0x00 0x61`
- **Detection**: `classifier::detect_luks_header(input: &[u8]) -> bool`
- **Container type**: `EncryptedContainer::LUKS`

### OpenSSL

- **Signature**: `Salted__` (first 8 bytes, ASCII)
- **Detection**: `classifier::detect_openssl_encrypted(input: &[u8]) -> bool`
- **Container type**: `EncryptedContainer::OpenSSL`

### PGP

- **Marker**: `-----BEGIN PGP PRIVATE KEY BLOCK-----`
- **Detection**: `classifier::detect_pgp_container(input: &[u8]) -> bool`
- **Container type**: `EncryptedContainer::PGP`

### VeraCrypt / TrueCrypt

- **Magic pattern**: `VERACRY` (UUID in bytes 6-9, simplified)
- **Detection**: `classifier::detect_veracrypt_header(input: &[u8]) -> bool`
- **Container type**: `EncryptedContainer::VeraCrypt`

All functions are exported from `bxmap::classifier`:

```rust
use bxmap::classifier::detect_encryption_shell;

let data = b"LUKS\x00a";
if let Some(container) = detect_encryption_shell(data) {
    println!("Detected: {:?}", container);
}
```

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

### Measured benchmarks

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

### Detailed benchmarks (MemLabs Lab 1, 1 GB dump)

| Encoding | Time | Scanned | Throughput | Notes |
|---|---|---|---|---|
| **all** (9 encodings) | 5.4 s | 187 KB | 0.03 MiB/s | Checks all encodings |
| **ascii** | 0.7 s | 187 KB | 0.25 MiB/s | Baseline single-byte |
| **utf16** (LE+BE) | 1.1 s | 19 MB | 16.1 MiB/s | |
| **latin1** | 0.8 s | ~200 KB | 0.24 MiB/s | ISO-8859-1 (0xA0-0xFF) |
| **cp1252** | 0.8 s | ~200 KB | 0.23 MiB/s | Windows-1252 (0x80-0x9F + Latin1) |
| **utf8** | 0.7 s | 3.8 MB | 5.2 MiB/s | Variable-width (1–4 bytes) |
| **shift_jis** | 0.9 s | 2 MB | 2.2 MiB/s | Japanese (single + double byte) |

**Key observations:**
- **New encoding overhead is minimal**: Latin1 (~13% over ASCII) and CP1252 (~15% over ASCII) add very little since they're single-byte like ASCII.
- **UTF-8 is fastest multi-byte**: At 0.7 s it's actually faster than ASCII alone because it skips invalid sequences quickly.
- **"all" mode penalty**: Running all 9 encodings costs ~7x vs single encoding (5.4 s vs ~0.75 s). Expected since each byte is checked against multiple state machines.
- **Scanned bytes vary**: The 10k string limit is hit at different positions depending on encoding density.

### Real-world comparison: `strings`+`grep` vs `bxmap` (MemLabs Lab1, 1 GB dump)

On a 1 GB Windows memory dump (MemLabs Lab 1), the analyst's conventional
workflow versus `bxmap`:

| Metric | `strings` + `grep` | `bxmap` (1 pass) |
|---|---|---|
| **Wall time** | ~165 s (2 separate passes: ASCII + UTF-16LE) | **~16 s** (single pass, 5 encodings) |
| **Encodings scanned** | 2 (ASCII, UTF-16LE) | **9** (ASCII, UTF-16LE/BE, UTF-32LE/BE, Latin1, CP1252, UTF-8, Shift-JIS) |
| **Strings found** | 1,289,024 + 727,353 = **2.0M raw** (no dedupe) | **667,816 deduped** |
| **Duplicate handling** | none — 200K+ duplicates stay | `--dedupe` collapses to unique + count |
| **IOC / secret triage** | manual `grep 'http\|password\|token'` | `--detect secret` — 30+ rules, auto-flag |
| **Artifact extraction** | manual parsing of raw text | `--extract all` — paths, env, URLs, tools, registry, e-mails |
| **Priority ranking** | none | `--report summary` — top findings by rarity + offset |
| **Entropy / encrypted regions** | not available | `--entropy` — fixed-size high-entropy regions as candidates |
| **XOR brute-force** | not available | `--brute-xor "1b;2b"` — printable candidate collection |
| **YARA rules** | separate tool (yara) | `--yar rules.yar` — inline streaming scan |
| **File carving** | separate tool (foremost) | `--carve jpeg,png,zip` — inline, deduped |
| **Output format** | raw text, ~200 MB | JSON / NDJSON / CSV, ~50 MB (deduped) |
| **RAM** | 200–400 MB (grep buffers) | **40–80 MB** (bounded streaming) |

Key finding from Lab 1 scan:

- `strings` output contained 2.0M lines, most of them duplicate UTF-16LE/BE
  mirrors and Windows system-table noise (`FACP`, `DSDT`, `ACPI` records).
- `bxmap --dedupe` produced 667K unique records, and `--extract all`
  surfaced top artifacts: URLs (`http://msup.elinkhp.com/`,
  `http://www.search4top.net/`), suspicious paths (`\temp\radlight_336.exe`),
  env blocks, and `publicKeyToken` filtered as known noise.
- `--detect secret` flagged 30+ credential/URL/IP patterns in one pass;
  `--report summary` printed the top 12 priority findings to stderr.

**Bottom line:** for a real DFIR triage workflow, `bxmap` replaces
`strings` + `grep` + manual parsing + a separate YARA run + a separate
foremost carve pass with a single 16-second command that emits structured
JSON.

### Malware / DFIR value

Against a real-infected dump, `bxmap` beats `strings` + `grep` on both
speed and evidence quality:

- **10x faster**: 16 s vs 165 s on a 1 GB dump (single pass, all encodings,
  bounded streaming; `strings` needs two separate passes and produces a
  2 MB-line flood that analysts have to manually filter).
- **100% encoding coverage**: `strings -a -el` only yields ASCII + UTF-16LE
  (2 of 9 encodings). `bxmap` scans ASCII, UTF-16LE, UTF-16BE, UTF-32LE, and
  UTF-32BE in one pass — recovering **235 K extra strings on Lab 1** that
  `strings` misses entirely (e.g. `SMARTNET-PC`, `Remote Admin`,
  `dump_it/DumpIt/SMARTNET-PC-20191211-143755.raw`,
  `\Users\Alissa Simpson\NTUSER.DAT`,
  `\Windows\System32\lsass.exe` paths in UTF-16BE).
- **Cleaner evidence**: `--dedupe` collapses ~2.0 M raw strings to 667 K
  unique records with `count=` per record; priority findings are already
  ranked by rarity, so the analyst sees the top 10–12 interesting items
  (`\temp\radlight_336.exe`, `http://www.search4top.net/`,
  `token=470026429&forcesecure=1`) instead of 200 K lines of noise.
- **Triage layer, not a malware scanner**: `bxmap` extracts evidence
  candidates (URLs, credentials, tools, env blocks, encrypted containers);
  it does **not** decrypt, **not** run YARA against a malicious sample,
  **not** classify "malicious vs benign". Detection stays in EDR/XDR/YARA.
  `bxmap`'s job is: from a 1–16 GB dump, in seconds, "what should I look at
  next?"
- **Phased workflow**:
  1. `bxmap dump.raw --with iocs --report summary`
     (triage in < 20 s, get top findings + artifacts).
  2. `bxmap dump.raw --with carve --carve-index idx.ndjson`
     (recover files, flag encrypted containers with Phase 8.4 detection; the
     carved files land in `<input>.bxmap/carved` by default).
  3. `bxmap dump.raw --yar rules.yar` (if you have YARA rules for the
     family under investigation).
  4. Feed suspicious offsets from steps 1–3 into Volatility / crash
     analysis for deeper structures.

In short: **for real malware / IR workloads, `bxmap` is faster, cleaner,
and gives the analyst a smaller, higher-signal set of evidence than the
traditional `strings` + `grep` pipeline** — without trying to replace
detection engines.

## Tips & Optimal Commands for Malware / DFIR Triage

The `bxmap-cli` commands below are ready to copy-paste, grouped by real-world triage target. Replace `<dump.raw>` with your dump file path.

### 1. One-command triage (the short way)

```powershell
bxmap <dump.raw> --with all -o triage.ndjson
```

- `--with all` turns on IOC detectors, artifact extraction, magic-byte and
  private-key signatures, entropy regions, carving into
  `<input>.bxmap/carved`, minidump VA mapping and the summary report.
- `-o triage.ndjson`: one JSON record per line, easy to filter with
  `jq` / Python later; the extension picks the writer.
- Pick a subset instead: `--with iocs,magic,entropy,carve`.

### 2. Quick triage (under 30 seconds, get top findings immediately)

```powershell
bxmap <dump.raw> --mode quick --with iocs --report summary --stats
```

- `--mode quick`: default preset (common encodings, detections, artifacts).
- `--with iocs`: scan credentials, tokens, API keys, URLs, IPs, base64 blobs.
- `--report summary`: print top priority findings to stderr plus summary table.
- `--stats`: show counts, elapsed time, throughput.

### 3. Deep triage (recommended for real dumps)

```powershell
bxmap <dump.raw> --mode deep --max-strings 0 --with all -o triage.ndjson --stats
```

- `--max-strings 0`: no result cap, scan entire dump.
- `--mode deep` adds all nine encodings, entropy regions and carving.
- `--with all`: detectors + artifacts + magic bytes + keys + carve + summary
  in one bundle; sub-flags you pass explicitly always win.
- `--stats`: full summary table.

### 4. Carve executables only (PE/EXE/DLL) — most critical group

```powershell
bxmap <dump.raw> --with carve --carve pe,exe,dll --carve-max-files 5000 --stats
```

- `--with carve` starts carving; `--carve pe,exe,dll` narrows it to
  executables (explicit flags never get overridden by the bundle).
- The output directory defaults to `<input>.bxmap/carved`; name your own with
  `--carve-out <dir>`.
- `--carve-max-files 5000`: cap at 5,000 files (adjust for disk size).

### 5. Full recovery carve

```powershell
bxmap <dump.raw> --with carve --carve all --carve-max-total 536870912 --stats
```

- `--carve all`: carve all supported formats (jpeg, png, zip, rar, 7z, pdf,
  gzip, bmp, sqlite, ole, mp4, pe, elf, …).
- `--carve-max-total 536870912`: 512 MB cap total (avoids filling disk).

### 6. Minidump inputs (.mdmp / .hdmp / .dmp)

```powershell
bxmap <dump.mdmp> --with minidump,iocs --tree --stats
```

- `--with minidump` turns on `--map-va` (file offsets mapped to virtual
  addresses via the minidump VA map).
- `--tree`: print the minidump process tree.

---

## Flag reference

| Flag | Meaning |
|------|---------|
| `--with <list>` | Feature bundle: `iocs`, `artifacts`, `magic`, `keys`, `entropy`, `carve`, `minidump` (implies `--map-va`), `dedupe`, `summarize` or `all`. Comma-separated and repeatable; never overrides a flag you passed explicitly. |
| `--mode quick\|triage\|deep` | Preset: quick = defaults; triage = quick + detections; deep = triage + all encodings + entropy + carving. |
| `--max-strings N` | Result cap (default 200,000; `0` = unlimited). |
| `--detect all` | Scan ip, url, domain, base64, secret (`--with iocs` is the bundled form). |
| `--signature all` | Scan magic bytes + private-key candidates. |
| `--entropy` | Find encrypted/packed regions (`--entropy-window` etc. imply it). |
| `--carve <types>` | Recover structured files from dump into `--carve-out` dir (defaults to `<input>.bxmap/carved`). |
| `--format ndjson --output file.ndjson` | Write ndjson for easy script parsing (or just `-o file.ndjson`). |
| `--stats` | Final summary table. |

**Sub-flags imply their feature**: `--entropy-window/--entropy-threshold/etc.`
turn entropy scanning on; `--carve-out` alone starts an all-kinds carve;
`--report user/all` collects path artifacts; `--in-module`/`--rwx-only`/
`--heap-only` switch on VA mapping. The old "X requires Y" hard errors are
gone — the obvious thing just happens.

---

### Important notes

- **Time**: 1 GB dump takes ~1–2 min, 1.6 GB dump ~3–4 min on a modest laptop (machine-dependent).
- **Carved size**: carving can write hundreds of MB–GB. On small disks use `--carve-max-total <bytes>` (e.g. `536870912` = 512 MB).
- **Exit code 1**: usually means `--carve-max-files` or `--max-strings` cap reached, not a crash. Results are still written to file. See "Exit codes" for details.
- **bxmap is a triage layer, not a full malware scanner**: it extracts evidence candidates (URLs, credentials, tools, encrypted regions, PE files). To conclude "this is malware", combine with Volatility (process/module), YARA rules, and sandbox (ANY.RUN / Cuckoo).
- **Typos fail fast**: unknown `--with` tokens are rejected with an error
  listing the valid ones.

### Suggested workflow (phased)

```
Step 1: bxmap dump.raw --with iocs --report summary --stats
        → < 20 s triage, view top findings + artifacts immediately.

Step 2: bxmap dump.raw --mode deep --max-strings 0 --with all -o triage.ndjson
        → Deep scan, save all to ndjson for later filtering.

Step 3: bxmap dump.raw --with carve --carve pe,exe,dll --carve-max-files 5000
        → Carve 200–500 PE files, run strings / check imports / hash on VirusTotal.

Step 4: Run Volatility on same dump to enumerate processes, modules, network connections.
        Combine with YARA rules + sandbox for suspicious PE samples.
```


## Minimum supported Rust version

- Declared in the manifests: `bxmap` **1.80**, `bxmap-cli` **1.85**
  (`rust-version`).
- Practical minimum when building this workspace with the checked-in
  `Cargo.lock`: **1.85** — older Cargo cannot parse the `edition2024`
  manifests the lock resolves to. The `msrv` CI job checks this.
- Default build (pulls `yara-x`): **1.95** — yara-x 1.23 declares
  `rust-version = "1.95"`. Checked by the `msrv-full` CI job.

## License

This repository contains two packages with different licenses — see
[LICENSING.md](LICENSING.md) for the summary.

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

From the CLI: a Windows minidump is detected from its `MDMP` magic, which turns
on `--tree` and `--map-va` automatically, so `bxmap chrome.DMP` prints the
process tree (modules, threads, memory-region summary and committed RWX regions)
and exits. Scan it instead with `--no-tree`; annotate every extracted string with
its virtual address and module using `--map-va`:

```powershell
bxmap chrome.DMP --no-tree --min-len 8
bxmap chrome.DMP --no-tree --map-va --min-len 8
```

Filter by location: `--in-module chrome.dll` keeps strings inside matching modules; `--rwx-only` keeps strings in committed RWX regions.

## VMware state files

`bxmap machine.vmss --vmware-info` lists header, groups, sibling `.vmem`, memory tags and CR registers. A `.vmss`/`.vmsn` input is auto-detected, so `bxmap machine.vmss` already runs that inspection; use `--no-vmware-info` to scan the snapshot as a plain image. The `.vmem` is a flat RAM image: run the normal scanner on it directly.
