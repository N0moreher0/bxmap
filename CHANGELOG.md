# Changelog

All notable changes to `bxmap` / `bxmap-cli` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- A synthetic regression corpus (`tests/common/corpus.rs`): a small, fully
  generated dump with a fixed layout -- ASCII, UTF-16LE/BE, UTF-8, IOC
  tokens, a Windows path, an UTF-16LE environment block, a cloud key and a
  card number -- on a background that cannot form a printable run in any
  encoding. `tests/regression_corpus.rs` asserts that every planted string is
  reported at its exact offset and that the background produces nothing.
- `--max-memory <bytes>` caps the RAM the scanner may use for its own buffers
  (0 = unlimited, the default). When the cap does not fit the requested worker
  count, fewer workers are used and the change is reported on stderr; a cap
  that cannot fit a single worker is a clear error. The library exposes
  `scan_working_set_bytes`, `PARALLEL_REGION_SIZE` and `SEQUENTIAL_BUFFER_SIZE`
  so callers can size the budget themselves.
- `BTC_SEGWIT` classification: bech32/bech32m addresses are recognised and
  validated with the Bech32 checksum.
- `CREDIT_CARD` classification (new `FINANCE` group): a number is only
  reported as a card when its length, issuer prefix and Luhn checksum all
  match.
- `validate_credit_card` is exported from the library root.
- CI `fuzz` job runs every `cargo-fuzz` target for 30 s on each push/PR, as a
  panic/OOM gate for the parsers.
- `LICENSING.md` explains which license covers which package; the stale
  AGPL-3.0 `LICENSE` at the repo root is gone so GitHub no longer reports the
  MIT/Apache library as AGPL. The CLI's AGPL text stays at
  `cli/LICENSE-AGPL`.
- Regression test `parallel_matches_sequential_on_multi_region_data`: the
  buffered and streaming parallel scans (1/2/4 threads) must produce the same
  set and offset order as the in-memory scanner across region boundaries, with
  ASCII/UTF-16LE/UTF-16BE runs that straddle, end on and start on a boundary,
  plus encoding filters and `max_strings` truncation parity.

### Changed
- String classification now checksums crypto and card values before labelling
  them: a Bitcoin address with a broken Base58Check/Bech32 checksum, or a digit
  run that is not a real card number, is no longer reported under that type.
  Checksum failures do not delete evidence, they only change the label.
- The non-secret rule set used by `classify()` gets the same anchor prefilter
  the secret patterns already had: one Aho-Corasick pass decides which rules
  can possibly match, so a plain string no longer runs 20+ regexes. The
  outcome is unchanged (regression test compares against running every rule).
- `validate_jwt` now requires the `alg` header (mandatory in RFC 7519) instead
  of `typ` (optional), accepts an empty signature only for `alg: none`, and
  rejects a signature that is not base64url.

### Fixed
- UTF-8 strings containing CJK characters are no longer cut at the first
  multi-byte character. The UTF-8 and Shift-JIS branches both advanced the
  shared scan index, so the Shift-JIS branch consumed a byte of the UTF-8
  sequence and the run was flushed half way through. Found while building the
  synthetic regression corpus.
- `--vmss`/`.vmsn` tag walking no longer overflows on a hostile group table:
  a `tags_offset` of `u64::MAX` made `pos + 2` (and `pos + 8`) abort the
  process with overflow checks on. Both bounds checks now use `checked_add`.
  Found by the new `fuzz` CI job on its first run; two regression tests cover
  the hostile offset and a `u32::MAX` data length.
- `bxmap --carve jpeg dump.bin` no longer fails with `unknown option 'jpeg'`:
  the dump path may now appear anywhere on the command line, a second bare
  token is reported as an extra argument, and a missing path says so instead
  of parsing the first flag as the file name. `--help-advanced` / `--help-all`
  now print the advanced help instead of being treated as a path.
- `--carve 7z` now verifies `StartHeaderCRC` over the start header before
  trusting the declared sizes, so random data with the 7-Zip signature is
  rejected instead of reported as a complete archive.
- README MSRV section matches the real minimums (1.80 declared, 1.85 with the
  locked workspace, 1.95 for the default yara-x build) instead of "Rust 1.70".

## [1.0.18] - 2026-11-10

CLI release aligned with `bxmap` 1.0.7. No CLI code changes.

### Changed
- Depends on `bxmap` 1.0.7.

## [1.0.7] - 2026-11-10

### Fixed
- Multi-byte decoding (UTF-8, Shift-JIS) no longer emits unreadable text:
  invalid UTF-8 structure, unassigned Shift-JIS pairs, undefined CP1252 bytes,
  replacement/C1/private-use characters and decoded runs made mostly of them
  are rejected.
- Long decoded runs are scored by bad-character and non-readable ratios while
  short runs require hard evidence, so normal text and short strings survive.

## [1.0.17] - 2026-11-10

### Changed
- Internal clippy cleanups only (`Option::is_none_or`); no behaviour change.

## [1.0.16] - 2026-11-10

CLI release aligned with `bxmap` 1.0.6.

### Fixed
- `--detect-strict` now drops findings below confidence 0.60, so noisy
  generic/public-client matches no longer survive strict scans.
- `--dedupe` merges findings by value across rules (including rich output)
  and keeps the lowest-confidence classification instead of promoting it.
- Secret detection on real memory dumps no longer reports Azure SAS tokens for
  non-Azure signed URLs, or generic secrets for identifiers, UUIDs, paths and
  low-entropy values.

### Changed
- Depends on `bxmap` 1.0.6.
- Lite MSRV is 1.85; the full default build requires Rust 1.95 (yara-x 1.23).

## [1.0.6] - 2026-11-09

### Fixed
- Secret detection false positives on real memory dumps: fixed-prefix rules now
  use token boundaries; `AZURE_SAS_TOKEN` requires an Azure storage host, so
  YouTube signed URLs are no longer reported as SAS tokens.
- `GENERIC_SECRET` now rejects query strings, paths, camelCase API identifiers,
  short hex GUID/.NET assembly tokens, UUIDs and low-entropy values.
- `--detect-strict` drops findings below confidence 0.60 (generic, public
  client, OAuth client id and Google API key stay available in non-strict mode).
- `--dedupe` collapses findings by value across rules and keeps the
  lowest-confidence classification, so a public client key cannot be promoted.
- Calibrated `GENERIC_SECRET`, `PUBLIC_CLIENT_KEY`, `GOOGLE_OAUTH_CLIENT_ID`
  and `GOOGLE_API_KEY` confidence/severity.

### Changed
- Lite MSRV is 1.80 (Cargo 1.70-1.75 cannot resolve the optional yara-x graph);
  the full default build requires Rust 1.95 (yara-x 1.23).

## [Unreleased]

### Added
- Encoding-scoped scanning (`EncodingFilter`) so `--encoding ascii|utf16|utf32`
  only scans requested encodings instead of all 5.
- 8-byte word fast-skip in the no-open-run path for random / high-byte data.
- Shared `scratch` buffer reuse in `StringRunScanner` to reduce allocations.
- CVE-like secret patterns with an Aho-Corasick anchor prefilter in the
  classifier.
- Structured detector output (`--detect-format rich`) with `rule`, `value`,
  `confidence`, `severity`, `context` and the original `text` preserved.
- `classifier::DetectedFinding`, `SecretFinding` and `detect_secrets_detailed`
  for library users that need match spans and provenance.
- `--max-strings 0` now means unlimited.
- Truncation is no longer silent: the CLI prints a clear warning and exits with
  code `3` when `--max-strings` stops the scan early; `json-tree` metadata also
  reports `truncated` and `scanned_until`.
- Generic-secret false positives are filtered: identifiers (`GetTokenInformation`,
  `Malloc`, `DigiCert`), keywords (`true`/`false`/`undefined`), JavaScript
  fragments and known .NET `publicKeyToken` values are no longer reported.
- `--start <offset>` / `--end <offset>` to scan only a byte range (decimal or
  `0x` hex). The new `extract_strings_from_file_streaming_range_with_encodings`
  API reads `MAX_RUN_CHARS` of overlap on each side so strings crossing a
  boundary stay intact, and only emits strings that start inside the range.
- Truncation detection now asks the scanner for one extra result, so a scan that
  ends exactly at `--max-strings` is no longer reported as truncated.
- `--dedupe` collapses repeated results: each unique string is emitted once
  with `count=<N>` and its first offset (text/json/json-tree). With
  `--detect-format rich`, findings are grouped by `(rule, value)`.
- `--format ndjson` writes newline-delimited JSON: one self-contained record per
  line with a `type` discriminator (`string`, `finding`, `magic`, `yara`, `xor`,
  `entropy`) plus a trailing `{"type":"metadata"}` record with `total_records`,
  `truncated` and `scanned_until`. It streams records instead of buffering a
  JSON array, which keeps memory flat on multi-gigabyte dumps.
- `--signature <types>` replaces `--magic-bytes`/`--find-keys`; scans for
  `magic` (PE/ELF/ZIP/PDF/PNG/RAR/7z/GZIP/SQLite) and `keys` (DER PKCS#8
  RSA/EC, OpenSSH private-key blobs) signatures; `all` or `none` accepted.
- `--carve` gains four new formats: `ole` (OLE/Office 97-2003), `mp4`
  (ISO media), `pe` (Windows PE/EXE), `elf` (ELF executable), alongside the
  existing `jpeg,png,zip,rar4,rar5,7z,pdf,gzip,bmp,sqlite`.
- `--reassemble` (with `--carve` on a minidump) collects carve fragments, maps
  file offsets to virtual addresses via the minidump, merges adjacent fragments
  within one 4 KiB page, and writes each merged group as one reassembled
  `.carved` file. New library API: `Carver::collect_fragments()`,
  `reassemble_fragments()`, `CarveFragment`, `ReassembledFile`,
  `ReassemblyReport`.
- `--format csv` writes RFC 4180 CSV with a fixed header
  (`type,offset,encoding,text,rule,value,severity,confidence,context,count,pid`).
  Strings, rich findings and `--extract` artifacts are supported; combining it
  with `--signature`, `--yar`, `--brute-xor` or `--entropy` is rejected, use
  json/ndjson for those.
- `--compact` minifies `--format json` / `json-tree` output (no indentation or
  newlines), which keeps large exports smaller and easier to pipe.
- `--entropy-no-data` omits the `data_hex` payload from `--entropy` records, so
  the report stays small when only offsets/lengths/entropy are needed.
- Entropy scanning is now configurable: `--entropy-window <BYTES>` sets the
  block size, `--entropy-threshold <BITS>` sets the cutoff (0–8), and
  `--entropy-merge` collapses contiguous high-entropy windows into one region
  with the exact merged entropy. The new
  `bxmap::scan_entropy_from_file_with_options` API takes an
  `EntropyScanOptions` (`window`, `threshold`, `merge`, `max_data`).
- `--entropy-max-data <BYTES>` caps the `data_hex` payload per region (default
  4096 bytes, `0` keeps none); capped records add `data_truncated` in JSON and
  `data_truncated=1` in text so the full `length` is still reported.
- Errors are printed as `Error: <message>` without the `Debug` quoting.
- `-o out.json.gz` gzip-compresses output on the fly (any `--format`). The
  gzip trailer is written even when the scan exits early with truncation.
- `--progress` / `--no-progress` print a live status line on stderr (percent,
  MiB/s, scanned offset). Progress is on by default when stderr is a terminal
  and results are not going to the terminal. The new
  `extract_strings_from_file_streaming_range_with_encodings_progress` API
  reports consumed bytes per chunk.
- `--extract <paths|env|urls|emails|registry|tools|all>` appends deduped
  structured artifacts (file paths, environment assignments, URLs, e-mails,
  registry keys, memory-capture tool traces) after the normal rows for `text`,
  `json`, `ndjson` and `csv`. Each artifact keeps its first offset, an
  occurrence count and optional `detail`
  (`user=<name>;category=<...>` for paths, `name=...;sensitive=true` for
  credential-like env names, `evidence=...;category=...;trace=...` for tools);
  the list is sorted rarest-first so unusual evidence floats to the top. The
  new `bxmap::artifacts` module (`ArtifactCollector`, `ArtifactKinds`,
  `Artifact`) exposes the same logic to library users. `--format json-tree`
  rejects `--extract` because artifacts are a flat record type.
- `--extract tools` names the capture/analysis tooling visible in the dump
  (DumpIt, WinPmem, FTK Imager, Magnet RAM Capture, Belkasoft, LiME, AVML,
  Volatility, Rekall, ProcDump) plus default image names such as
  `DESKTOP-<host>-<date>-<time>.raw` or `physicalmemory.mem`. Matches are
  case-insensitive, word-bounded and reported once per string; `trace=` records
  every evidence kind seen for a tool (`path`, `command`, `prefetch`, `string`,
  `filename`) so a DumpIt prefetch entry and its `.exe` path merge into one
  artifact.
- `--report summary` enriches the stderr summary with the string count per
  encoding, the scanned byte range (percentage of the requested window and of
  the file), whether `--max-strings` stopped the scan, and the top artifacts
  collected by `--extract`. `--report none` restores the compact summary.
- `--report user|all` prints a consolidated per-user file list (one line per user)
  when `--extract paths` is active. Shows file count, AppData count, and AppData
  percentage. Filter with `--min-files-in-user <N>`.
- `--filter-appdata` adjusts the AppData percentage denominator to visible files
  (total minus AppData) for `--report user|all`. Does not remove AppData paths
  from collection.
- New `bxmap::magic` module: `SIGNATURES` (PE/ELF/ZIP/PDF/PNG headers),
  `MagicMatch` and `scan_file(path, max_matches)`. The table is the single
  source of truth for header detection and will be reused by `--carve`.
- New `bxmap::chunk` module: `for_each_chunk(path, chunk_size, overlap, ..)`
  hands out windows with absolute offsets plus the overlap prefix length, so
  signature scanners skip re-reported hits instead of duplicating the carry
  bookkeeping.
- New `bxmap::carve` module: `CarveKind`, `CarveOptions`, `CarvedFile`,
  `CarveReport`, `Carver::{scan,carve_to_dir}` and validators for JPEG,
  PNG, ZIP, RAR4, RAR5, 7z, PDF, GZIP, BMP, SQLite. Carving is an
  independent pass that runs before the string scan, uses the shared
  `bxmap::magic::SIGNATURES` table, deduplicates by SHA-256, writes files
  with a neutral `.carved` extension, and produces a separate `--carve-index`
  (JSON array or NDJSON).
- CLI flags: `--carve <types>`, `--carve-out <dir>`, `--carve-index <file>`,
  `--carve-min-size`, `--carve-max-size`, `--carve-max-total`, `--carve-max-files`.
  Exit code `3` when a carve cap stops the scan early. `--carve-out` is
  required with `--carve`; existing files are never overwritten.
- `bxmap::magic::Signature` gained a `carve` field; `SIGNATURES` extended to
  11 formats (JPEG, RAR4, RAR5, 7z, GZIP, SQLite).
- `--mode quick|triage|deep` presets. `triage` enables ascii/utf16/utf8,
  `--min-len 5`, detectors, artifacts, `--dedupe`, magic bytes and
  `--report summary` (unlimited `--max-strings` when `-o` is used); `deep` adds
  all encodings, merged entropy regions and carving into
  `<input>.bxmap/carved`. Presets only fill the flags you did not pass, so
  explicit flags win in any position, and no `--mode` keeps the old defaults.
- Input auto-detection: a `MDMP` magic enables `--tree` + `--map-va`, and a
  `.vmss`/`.vmsn` file enables `--vmware-info`; `.vmem` still scans like any
  other image. Opt out with `--no-tree`, `--no-map-va` or `--no-vmware-info`.
- `--encoding` accepts a comma-separated list (`ascii,utf16,utf8`) in addition
  to the single values, which keep their previous meaning.
- `-o <file>` infers the output format from the extension (`.json`, `.ndjson`,
  `.csv`, `.md`, `.html`, `.txt`; a trailing `.gz` is ignored). An explicit
  `--format` still wins.
- `--find-keys` scans the dump for stored private-key material (DER PKCS#8
  RSA/EC envelopes and OpenSSH binary private-key blobs) and reports each hit
  as a `KEY` record with offset, algorithm, length and SHA-1 fingerprint.
  Raw key bytes are never surfaced and nothing is decrypted.

### Changed
- Shift-JIS (`--encoding shift_jis`) now decodes through `encoding_rs`
  (JIS X 0208 with the usual extension axes), replacing the partial
  hand-rolled table. New optional dependency `encoding_rs` sits behind a
  default-on feature `shift-jis`; builds with `--no-default-features` keep the
  legacy decoder and stay small. Library tests cover bytes
  [0x93, 0xFA, 0x96, 0x7B, 0x8C, 0xEA] decoding to "日本語", a mixed
  ASCII + kanji run, and the absence of U+FFFD replacement characters.
- `--magic-bytes` now runs through `bxmap::magic` (Aho-Corasick over the shared
  signature table) instead of a hand-rolled `windows()` scan in the CLI. Same
  output, no per-signature pass over each chunk.
- `apply_detectors` allocates output capacity up front and clones lazily.
- Flat detector output (`--detect-format flat`, default) is unchanged.
- `--start`/`--end` force the sequential streaming scanner even when
  `--threads` is greater than 1.
- The stderr summary reports the number of unique artifacts when `--extract`
  is active, and NDJSON `total_records` now counts auxiliary records (YARA,
  XOR, magic, entropy, artifacts) instead of only strings.

### Performance
- New `extract_strings_from_file_parallel_streaming_with_encodings` and
  `..._progress` APIs: scan a window of `PARALLEL_CHUNK_SIZE` regions in
  parallel, emit their results in ascending offset order, then drop them. Peak
  memory no longer grows with the number of matches, unlike the buffered
  parallel API.
- `PARALLEL_CHUNK_SIZE` reduced from 64 MiB to 16 MiB: peak RSS on a 256 MiB
  corpus dropped from ~358 MB to ~142 MB with throughput unchanged.
- `--brute-xor` rewritten: keys are scored in parallel on the rayon pool with a
  per-thread top-N accumulator and a reused plaintext buffer, so the hot loop
  allocates nothing. A 96-byte prefilter and known-plaintext cribs (`MZ`,
  `This program cannot be run`, `http://`, `.dll`, `PK`, `<?xml`, `SELECT`)
  reject wrong keys early. 1–2 byte keys stay exhaustive (256 / 65,536); key
  sizes ≥ 3 use a frequency-guided search (top-3 ciphertext bytes per column ×
  6 common plaintext bytes = 5,832 keys instead of 16,777,216) and print the
  key count up front.
- `--xor-exhaustive` forces the full key space for 3-byte keys and prints a
  byte-op estimate before starting.
- XOR candidate collection now reads 1 MiB blocks and uses `memchr` to split on
  NUL bytes instead of calling `read()` one byte at a time.
- `--extract` prefilters each string with cheap byte checks (`:`, `\`, `/`,
  `=`, `://`, `@`, `HK`) before running the regexes; `--extract all` on a
  256 MiB corpus went from ~42 s to ~16 s.
- New criterion benchmarks (`benches/extract.rs`) for in-memory ASCII, UTF-16
  and all-encoding scans plus the parallel file path, and `bench/bench.py` for
  end-to-end wall time, throughput and peak RSS (optionally against `strings`).

### Fixed
- Carving: a candidate whose deflate stream was corrupt (false positive behind a
  gzip magic hit) aborted the whole scan with `carve failed: deflate
  decompression error`. Corrupt candidates are now treated as `Invalid` verdicts
  and the scan continues, so one bad region no longer kills the pass.
- The `--report summary` throughput line is now computed over the bytes that
  were actually scanned. A run stopped early by `--max-strings` used to divide
  the whole file size by a short elapsed time (e.g. "400 MiB/s" after scanning
  0.1% of the dump).
- `--threads > 1` no longer buffers every match in RAM and sorts at the end; it
  streams through the parallel path like the single-threaded one, which is what
  made large `--max-strings` runs look like a hang.
- Printing more than 10,000 results to a terminal now prints a hint suggesting
  `-o <file>`.
- Scanner: Latin-1 / CP1252 / UTF-8 / Shift-JIS runs were not terminated by
  non-printable bytes when no ASCII/UTF-16/UTF-32 run was open (the fast-skip
  ignored them), so strings were merged across junk bytes, and with
  `--encoding utf8|shift_jis` the first character of every later string was
  dropped. UTF-8 / Shift-JIS runs that start with a multi-byte character are now
  detected, and the very last byte of the input is no longer ignored.
- Streaming scans now carry 4 bytes (was 1) across 32 MiB chunk boundaries, so
  UTF-32 and UTF-8 units that straddle a boundary are no longer lost.
- Parallel scan: a string crossing a 16 MiB region boundary was also reported
  as a duplicate tail fragment starting at the boundary; regions now look back
  one run length, matching the sequential scanner.
- Minidump parser: module / thread / memory-info streams smaller than their
  fixed header returned a panic instead of an error; memory regions are sorted
  before binary search and address arithmetic is overflow-checked.
- VMware parser: tag offsets near `u64::MAX` no longer overflow.
- `--format markdown|html` wrote an empty file on the default streaming path;
  those formats now go through the report writer.
- The 21-line ASCII logo is only printed by `-h`/`--help`, not on every scan,
  and the leftover `[DEBUG]` lines were removed from the report writer.

## [1.0.14] - 2026-10-30 (`bxmap-cli`)

### Changed
- CLI version bump (see CLI changelog below); uses `bxmap 1.0.4`.

## [1.0.4] - 2026-10-30 (`bxmap`)

### Added
- Encoding-scoped extraction APIs for library users.
- Encoding-filtered CLI scans.
- Candidate-byte fast-skip table in `StringRunScanner`.
