# Changelog

All notable changes to `bxmap` / `bxmap-cli` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **MP4/MOV rebuild from a surviving `moov` (ROADMAP 8.11, P1)**. When the
  original `ftyp`/`mdat` header is encrypted but the `moov` box (usually at
  the end of the file) survived, bxmap now parses `moov` (`mvhd`, tracks,
  `stbl` with `stsd`, `stts`, `stsc`, `stsz` or `stz2`, `stco` or `co64`),
  cross-checks the tables (`stts` total samples == `stsz` entry count;
  `stsc` covers every chunk; chunk offsets strictly non-decreasing;
  samples accounted for exactly once), and writes a **fresh `ftyp` +
  `mdat` header with every chunk offset shifted by 32**. A `stco` table
  whose entries would overflow 32 bits after the shift is promoted to
  `co64` (no 4 GB limit like the reference repair tools). The rebuilt
  file replaces only the header: the encrypted head stays garbage, the
  rest of the video plays. The rebuilt file re-passes bxmap's own MP4
  validator before it is handed out; failures are rejected with a reason,
  never written. The ransomware trailer after `moov` (often a victim ID)
  is cut out of the rebuilt file and recorded in the index. Fragmented
  MP4s (`mvex`) and compressed moovs (`cmov`) are rejected. New
  `CarveRole::Rebuilt` (index `role: "rebuilt"`), `.mp4.rebuilt.carved`
  naming, tier 2, `confidence: medium`, evidence
  `moov_ok`/`tables_cross_ok`/`chunk_range_ok`, and index fields
  `trailer_offset`, `trailer_len`, `trailer_sha256`, `trailer_preview`
  (hex + ASCII, capped at 1 MiB; `null` for other roles). mp4 salvage
  runs inside `--carve` whenever a valid `moov` is found — no new flag.

### Fixed
- **`carve_mp4` walked boxes 8 bytes short** (`skip(size - 8)` although
  `peek_array` does not consume): almost every structurally valid MP4
  was carved as `Truncated` and landed in `partial/` instead of being
  validated. `carves_mp4_file` only passed by accident of the
  `size == 0` branch. MP4 files now validate at the correct box
  boundaries.

### Added
- **Periodic partial-encryption heuristic** (`ROADMAP 8.7.3`). Carved files
  whose 4 KiB windows show a repeating high-entropy phase (e.g. every 4th
  block, 1:3 duty) now carry `suspected-partial-encryption` in the carve
  index (`partial_encryption: { period, duty, threshold }`, or `null`),
  labelled as a **heuristic hint, not a ransomware verdict**: compressed
  data scores as high entropy too. Uniformly high or fully structured files
  are not flagged (they are not *partial*). Detection: one extra streaming
  pass over the carved region; files smaller than 16 windows (64 KiB, i.e.
  8 cycles of the shortest detector period) produce no label. The
  `evidence` array gains `suspected-partial-encryption` when the label
  applies. Positioned after `entropy_spike_at` in the index; all existing
  fields keep their names and order.

## [1.1.1] - 2026-11-15

Packaging bugfix. The CLI crate lost its `[[bin]]` section in the 1.0.17
restructure, so the binary was installed as `bxmap-cli` and the release
binary was named `bxmap-cli` instead of `bxmap`; `cargo install bxmap-cli`
and the GitHub release asset did not match the docs. Restored
`[[bin]] name = "bxmap"`. `bxmap` (library) is unchanged at 1.1.0.

## [1.1.0] - 2026-11-15

CLI release aligned with `bxmap` 1.1.0. Highlights:
- **Carved files are named after the format they contain** (e.g.
  `0001a2b0-zip-9f3c1e2a.docx.carved`) with content-refined extensions,
  evidence fields in the index (`ext`, `ext_source`, `role`, `tier`,
  `evidence`, `confidence`), `.txt.carved` plaintext and `.tail.carved`
  salvaged tails. `.carved` stays last so nothing auto-opens.
- **The string scanner no longer effectively hangs on binary-heavy dumps**
  (the Latin-1/CP1252 fast-skip could leave a run open for the rest of the
  file); Lab 6 (~1.5 GiB) finishes again.
- Minor bump per the visible behaviour change of the carve file names.

### Added
- `--carved` and its companions (`--carved-out`, `--carved-index`,
  `--carved-min-size`, `--carved-max-size`, `--carved-max-total`,
  `--carved-max-files`) are aliases of the matching `--carve*` option,
  resolved in the argument parser, so there is a single configuration and
  identical behaviour either way. Giving both spellings of one option is a
  clear "same option" error instead of a silent last-one-wins. `bxmap.toml`
  accepts `carved` / `carved-out` as aliases of `carve` / `carve-out` (both
  spellings of one key is an error). Shell completions list the new flags.
- **Behaviour change:** specific extensions are now exact filters. `--carve
  docx` writes only files whose sniffed extension is `docx` (it used to write
  every ZIP); likewise `xlsx pptx odt ods odp jar apk` (zip), `doc xls ppt msi
  msg` (ole), `dll sys` (pe), `mov m4a` (mp4) and `so` (elf). Whole-format
  names (`zip`, `ole`, `pe`/`exe`, `mp4`, `elf`, `all`) still write every file
  of the format, and naming a kind both ways (`docx,zip`) keeps the whole
  format. The scan still runs once per format; only the written set changes.
  Skipped files are tallied as `filtered` (`--report summary` appends "N
  file(s) filtered by extension") and do not count toward
  `--carve-max-total` / `--carve-max-files`. A ZIP without a central
  directory (not sniffable) and footer-salvaged tails keep the default `zip`
  extension, so an exact filter skips them; `--carve zip` still returns them.
  Library: new `ExtFilter`, `Carver::with_ext_filter` and
  `CarveReport::filtered`; `odp` is now accepted as a carve type.
- `--carve bin`: new opt-in carve of unclassified high-entropy data
  (compressed, encrypted or packed regions no other type claimed). `Bin` is
  a `CarveKind` that is NOT in `CarveKind::ALL`: `--carve all` is unchanged;
  ask for it with `--carve bin` (or `all,bin`). It runs after the text pass:
  4 KiB blocks at or above the entropy threshold (7.2 bits/byte) are merged
  into runs, already-carved ranges are subtracted and runs under 16 KiB are
  dropped. Each run is written to `partial/` as
  `{offset:08x}-bin-{sha8}.bin.carved` (split into `--carve-max-size`
  pieces) with `complete: false`, `tier` 3, `evidence` `["entropy"]`,
  `confidence` `low` and a `bin:region` note. Dedupe and the
  `--carve-max-files`/`--carve-max-total` caps apply. Nothing is decrypted.
- Carve index: every record now also has `file_name`, `ext`, `ext_source`,
  `role` (`whole|tail|reassembled`), `tier` (1 = structure validated to the
  terminator, 2 = incomplete header or footer-found tail, 3 = readable text),
  `evidence` (`magic`, `structure_ok`, `terminator_ok`, `structure_partial`,
  `footer`, `text_ratio`, `sniff:<rule>`) and `confidence`
  (`high|medium|low`). Existing fields are unchanged. `--report summary`
  appends the count per tier and per extension. Library: `CarvedFile` gains
  `role`, `tier`, `evidence`, `confidence` and the new `CarveConfidence` enum.
- `--carve text`: new opt-in carve of plaintext regions (notes, logs,
  Markdown, source dumps). `Text` is a `CarveKind` that is NOT in
  `CarveKind::ALL`: `--carve all` is unchanged; ask for it with
  `--carve text` (or `all,text`). Detection is content-based: 4 KiB blocks
  scoring >= 97% text tokens (printable ASCII, common whitespace, valid
  UTF-8), merged with a one-block bridge, refined to byte-exact edges, cut to
  the first/last newline and clipped against files already carved. Each
  region is written to `partial/` with `complete: false` and a note
  `text:region 0x..-0x..; boundary cut to newline; looks like
  json|xml|html|csv|text`. Verified on a synthetic `md.dump` (455,111 B,
  head 25% random): the pass recovered the full plaintext tail byte
  for byte (341,323/341,323 bytes identical to `orig.md`) and reported
  nothing on pure-random data.
- Footer-first salvage now understands PNG: when the head of a PNG (signature,
  IHDR, first IDATs) is gone but the `IEND` chunk survived, the carver walks
  back from it over contiguous IDAT chunks whose length and CRC verify and keeps
  that run in `partial/` with a note
  (`salvage:tail: PNG IDAT run (N chunk(s)) + IEND at 0x...; signature and IHDR
  are missing`). The file is evidence of the compressed pixel data, not a
  viewable image (the zlib header and IHDR are lost with the head).
- Multi-format carving (8.8): `--carve` now recognises 41 kinds. New
  validators for `gif`, `ico`, `tar`, `pcap`, `pcapng`, `lnk`, `wasm`, `dex`,
  `kdbx`, `pem`, `avi`/`wav`/`webp` (RIFF), `mkv`/`webm` (EBML), `ogg`/`opus`,
  `flac`, `mp3`, `tif`, `vdi`, `vmdk`, `bz2`, `xz`, `class`, `rtf` and `evtx`;
  every candidate is structurally validated and nothing is decrypted or
  executed. File extensions that share a container are accepted as aliases
  (`docx`/`xlsx`/`pptx`/`odt`/`ods`/`jar`/`apk` -> zip, `doc`/`xls`/`ppt`/
  `msi`/`msg` -> ole, `dll`/`sys` -> pe, `so` -> elf, `db`/`sqlite3` ->
  sqlite, `mov`/`m4a` -> mp4, `tiff` -> tif). Formats without a magic number
  (plain text, json, xml, html, sql, csv, source code, `.dat`, `.key`) are
  not carved, except plaintext via the opt-in 	ext kind above. Entropy
  stays a boundary hint only, never a rejection rule.
  TAR is matched on the `ustar` field at offset 257 and back-adjusted to the
  true start; the matcher now reports every pattern that shares a needle
  (e.g. `OggS` for both ogg and opus).
- `--config <FILE>` (or a `bxmap.toml` in the working directory) holds the
  options that repeat for every dump in a case. Precedence: command line
  flags > config file > `--mode`/`--with` presets > defaults. The file is
  TOML and mirrors the flag names (`min-len`, `encoding`, `detectors`,
  `format`, `output`, `report`, `carve`, ...); a value of the wrong type is
  reported with the option name.
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

- **`--carve` file names now keep the format's own extension before `.carved`**: `0001a2b0-zip-9f3c1e2a.zip.carved`, `…-pe-….exe.carved`, `…-jpeg-….jpg.carved`; plaintext from `--carve text` is `….txt.carved`; a footer-first salvaged tail is `….png.tail.carved` (head missing, will not open directly); reassembled files are `…-reassembled.<ext>.carved`. `.carved` stays last so nothing auto-opens or runs. The extension comes from a static per-kind table (`CarveKind::default_ext`), never from file contents; one `carved_file_name()` builds every name. Scripts that parse names should read `path` from the index instead.
- **Carved file extensions are refined from the content (ROADMAP 8.10.3)**: after a file validates, a bounded sniff (head window, ZIP central directory, OLE directory; no extra pass over the dump) picks a more specific extension: PE `dll`/`sys`, ZIP `docx`/`xlsx`/`pptx`/`odt`/`ods`/`odp`/`apk`/`jar`, OLE `doc`/`xls`/`ppt`/`msg`/`msi`, MP4 `m4a`/`mov`, ELF `so`. Evidence only: anything that is not proven keeps the kind's default (`zip`, `ole`, `exe`, `mp4`, `elf`), and the extension is always a static string, never text from the file. `CarvedFile` gains `ext` and `ext_source` (`kind`, `sniff:<rule>` or `fallback`); salvaged tails, reassembled files and text regions keep the default extension.
- `--carve` no longer takes a `salvage` token: the parameter selects file
  types only, never a technique. Every carve runs the full recovery stack —
  header-first, incomplete-candidate `partial/` layout and footer-first
  salvage (ZIP central directory + end record, PDF `startxref` + `%%EOF`) —
  for the selected types. `--carve salvage` (or `zip,pdf,salvage`) now exits
  with a clear error naming the removed token. `salvage:tail` notes, the
  high-entropy back-walk and the `partial/` output are unchanged.
- Incomplete files (`complete: false`) are always written to a `partial/`
  subfolder of `--carve-out` with `corrupted_offset`/`entropy_spike_at` in the
  index; there is no longer a flat mode.
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

### Removed
- `--carve-incomplete`: the `partial/` layout is always on, so the flag is
  gone. Passing it is an unknown-flag error. Library API unchanged:
  `Carver::with_salvage(bool)` / `Carver::with_incomplete_dir(bool)` remain
  opt-in for library callers. Carved files keep the `.carved` extension.

### Fixed
- `--carve ole`: the OLE validator read the sector-size power at offset
  0x1C (the byte-order mark `0xFFFE`) instead of 0x1E, so it rejected every
  real `.doc`/`.xls`/`.ppt`/`.msi` with `implausible OLE sector size`. Fixed;
  the test fixture used the same wrong offset and is corrected too. Verified
  on a real installer (`msi`, `sniff:ole/msi`).
- `--carve png`: a PNG whose chunk CRC (or chunk length) is damaged after the
  header — e.g. partial encryption or overwrite of the middle/tail — is no
  longer dropped. The chunks that verified are kept, the file ends right before
  the damaged chunk and lands in `partial/` with a note
  (`PNG IDAT chunk CRC mismatch at 0x...; kept N valid chunk(s)`). A bad IHDR is
  still rejected.
- Generic `password=`/`token=` matches that are really something else are
  filtered out: e-mail addresses, URLs, dates and timestamps (`2024-01-15`,
  `10:30:00`, ISO-8601) and long runs of digits (ids, counters, phone
  numbers).
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
- The single-threaded string scan could appear to hang forever on dumps made
  mostly of binary noise: the fast-skip ignored `latin1`/`cp1252` runs, so a
  run stayed open and every byte travelled the full per-byte pipeline (Lab 6,
  ~1.5 GiB, never finished; 100% CPU). The fast-skip only skips when all
  enabled runs are closed, the legacy single-byte flushes reject mostly-binary
  runs with one cheap ASCII-ratio check before the heavier filters, and
  pending-emission now compares each candidate against its same-offset group
  instead of the whole batch (O(n^2) -> O(n.k) per batch). Emission order at
  equal offsets is now a full `(offset, encoding, text)` sort, so a
  `--max-strings` cut always lands on the same prefix. Lab 6 with
  `--carve all --max-strings 1` now finishes in seconds.

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

## [1.0.14] - 2026-10-30 (`bxmap-cli`)
### Changed
- CLI version bump (see CLI changelog below); uses `bxmap 1.0.4`.

## [1.0.4] - 2026-10-30 (`bxmap`)
### Added
- Encoding-scoped extraction APIs for library users.
- Encoding-filtered CLI scans.
- Candidate-byte fast-skip table in `StringRunScanner`.
