# Changelog

All notable changes to `bxmap` / `bxmap-cli` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
- `--progress` / `--no-progress` print a live status line on stderr (percent,
  MiB/s, scanned offset). Progress is on by default when stderr is a terminal
  and results are not going to the terminal. The new
  `extract_strings_from_file_streaming_range_with_encodings_progress` API
  reports consumed bytes per chunk.

### Changed
- `apply_detectors` allocates output capacity up front and clones lazily.
- Flat detector output (`--detect-format flat`, default) is unchanged.
- `--start`/`--end` force the sequential streaming scanner even when
  `--threads` is greater than 1.

## [1.0.14] - 2026-10-30 (`bxmap-cli`)

### Changed
- CLI version bump (see CLI changelog below); uses `bxmap 1.0.4`.

## [1.0.4] - 2026-10-30 (`bxmap`)

### Added
- Encoding-scoped extraction APIs for library users.
- Encoding-filtered CLI scans.
- Candidate-byte fast-skip table in `StringRunScanner`.
