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

### Changed
- `apply_detectors` allocates output capacity up front and clones lazily.
- Flat detector output (`--detect-format flat`, default) is unchanged.

## [1.0.14] - 2026-10-30 (`bxmap-cli`)

### Changed
- CLI version bump (see CLI changelog below); uses `bxmap 1.0.4`.

## [1.0.4] - 2026-10-30 (`bxmap`)

### Added
- Encoding-scoped extraction APIs for library users.
- Encoding-filtered CLI scans.
- Candidate-byte fast-skip table in `StringRunScanner`.
