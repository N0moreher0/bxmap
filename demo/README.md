# bxmap Demo Suite — MemLabs Cases

This directory contains synthetic memory dumps and demonstration scripts that reproduce key findings from MemLabs Lab 1, 2, 4, and 6 scenarios.

## Quick Start

```bash
# Generate demo dumps (one-time setup)
python demo/generate_demo_dumps.py

# Build release binary
cargo build --release --manifest-path cli/Cargo.toml --no-default-features

# Run demos
./target/release/bxmap-cli demo/dumps/lab1.dmp --auto-tune --extract all --report all
./target/release/bxmap-cli demo/dumps/lab6.dmp --auto-tune --extract env --report user
./target/release/bxmap-cli demo/dumps/lab4.dmp --auto-tune --extract all --report all --max-strings 50000
./target/release/bxmap-cli demo/dumps/minidump.dmp --map-va --rwx-only --auto-tune
```

---

## Demo 1: Lab 1 — Basic String Extraction

**File:** `demo/dumps/lab1.dmp` (50 MB)

```bash
bxmap demo/dumps/lab1.dmp --auto-tune --extract all --report all
```

**Key findings:**
- ASCII strings: process paths, commands, registry keys, IPs, emails
- UTF-16LE strings: environment variables with credentials (`RAR password=...`, `AWS_SECRET_ACCESS_KEY=...`)
- UTF-16BE mirrors suppressed (dedup logic works)
- Artifacts: paths (with `user=victim;category=...`), emails, registry, env vars
- User report: `victim` with 2 files (1 AppData = 50%)

**Performance:** ~12 MiB/s, 4.1s, 6 threads

---

## Demo 2: Lab 6 — RAR Password in UTF-16 Env Block

**File:** `demo/dumps/lab6.dmp` (120 MB)

```bash
bxmap demo/dumps/lab6.dmp --auto-tune --extract env --report user
```

**Key findings:**
- **RAR password found in UTF-16LE env block:** `BRAR password=MySecretRARPassword2024!` at offset 0x14
- Also detected as UTF-16BE mirror (suppressed) and partial ASCII
- 6 RAR5 signatures embedded (`Rar!\x1a\x07\x01\x00`) for carving demo
- Bitcoin wallet in env: `BITCOIN_WALLET=bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh`
- AES-256 encryption key: `ENCRYPTION_KEY=AES256KeyForFileEncryption123456789012`

**Performance:** ~43 MiB/s, 2.8s, 6 threads

**Next steps (manual):**
1. Use `--carve rar` (Phase 8) to extract the 6 RAR files
2. Open extracted RAR with password `MySecretRARPassword2024!`

---

## Demo 3: Lab 4 — 1GB User Profile Analysis

**File:** `demo/dumps/lab4.dmp` (100 MB, simulates 1GB)

```bash
bxmap demo/dumps/lab4.dmp --auto-tune --extract all --report all --max-strings 50000
```

**Key findings:**
- **User `eminem`**: 11 files across Desktop, Documents, Downloads, AppData, Pictures, Music, Videos
- Tool traces: **DumpIt** (evidence: Desktop\DumpIt.zip, path+command), **WinPmem**, **FTK Imager**, raw image `DESKTOP-VICTIM-20240115-143022.raw`
- Registry: Run keys for persistence, service malware
- Network: C2 at `http://192.168.1.100/exfil`, exfil to pastebin
- Emails: `victim@company.com`, `admin@company.com`, `attacker@evil.com`

**User report:**
```
eminem                    11 files  AppData:    2 ( 18.2%)
```

**Performance:** ~47 MiB/s, 2.1s (scanned 3.6% before 50k limit)

---

## Demo 4: Minidump VA Mapping

**File:** `demo/dumps/minidump.dmp` (30 MB)

```bash
bxmap demo/dumps/minidump.dmp --map-va --rwx-only --auto-tune
```

**Purpose:** Demonstrate `--map-va`, `--rwx-only`, `--heap-only` for minidump analysis.
- Maps virtual addresses to module names (ntoskrnl.exe, evil.exe, payload.dll)
- Filters to RWX regions (shellcode/injected code)
- Shows VA + module/region for each string

---

## Comparison: bxmap vs `strings | grep`

| Aspect | `strings -el memory.dmp | grep -i password` | `bxmap memory.dmp --extract env --report user` |
|--------|----------------------------------------------|------------------------------------------------|
| **Encodings** | ASCII + UTF-16LE only (misses UTF-16BE, UTF-32) | All 5 encodings in single pass |
| **Dedup** | Manual `sort -u` needed | Automatic, with counts |
| **Context** | Just the matching line | Offset, encoding, artifact detail (`user=...;category=...`) |
| **Noise** | All matches including period-1/2 fill | Conservative noise filter (configurable) |
| **Speed** | Multiple passes (strings + grep) | Single pass, parallel |
| **Output** | Unstructured text | JSON/NDJSON/CSV/Text with structured artifacts |

**Honest assessment:** bxmap wins on **one-pass multi-encoding**, **structured output**, **dedup with counts**, and **parallel speed**. It does not "find things strings cannot" — it finds them **faster, with context, in one command**.

---

## Benchmark Numbers

| Dump | Size | Time | Throughput | Peak RAM | Output (50k limit) |
|------|------|------|------------|----------|---------------------|
| Lab 1 | 50 MB | 4.1s | 12.2 MiB/s | ~150 MB | 200k strings, 305 artifacts |
| Lab 2 | 80 MB | ~3s | ~25 MiB/s | ~180 MB | — |
| Lab 4 | 100 MB | 2.1s* | 47 MiB/s | ~200 MB | 50k strings, 110 artifacts |
| Lab 6 | 120 MB | 2.8s | 43 MiB/s | ~220 MB | 200k strings, 240 artifacts |
| Minidump | 30 MB | 0.8s | 37 MiB/s | ~100 MB | — |

*Lab 4 stopped at `--max-strings 50000` (3.6% of file). Full scan would be ~60s.

---

## Running Full Benchmarks

```bash
# Full scan (no limit) - adjust based on RAM
bxmap demo/dumps/lab4.dmp --auto-tune --max-strings 0 -o lab4_full.json
bxmap demo/dumps/lab6.dmp --auto-tune --max-strings 0 -o lab6_full.json

# With gzip compression
bxmap demo/dumps/lab6.dmp --auto-tune --max-strings 0 -o lab6_full.json.gz
```

---

## Redacting Credentials

Before sharing screenshots/GIFs:

```bash
# Redact sensitive values in JSON output
jq 'del(.text) | .text = "[REDACTED]"' output.json > output_redacted.json

# Or use bxmap's --max-str-len to truncate
bxmap dump.dmp --max-str-len 50 --format json
```

---

## Publishing Demo

1. Record asciinema:
   ```bash
   asciinema rec demo.cast -c "bxmap demo/dumps/lab6.dmp --auto-tune --extract env --report user"
   asciinema upload demo.cast
   ```

2. Convert to GIF:
   ```bash
   agg demo.cast demo.gif --theme solarized --font-size 14
   ```

3. Add to README.md and post to r/computerforensics, r/netsec, Show HN, TWiR.