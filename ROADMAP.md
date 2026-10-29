# bxmap Roadmap - Enhanced Features

This document outlines the implementation plan for four major feature requests.

---

## 1. Thêm lọc UTF-16BE, UTF-32 (Add UTF-16BE, UTF-32 encoding support)

### Current State
- bxmap supports ASCII and UTF-16LE only (single-pass simultaneous detection)
- UTF-16LE detection: low byte printable + high byte == 0x00

### Implementation Plan

#### Phase 1: Core Library Changes (`src/lib.rs`)
1. **Extend `ExtractedString` encoding field**
   - Change from `&'static str` to support: `"ascii"`, `"utf16le"`, `"utf16be"`, `"utf32le"`, `"utf32be"`

2. **Add new scanner state for UTF-16BE/UTF-32**
   - UTF-16BE: high byte printable + low byte == 0x00 (big-endian)
   - UTF-32LE: byte[0] printable + byte[1..3] == 0x00, 0x00, 0x00
   - UTF-32BE: byte[3] printable + byte[0..2] == 0x00, 0x00, 0x00

3. **Update `StringRunScanner`**
   - Add new fields: `u16be_start`, `u16be_next_pos`, `u16be_buf`, `u32le_start`, `u32be_start`, etc.
   - Extend `feed()` to handle all 5 encodings simultaneously
   - Maintain single-pass optimization

4. **Add `--encoding` CLI options**
   - New values: `utf16be`, `utf32`, `utf32le`, `utf32be`, `all` (includes all)

#### Phase 2: CLI Integration (`cli/src/main.rs`)
1. Extend `Encoding` enum
2. Update help text and argument parsing
3. Add filtering logic for new encodings

#### Complexity
- **Medium-High**: Requires careful state management in the hot path
- **Risk**: Performance impact on the critical scanning loop

---

## 2. Timeline đơn giản từ PE header / Registry (Simple timeline with timestamps)

### Current State
- Minidump parser extracts: modules (with timestamps), threads, memory regions
- PE header timestamps available in `Module.timestamp` (Unix time)
- Registry hive parsing: NOT currently implemented

### Implementation Plan

#### Phase 1: PE Timestamp Extraction (Low-hanging fruit)
1. **Extend `Module` struct** - Already has `timestamp: u32` (PE TimeDateStamp)
2. **Add helper to convert PE timestamp to human-readable**
   - PE timestamps are seconds since 1970-01-01 UTC
3. **Add timeline output mode** `--timeline` or `--format timeline`
4. **Correlate strings with module timestamps**
   - For each extracted string, find containing module via VA mapping
   - Attach module's PE timestamp as "string timestamp"

#### Phase 2: Registry Hive Parsing (Advanced)
1. **Detect registry hive signatures** in memory
   - `regf` magic (0x66676572) for standard hives
2. **Parse basic hive structure** to extract:
   - Last write timestamps on keys
   - Key paths + values
3. **Correlate strings with registry timestamps**

#### Phase 3: Output Format
```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "source": "PE|Registry",
  "offset": 12345,
  "module": "kernel32.dll",
  "text": "suspicious string"
}
```

#### Complexity
- **PE timestamps**: Low (data already parsed)
- **Registry parsing**: High (new parser needed)

---

## 3. Redesign JSON Output - Tree Structure

### Current JSON Output (per line in array)
```json
{"offset":12345,"encoding":"ascii","text":"AKIA...","pid":1234}
```

### Target JSON Output (hierarchical tree)
```json
{
  "groups": [
    {
      "group": "SECRET",
      "type": "AWS_KEY",
      "items": [
        {
          "text": "AKIA...",
          "offset": 12345,
          "entropy": 4.7,
          "encoding": "ascii",
          "timestamp": "2024-01-15T10:30:45Z",
          "module": "kernel32.dll"
        }
      ]
    },
    {
      "group": "NETWORK",
      "type": "URL",
      "items": [...]
    }
  ],
  "metadata": {
    "scan_time_ms": 1250,
    "file_size": 1073741824,
    "total_strings": 45231
  }
}
```

### Implementation Plan

#### Phase 1: Classification Engine (New module)
1. **Create `classifier.rs`** with:
   - `ClassificationRule` struct: group, type, regex patterns, entropy thresholds
   - Built-in rules for: SECRET (AWS, Azure, GCP, GitHub, JWT, private keys), NETWORK (URL, IP, domain), CRYPTO (BTC, ETH, XMR), MALWARE (C2, mutex, suspicious paths)
   - `classify(text: &str) -> Option<(group, type)>`

2. **Integrate with string extraction**
   - Run classification on each extracted string
   - Attach classification to `ExtractedString` (or new wrapper struct)

#### Phase 2: JSON Tree Builder
1. **New output function** `write_json_tree()`
2. **Group by (group, type)** into hierarchical structure
3. **Include metadata block** at root

#### Phase 3: CLI Flag
- `--format json-tree` or `--format json --group`
- Backward compatible with existing `--format json`

#### Complexity
- **Medium**: New classification logic + output restructuring
- **Benefit**: Much more actionable output for analysts

---

## 4. Lọc file .mdmp + .hdmp (Support for .mdmp and .hdmp files)

### Current State
- bxmap treats input as raw bytes (no format parsing required)
- Minidump parser (`minidump.rs`) only handles `MDMP` signature (0x504d_444d)
- `.hdmp` = heap dump (subset of minidump), `.mdmp` = minidump

### File Format Analysis

| Extension | Signature | Description |
|-----------|-----------|-------------|
| `.dmp` / `.mdmp` | `MDMP` (0x504d_444d) | Full minidump |
| `.hdmp` | `MDMP` + specific stream types | Heap dump (minidump with only heap streams) |
| `.hdmp` (Windows Error Reporting) | May have different header | WER heap dump |

### Implementation Plan

#### Phase 1: Signature Detection
1. **Add file type detection** at CLI entry
2. **Read first 4 bytes** to identify format
3. **Route to appropriate handler**

#### Phase 2: Minidump Parser Enhancements
1. **Already handles `.mdmp`** (same as `.dmp`)
2. **For `.hdmp`**: 
   - Parse as minidump (same signature)
   - Filter streams: only `ST_MEMORY64_LIST` with heap regions
   - Add `--heap-only` flag to restrict scanning to heap ranges

#### Phase 3: WER `.hdmp` Support (if different)
1. **Research WER heap dump format**
2. **Add specific parser if needed**

#### Phase 4: CLI Integration
```bash
bxmap crash.mdmp --map-va        # Works now (same as .dmp)
bxmap heap.hdmp --heap-only      # New: only scan heap regions
bxmap dump.dmp --format json-tree --timeline
```

#### Complexity
- **Low-Medium**: `.mdmp` already works; `.hdmp` needs stream filtering

---

## Implementation Priority & Timeline

| Priority | Feature | Effort | Dependencies |
|----------|---------|--------|--------------|
| **P1** | JSON Tree Output | 2-3 weeks | None |
| **P2** | .mdmp/.hdmp Support | 1-2 weeks | Minidump parser |
| **P3** | PE Timeline | 1-2 weeks | Minidump parser |
| **P4** | UTF-16BE/UTF-32 | 3-4 weeks | Core scanner rewrite |
| **P5** | Registry Timeline | 4-6 weeks | New parser |

---

## Technical Considerations

### Performance
- UTF-16BE/UTF-32: Must maintain single-pass O(n) scanning
- Classification: Run after extraction, not during (separate pass)
- Timeline: Minimal overhead (lookup in existing module map)

### Backward Compatibility
- New `--format json-tree` doesn't break existing `--format json`
- New encodings opt-in via `--encoding`
- Timeline opt-in via `--timeline`

### Testing Strategy
- Unit tests for each encoding's edge cases
- Integration tests with real minidumps
- Golden JSON files for tree output comparison
- Fuzzing for new parsers

---

## File Changes Summary

| File | Changes |
|------|---------|
| `src/lib.rs` | UTF-16BE/UTF-32 scanner, new `ExtractedString` fields |
| `src/classifier.rs` | **NEW** - Classification engine |
| `src/timeline.rs` | **NEW** - Timeline correlation logic |
| `src/minidump.rs` | Heap-only filtering, WER support |
| `cli/src/main.rs` | New CLI flags, JSON tree output, format routing |
| `Cargo.toml` | Potentially: `chrono` for timestamps, `serde_json` for tree |

---

## Next Steps

1. **Start with JSON Tree Output** (highest impact, lowest risk)
2. **Add .mdmp/.hdmp detection** (quick win)
3. **Implement PE Timeline** (leverages existing minidump data)
4. **Tackle UTF-16BE/UTF-32** (core rewrite, do last)
5. **Registry Timeline** (separate major feature)