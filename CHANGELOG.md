# Changelog

All notable changes to `bxmap` / `bxmap-cli` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **DC-equalized sibling for rebuilt JPEGs (ROADMAP 8.12.6)**.
  A rebuilt baseline JPEG's scan starts at MCU 0 with the DC predictor
  forced to zero, so every channel of a mostly-uniform image is shifted
  by a constant. The rebuilt file now detects the per-component shift and,
  when it is not mid-gray (or neutral chroma), emits an **additional**
  `.jpg.adjusted.rebuilt.carved` next to the raw `.jpg.rebuilt.carved`:
  the first DC difference of each shifted component is rewritten at bit
  level (new category code from the build's DC table, new amplitude bits,
  rest of the bitstream untouched). Both files pass the own validator and
  the MCU walker; the adjusted one is validated before it is written, and
  a failing splice keeps the raw file with no sibling. The raw rebuilt
  record is unchanged (no `dc_adjusted` evidence/notes); the sibling
  carries evidence `dc_adjusted`, notes `; dc-adjusted`, the same offset,
  tier and confidence. New fixture `baseline_512x384_dark_q80.jpg` drives
  the test. 287 lib tests, 117 golden, clippy `-D warnings`, fmt clean.

### Changed
- **The 8.12.4 estimation probe is now parallel (ROADMAP 8.12.8a)**.
  The bit-sync anchor sweep (16 KiB × 8 phases × 130k 64-MCU walks) and
  the two-chain verification sweep run on rayon; the per-thread
  frequency maps merge commutatively, so results are byte-identical to
  the serial version (verified on the bench: 32/32 files identical,
  SHA-256). `walk_mcus` gained a `collect_dc` switch — probe/kept walks
  no longer record the luma DC series. Bench `--carve all` on the 412 MB
  image: 72.55 s → 50.7 s (~30% faster); recovery 30/63 unchanged.
  JPEG-only carve ~54 s; the entire remainder is the three ruined JPEGs
  (~13–15 s each, within the 5–30 s target). 286 lib tests, 117 golden,
  clippy `-D warnings`, fmt clean.

- **Carved files are named with dots, not dashes (ROADMAP 8.10.14)**.
  `{offset:08x}-{kind}-{sha8}.{ext}.carved` is now
  `{offset:08x}.{kind}.{sha8}.{ext}.carved` (`00842000.pe.cb18a6c0.dll.carved`),
  for every `CarveKind` and every role suffix: `.tail`, `.rebuilt`, `.cut`
  stay in place (`…mp4.9f3c1e2a.mp4.rebuilt.carved`); `reassembled` still
  replaces the hash. `.carved` is always the last extension as before; the
  index (`path`, `role`, `tier`, evidence) is unchanged, and the name
  whitelist in the golden tests is tightened to `[a-z0-9.]`. HELP and the
  READMEs updated. 283 lib tests, 117 golden, clippy `-D warnings`,
  fmt clean.

### Added
- **In-source donor rebuild for JPEGs whose table chain was destroyed
  (ROADMAP 8.12.5)**. When the exact rebuild fails and a `Whole` baseline
  JPEG exists elsewhere in the dump, bxmap now harvests its tables: one
  matcher pre-pass keeps up to 64 distinct baseline 8-bit JPEGs (structural
  segments only — DQT/SOF/DRI/DHT/SOS; APPn/COM are stripped at harvest),
  then the ruined candidate is rebuilt with the donor's exact tables and
  dimensions — no `cols` estimation, no Annex K assumption — through the
  same gates (≥ 64 px per side, aspect 0.1–10, ≥ 5 rows, walker consuming
  exactly `rows × cols` MCUs at the `EOI`, plus the own validator and
  `verify_scan`). Confidence is `high`; the result always lands in
  `partial/` (the head rows are lost for good), tier 2, `role: rebuilt`.
  Provenance is carried in the index: evidence `donor_tables` +
  `donor=<tag>`, notes `tables=donor:<tag>`. A direct fast path skips the
  probe entirely when the scan is intact from MCU 0 (the header-only
  ruin): one decode pass, milliseconds. `DRI`-coded donors are still
  refused (restart phase unknown), RSTn ruins keep the plain `Tail`. The
  estimation path (8.12.4) runs unchanged as the fallback whenever no
  donor fits. 286 lib tests, 117 golden, clippy `-D warnings`,
  fmt clean.
- **PE sniff gained a measured elimination ladder for ruined import
  tables (ROADMAP 8.10.13)**. RAM-dump PEs whose import descriptors
  were zeroed (every one of the Lab 6 driver cases) now classify on
  the surviving evidence, in order: (1) a delay-load directory
  refines to `.dll`/`.exe` (`sniff:pe/user-delay`) — kernel drivers
  never delay-load; (2) an `INIT` section refines to `.sys`
  (`sniff:pe/kernel-section`) — present in 100% of Windows 11 drivers
  (479/479), in 1.09% of `.dll` and 0.16% of `.exe`; (3)
  `SUBSYSTEM_NATIVE` + DLL bit + no export directory refines to
  `.sys` (`sniff:pe/kernel-noexports`), the symcryptk.dll profile.
  The ladder outranks the DLL bit on purpose. Validated on 4,773
  real PEs (Windows 11): the 47 remaining mismatches are all Windows
  kernel-role images shipped as `.dll`/`.exe` (kernel debugger
  transports, HAL extensions, microcode/secure-firmware components),
  plus the unavoidable subsystem-16 boot apps; no `.sys` is demoted
  anywhere on the corpus. On Lab 6 the three kernel-mode images
  previously labelled `.dll` now get `.sys`; the five user-mode
  images that happen to carry delay-load directories get their own
  evidence (`sniff:pe/user-delay`). 283 lib tests, 117 golden,
  clippy `-D warnings`, fmt clean.
- **PE subtype sniff now uses the import table, not just the
  characteristics/subsystem (ROADMAP 8.10.12)**. `refine_ext` for
  `CarveKind::Pe` previously assigned `.sys` only to subsystem NATIVE
  images; on Windows 10/11 many real kernel drivers set
  `IMAGE_FILE_DLL` and so were named `.dll`, while native user-mode
  EXEs (`smss.exe`, `csrss.exe`) also use subsystem NATIVE and were
  named `.sys`. The new order: (1) a readable import table naming
  `ntoskrnl.exe` / `wdf01000.sys` / `wdfldr.sys` or an
  `ext-ms-win-ntos-*` API set refines to `.sys`
  (`sniff:pe/kernel-import`) — every Windows 11 kernel driver imports
  the kernel, even ones with an empty export table; (2) otherwise the
  `IMAGE_FILE_DLL` bit refines to `.dll` as before; (3) a readable
  import table with only user-mode modules refines to `.exe`
  (`sniff:pe/user-import`); (4) an unreadable import table falls back
  to the old subsystem rule. Validated against 4,773 real PE files on
  Windows 11 (System32 + drivers): only 7 files land outside the
  expected family (kernel images shipped with `.dll`/`.exe` extensions
  or boot apps). 279 lib tests, 117 golden, clippy `-D warnings`,
  fmt clean.
- **JPEG whose table chain is destroyed is rebuilt with the ITU-T T.81
  Annex K tables by estimation (ROADMAP 8.12.4, P1)**. When the ruin
  destroys the `DQT`/`SOF`/`DHT` segments but not the entropy-coded
  scan, `--carve` no longer keeps only a tail: a bit-sync probe walks
  every bit position in the first 16 KiB across 8 phases and 6 layouts
  (4:2:0, 4:2:2, 4:4:4, 4:1:1, 4:1:0, gray — tried in that order),
  walking the Annex K tables for 64 MCUs per position. Positions whose
  boundary lists recur at least 32 times form the standard boundary
  (two independent chains must additionally agree for ≥ 64 MCUs from
  it). `cols` is estimated from the per-MCU luma DC predictor series:
  Pearson correlation at lags `[8, min(1024, N/5)]` is gated by a
  block-level seam test (mean |ΔDC| ratio across the row join, all
  MCU-aligned residue classes, ≥ 1.5×), and the smallest lag with
  correlation ≥ 0.97 × peak wins; corr ≥ 0.55 → `medium`, ≥ 0.30 →
  `low`, otherwise the image is rejected rather than guessed
  (`geometry_unreasonable` / `no_row_signal`). The surviving scan is
  copied bit-exactly from the converged boundary plus whole MCU rows,
  and re-assembled as `SOI` + minimal APP0 + IJG quality-90 DQT
  (computed from the Annex K bases — byte-exact against
  `cjpeg -quality 90`) + `SOF0` + the four Annex K DHTs + `SOS` + the
  kept scan, padded with 1 bits and re-stuffed. The rebuilt file then
  passes the same two gates as the exact rebuild (own validator + the
  MCU walker: exactly `rows × cols` MCUs ending at `EOI` with ≤ 7
  all-1s padding bits), and lands in `partial/` as `role: rebuilt`,
  `complete: true`, `tier 2`/`3`, with `evidence`
  `stuffing_run`, `annexk_walk_ok`, `eoi_aligned`, `converged_boundary`,
  `cols_corr=0.xx`, `seam=x.x`, `annexk_q90` and a notes line carrying
  the layout/corr/seam/rows/skip/lost-rows estimate. Scans with
  `RSTn`/`DRI` are refused (`dri: needs donor`), and images with no
  measurable row period are refused — never reconstructed by guessing.
  Measured on ruined-head fixtures (IJG/Annex K encoder, scan fully
  intact): `camera` 640×480 rebuilt completely (correlation 0.99
  against the original, modulo the assumed-q90 quantisation),
  `flat`-texture rebuilt completely, `head4k` (4 KiB of scan destroyed)
  rebuilt as a 29-row crop, weak noise-textured photos refused, the
  EOB-flat monochrome scan refused. The two JPEG bench cases whose
  table chain was destroyed by the `trunc` scenario now score REBUILT
  (was EXACT), both fully recovered.
  Two synthetic fixtures (one lib test, one golden test) whose bodies
  were PRNG noise were switched to an all-`FF` body: with 8.12.4 the
  estimator could (rarely) "rebuild" noise into a plausible-looking
  payload; those fixtures mean to test the salvage/tail path, and now
  do so deterministically. 275 lib tests (was 269, +6), 117 golden,
  clippy `-D warnings`, fmt clean. Bench (412 MB, 63 items) unchanged
  on all four `--carve all` variants (30/30/36/42); Lab 6 (1.61 GiB)
  unchanged (128 files). Note: the 8.12.4 estimate costs ~5-30 s of
  probing per ruined JPEG (it walks every position in the window),
  which shows up as wall time on dump sets with ruined-head JPEGs;
  performance of the estimate path is tracked in ROADMAP 8.12.8.
- **The JPEG MCU walker is now a complete, tested module with the ITU-T
  T.81 Annex K tables built in (ROADMAP 8.12.3)**. `src/jpeg_scan.rs`
  gained: (1) `decode_block` extracted from the decode loop (DC diff +
  AC run/size + EOB + ZRL; no dequantization, no IDCT); (2)
  `walk_mcus(unstuffed, restarts, geometry, tables, start_bit,
  limit_mcus) -> WalkStats {mcus, blocks, end_bit, err, first_boundaries,
  dc_luma, restarts_consumed, geometry}` — the single walker behind
  `verify_scan`, with an arbitrary `start_bit` (for the 8.12.4 probes) and
  a caller-controlled MCU limit; (3) the four Annex K tables
  (DC/AC × luma/chroma) as compile-time constants validated byte-exact
  against the `DHT` segments libjpeg actually writes in the repo
  fixtures, built once via `OnceLock` into 16-bit lookups (~0.5 MiB),
  with `AnnexK::for_components` mapping component 0 → luma tables, the
  rest → chroma; (4) safety caps: `dc_luma` keeps only the first 65 536
  entries, `first_boundaries` only the first 1 100; every loop is bounded
  by the remaining bits or by `limit_mcus`; table/component count
  mismatch and garbage input return `err` in `WalkStats`, never panic.
  `verify_scan` now re-uses `walk_mcus` instead of its own copy of the
  loop; behavior is unchanged. Tests: symbol counts 12/12/162/162, Kraft
  sums ≤ 1, LUT slot checks for every symbol, canonical encode →
  incremental 1-bit decode roundtrip, `OnceLock` built-once identity,
  and a bit-for-bit equality check between the Annex K walk and the
  file-tables walk on libjpeg fixtures (IJG embeds the Annex K tables).
  269 lib tests (was 258), 117 golden; clippy `-D warnings`; fmt clean.
  Bench (412 MB, 63 items) unchanged on all four `--carve all` variants
  (30/30/36/42 recovered); Lab 6 (1.61 GiB) unchanged at 128 files.
- **JPEG whose head was destroyed but whose table chain survives is rebuilt
  exactly (ROADMAP 8.12.2, P1)**. When ransomware destroyed only the
  leading `APP0`/`EXIF` region (the corruption shape the bench's `head4k`
  reproduces on real camera images), the `DQT* SOF0/1 DHT* DRI?` chain sits
  right before the `SOS` and survives intact. `--carve` now reconstructs
  the file instead of only salvaging a tail: candidate chains are walked
  forward from every plausible start marker within ~8 KiB before the
  surviving `SOS` (each segment's own length field is walked:
  `DQT`* (ids tracked, ≤ 4 sub-tables each) → `SOF0/1` (P=8, X/Y>0, 1..4
  components with h,v ∈ 1..4, every referenced `DQT` present) → `DHT`*
  (each sub-table ≤ 256 symbols, symbol count == sum of counts) → optional
  `DRI` (exactly 4 bytes)); the chain must land exactly on the `SOS`
  marker. The `SOS` is cross-checked too: component table matches SOF,
  `Ss=0`/`Se=63`/`Ah=0`/`Al=0`, every referenced Huffman table present.
  The rebuilt file is `SOI` + a minimal JFIF `APP0` + the surviving
  segments **verbatim** + the `SOS`..`EOI` region **verbatim**: every
  byte is either a known table segment or entropy data the decoder proved
  correct. Post-checks both must pass: the own JPEG validator
  (`carve_jpeg` = `Valid`, checked on the rebuilt bytes via a temporary
  file) and the new MCU walker (`src/jpeg_scan.rs`, ROADMAP 8.12.3's
  core: baseline/sequential Huffman, SOF0/SOF1, 8-bit, restart support,
  ≤ 7 padding bits of 1s expected at the end of scan, every table read
  from the file's own `DHT`, never Annex K) which must decode the scan
  to exactly `cols × rows` MCUs ending at `EOI`. On success the file goes
  to the **main folder** as `<offset>-jpeg-<hash>.jpg.rebuilt.carved`
  (`offset` = the `SOS` offset per ROADMAP 8.12.7) with `role: rebuilt`,
  `complete: true`, tier 1, `confidence: high`, `corrupted_offset` =
  first surviving chain segment, evidence
  `stuffing_run`, `sof:sequential`, `tables_exact`, `seg_chain_ok`,
  `mcu_walk_ok`, plus any trailer bytes found after the `FF D9` (same
  trailer handling as the MP4/JPEG-tail paths). On any failure the scan
  falls back to the 8.12.1 tail path (`partial/`), so nothing is lost
  relative to before. No new flag; the MCU walker is a private module
  (pixel decoding stays out of scope).
  Prerequisite fix (found while bringing this up): the stuffing oracle
  that unstuffs `FF 00` in the entropy data incorrectly emitted a zero
  byte instead of the stuffed `FF` byte, shifting every stuffed entropy
  byte by one and desynchronising the Huffman decode; the 8.12.1 tail
  path was unaffected (it walks raw `FF`-pairs and never unstuffs) but
  the MCU walker depends on the unstuffed bitstream; fixed before commit.
  Unit tests cover a real baseline fixture with a ruined head (rebuilt
  and decoded) and a fully destroyed chain (refused; nothing emitted).
  Verification: end-to-end via the CLI on a synthetic camera-like JPEG
  (EXIF `APP1` ~20 KB ahead of the tables, 4 KiB of head overwritten
  with random data): rebuilt, decoded with PIL to exactly 640×480,
  **pixel-identical** to the intact original (0/921,600 channel
  differences), `complete: true`, tier 1, `confidence: high`. The bench
  corpus gained `img_camera.jpg` (PIL-built camera-like JPEG, 640×480,
  EXIF `APP1` 12,268 B ahead of the table chain at `0x3002`): on the new
  412,713,446-byte, 63-item image the `head4k` scenario carves it as
  `REBUILT` on all four `--carve all` variants (default/raised/text/
  headloss) and the rebuilt file decodes **pixel-identical** to the
  corpus original; `intact` and `trunc` score `EXACT`. Recovered totals
  went 27→30 (default/raised), 33→36 (text), 39→42 (headloss);
  `img_photo.jpg head4k` (APP0-only, tables die with the head) still
  scores `COVERAGE 96%` via the 8.12.1 tail path — recorded, not a
  regression. The bench numbers from before this change refer to the
  previous 388 MB / 60-item image. Lab 6 (1.61 GiB) unchanged vs
  8.12.1; see ROADMAP 8.12.2 for details.

- **JPEG entropy-coded scan survives while the head is destroyed: `--carve`
  now salvages a JPEG tail (ROADMAP 8.12.1, P1)**. A bare `FF D9` footer is
  not a trustworthy footer, so the salvage pass only accepts one when the
  bytes behind it are stuffing-clean: every `FF` must be followed by `00`
  (stuffed literal), `D0..D7` (RSTn) or another `FF` (padding). Random data
  violates ~every 267 bytes, so an 8 KiB stuffing-clean run behind an
  `FF D9` cannot happen by chance (measured: 0 candidate tails in 8 MiB of
  noise; `--carve jpeg` on the 388 MB bench image finds exactly the ruined
  `img_photo.jpg` tail). The walk is **footer-first, backwards, in 16 KiB
  windows** and stops at the last stuffing violation. Guard rails: run
  length >= 8 KiB; a run that is > 90% NUL bytes is rejected (zero padding
  is not scan data); the coding process is read from the header when it
  survives — SOF0/SOF1 (baseline/extended sequential Huffman) is accepted,
  SOF2..SOF15 and `DAC` (arithmetic) are refused; an unreadable header
  (the normal ruined-head case) is accepted and labelled `sof:unreadable`.
  `RST` markers are legal in the run (`dri_seen`); an `SOS` boundary stops
  the run at the last scan (`multi-scan?`, progressive). Output: the scan
  goes to `partial/` as `<offset>-jpeg-<hash>.jpg.tail.carved` with
  `role: tail`, `complete: false`, tier 2, `confidence: low`, evidence
  `footer`/`stuffing_run` (plus `sof:…`, optionally `dri_seen`,
  `multi-scan?`); `corrupted_offset` = tail start. Ransomware trailer
  bytes after the EOI are cut from the file and recorded in the index
  (`trailer_offset`, `trailer_len` (<= 1 MiB), `trailer_sha256`,
  `trailer_preview` <= 64-byte `hex | ascii` preview), exactly like the
  MP4 path. No new flag; runs as part of `--carve` (all/jpeg), and
  `--carve-out` refuses to overwrite an existing file. Unit tests cover
  the ruined-head salvage, RST handling, the SOS boundary, the NUL gate,
  the 8 KiB floor, `prior_end` coverage, and the sequential/progressive/
  arithmetic SOF gates; the golden CLI fixture covers the whole path
  (`golden_carve_jpeg_tail_after_partial_encryption`).
  Bench (388 MB, 60 labelled items): `img_photo.jpg head4k` MISS →
  **COVERAGE 96%** (tail 105 KB of the 108 KB scan), `img_photo.jpg
  trunc` MISS → **EXACT 100%** (the last 60% survived and the tail starts
  at the cut); recovered total 25 → 27 (spurious unchanged: 3);
  `all,text` 31 → 33, `all,headloss` 37 → 39. Lab 6 dump (1.6 GB, `--carve
  all`): 128 files, unchanged — no JPEG tails and no regressions.
  Scoring note: `bench/score.py` now (a) attributes a `role=tail` carve to
  the item whose range contains its **end** (a backward walk may swallow
  arbitrarily much clean noise before the damage boundary), and (b) scores
  such tails by the **longest common suffix** with the corpus (>= 50% =
  COVERAGE), because a tail necessarily starts inside the destroyed head.
- **ZIP with a surviving central directory is rebuilt instead of only
  tail-salvaged (ROADMAP 8.13.1, ZIP part, P1)**. When the first 4 KiB of an
  archive were overwritten, the header pass sees nothing, but the central
  directory and end record (always at the end) survive: the archive's logical
  start is computed exactly (`cd_abs - cd_offset`) and the reconstruction
  drops only the member(s) whose local headers are inside the destroyed
  head, keeps every surviving member's byte range, and rewrites the central
  directory and end record with adjusted local-header offsets. The result is
  a smaller, fully valid archive that opens in real tools (Python `zipfile`
  `testzip` passes on the bench's real files: 5/6 members recovered from a
  head-destroyed `archive_notes.zip`, all ZIPs named in this entry unwrap
  clean). Members dropped are recorded by name in the notes (never silent);
  the rebuilt file re-passes bxmap's own ZIP validator before it is handed
  out, otherwise it is rejected with a reason. Named
  `.zip.rebuilt.carved` (or `.docx.rebuilt.carved` when the kept directory
  names sniff to OOXML), role `rebuilt`, `complete: false`, tier 2,
  `confidence: medium`, evidence `eocd_ok`/`cd_ok`/`local_headers_ok`,
  `corrupted_offset` at the first surviving member. Runs inside the salvage
  pass (part of `--carve`), no new flag; when the archive cannot be
  reconstructed (no surviving member, no parseable CD), it falls back to the
  existing `salvage:tail` behavior unchanged.
- **`--carve headloss`: clean tail of a file whose head was overwritten
  (ROADMAP 8.13.3)**. New opt-in kind (`CarveKind::HeadLoss`, not part of
  `all`; ask for it with `--carve headloss` or `--carve all,headloss`).
  The header pass cannot see a file whose first 4 KiB were overwritten
  with random bytes (the magic is gone), so a new pass looks for the
  entropy drop instead: a high-entropy run followed by structured data.
  Each structured run of 8 KiB or more is cut out as a `tail`-role record
  in `partial/` (`...bin.tail.carved`) with `complete: false`, `tier` 3,
  `entropy_drop` evidence, `corrupted_offset` at its first byte and a
  `salvage:head4k` note. Edges are found on the 4 KiB grid, refined with
  128-byte windows and pulled 256 bytes inside the clean side so no
  random byte leaks into a tail. Zeros and wiped gaps are never
  evidence, ranges an earlier pass already carved are subtracted, and
  each tail is capped at `--carve-max-size` (64 MiB when unset). It runs
  after the text pass and before the bin pass. Nothing is decrypted,
  rebuilt or guessed; the format stays unknown. On the synthetic carve
  bench (388 MB, 60 items) `--carve all,headloss` recovers 36/60 items
  against 24/60 for `--carve all` (`head4k` 2/19 to 7/19, `trunc` 3/19
  to 8/19, plus two plaintext files with no magic that `all` skips),
  with every tail inside a real item and about 0.5 s more wall time. A
  PE with high-entropy resource blocks comes out as several fragments.
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
- **NAL validity oracle for rebuilt MP4s (ROADMAP 8.11.4, P1)**. Every
  video track (AVC/HEVC: `avc1`/`avc3`/`hvc1`/`hev1`) is checked sample by
  sample: each NAL must be exactly consumed, including the header byte's
  forbidden zero bit — an intact frame passes, an encrypted one almost
  never does, and a frame whose NALs add up to exactly `stsz` wins
  overwhelmingly. `tracks_intact` in the index records `codec`, `samples`,
  `intact`, `intact_ratio`, `broken_prefix_samples`,
  `first_intact_sync_sample` (via `stss`; no table = all samples are sync)
  and `first_intact_sync_time` (`mvhd` timescale + `stts` deltas, seconds).
  Sample sizes still come from the moov (intact even for encrypted frames,
  so the oracle needs no decode and no IDCT). Rebuilt files whose every
  checked video track is 100% intact at dump offset 0 get
  `confidence: high`; nothing surviving gets `low`; otherwise `medium`.
  Audio tracks are not checked (no oracle) and the notes say so. Evidence
  gains `nal_oracle`; the entropy-coded video bytes are never used as a
  signal (video looks random either way).
- **Edit-list cut alongside the full rebuild (ROADMAP 8.11.5, P2)**.
  When the NAL oracle finds at least one surviving sync sample in a video
  track, a sibling cut file is written next to the rebuilt one, named
  `.mp4.cut.carved`. Same payload and sample tables (nothing is
  re-laid-out, `stsz`/`stsc`/`stco`/`stts`/`stss` byte-identical, same
  trailer cut rule); every `trak` gains an `edts`→`elst` pair (v0, one
  entry: `segment_duration` `0xFFFFFFFF` = rest of the track,
  `media_time` in each track's `mdhd` timescale set to the first intact
  sync sample's time, rate 1.0). Playback starts where the video is
  intact instead of at the damaged head. New `CarveRole::Cut` (index
  `role: "cut"`), tier 2, confidence mirrors the rebuilt file (`high`
  only when every checked video track is intact and the head sits at
  dump offset 0), evidence gains `elst_cut`. Written automatically — no
  new flag — and always paired with the full rebuilt file; skipped when
  the oracle found nothing intact, when `t = 0` (nothing to skip), when
  no `trak` has a usable `mdhd`, when the cut would exceed
  `--carve-max-size`, or when the cut fails its own post-check (parse of
  the new `moov` + own MP4 validator; then only the full rebuild ships).
  Both files are hashed in a single pass; `tracks_intact`, trailer
  fields and dedupe semantics match the rebuilt record.

### Fixed
- **Intact MP4/MOV files are carved as themselves, not rebuilt.** The `ftyp`
  header needle only matched the 32-byte box, so the far more common 24-byte
  form (phones, ffmpeg) never matched and every intact file was reached only
  through its `moov`, i.e. always taken down the rebuild path and written as a
  `rebuilt` sibling. `ftyp` boxes of 0x14, 0x18, 0x1c, 0x20, 0x24 and 0x28
  bytes now match. The box walk also continues past `mdat` to the trailing
  `moov` (and through fragmented `moof` runs), so a normal non-fast-start file
  is one `whole`/`complete`/`high` carve, and the rebuild only runs when the
  head is actually gone. A box with a 64-bit size (`size == 1`) read the 8
  header bytes again instead of the 8 after the type and was mis-parsed; it
  now reads the extended size correctly.
- **PE and ELF carves are sized and labelled from their headers.** The PE validator
  used to check `MZ` + `PE\0\0`, skip a fixed 4 KiB and report the file as
  complete (tier 1, `high`, `terminator_ok`), so real 40-360 KB executables
  were cut to the header yet claimed as intact. It now reads the COFF /
  optional header and section table (PE32 and PE32+), ends the file at the
  furthest `PointerToRawData + SizeOfRawData` or certificate table, and only
  then reports `complete`. A cut PE, or one whose headers cannot be
  validated, is carved as before (never the whole window) but reported as
  incomplete (`medium`, `PE header only` / `PE section data runs past the end
  of the carve window`). An overlay appended after the last section is not
  declared by the headers and is not counted. ELF got the same treatment: it
  used to skip a fixed 4 KiB and report `complete`; it now ends at the furthest
  of the section header table and every program header's file image
  (ELF32/ELF64, either byte order), and falls back to `medium` /
  `ELF header only` when the headers do not hold together.
- **XZ and BZIP2 carves no longer swallow the dump up to the candidate
  window.** Both used to validate only the header and run to the end of the
  window (64 MB), so an 18 KB `readme.md.xz` produced a pseudo-file that
  absorbed 12 real files behind it (both MP4s, `loot.sqlite`, `capture.pcap`).
  XZ now ends at the first footer that checks out (footer CRC-32, stream
  size a multiple of 4, index indicator byte `0x00` at the position the
  backward size points to); BZIP2 ends at its 48-bit end-of-stream marker
  found at any bit alignment, plus the 32-bit CRC. Without a terminator the
  carve is still `Truncated` to the window, as before. Tests: footer/marker
  at an unaligned bit offset with trailing junk, and a corrupt XZ footer.
- **`carve_mp4` walked boxes 8 bytes short** (`skip(size - 8)` although
  `peek_array` does not consume): almost every structurally valid MP4
  was carved as `Truncated` and landed in `partial/` instead of being
  validated. `carves_mp4_file` only passed by accident of the
  `size == 0` branch. MP4 files now validate at the correct box
  boundaries.
- **`carve_pdf` and `salvage_pdf_tail` now refuse a planted
  `startxref`/`%%EOF` with no PDF structure (fake footer, ROADMAP
  8.13.4)**: two fake-footer shapes slipped through. `%PDF-` + random +
  `%%EOF` was declared `Valid` (tier 1, complete) because the validator
  never looked at the body; a `startxref 123456 %%EOF` planted alone in
  random data produced a salvaged "tail" file. The validator now parses
  the body for at least one object header (`N M obj`) or a `trailer`
  before calling a PDF complete (Random = reject) or accepting a salvaged
  tail (must carry structure in its last 4 KiB). Bench-synthetic
  fixtures: `fake-pdf-eof.bin` (footer alone) and `pdf-magic-decoy.bin`
  (magic + planted EOF in noise) now produce **zero** files; the intact
  bench PDF still carves EXACT, and the unit trailer fixture still
  salvages.
- **`carve_pdf` no longer writes megabytes of "partial" PDFs from random
  garbage (found by the real-file bench decoy)**: the bench plants a
  `%PDF-1.4\n` decoy followed by 8 KB of random bytes and expects every
  carver to reject it. `carve_pdf` accepted any `%PDF-` body whose
  `%%EOF` was missing as a `Truncated` (tier-2 `structure_partial`)
  record, so the decoy was written as a **7,986,146-byte
  `.pdf.carved`** from pure noise — the whole remaining dump run. The
  validator now rewinds and requires at least one PDF object header
  (`N M obj`) inside the scanned window before declaring a
  `Truncated`; without one it returns
  `Invalid("PDF magic, but no %%EOF and no objects: not a PDF")`.
  A body with an object (e.g. a partly-encrypted or truncated PDF)
  keeps the exact previous behavior, cut at the end of the scanned
  window. Also pinned down and fixed the decoy offset drift in
  `.scratch-enc/bench/build_image.py` (`offset += 8 + 8192` assumed
  every magic is 8 bytes; the recorded decoy offsets were cumulative
  nibbles off the real positions).
- **Fuzz coverage for the footer-first anchors (ROADMAP 8.13.4)**:
  synthetic fake-footer dumps (fake EOCD, empty-claim EOCD, bare IEND,
  lone `startxref`/`%%EOF`, head-4 KiB-overwritten valid ZIP/PNG) are
  added to `fuzz/corpus/carve_scan/` so CI's fuzz smoke covers the
  tail-anchored paths. Local `cargo fuzz` needs clang and this machine
  has none; instead a seeded deterministic property test
  (`carve_scan_survives_seeded_junk_and_mutated_fixtures`, 2400 cases:
  pure junk, junk with sprinkled `PK\x05\x06`/`PK\x01\x02`/`PK\x03\x04`/
  `%%EOF` needles, byte-flipped multi-member ZIP and PDF fixtures)
  asserts `carve_scan` never panics, with and without salvage.
- **`carve_zip` accepted un-openable archives as `complete`** (found by the
  Lab 6 forensic dump and the real-file bench): the validator walked local
  headers and required a `PK\x05\x06` to exist, but never checked the
  central directory's member offsets against them. Measured: all eight
  `complete` ZIPs bxmap previously carved from the Lab 6 dump cannot be
  opened by Python `zipfile` (`Bad magic number for central directory`; one
  of them structurally opens with a corrupt `background.js` member), so
  every Lab 6 "complete ZIP" it ever reported was a false positive. The
  validator now strictly verifies the CD chain (EOCD count matches CD
  records, records bounded and in order, each member's local header exists,
  and local and CD names agree byte for byte). Archives that pass stay
  `complete`; everything else is rejected or fixed by the rebuild below.
  ZIP64 sentinels and absurdly large directories are given the benefit of
  the doubt (kept `complete`).
- **XZ validator rejected every real-world XZ file** (found by the real-file
  carve bench): the stream-header CRC-32 was computed over `magic + flags`
  instead of the two stream-flag bytes only, and with the wrong (unconditioned)
  CRC32. Every `.xz` produced by `lzma.compress` failed the header check.
  The CRC now covers `header[6..8]` with the standard zlib conditioning.
- **GIF validator desynced inside any GIF with a color table** (found by the
  same bench): the global/local color table was skipped with `3 << bits`
  instead of `3 * 2^(bits+1)` (6 << bits), so every GIF with a GCT/LCT was
  rejected (or silently misparsed). The walker now skips the correct table
  size for both tables.
- **MP3 validator accepted a single noise-matching frame as a complete T1
  MP3** (found by the same bench, 992–3127 false positives per image,
  starving `--carve-max-files`): a file is now complete only when the stream
  resyncs at least once more, i.e. at least two consecutive frames. This
  eliminates the random-data MP3 false positives seen on the bench image
  (spurious carves dropped from 2458 to 5).

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
