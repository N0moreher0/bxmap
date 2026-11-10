# ROADMAP — bxmap

Mục tiêu: biến bxmap thành công cụ trích xuất chuỗi / triage cho memory dump **nhanh, đáng tin cậy và dễ nhúng**, ưu tiên độ an toàn khi xử lý input không tin cậy.

Ký hiệu: `[ ]` chưa làm · `[~]` đang làm · `[x]` xong. Độ ưu tiên: **P0** làm trước · **P1** quan trọng · **P2** nên có.

Phiên bản hiện tại: `bxmap` **1.0.7**, `bxmap-cli` **1.0.18** (Phase 4.1 noise filter + ACPI filtering shipped). Các mốc ở cuối tài liệu tính từ bản kế tiếp.

---

## Phase 1 — Dọn nền (tài liệu, giấy phép, release) · P0

Chi phí thấp, hiệu quả cao nhất. Làm trước khi thêm tính năng.

### 1.1 README và tài liệu
- [x] Sửa các chỗ mâu thuẫn: "ASCII/UTF-16LE" vs UTF-16BE/UTF-32; "No MDMP parsing" vs module `Minidump`; "Rust API only" vs `minidump`.
- [x] Xóa mục bị lặp (`--encoding`, `--magic-bytes`, IOC triage).
- [x] Tách `cli/README.md` (cách dùng CLI); README gốc chỉ giữ phần library + link sang CLI.
- [x] Thêm `CHANGELOG.md`, `SECURITY.md` (cách báo lỗi), `CONTRIBUTING.md`.
- [x] **Thêm 4 encoding mới: Latin1 (ISO-8859-1), CP1252 (Windows-1252), UTF-8, Shift-JIS** — cập nhật README (benchmark, tips chọn encoding, CLI `--encoding all|ascii|utf16|utf32|latin1|cp1252|utf8|shift_jis`).
- [ ] Thêm badge: CI, MSRV, crates.io version, docs.rs.

**Xong khi:** đọc README từ đầu đến cuối không còn câu nào trái với code hiện tại.

### 1.2 Giấy phép
- [x] Quyết định giấy phép cho **library** (`bxmap`): **MIT OR Apache-2.0** (chuẩn Rust crate); giữ **AGPL-3.0** cho `bxmap-cli`.
- [x] Cập nhật `Cargo.toml`, `LICENSE-MIT` + `LICENSE-APACHE` (library), `cli/LICENSE-AGPL` (CLI), ghi rõ trong README.

### 1.3 Release và chuỗi cung ứng
- [x] Chuyển từ "mỗi push `main` ra release" sang **release theo tag semver**; push `main` chỉ build artifact CI (nightly).
- [x] Sinh `SHA256SUMS` cho mọi binary; ký bằng cosign/minisign còn làm thêm.
- [x] Xuất SBOM (`cargo-cyclonedx`) kèm release (workflow `release.yml`).
- [ ] Chuyển `sample_demo.dmp` ra khỏi git history sang release asset hoặc Git LFS.
- [x] Job CI kiểm tra **MSRV**: `msrv` (1.70 lite) và `msrv-full` (1.80 default).

---

## Phase 2 — Độ an toàn và độ đúng · P0

Dump đến từ máy nhiễm mã độc, parser phải chịu được input thù địch.

### 2.1 Fuzzing và hardening
- [x] `cargo-fuzz` cho: parser minidump, parser `.vmss` (VmwareState), reader chunk/overlap, magic-byte scanner, entropy scanner, artifact collector, **validator carve** (tất cả 10 validators). **Đã có 7 target** trong `fuzz/fuzz_targets/`: `minidump_parse`, `vmware_parse`, `string_scanner` (chunk/overlap + mọi encoding), `magic_scan`, `entropy_scan`, `classifier_detect` (detector + vỏ mã hoá), `carve_scan` (mọi validator qua `scan_from_reader`; fix `9d6fd53`). **CI job `fuzz` (2026-11-10)** chạy mỗi target 30 s trên push/PR — smoke gate cho panic/OOM, không phải campaign coverage (chạy dài vẫn ở local).
- [x] **Giới hạn cấp phát (anti-OOM)**: mọi validator carve giờ kiểm tra header-declared size chống đỡ OOM (JPEG segment, PNG chunk, ZIP packed, RAR4/5 data, GZIP extra/name/comment, PDF search window). Header khai báo size quá lớn → reject sớm thay vì skip/alloc.
- [x] Chạy `clippy -D warnings`, `cargo audit`, `cargo deny` trong CI.

### 2.2 Bộ test
- [x] Unit test cho từng encoding (ASCII, **Latin1, CP1252, UTF-8, Shift-JIS**, UTF-16LE/BE, UTF-32LE/BE), gồm chuỗi nằm **vắt ngang ranh giới chunk** và ngang ranh giới region song song.
- [x] Test đảm bảo kết quả song song == kết quả tuần tự (cùng tập, cùng thứ tự theo offset). `parallel_matches_sequential_on_multi_region_data` (2026-11-10): dump 8 region (~32 KiB, region 4 KiB trong `cfg(test)`) có nhiễu nhị phân + chuỗi ascii/UTF-16LE/UTF-16BE vắt qua, kết thúc đúng và bắt đầu đúng tại ranh giới region; so khớp in-memory vs buffered parallel vs streaming parallel (`threads` 1/2/4), lọc `EncodingFilter::utf16()` và cắt `max_strings` — tất cả trùng tập + trùng thứ tự offset.
- [~] Golden test cho output `text`, `json`, `json-tree` (integration smoke tests).
- [ ] Bộ dump mẫu nhỏ, tổng hợp (không chứa dữ liệu thật) cho test hồi quy.

**Xong khi:** CI chạy fuzz smoke test mỗi PR và không còn panic đã biết.

---

## Phase 2.5 — Bug đã xác nhận từ test thực tế (MemLabs Lab 4 & 6) · P0

Phát hiện khi chạy bxmap trên `MemoryDump_Lab6.raw` (~1.6 GB). Đã đối chiếu byte thật trong dump.

- [x] **Trùng UTF-16LE/BE.** Đã suppress bản BE mirror khi cùng nội dung và offset lệch 1 byte.
- [x] **Chuỗi chứa xuống dòng bị in nguyên**: output text escape control chars (\n, \r, \t, ...) thành một dòng.
- [x] **Chuỗi quá dài**: thêm `--max-str-len` để cắt output.
- [ ] Số liệu xác nhận thêm trên Lab 4 (dump 1 GiB, `--min-len 8`): 305.742/544.317 (~56%) chuỗi UTF-16BE là bản trùng của LE.
- [x] **Thứ tự output:** README ghi "sorted by ascending offset" nhưng output thực tế không tăng dần chặt chẽ (BE offset `+1` đôi khi đứng trước LE). **Đã sửa**: scanner giờ buffer kết quả và emit theo thứ tự offset (`emit_pending`/`flush_pending` trong `StringRunScanner`); thêm test `streaming_results_are_sorted_by_offset`.
- [x] **Chạm `--max-strings` thì dừng im lặng** (Lab 4: đúng 200.000 bản ghi, mới quét ~52 MiB của 1 GiB). Phải in cảnh báo rõ ràng ("đã chạm giới hạn tại offset X / tổng Y, kết quả chưa đầy đủ") và trả exit code khác 0 (hoặc cờ `truncated: true` trong JSON). Đã in cảnh báo + exit code 3; `json-tree` có `metadata.truncated`.
- [x] Test hồi quy: dump mẫu có text ASCII-in-UTF-16 để chắc chắn bug LE/BE không quay lại.

**Xong khi:** quét lại Lab 6 không còn cặp LE/BE trùng và mỗi chuỗi tối đa một dòng output.

---

## Phase 2.6 — Lỗi tìm được qua review mã nguồn (2026-11-09) · P0

Nguồn: review toàn repo + `cargo test --workspace --locked` (245 test pass), `clippy -D warnings`, đối chiếu CI GitHub (run #143–#147 đỏ). Các mục **đã tái hiện** ghi rõ; mục **nghi vấn** chưa đọc được log CI (thiếu `GITHUB_TOKEN`).

### 2.6.1 Đã xác nhận
- [x] **CI đỏ do clippy (`cli`)**: `cli/src/helpers.rs:540` — `clippy::question_mark` (khối `if let Err(e) = ... { return Err(e); }`). Sửa bằng toán tử `?`.
- [x] **`scan_yara_from_reader_streaming` báo trùng khi reader trả dữ liệu ngắn** (pipe/stdin/reader tuỳ biến): hàm gọi `read` một lần thay vì lặp đến khi đầy buffer, nên cửa sổ rất nhỏ + overlap 64 KiB quét lại gần hết dữ liệu. Tái hiện: cùng dữ liệu, reader đủ → 1 hit; reader 10 KB/lần → **7 hit trùng** cùng offset. CLI chỉ dùng bản `file_streaming` nên ít dính; thư viện thì dính.
- [x] **YARA streaming báo hit nằm trong vùng overlap 2 lần** (theo đọc code, kể cả file thường: hit trong 64 KiB cuối mỗi cửa sổ 32 MiB). Cần bỏ hit nằm trọn trong phần carry (cùng ý tưởng `Chunk::is_new` ở `chunk.rs`).

### 2.6.2 Lỗi nhỏ / độ bền
- [x] `minidump.rs`: `region_for_va` dùng `partition_point` nhưng `regions` chưa sắp xếp (`ranges` thì có) → dump không theo thứ tự sẽ tra sai. Sắp xếp theo `base` sau khi parse.
- [x] `minidump.rs`: `offset_to_va` cộng `start + delta` không kiểm tra tràn → panic ở bản debug với dump giả mạo. Dùng `checked_add`.
- [x] `.gitignore`: dòng `benches/` gây hiểu nhầm (`benches/extract.rs` đang được track, file mới trong thư mục sẽ bị bỏ qua). Bỏ dòng này.
- [x] `deny.toml`: còn khóa cũ `vulnerability`, `notice` (cargo-deny bản mới đã gỡ) — nghi là nguyên nhân job `cargo deny` đỏ. **Đã xác nhận:** bỏ 2 khóa đó, job `cargo deny` xanh trong CI #158.
- [x] `carve_7z` chỉ kiểm tra độ dài, **không kiểm tra CRC** `StartHeaderCRC` → có thể báo `Valid` cho dữ liệu rác có đúng magic. **Đã sửa (2026-11-10):** `carve_7z` tính `crc32` trên 20 byte `NextHeaderOffset|NextHeaderSize|NextHeaderCRC` và so với `StartHeaderCRC`; lệch → `Verdict::Invalid` (không carve). Thêm 2 test: 7z dựng tay có CRC đúng được carve `complete`, CRC sai bị `rejected`.

### 2.6.3 Nghi vấn — cần log CI để chốt
- [x] Job `msrv (lite)` (1.70) và `msrv (full)` (1.80) đều đỏ, fail sau ~15 giây. `Cargo.toml` khai `rust-version = "1.70"` nhưng comment trong file nói rayon 1.12 cần ≥ 1.80 và `Cargo.lock` đang ghim rayon 1.12.0 → khai báo MSRV có thể sai; bản full (yara-x 1.23) có thể cần Rust mới hơn 1.80. **Đã xử lý:** job `msrv` ghim 1.85 (Cargo đầu tiên đọc được manifest `edition2024` trong lock), `msrv-full` ghim 1.95 (yara-x 1.23); `rust-version` khai 1.80 (lib) / 1.85 (CLI) và README ghi rõ 3 mốc. CI run #158 xanh.
- [x] Job `cargo audit` đỏ (chưa rõ advisory nào) và `semver-checks` (optional) đỏ. **Đã xử lý:** `cargo audit` xanh trong CI #158; `semver-checks` để `continue-on-error` (rustdoc của yara-x 1.23 lỗi upstream), không chặn workflow.
- [x] Làm rõ giấy phép: thư mục gốc có `LICENSE` là AGPL-3.0 trong khi crate lõi khai `MIT OR Apache-2.0` (CLI mới là AGPL) — nên chuyển bản AGPL về `cli/` hoặc ghi chú rõ trong README. **Đã sửa (2026-11-10):** xóa `LICENSE` AGPL ở gốc (bản AGPL duy nhất còn ở `cli/LICENSE-AGPL`, nội dung tương đương); thêm [`LICENSING.md`](./LICENSING.md) tóm tắt license từng package; README link sang file đó.
- [x] Hai commit mới nhất trên local (`d0d6fe7`, `034a1b5`) chưa thấy run CI trên GitHub — kiểm tra đã push chưa. **Đã xử lý:** đã push, CI chạy đủ trên `main`.

### 2.6.4 Kết quả sửa (2026-11-09)
- `cli/src/helpers.rs`: thay khối `if let Err(e) ... return Err(e)` bằng `?` → `clippy -D warnings` sạch cả 2 crate.
- `src/lib.rs`: tách lõi `scan_yara_windowed(chunk_size, overlap_size)`; lặp `read` đến khi đầy buffer (xử lý cả `Interrupted`) và bỏ hit nằm trọn trong phần carry. Bản công khai vẫn dùng `CHUNK_SIZE` 32 MiB + overlap 64 KiB. Thêm 4 test `yara_window_tests` (đọc ngắn, đọc ngắn == đọc đủ, hit trong overlap, mọi needle đúng 1 lần qua nhiều cửa sổ).
- `src/minidump.rs`: sắp xếp `regions` theo `base`; `va_to_offset`/`offset_to_va` dùng `checked_add`. Thêm 2 test hồi quy (region ghi ngược thứ tự, range giả mạo gần `u64::MAX`).
- `.gitignore`: bỏ dòng `benches/`. `deny.toml`: bỏ khóa `vulnerability`, `notice` (`[~]` vì máy local không có `cargo-deny`, chờ CI xác nhận).
- Kiểm tra sau khi sửa: `cargo test --workspace --locked` **251 test pass** (lib 116, smoke 2, CLI unit 29, golden 103, doctest 1), `clippy -D warnings` sạch root + cli, `cargo fmt --check` sạch, `--no-default-features --lib` 110 test pass.
- **Còn mở (2026-11-09):** 2.6.2 `carve_7z` kiểm tra CRC (hoãn), toàn bộ 2.6.3 (MSRV, audit, semver, giấy phép, push commit) — cần log CI/`GITHUB_TOKEN` hoặc quyết định của chủ repo. Chưa push, nên CI GitHub chưa chạy lại trên bản sửa.

### 2.6.5 Đóng các mục còn mở (2026-11-10)
- `carve_7z`: xác thực `StartHeaderCRC` trên 20 byte start header + 2 test (đúng CRC → carve, sai CRC → reject).
- `LICENSE` gốc (AGPL) đã xóa; license từng package nằm ở `LICENSE-MIT` + `LICENSE-APACHE` (lib) và `cli/LICENSE-AGPL` (CLI), tóm tắt trong `LICENSING.md`.
- README: mục MSRV ghi đúng 3 mốc (1.80 khai báo / 1.85 build theo lock / 1.95 full) thay cho "Rust 1.70".
- `fuzz/`: thêm CI job `fuzz` (7 target × 30 s) và ignore `fuzz/corpus/`, `fuzz/target/`; cập nhật `fuzz/Cargo.lock` theo `bxmap` 1.0.7. Lần chạy đầu **bắt được một panic thật**: `src/vmware.rs` cộng `pos + 2` / `pos + 8` trên `tags_offset` do input khai (`u64::MAX`) → tràn số. Đã sửa bằng `checked_add` + 2 test hồi quy; job upload `fuzz/artifacts/` khi fail để tải được input gây lỗi.
- CI #158 (HEAD `82301ae`) xanh toàn bộ job, gồm `cargo audit`, `cargo deny` và cả hai job MSRV → các nghi vấn 2.6.3 đã chốt.

**Xong khi:** CI `main` xanh toàn bộ job bắt buộc, và có test hồi quy cho từng lỗi 2.6.1 / 2.6.2 (trừ mục đã hoãn).

---

## Phase 3 — Hiệu năng · P1

- [ ] Thêm benchmark `criterion` + script benchmark end-to-end (GB/s, RAM đỉnh) trên dump mẫu. `benches/extract.rs` (quét trong RAM, MiB/s) và `bench/bench.py` (wall time + peak RSS trên corpus 256 MiB, so sánh được với `strings`). (chưa commit: `bench/` và `benches/` đang gitignore)
- [~] So sánh công khai với `strings`, FLOSS, bstrings; đưa bảng số liệu vào README (kèm máy và dữ liệu đo). Đã có bảng bxmap vs `strings -a -el -n 4` (cùng corpus, best-of-3) trong README, kèm ghi chú trung thực về chênh lệch output; FLOSS/bstrings chưa cài trên máy đo nên chưa có số.
- [~] Tối ưu đường quét: `memchr`/SIMD cho ASCII, thử mmap cho file lớn, tránh cấp phát từng chuỗi nhỏ. Đã dùng `memchr` cho việc tách candidate `--brute-xor` (bỏ đọc từng byte), thêm prefilter byte cho `--extract all` (nhanh ~2,4x), giảm `PARALLEL_CHUNK_SIZE` 64→16 MiB (peak RSS 358→142 MB). Scanner ASCII đã có fast-skip 8 byte sẵn; mmap/SIMD thật vẫn chưa.
- [x] **`--brute-xor`:**
  - [x] Song song hóa bằng rayon — mỗi key là một task, gộp top-N theo thread, tái dùng buffer plaintext (không cấp phát mỗi key).
  - [x] Known-plaintext crib (`MZ`, `This program cannot be run`, `http`, `.dll`, `PK`, `<?xml`, `SELECT`) cộng điểm + prefilter 96 byte để loại key sớm.
  - [x] Phát hiện key 1 byte bằng phân bố tần suất thay vì thử toàn bộ. Key 1–2 byte vẫn duyệt đủ (256/65.536 key, rẻ); key ≥ 3 byte dùng tần suất: top-3 byte mỗi cột × 6 byte plaintext phổ biến → 5.832 key thay vì 16,7 triệu.
  - [x] Cảnh báo/ước lượng thời gian khi dùng key 3 byte — in số key sẽ thử; `--xor-exhaustive` in ước lượng byte-ops trước khi chạy hết không gian.
- [ ] `--auto-tune` mở rộng sang các stage khác (XOR, detector), không chỉ worker trích chuỗi. (XOR giờ tự chạy song song trên pool rayon hiện có, nên `--threads`/`--auto-tune` cũng ảnh hưởng, nhưng chưa có tuning riêng.)
- [x] **Không "đứng" khi `--max-strings` lớn**: thêm `extract_strings_from_file_parallel_streaming_with_encodings(_progress)` — quét song song theo cửa sổ `threads` region, phát kết quả tăng dần theo offset rồi bỏ, RAM không tăng theo số match. CLI dùng đường này cho mọi `--threads > 1` khi không cần `json-tree`/`--dedupe`.
- [x] `--max-strings 0` = không giới hạn (đi kèm stream), và `--max-memory` để đặt trần RAM. (`--max-strings 0` đã xong; **`--max-memory` xong (2026-11-10)**: cờ `--max-memory <bytes>`, 0 = không giới hạn. Thư viện expose `scan_working_set_bytes()` + `PARALLEL_REGION_SIZE`/`SEQUENTIAL_BUFFER_SIZE`; CLI giảm số worker khi trần không đủ chỗ và báo trên stderr, quá nhỏ thì báo lỗi rõ ràng. Trần tính cho buffer đọc, không tính kết quả (đã stream) và page cache.)
- [x] **Thanh tiến độ trên stderr:** offset hiện tại, % dump, tốc độ MB/s, số kết quả — để người dùng biết tool đang chạy hay treo (in terminal có ảnh nền/nhiều dòng rất chậm, dễ nhầm là treo). Đã có `--progress` / `--no-progress`; tự bật khi stderr là terminal và kết quả không in ra terminal. Cập nhật tối đa 5 lần/giây qua API `extract_strings_from_file_streaming_range_with_encodings_progress`.
- [x] `--start <offset>` / `--end <offset>` để quét một khoảng và chia việc cho nhiều tiến trình; tài liệu hóa cách chia khối có gối nhau (overlap) để không cắt đôi chuỗi. Đã có API `extract_strings_from_file_streaming_range_with_encodings` (đọc thêm `MAX_RUN_CHARS` mỗi phía, chỉ phát chuỗi bắt đầu trong `[start, end)`) và cờ CLI nhận số thập phân hoặc `0x` hex.
- [x] Cảnh báo/gợi ý khi stdout là terminal với lượng kết quả rất lớn ("hãy dùng `-o file`"): in gợi ý khi > 10.000 kết quả và không có `-o`.
- [x] Sửa số liệu sai: `throughput` trong `--report summary` giờ tính trên số byte thực sự đã quét (trước đây chia cả file size cho thời gian ngắn khi bị `--max-strings` cắt → báo 400 MiB/s sau khi quét 0,1%).

---

## Phase 4 — Chất lượng kết quả · P1

### 4.1 Lọc nhiễu
- [x] Noise filter: chu kỳ 1/2/3-8 + zero-page filter + ACPI field/table signature filter (Latin1/CP1252).
- [x] `--dedupe`: chuỗi duy nhất kèm số lần xuất hiện + offset đầu tiên. Áp dụng cho `text`/`json`/`json-tree`; với `--detect-format rich` thì gộp theo `(rule, value)`.
- [~] **Lọc rác nhị phân/bảng ACPI** (MemLabs Lab1): remove `FACP`/`DSDT`/`VBOX` và AML field names. Latin1/CP1252 strings giảm từ ~40k xuống ~26 trên cùng scan prefix. ASCII unaffected (18 MiB/s).
- [x] **Lọc ký tự lạ sau giải mã (utf8 / shift_jis)** (2026-11-09): `decoded_text_noise` bỏ chuỗi có nhiều U+FFFD, ký tự điều khiển C0/C1, Private Use/noncharacter, hoặc tỷ lệ ký tự đọc được thấp (< 60%). Trước đây utf8 và shift_jis chỉ có lọc lặp. Tắt cùng `--noise-threshold 0` (`NoiseConfig::disabled`); chuỗi ngắn (< 8 ký tự) chỉ bị loại khi chứa ký tự "xấu", không dùng tỷ lệ, để không mất bằng chứng ngắn. latin1/cp1252 đã có lọc riêng (ACPI + entropy) nên giữ nguyên. Còn lại: shift_jis giải ra kanji ngẫu nhiên "hợp lệ" vẫn lọt (chưa có heuristic riêng).
- [~] **Output gọn:** JSON pretty-print của 1,9 triệu bản ghi nặng 160 MB. Đã có `--format ndjson` (một record/dòng, có `type` + dòng `metadata`), `--compact` (json/json-tree một dòng) và nén gzip tự động khi `-o` kết thúc bằng `.gz`. Còn lại: `.zst`, và tùy chọn bỏ trường không cần.
- [ ] Giữ mặc định bảo thủ (không làm mất bằng chứng ngắn như `0000`); mọi bộ lọc mới đều opt-in hoặc có cờ tắt.

### 4.2 Entropy
- [x] Kích thước cửa sổ và ngưỡng cấu hình được (`--entropy-window`, `--entropy-threshold`).
- [x] Gộp các vùng entropy cao liền kề thành một record (`--entropy-merge`; entropy của vùng gộp tính chính xác từ histogram).
- [x] `--entropy-no-data` / giới hạn kích thước `data_hex` để output không phình (`--entropy-no-data`, `--entropy-max-data`, mặc định 4096 byte kèm `data_truncated`).

### 4.3 IOC / secret
- [x] Validate để giảm false positive: checksum Base58Check/Bech32 (ví crypto), Luhn, cấu trúc JWT (decode header/payload), độ dài và prefix theo từng nhà cung cấp. **Đã có (2026-11-10):** `validate_base58check` (BTC), `validate_bech32` (segwit), `validate_luhn`, `validate_credit_card` (mới: 13-19 số + prefix issuer + Luhn), `validate_jwt` (bắt buộc `alg`, `typ` tuỳ chọn, signature phải base64url, kiểm tra `exp`), và prefix+độ dài cho AWS/GitHub/Slack/Azure. `classify()` giờ **bỏ nhãn** khi checksum sai (rule có kiểm tra cấu trúc như JWT/SAS chỉ hạ `confidence` trong `--detect`, không xoá bằng chứng). Thêm rule `CREDIT_CARD` (nhóm `FINANCE`) và `BTC_SEGWIT` + 8 test hồi quy.
- [x] Output detector giữ cả `text` gốc, `match` và vài byte ngữ cảnh (không chỉ thay bằng token).
- [x] Dùng `RegexSet` / aho-corasick làm prefilter để 30+ pattern không làm chậm quét. **Đã có (2026-11-10):** bộ `SECRET_PATTERNS` đã có prefilter aho-corasick từ trước; nay bộ rule thứ hai (`RULES`, dùng cho `classify()`) cũng có: `RULE_ANCHORS` (mỗi rule phải chứa ít nhất một literal) + `RULE_MIN_LEN` (độ dài tối thiểu) → một lần quét aho-corasick loại được phần lớn rule, chuỗi ngắn không chạy regex nào. Test `rule_prefilter_is_equivalent_to_running_every_regex` chứng minh kết quả không đổi so với chạy hết rule.
- [ ] Cho phép chọn nhiều loại: `--detect ip,url,secret`.
- [ ] Nạp pattern tùy chỉnh từ file (`--detect-rules`).
- [~] **Giảm false positive của generic secret** (thấy rõ trên Lab 6): `Token: GetTokenInformation`, `Token: Malloc`, `Token:DigiCert`, `Password: false,`, `ApiKey=function(a){...}`. Yêu cầu giá trị trông giống secret (entropy, độ dài, không phải identifier/từ tiếng Anh/`true`/`false`/mã JS). Đã lọc identifier/từ khóa/mã JS và publicKeyToken; còn cần wordlist/entropy rộng hơn.
- [x] Loại hoặc hạ điểm các mẫu biết trước là không phải secret: `publicKeyToken="..."` trong manifest assembly (`6595b64144ccf1df`, `31bf3856ad364e35`, `1122334455667788`).
- [ ] **Phân loại key công khai phía client**: `AIza...` trong request trình duyệt (vd. tới `*.clients6.google.com`) gắn nhãn `public-client-key`, confidence thấp; khác với secret phía server/người dùng.
- [x] **Output có cấu trúc cho mọi finding:** thêm `rule` (vd. `google_api_key`, `generic_password`), `confidence`/`severity`, và `context` (vài chục byte quanh match). Hiện `--detect secret` chỉ có `offset`, `encoding`, `text`.
- [~] **Nhận diện khối biến môi trường** (`NAME=value\0NAME=value\0` trong UTF-16): `password=`/`key=` trong env block xếp ưu tiên cao (case thật: `RAR password=easypeasyvirus` trong dump Lab 6). Đã có `--extract env` (gắn `sensitive=true`) nhưng chưa đẩy các env nhạy cảm lên nhóm priority findings.
- [~] `--dedupe` mặc định cho detector: cùng một key lặp nhiều lần chỉ hiện một dòng kèm `count` và danh sách offset. (`--dedupe` đã gộp theo `(rule, value)` kèm `count`; còn thiếu danh sách offset và việc bật mặc định.)

### 4.4 Trích xuất artifact có cấu trúc (tiếp tục)
- [x] Ghi kết quả benchmark real-world (Lab 1, 1 GB) vào README: bxmap so với `strings`+`grep` (thời gian, encoding, dedupe, IOC, RAM).
Mục tiêu: từ biển chuỗi, trả ngay "bức tranh" của máy thay vì bắt analyst tự lọc (case Lab 4).
- [x] `--extract paths`: gom đường dẫn file/thư mục (Windows và Unix, cả dạng 8.3 `GALF~1.JPE`, `\\Device\\HarddiskVolume2\\...`), chuẩn hóa chữ hoa/thường, dedupe, đếm tần suất, sắp theo độ hiếm. (Module `bxmap::artifacts`, cờ CLI `--extract paths`.)
- [x] Gom theo **hồ sơ người dùng** (`C:\Users\<name>\...`): mỗi path có `detail` dạng `user=<name>;category=<desktop|documents|downloads|appdata|temp|other>` để lọc nhanh file người dùng. Lab 4: user `eminem`, `secrets.txt`, `galf.jpeg`, `FLAG NOT HERE.BMP`, `Screenshot1.png`, `DumpIt.zip`.
- [x] Danh sách user tổng hợp (một dòng/user kèm số file) và lọc hẳn nhiễu thư mục hệ thống/`AppData` khỏi kết quả — hiện mới gắn nhãn `category=appdata`. Cờ mới: `--report user|all`, `--min-files-in-user <N>`, `--filter-appdata`. `build_user_stats` / `print_user_report` in `cli/src/main.rs`.
- [x] Nhận diện **công cụ tạo dump** (DumpIt, WinPmem, FTK Imager, `.raw`/`.mem` tên mặc định) và dấu vết khởi chạy. (Cờ `--extract tools`; artifact `tool` với `detail=evidence=...;category=capture|analysis|image;trace=path|command|prefetch|filename|string`, gộp mọi trace của cùng một tool.)
- [x] `--extract env`: tách khối biến môi trường `NAME=value\0` (case Lab 6: `RAR password=...`); tên nhạy cảm (`password`, `token`, `secret`, ...) được đánh dấu `sensitive=true`.
- [x] `--extract urls|emails|registry` với dedupe và đếm.
- [x] Báo cáo tóm tắt (`--report summary`) in đầu/cuối: số chuỗi theo encoding, phần dump đã quét, giới hạn đã chạm, top artifact.

---

## Phase 5 — API và CLI · P1

### 5.1 Library
- [ ] Đổi `encoding: &'static str` thành enum `Encoding` (`#[non_exhaustive]`), kèm `Display`.
- [ ] API hỗ trợ đủ UTF-16BE/UTF-32 ở mức library, không chỉ CLI.
- [ ] Iterator/callback streaming (không bắt buộc gom `Vec`), hỗ trợ hủy (cancellation) và báo tiến độ.
- [ ] Ổn định API trước `1.0`: tài liệu hóa quy ước semver, đánh dấu phần chưa ổn định bằng feature flag. (Thực tế đã ở 1.0.x — cần chốt semver cho các API mới như `artifacts`/`carve`.)

### 5.2 CLI
- [x] Output `ndjson` và `csv` (ndjson kèm `type` + dòng `metadata`; csv có header cố định, hỗ trợ string/finding, không đi cùng stage phụ).
- [x] Thanh tiến độ trên stderr (tắt được khi pipe) — xem Phase 3.
- [~] Shell completions (bash/zsh/fish/pwsh), `--version` chi tiết (commit, feature build: full/lite, target triple). Man page chưa có. (đã commit `feat(cli): add completions subcommand and richer --version output`; `bxmap completions <shell>` hoạt động)
- [~] Exit code rõ ràng (0 sạch, 1 lỗi, 2 có phát hiện nghiêm trọng nếu bật cờ). Đã dùng và ghi trong `cli/README.md`: 0, 1, 3 (kết quả bị cắt/truncated); còn thiếu code 2 cho "có phát hiện nghiêm trọng".
- [ ] File cấu hình (`bxmap.toml`) cho các tùy chọn lặp lại.

**Refactor CLI (Phase 4-core, hoàn thành trong lượt này):** `cli/src/main.rs` đã giảm từ ~5.000 dòng xuống ~360 dòng; logic được tách ra `args.rs`, `detect.rs`, `xor.rs`, `report.rs`, `carve.rs`, `output.rs`, `entropy.rs`, `yara.rs`, `scan.rs`; ma trận cờ xung đột tập trung ở `args.rs::validate()` và có golden test (vd. `golden_csv_rejects_magic_bytes`). Golden test 68 cũ giữ nguyên, thêm 15 test cho các cờ chưa覆盖; toàn bộ 83 test pass byte-for-byte.

---

## Phase 6 — Mở rộng định dạng và tính năng · P2

- [ ] Windows **full crash dump** (không chỉ minidump).
- [ ] ELF core dump, LiME, `hiberfil.sys`.
- [ ] Mở rộng `.vmss`/`.vmem`: ánh xạ địa chỉ vật lý, thêm các định dạng VM snapshot khác.
- [ ] Ánh xạ VA → module/section/export cho thêm kiến trúc; hiển thị cây tiến trình đầy đủ hơn.
- [ ] **`--magic-bytes` mở rộng:** RAR4/RAR5 (`Rar!\x1a\x07\x00` / `...\x01\x00`), 7z, GZIP, JPEG, SQLite, ngoài PE/ELF/ZIP/PDF/PNG hiện có.
- [ ] **Carving file theo chữ ký** → xem **Phase 8 — Module `--carve`**.
- [ ] Xuất báo cáo HTML/Markdown tự đóng gói cho case management.
- [ ] Binding Python (PyO3) để dùng trong notebook và pipeline.

---

## Phase 7 — Chứng minh giá trị (demo & benchmark) · P1

Mục tiêu: có vài case thật cho thấy bxmap tìm ra thứ có ý nghĩa nhanh hơn `strings | grep`.

- [x] Bộ demo MemLabs (Lab 1, 2, 6): mỗi lab một mục "đáp án nói cần tìm X → `strings` ra N dòng → bxmap ra X trong M dòng", kèm thời gian và RAM.
- [x] Case Lab 6: bxmap `--extract env` bắt `RAR password=...` trong env block (UTF-16) → dẫn tới file RAR; ghi rõ bước còn lại (carve RAR, mở bằng mật khẩu).
- [x] Trình bày trung thực: so sánh công bằng với `strings -el | grep`, nêu rõ điểm thắng là một lần quét đủ encoding + phân loại + tốc độ, không phải "chỉ bxmap tìm được".
- [x] Một bài viết ngắn kể case + GIF/asciinema ở đầu README; đăng r/computerforensics, r/netsec, Show HN, This Week in Rust.
- [x] Case Lab 4: quét 1 GiB, lọc ra user `eminem`, công cụ DumpIt và các file đáng ngờ trên Desktop bằng một lệnh; ghi rõ giới hạn (chỉ tên file/metadata, chưa lấy nội dung — cần `--carve`).
- [x] Ghi lại thời gian, RAM đỉnh và kích thước output cho cả Lab 4 (1 GiB) và Lab 6 (1,6 GB) làm số liệu benchmark thật.
- [x] Thêm một dump `.DMP` tự tạo trong VM để demo `--map-va`, `--rwx-only`, `--heap-only` (MemLabs là `.raw`, không dùng được các cờ này).
- [x] Redact mọi credential thật trước khi đăng ảnh/bài.

---

## Phase 8 — Module `--carve` (phục hồi file từ dump) · P1

Mục tiêu: từ dump thô, cắt ra các file có cấu trúc (JPEG, PNG, ZIP, RAR...) và **khoanh vùng** dữ liệu mã hoá, để analyst lấy được nội dung thay vì chỉ thấy tên file (case Lab 4: `galf.jpeg`, `FLAG NOT HERE.BMP`, `DumpIt.zip`; case Lab 6: 6 chữ ký RAR).

Nguyên tắc phạm vi:
- Carve theo chữ ký + xác thực cấu trúc; **không giải mã, không crack mật khẩu**.
- File trong RAM thường phân mảnh theo trang 4 KB: bản đầu chỉ carve phần liền kề và đánh dấu `complete`.
- Mọi parser header là input không tin cậy → bắt buộc có giới hạn và fuzz (Phase 2).

Thiết kế module (giữ đồng bộ với `bxmap::artifacts`):
- `bxmap::carve`: `CarveOptions` (types, min/max size, trần tổng), `Carver` (nạp dữ liệu theo chunk, gọi validator), `CarvedFile { offset, kind, size, sha256, entropy, complete, notes, path }`.
- Chữ ký dùng chung với `--magic-bytes` (một bảng `Signature` duy nhất) để không có hai nguồn sự thật.
- Đọc file qua `bxmap::chunk` (thêm ở 8.0) thay vì viết reader riêng; overlap nhỏ vì header ngắn.

### 8.0 Chuẩn bị (dọn đường trước khi viết carver)
- [x] Tách bảng chữ ký khỏi `cli/src/main.rs` thành `bxmap::magic::{Signature, SIGNATURES, MagicMatch, scan_file}` dùng aho-corasick; `--magic-bytes` giờ chỉ là wrapper mỏng và `--carve` sẽ gọi cùng hàm.
- [x] Chuẩn hóa reader chunk: thêm `bxmap::chunk::{Chunk, for_each_chunk}` (cửa sổ có overlap, offset tuyệt đối, `spans_new_bytes` để không báo trùng). Carver dùng lại với overlap ≈ header dài nhất (≤ 64 byte); ba reader cũ (`MAX_RUN_CHARS`, magic 16 byte, `YARA_OVERLAP_SIZE`) chưa gộp vì đã ổn định, sẽ gộp khi có nhu cầu.
- [x] Chốt quy ước exit code: dùng chung code `3` cho mọi trường hợp "kết quả không đầy đủ" (`--max-strings`, sau này là `--carve-max-total`); cảnh báo trên stderr phải nêu rõ nguồn gây cắt. Đã ghi trong `cli/README.md`.

### 8.1 Lõi carver
- [x] Cờ CLI: `--carve <types>` (vd. `jpeg,png,zip,rar`), `--carve-out <dir>`, `--carve-index <file>`, `--carve-min-size`, `--carve-max-size`, `--carve-max-total`.
- [x] Quét streaming tái dùng reader chunk có gối (overlap ≥ độ dài header dài nhất); hỗ trợ `--start/--end` (Phase 3); chạy song song, kết quả ổn định theo offset.
- [x] Tìm chữ ký nhanh bằng `memchr`/aho-corasick (dùng lại prefilter đã có ở classifier); không đọc lại toàn dump cho từng loại.
- [x] Trần an toàn: dừng khi chạm `--carve-max-total`, in cảnh báo rõ (không im lặng như `--max-strings`), exit code riêng.

### 8.2 Bộ validator theo định dạng
- [x] **JPEG:** `FF D8 FF` … `FF D9`, đi theo marker (SOI/APPn/DQT/SOF/DHT/SOS), loại false positive; xử lý thumbnail nhúng (EXIF) để không tạo bản trùng lồng nhau.
- [x] **PNG:** đi theo chunk, kiểm CRC, kết thúc ở `IEND`.
- [x] **ZIP:** `PK\x03\x04` … end-of-central-directory; nhận biết ZIP mã hoá (cờ bit 0) và OOXML/JAR (docx, xlsx, apk...).
- [x] **RAR4/RAR5, 7z:** theo chiều dài header; nhận biết archive mã hoá header.
- [x] **PDF, GZIP:** theo footer/độ dài; BMP và SQLite ở bước sau (BMP: `BM` + kích thước header; SQLite: page size × số trang).
- [x] Luôn chặn kích thước khai trong header bằng `--carve-max-size` và kích thước dump còn lại; không tin header.
- [x] Mỗi validator trả về `complete: true|false`, `truncated`, `reason` (vì sao dừng).

### 8.3 Đầu ra và an toàn
- [x] Index JSON/NDJSON: `offset`, `type`, `size`, `sha256`, `entropy`, `complete`, `notes`, đường dẫn file đã ghi.
- [x] Dedupe theo SHA256; gom các bản trùng thành một dòng kèm danh sách offset.
- [x] File ghi ra có đuôi trung tính (`.carved`), tên theo `offset-type-hash`; không mở, không chạy, không giải nén.
- [x] Cảnh báo trong README: file carve có thể là mã độc, chỉ xem trong môi trường cô lập.
- [x] `--carve-out` là **bắt buộc**: không có thư mục đích thì dừng với lỗi rõ ràng thay vì ghi vào cwd.
- [x] Ghi đè an toàn: không ghi ra ngoài `--carve-out`, chống path traversal ở tên file, từ chối ghi đè file đã tồn tại.
- [x] Index là kênh riêng (`--carve-index`), không trộn vào `--format` chính; thêm dòng tóm tắt vào `--report summary` (số file, số `complete`, tổng byte).

### 8.4 Nhận diện vỏ mã hoá (chỉ khoanh vùng)
- [x] Chữ ký container: BitLocker (`-FVE-FS-`), LUKS, OpenSSL (`Salted__`), PGP, VeraCrypt/TrueCrypt (nếu nhận diện được), ZIP/7z/RAR có mã hoá.
- [~] Vùng entropy cao không có chữ ký: xuất làm ứng viên với nhãn `high-entropy` (không phân biệt chắc nén với mã hoá), kèm offset và độ dài. ( entropy scanner ở Phase 4.2 xong )
- [x] Tái dùng module entropy đã có ở Phase 4.2 (cửa sổ, ngưỡng, gộp vùng liền kề) thay vì viết lại. ( Phase 4.2 xong )

### 8.5 Mở rộng sau (P2)
- [x] **Quét khoá trong RAM** (`--find-keys`, module `bxmap::keys`): khoá RSA/PEM
  dạng nhị phân (vỏ PKCS#8 DER RSA/EC và blob OpenSSH) được quét streaming qua
  `bxmap::chunk`, mỗi hit báo `KEY` với offset, thuật toán, độ dài và vân tay
  SHA-1 (không giải mã, không xuất byte khoá thuần). AES key schedule (kiểu
  aeskeyfind) chưa làm, là follow-up sau.
- [ ] Ghép mảnh (reassembly) theo thứ tự trang khi có bảng trang (dump `.DMP`, VM snapshot).
- [x] Thêm định dạng: BMP, SQLite, OLE/Office cũ, MP4, executable (PE/ELF carve).

### 8.6 Test và đối chiếu
- [x] Dump tổng hợp đặt file ở offset biết trước: nằm trọn, vắt qua ranh giới chunk, bị cắt cụt, bị lồng nhau.
- [x] Golden test CLI trong `cli/tests/golden.rs` (cùng kiểu các phase trước): carve 1 JPEG + 1 PNG, kiểm index và `complete`.
- [x] Fuzz validator cho `Carver` qua `scan_from_reader` (mới: `fuzz/fuzz_targets/carve_scan.rs`, target `carve_scan`): header khai kích thước khổng lồ, marker lặp vô hạn, chunk PNG sai CRC — input không tin cậy đi qua mọi validator, carver không panic. (fix lõi: corrupt deflate candidate → `Invalid`, không fatal — commit `9d6fd53`)
- [ ] So sánh với foremost, PhotoRec, bulk_extractor trên cùng dump: số file, số false positive, thời gian, RAM.
- [x] Case thật: Lab 6 (6 chữ ký RAR → mở bằng mật khẩu tìm thấy), Lab 4 (JPEG/BMP/ZIP trên Desktop); ghi rõ file nào lấy lại được hoàn chỉnh, file nào không. Số liệu carve thật ghi trong README mục "Case study: real-dump carving" (Lab6: 102 candidates → 95 complete; Lab4: 534 → 534 complete; cả hai dừng ở cap `--max-strings` nên cần `--max-strings 0` để full).

**Xong khi:** carve được JPEG/PNG/ZIP/RAR hoàn chỉnh từ dump tổng hợp với 0 false negative trên bộ test; không panic và không vượt trần bộ nhớ trên input hỏng; so sánh công khai với foremost/PhotoRec có số liệu.

---

## Mốc phát hành đề xuất

| Mốc | Nội dung | Điều kiện |
|-----|----------|-----------|
| **1.1** | Phase 1 + 2 + 2.5 | README khớp code, CI có fuzz + MSRV, release theo tag có checksum |
| **1.2** | Phase 3 | Có benchmark công khai, XOR chạy song song, quét dump lớn không treo (stream + tiến độ + cảnh báo giới hạn) |
| **1.3** | Phase 4 (phần còn lại của 4.1/4.3) | Noise filter, validate secret, dedupe mặc định |
| **1.4** | Phase 5 | Completions, config, exit code có tài liệu |
| **1.5** | Phase 7 | Demo MemLabs + bài viết + số liệu benchmark thật |
| **1.6** | Phase 8 (8.1–8.4, 8.6) | `--carve` JPEG/PNG/ZIP/RAR có index + test + fuzz; nhận diện vỏ mã hoá |
| **2.0** | Chốt API | API library ổn định, tài liệu đầy đủ, fuzz sạch |
| **2.x** | Phase 6, 8.5 | Thêm định dạng, tìm khoá trong RAM, binding theo nhu cầu |

---

## Thứ tự làm gợi ý

1. Sửa README + quyết định giấy phép
2. Release theo tag + checksum
3. Sửa bug LE/BE trùng + chuỗi nhiều dòng, fuzz parser, test chunk boundary
4. Stream + tiến độ + cảnh báo chạm giới hạn, benchmark + tối ưu XOR
5. Giảm false positive secret + dedupe + trường `rule`/`confidence`/`context`
6. Enum encoding + NDJSON/CSV
7. Demo MemLabs + bài viết
8. `--carve` (Phase 8: 8.1 → 8.2 → 8.3, rồi 8.4, 8.6)
9. Định dạng mới, tìm khoá trong RAM (8.5), binding

## Ngoài phạm vi (cố ý không làm)

- Giải mã/giải nén dữ liệu entropy cao (bxmap chỉ báo hiệu, không decrypt). `--carve` chỉ cắt file có cấu trúc và khoanh vùng vỏ mã hoá.
- Crack/brute-force mật khẩu của archive hay container.
- Tự giải nén hoặc thực thi file đã carve.
- Phán quyết "độc hại / không độc hại": detector chỉ là gợi ý triage.
- Phân tích hành vi hoặc dựng lại đối tượng kernel như Volatility.

