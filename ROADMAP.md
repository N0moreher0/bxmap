# ROADMAP — bxmap

Mục tiêu: biến bxmap thành công cụ trích xuất chuỗi / triage cho memory dump **nhanh, đáng tin cậy và dễ nhúng**, ưu tiên độ an toàn khi xử lý input không tin cậy.

Ký hiệu: `[ ]` chưa làm · `[~]` đang làm · `[x]` xong. Độ ưu tiên: **P0** làm trước · **P1** quan trọng · **P2** nên có.

Phiên bản hiện tại: `bxmap` **1.0.4**, `bxmap-cli` **1.0.14** (Phase 4.4 gần xong). Các mốc ở cuối tài liệu tính từ bản kế tiếp.

---

## Phase 1 — Dọn nền (tài liệu, giấy phép, release) · P0

Chi phí thấp, hiệu quả cao nhất. Làm trước khi thêm tính năng.

### 1.1 README và tài liệu
- [x] Sửa các chỗ mâu thuẫn: "ASCII/UTF-16LE" vs UTF-16BE/UTF-32; "No MDMP parsing" vs module `Minidump`; "Rust API only" vs `minidump`.
- [x] Xóa mục bị lặp (`--encoding`, `--magic-bytes`, IOC triage).
- [x] Tách `cli/README.md` (cách dùng CLI); README gốc chỉ giữ phần library + link sang CLI.
- [x] Thêm `CHANGELOG.md`, `SECURITY.md` (cách báo lỗi), `CONTRIBUTING.md`.
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
- [x] Job CI kiểm tra **MSRV** cho bản `lite` (1.70); bản `full` dùng stable.

---

## Phase 2 — Độ an toàn và độ đúng · P0

Dump đến từ máy nhiễm mã độc, parser phải chịu được input thù địch.

### 2.1 Fuzzing và hardening
- [ ] `cargo-fuzz` cho: parser minidump, parser `.vmss`, reader chunk/overlap, các detector regex, **validator carve (Phase 8)**.
- [ ] Giới hạn cấp phát: header khai báo số stream/region/size quá lớn không được gây OOM.
- [~] Kiểm tra bounds, tránh `unwrap`/panic trên đường parse (minidump + VMware hardened + mini-fuzz no-panic); vẫn tiếp tục các parser khác.
- [ ] Chạy `clippy -D warnings`, `cargo audit`, `cargo deny` trong CI.

### 2.2 Bộ test
- [ ] Unit test cho từng encoding (ASCII, UTF-16LE/BE, UTF-32LE/BE), gồm chuỗi nằm **vắt ngang ranh giới chunk** và ngang ranh giới region song song.
- [ ] Test đảm bảo kết quả song song == kết quả tuần tự (cùng tập, cùng thứ tự theo offset).
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

## Phase 3 — Hiệu năng · P1

- [ ] Thêm benchmark `criterion` + script benchmark end-to-end (GB/s, RAM đỉnh) trên dump mẫu.
- [ ] So sánh công khai với `strings`, FLOSS, bstrings; đưa bảng số liệu vào README (kèm máy và dữ liệu đo).
- [ ] Tối ưu đường quét: `memchr`/SIMD cho ASCII, thử mmap cho file lớn, tránh cấp phát từng chuỗi nhỏ.
- [ ] **`--brute-xor`:**
  - [ ] Song song hóa bằng rayon (hiện chưa).
  - [ ] Known-plaintext crib (`MZ`, `This program cannot be run`, `http`, `.dll`) để loại key sớm, không chấm điểm đầy đủ.
  - [ ] Phát hiện key 1 byte bằng phân bố tần suất thay vì thử toàn bộ.
  - [ ] Cảnh báo/ước lượng thời gian khi dùng key 3 byte (16.777.216 key mỗi candidate).
- [ ] `--auto-tune` mở rộng sang các stage khác (XOR, detector), không chỉ worker trích chuỗi.
- [ ] **Không "đứng" khi `--max-strings` lớn** (user báo cáo): stream kết quả ra output ngay cả ở chế độ song song thay vì gom hết vào RAM rồi sắp xếp (kiểm chứng bằng đo RAM đỉnh).
- [~] `--max-strings 0` = không giới hạn (đi kèm stream), và `--max-memory` để đặt trần RAM. (`--max-strings 0` đã xong; `--max-memory` chưa.)
- [x] **Thanh tiến độ trên stderr:** offset hiện tại, % dump, tốc độ MB/s, số kết quả — để người dùng biết tool đang chạy hay treo (in terminal có ảnh nền/nhiều dòng rất chậm, dễ nhầm là treo). Đã có `--progress` / `--no-progress`; tự bật khi stderr là terminal và kết quả không in ra terminal. Cập nhật tối đa 5 lần/giây qua API `extract_strings_from_file_streaming_range_with_encodings_progress`.
- [x] `--start <offset>` / `--end <offset>` để quét một khoảng và chia việc cho nhiều tiến trình; tài liệu hóa cách chia khối có gối nhau (overlap) để không cắt đôi chuỗi. Đã có API `extract_strings_from_file_streaming_range_with_encodings` (đọc thêm `MAX_RUN_CHARS` mỗi phía, chỉ phát chuỗi bắt đầu trong `[start, end)`) và cờ CLI nhận số thập phân hoặc `0x` hex.
- [ ] Cảnh báo/gợi ý khi stdout là terminal với lượng kết quả rất lớn ("hãy dùng `-o file`").

---

## Phase 4 — Chất lượng kết quả · P1

### 4.1 Lọc nhiễu
- [ ] Mở rộng noise filter ngoài chu kỳ 1–2: chu kỳ N, độ đa dạng ký tự thấp, điểm n-gram để loại chuỗi rác/ngẫu nhiên.
- [x] `--dedupe`: chuỗi duy nhất kèm số lần xuất hiện + offset đầu tiên. Áp dụng cho `text`/`json`/`json-tree`; với `--detect-format rich` thì gộp theo `(rule, value)`.
- [ ] **Lọc rác nhị phân/bảng hệ thống** (Lab 4: 820 nghìn chuỗi ASCII, phần lớn là bảng ACPI `FACP`/`DSDT`/`VBOXBIOS` và dữ liệu nhị phân ở đầu dump): điểm "độ giống văn bản", loại chuỗi có tỉ lệ ký tự không in cao hoặc entropy ký tự lạ.
- [~] **Output gọn:** JSON pretty-print của 1,9 triệu bản ghi nặng 160 MB. Đã có `--format ndjson` (một record/dòng, có `type` + dòng `metadata`), `--compact` (json/json-tree một dòng) và nén gzip tự động khi `-o` kết thúc bằng `.gz`. Còn lại: `.zst`, và tùy chọn bỏ trường không cần.
- [ ] Giữ mặc định bảo thủ (không làm mất bằng chứng ngắn như `0000`); mọi bộ lọc mới đều opt-in hoặc có cờ tắt.

### 4.2 Entropy
- [x] Kích thước cửa sổ và ngưỡng cấu hình được (`--entropy-window`, `--entropy-threshold`).
- [x] Gộp các vùng entropy cao liền kề thành một record (`--entropy-merge`; entropy của vùng gộp tính chính xác từ histogram).
- [x] `--entropy-no-data` / giới hạn kích thước `data_hex` để output không phình (`--entropy-no-data`, `--entropy-max-data`, mặc định 4096 byte kèm `data_truncated`).

### 4.3 IOC / secret
- [ ] Validate để giảm false positive: checksum Base58Check/Bech32 (ví crypto), Luhn, cấu trúc JWT (decode header/payload), độ dài và prefix theo từng nhà cung cấp.
- [x] Output detector giữ cả `text` gốc, `match` và vài byte ngữ cảnh (không chỉ thay bằng token).
- [ ] Dùng `RegexSet` / aho-corasick làm prefilter để 30+ pattern không làm chậm quét.
- [ ] Cho phép chọn nhiều loại: `--detect ip,url,secret`.
- [ ] Nạp pattern tùy chỉnh từ file (`--detect-rules`).
- [~] **Giảm false positive của generic secret** (thấy rõ trên Lab 6): `Token: GetTokenInformation`, `Token: Malloc`, `Token:DigiCert`, `Password: false,`, `ApiKey=function(a){...}`. Yêu cầu giá trị trông giống secret (entropy, độ dài, không phải identifier/từ tiếng Anh/`true`/`false`/mã JS). Đã lọc identifier/từ khóa/mã JS và publicKeyToken; còn cần wordlist/entropy rộng hơn.
- [x] Loại hoặc hạ điểm các mẫu biết trước là không phải secret: `publicKeyToken="..."` trong manifest assembly (`6595b64144ccf1df`, `31bf3856ad364e35`, `1122334455667788`).
- [ ] **Phân loại key công khai phía client**: `AIza...` trong request trình duyệt (vd. tới `*.clients6.google.com`) gắn nhãn `public-client-key`, confidence thấp; khác với secret phía server/người dùng.
- [x] **Output có cấu trúc cho mọi finding:** thêm `rule` (vd. `google_api_key`, `generic_password`), `confidence`/`severity`, và `context` (vài chục byte quanh match). Hiện `--detect secret` chỉ có `offset`, `encoding`, `text`.
- [~] **Nhận diện khối biến môi trường** (`NAME=value\0NAME=value\0` trong UTF-16): `password=`/`key=` trong env block xếp ưu tiên cao (case thật: `RAR password=easypeasyvirus` trong dump Lab 6). Đã có `--extract env` (gắn `sensitive=true`) nhưng chưa đẩy các env nhạy cảm lên nhóm priority findings.
- [~] `--dedupe` mặc định cho detector: cùng một key lặp nhiều lần chỉ hiện một dòng kèm `count` và danh sách offset. (`--dedupe` đã gộp theo `(rule, value)` kèm `count`; còn thiếu danh sách offset và việc bật mặc định.)

### 4.4 Trích xuất artifact có cấu trúc
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
- [ ] Shell completions (bash/zsh/fish/pwsh), man page, `--version` chi tiết (commit, feature build: full/lite).
- [~] Exit code rõ ràng (0 sạch, 1 lỗi, 2 có phát hiện nghiêm trọng nếu bật cờ). Đã dùng và ghi trong `cli/README.md`: 0, 1, 3 (kết quả bị cắt); còn thiếu code 2 cho "có phát hiện nghiêm trọng".
- [ ] File cấu hình (`bxmap.toml`) cho các tùy chọn lặp lại.

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
- [ ] Cờ CLI: `--carve <types>` (vd. `jpeg,png,zip,rar`), `--carve-out <dir>`, `--carve-index <file>`, `--carve-min-size`, `--carve-max-size`, `--carve-max-total`.
- [ ] Quét streaming tái dùng reader chunk có gối (overlap ≥ độ dài header dài nhất); hỗ trợ `--start/--end` (Phase 3); chạy song song, kết quả ổn định theo offset.
- [ ] Tìm chữ ký nhanh bằng `memchr`/aho-corasick (dùng lại prefilter đã có ở classifier); không đọc lại toàn dump cho từng loại.
- [ ] Trần an toàn: dừng khi chạm `--carve-max-total`, in cảnh báo rõ (không im lặng như `--max-strings`), exit code riêng.

### 8.2 Bộ validator theo định dạng
- [ ] **JPEG:** `FF D8 FF` … `FF D9`, đi theo marker (SOI/APPn/DQT/SOF/DHT/SOS), loại false positive; xử lý thumbnail nhúng (EXIF) để không tạo bản trùng lồng nhau.
- [ ] **PNG:** đi theo chunk, kiểm CRC, kết thúc ở `IEND`.
- [ ] **ZIP:** `PK\x03\x04` … end-of-central-directory; nhận biết ZIP mã hoá (cờ bit 0) và OOXML/JAR (docx, xlsx, apk...).
- [ ] **RAR4/RAR5, 7z:** theo chiều dài header; nhận biết archive mã hoá header.
- [ ] **PDF, GZIP:** theo footer/độ dài; BMP và SQLite ở bước sau (BMP: `BM` + kích thước header; SQLite: page size × số trang).
- [ ] Luôn chặn kích thước khai trong header bằng `--carve-max-size` và kích thước dump còn lại; không tin header.
- [ ] Mỗi validator trả về `complete: true|false`, `truncated`, `reason` (vì sao dừng).

### 8.3 Đầu ra và an toàn
- [ ] Index JSON/NDJSON: `offset`, `type`, `size`, `sha256`, `entropy`, `complete`, `notes`, đường dẫn file đã ghi.
- [ ] Dedupe theo SHA256; gom các bản trùng thành một dòng kèm danh sách offset.
- [ ] File ghi ra có đuôi trung tính (`.carved`), tên theo `offset-type-hash`; không mở, không chạy, không giải nén.
- [ ] Cảnh báo trong README: file carve có thể là mã độc, chỉ xem trong môi trường cô lập.
- [ ] `--carve-out` là **bắt buộc**: không có thư mục đích thì dừng với lỗi rõ ràng thay vì ghi vào cwd.
- [ ] Ghi đè an toàn: không ghi ra ngoài `--carve-out`, chống path traversal ở tên file, từ chối ghi đè file đã tồn tại.
- [ ] Index là kênh riêng (`--carve-index`), không trộn vào `--format` chính; thêm dòng tóm tắt vào `--report summary` (số file, số `complete`, tổng byte).

### 8.4 Nhận diện vỏ mã hoá (chỉ khoanh vùng)
- [ ] Chữ ký container: BitLocker (`-FVE-FS-`), LUKS, OpenSSL (`Salted__`), PGP, VeraCrypt/TrueCrypt (nếu nhận diện được), ZIP/7z/RAR có mã hoá.
- [ ] Vùng entropy cao không có chữ ký: xuất làm ứng viên với nhãn `high-entropy` (không phân biệt chắc nén với mã hoá), kèm offset và độ dài.
- [ ] Tái dùng module entropy đã có ở Phase 4.2 (cửa sổ, ngưỡng, gộp vùng liền kề) thay vì viết lại.

### 8.5 Mở rộng sau (P2)
- [ ] **Quét khoá trong RAM** (module riêng, vd. `--find-keys`): lịch khoá AES (kiểu aeskeyfind), khoá RSA/PEM dạng nhị phân; nhắm tới việc tìm khoá cho vỏ ở 8.4.
- [ ] Ghép mảnh (reassembly) theo thứ tự trang khi có bảng trang (dump `.DMP`, VM snapshot).
- [ ] Thêm định dạng: BMP, SQLite, OLE/Office cũ, MP4, executable (PE/ELF carve).

### 8.6 Test và đối chiếu
- [ ] Dump tổng hợp đặt file ở offset biết trước: nằm trọn, vắt qua ranh giới chunk, bị cắt cụt, bị lồng nhau.
- [ ] Golden test CLI trong `cli/tests/golden.rs` (cùng kiểu các phase trước): carve 1 JPEG + 1 PNG, kiểm index và `complete`.
- [ ] Fuzz validator (`cargo-fuzz`): header khai kích thước khổng lồ, marker lặp vô hạn, chunk PNG sai CRC.
- [ ] So sánh với foremost, PhotoRec, bulk_extractor trên cùng dump: số file, số false positive, thời gian, RAM.
- [ ] Case thật: Lab 6 (6 chữ ký RAR → mở bằng mật khẩu tìm thấy), Lab 4 (JPEG/BMP/ZIP trên Desktop); ghi rõ file nào lấy lại được hoàn chỉnh, file nào không.

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
