# ROADMAP — bxmap

Mục tiêu: biến bxmap thành công cụ trích xuất chuỗi / triage cho memory dump **nhanh, đáng tin cậy và dễ nhúng**, ưu tiên độ an toàn khi xử lý input không tin cậy.

Ký hiệu: `[ ]` chưa làm · `[~]` đang làm · `[x]` xong. Độ ưu tiên: **P0** làm trước · **P1** quan trọng · **P2** nên có.

---

## Phase 1 — Dọn nền (tài liệu, giấy phép, release) · P0

Chi phí thấp, hiệu quả cao nhất. Làm trước khi thêm tính năng.

### 1.1 README và tài liệu
- [ ] Sửa các chỗ mâu thuẫn: "ASCII/UTF-16LE" vs UTF-16BE/UTF-32; "No MDMP parsing" vs module `Minidump`; "Rust API only" vs `minidump`.
- [ ] Xóa mục bị lặp (`--encoding`, `--magic-bytes`, IOC triage).
- [x] Tách `cli/README.md` (cách dùng CLI); README gốc chỉ giữ phần library + link sang CLI.
- [x] Thêm `CHANGELOG.md`, `SECURITY.md` (cách báo lỗi), `CONTRIBUTING.md`.
- [ ] Thêm badge: CI, MSRV, crates.io version, docs.rs.

**Xong khi:** đọc README từ đầu đến cuối không còn câu nào trái với code hiện tại.

### 1.2 Giấy phép
- [ ] Quyết định giấy phép cho **library** (`bxmap`): cân nhắc MIT/Apache-2.0 hoặc MPL-2.0 để dự án khác dùng được; giữ AGPL-3.0 cho `bxmap-cli` nếu muốn.
- [ ] Cập nhật `Cargo.toml`, `LICENSE` từng crate, ghi rõ trong README.

### 1.3 Release và chuỗi cung ứng
- [x] Chuyển từ "mỗi push `main` ra release" sang **release theo tag semver**; push `main` chỉ build artifact CI (nightly).
- [x] Sinh `SHA256SUMS` cho mọi binary; ký bằng cosign/minisign còn làm thêm.
- [ ] Xuất SBOM (`cargo-cyclonedx`) kèm release.
- [ ] Chuyển `sample_demo.dmp` ra khỏi git history sang release asset hoặc Git LFS.
- [x] Job CI kiểm tra **MSRV** cho bản `lite` (1.70); bản `full` dùng stable.

---

## Phase 2 — Độ an toàn và độ đúng · P0

Dump đến từ máy nhiễm mã độc, parser phải chịu được input thù địch.

### 2.1 Fuzzing và hardening
- [ ] `cargo-fuzz` cho: parser minidump, parser `.vmss`, reader chunk/overlap, các detector regex.
- [ ] Giới hạn cấp phát: header khai báo số stream/region/size quá lớn không được gây OOM.
- [~] Kiểm tra bounds, tránh `unwrap`/panic trên đường parse (minidump + VMware hardened + mini-fuzz no-panic); vẫn tiếp tục các parser khác.
- [ ] Chạy `clippy -D warnings`, `cargo audit`, `cargo deny` trong CI.

### 2.2 Bộ test
- [ ] Unit test cho từng encoding (ASCII, UTF-16LE/BE, UTF-32LE/BE), gồm chuỗi nằm **vắt ngang ranh giới chunk** và ngang ranh giới region song song.
- [ ] Test đảm bảo kết quả song song == kết quả tuần tự (cùng tập, cùng thứ tự theo offset).
- [ ] Golden test cho output `text`, `json`, `json-tree`.
- [ ] Bộ dump mẫu nhỏ, tổng hợp (không chứa dữ liệu thật) cho test hồi quy.

**Xong khi:** CI chạy fuzz smoke test mỗi PR và không còn panic đã biết.

---

## Phase 2.5 — Bug đã xác nhận từ test thực tế (MemLabs Lab 6) · P0

Phát hiện khi chạy bxmap trên `MemoryDump_Lab6.raw` (~1.6 GB). Đã đối chiếu byte thật trong dump.

- [x] **Trùng UTF-16LE/BE.** Đã suppress bản BE mirror khi cùng nội dung và offset lệch 1 byte.
- [x] **Chuỗi chứa xuống dòng bị in nguyên**: output text escape control chars (\n, \r, \t, ...) thành một dòng.
- [x] **Chuỗi quá dài**: thêm `--max-str-len` để cắt output.
- [ ] Test hồi quy: dump mẫu có text ASCII-in-UTF-16 để chắc chắn bug LE/BE không quay lại.
- [ ] **Auto-stop ESLint-like?** Khi scan binary lớn, tự chia output nếu string quá dài theo `--max-str-len` và báo thống kê số chuỗi đã cắt (để phân tích hiệu năng).

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

---

## Phase 4 — Chất lượng kết quả · P1

### 4.1 Lọc nhiễu
- [ ] Mở rộng noise filter ngoài chu kỳ 1–2: chu kỳ N, độ đa dạng ký tự thấp, điểm n-gram để loại chuỗi rác/ngẫu nhiên.
- [ ] `--dedupe`: chuỗi duy nhất kèm số lần xuất hiện + offset đầu tiên.
- [ ] Giữ mặc định bảo thủ (không làm mất bằng chứng ngắn như `0000`); mọi bộ lọc mới đều opt-in hoặc có cờ tắt.

### 4.2 Entropy
- [ ] Kích thước cửa sổ và ngưỡng cấu hình được.
- [ ] Gộp các vùng entropy cao liền kề thành một record.
- [ ] `--entropy-no-data` / giới hạn kích thước `data_hex` để output không phình.

### 4.3 IOC / secret
- [ ] Validate để giảm false positive: checksum Base58Check/Bech32 (ví crypto), Luhn, cấu trúc JWT (decode header/payload), độ dài và prefix theo từng nhà cung cấp.
- [ ] Output detector giữ cả `text` gốc, `match` và vài byte ngữ cảnh (không chỉ thay bằng token).
- [ ] Dùng `RegexSet` / aho-corasick làm prefilter để 30+ pattern không làm chậm quét.
- [ ] Cho phép chọn nhiều loại: `--detect ip,url,secret`.
- [ ] Nạp pattern tùy chỉnh từ file (`--detect-rules`).
- [ ] **Giảm false positive của generic secret** (thấy rõ trên Lab 6): `Token: GetTokenInformation`, `Token: Malloc`, `Token:DigiCert`, `Password: false,`, `ApiKey=function(a){...}`. Yêu cầu giá trị trông giống secret (entropy, độ dài, không phải identifier/từ tiếng Anh/`true`/`false`/mã JS).
- [ ] Loại hoặc hạ điểm các mẫu biết trước là không phải secret: `publicKeyToken="..."` trong manifest assembly (`6595b64144ccf1df`, `31bf3856ad364e35`, `1122334455667788`).
- [ ] **Phân loại key công khai phía client**: `AIza...` trong request trình duyệt (vd. tới `*.clients6.google.com`) gắn nhãn `public-client-key`, confidence thấp; khác với secret phía server/người dùng.
- [ ] **Output có cấu trúc cho mọi finding:** thêm `rule` (vd. `google_api_key`, `generic_password`), `confidence`/`severity`, và `context` (vài chục byte quanh match). Hiện `--detect secret` chỉ có `offset`, `encoding`, `text`.
- [ ] **Nhận diện khối biến môi trường** (`NAME=value\0NAME=value\0` trong UTF-16): `password=`/`key=` trong env block xếp ưu tiên cao (case thật: `RAR password=easypeasyvirus` trong dump Lab 6).
- [ ] `--dedupe` mặc định cho detector: cùng một key lặp nhiều lần chỉ hiện một dòng kèm `count` và danh sách offset.

---

## Phase 5 — API và CLI · P1

### 5.1 Library
- [ ] Đổi `encoding: &'static str` thành enum `Encoding` (`#[non_exhaustive]`), kèm `Display`.
- [ ] API hỗ trợ đủ UTF-16BE/UTF-32 ở mức library, không chỉ CLI.
- [ ] Iterator/callback streaming (không bắt buộc gom `Vec`), hỗ trợ hủy (cancellation) và báo tiến độ.
- [ ] Ổn định API trước `1.0`: tài liệu hóa quy ước semver, đánh dấu phần chưa ổn định bằng feature flag.

### 5.2 CLI
- [ ] Output `ndjson` và `csv`.
- [ ] Thanh tiến độ trên stderr (tắt được khi pipe).
- [ ] Shell completions (bash/zsh/fish/pwsh), man page, `--version` chi tiết (commit, feature build: full/lite).
- [ ] Exit code rõ ràng (0 sạch, 1 lỗi, 2 có phát hiện nghiêm trọng nếu bật cờ).
- [ ] File cấu hình (`bxmap.toml`) cho các tùy chọn lặp lại.

---

## Phase 6 — Mở rộng định dạng và tính năng · P2

- [ ] Windows **full crash dump** (không chỉ minidump).
- [ ] ELF core dump, LiME, `hiberfil.sys`.
- [ ] Mở rộng `.vmss`/`.vmem`: ánh xạ địa chỉ vật lý, thêm các định dạng VM snapshot khác.
- [ ] Ánh xạ VA → module/section/export cho thêm kiến trúc; hiển thị cây tiến trình đầy đủ hơn.
- [ ] **`--magic-bytes` mở rộng:** RAR4/RAR5 (`Rar!\x1a\x07\x00` / `...\x01\x00`), 7z, GZIP, JPEG, SQLite, ngoài PE/ELF/ZIP/PDF/PNG hiện có.
- [ ] **Carving cơ bản (`--carve <type> --out-dir`)**: cắt file theo chữ ký ra đĩa (RAR, ZIP, PNG, JPEG...) để phân tích tiếp (Lab 6 có 6 chữ ký RAR trong dump).
- [ ] Xuất báo cáo HTML/Markdown tự đóng gói cho case management.
- [ ] Binding Python (PyO3) để dùng trong notebook và pipeline.

---

## Phase 7 — Chứng minh giá trị (demo & benchmark) · P1

Mục tiêu: có vài case thật cho thấy bxmap tìm ra thứ có ý nghĩa nhanh hơn `strings | grep`.

- [ ] Bộ demo MemLabs (Lab 1, 2, 6): mỗi lab một mục "đáp án nói cần tìm X → `strings` ra N dòng → bxmap ra X trong M dòng", kèm thời gian và RAM.
- [ ] Case Lab 6: bxmap `--detect` bắt `RAR password=...` trong env block (UTF-16) → dẫn tới file RAR; ghi rõ bước còn lại (carve RAR, mở bằng mật khẩu).
- [ ] Trình bày trung thực: so sánh công bằng với `strings -el | grep`, nêu rõ điểm thắng là một lần quét đủ encoding + phân loại + tốc độ, không phải "chỉ bxmap tìm được".
- [ ] Một bài viết ngắn kể case + GIF/asciinema ở đầu README; đăng r/computerforensics, r/netsec, Show HN, This Week in Rust.
- [ ] Thêm một dump `.DMP` tự tạo trong VM để demo `--map-va`, `--rwx-only`, `--heap-only` (MemLabs là `.raw`, không dùng được các cờ này).
- [ ] Redact mọi credential thật trước khi đăng ảnh/bài.

---

## Mốc phát hành đề xuất

| Mốc | Nội dung | Điều kiện |
|-----|----------|-----------|
| **0.10** | Phase 1 + 2 + 2.5 | README khớp code, CI có fuzz + MSRV, release theo tag có checksum |
| **0.11** | Phase 3 | Có benchmark công khai, XOR chạy song song |
| **0.12** | Phase 4 | Detector có validate, dedupe, entropy gọn |
| **0.13** | Phase 5 | Encoding enum, NDJSON/CSV, completions |
| **1.0** | Chốt API | API library ổn định, tài liệu đầy đủ, fuzz sạch |
| **1.x** | Phase 6 | Thêm định dạng và binding theo nhu cầu |

---

## Thứ tự làm gợi ý

1. Sửa README + quyết định giấy phép
2. Release theo tag + checksum
3. Sửa bug LE/BE trùng + chuỗi nhiều dòng, fuzz parser, test chunk boundary
4. Benchmark + tối ưu XOR
5. Giảm false positive secret + dedupe + trường `rule`/`confidence`/`context`
6. Enum encoding + NDJSON/CSV
7. Demo MemLabs + bài viết
8. Định dạng mới, carving

## Ngoài phạm vi (cố ý không làm)

- Giải mã/giải nén dữ liệu entropy cao (bxmap chỉ báo hiệu, không decrypt).
- Phán quyết "độc hại / không độc hại": detector chỉ là gợi ý triage.
- Phân tích hành vi hoặc dựng lại đối tượng kernel như Volatility.
