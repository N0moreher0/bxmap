//! ROADMAP 8.14.1 — ZIP/OOXML **member salvage** cho hình phân kỳ
//! *header-footer encryption* kiểu ransomware: đầu file (Local File Header
//! đầu tiên) **và** Central Directory + EOCD cuối file bị mã hoá, các
//! member nằm giữa body còn nguyên.
//!
//! Nguyên tắc: **không đoán**. Mỗi member được kiểm chứng độc lập trước
//! khi được dùng:
//!
//! 1. cấu trúc local header hợp lệ (method ∈ {0 stored, 8 deflate},
//!    csize/usize ≤ trần, name printable, không control bytes);
//! 2. CRC-32 của dữ liệu member phải khớp CRC trong local header;
//! 3. method 8: dữ liệu giải nén ra đúng `usize` byte (flate2 đã là dep).
//!
//! Member nào không đạt là bị bỏ. Archive dựng lại **fresh CD + EOCD** từ
//! name/CRC/kích thước verbatim — không có byte nào được "sáng tạo".

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

use flate2::read::DeflateDecoder;

use crate::carve::crc32;

/// Trần số/kích thước của một member.
const MAX_NAME: u64 = 4096;
const MAX_PACKED: u64 = 64 * 1024 * 1024;
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;
/// Trần tổng byte member thu được từ một span (chống CRC-walk vô hạn).
const MAX_TOTAL_MEMBER_BYTES: u64 = 512 * 1024 * 1024;
/// Trần số member ghi nhận từ một span.
const MAX_MEMBERS: usize = 4096;

/// Một member sống sót sau phân kỳ.
#[derive(Debug, Clone)]
pub(crate) struct SalvagedMember {
    /// Offset tuyệt đối của local header (offset trong dump).
    pub start: u64,
    /// Offset ngay sau dữ liệu member (local header + data).
    pub end: u64,
    pub name: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub time: u16,
    pub date: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub extra: Vec<u8>,
    /// Dữ liệu member (dữ liệu nén nếu method ≠ 0).
    pub payload: Vec<u8>,
}

impl SalvagedMember {
    /// Tên hiển thị cho notes (UTF-8 lossy, tối đa 96 ký tự).
    pub(crate) fn display_name(&self) -> String {
        String::from_utf8_lossy(&self.name)
            .chars()
            .take(96)
            .collect()
    }
}

/// Archive dựng lại từ các member sống sót (ROADMAP 8.14.1).
#[derive(Debug)]
pub(crate) struct MemberRebuild {
    /// Bytes of the complete archive (local headers + fresh CD + EOCD).
    /// Empty when the rebuilt archive would exceed the 32-bit ZIP format
    /// (too many entries / too large) — caller falls back to `incomplete`.
    pub bytes: Vec<u8>,
    /// Number of members kept (CRC/inflate verified).
    pub kept: usize,
    /// Whether method 8 (deflate) is present — decides the evidence token.
    pub any_deflate: bool,
    /// Names of kept members (up to 8), for the notes.
    pub kept_names: Vec<String>,
    /// `PK\x03\x04` hits rejected because they failed verification
    /// (damaged structure/CRC) — the caller logs the count in notes.
    pub rejected: usize,
}

/// Kết quả của một lần quét member.
#[derive(Debug)]
pub(crate) struct MemberScan {
    /// Member sống sót (đã kiểm chứng).
    pub members: Vec<SalvagedMember>,
    /// `PK\x03\x04` hits bị loại vì không kiểm chứng được.
    pub rejected: usize,
}

/// Quét `[span_start, span_end)` tìm `PK\x03\x04`, kiểm chứng từng member
/// và trả về danh sách member sống sót (offset tuyệt đối).
pub(crate) fn scan_zip_members(
    file: &mut File,
    span_start: u64,
    span_end: u64,
    file_len: u64,
) -> io::Result<MemberScan> {
    let span_len = span_end.saturating_sub(span_start);
    if span_len < 30 {
        return Ok(MemberScan {
            members: Vec::new(),
            rejected: 0,
        });
    }
    let mut members: Vec<SalvagedMember> = Vec::new();
    let mut occupied: Vec<(u64, u64)> = Vec::new();
    let mut total_bytes: u64 = 0;
    let mut rejected: usize = 0;

    // Cửa sổ trượt 4 MiB với overlap 4 byte (chữ ký PK0304 dài 4).
    // Không cần phân biệt hit cũ/mới: `occupied` (span member đã kiểm
    // chứng) mới là khóa dedupe — một member kiểm chứng fail thì lần
    // validate lặp lại trong cửa sổ sau cũng fail y nguyên, chỉ tốn CRC.
    let window: u64 = 1 << 22;
    let mut base = span_start;
    let mut tail: Vec<u8> = Vec::new();
    while base < span_end {
        let take = (window).min(span_end - base) as usize;
        let mut chunk = vec![0u8; take];
        file.seek(SeekFrom::Start(base))?;
        file.read_exact(&mut chunk)?;
        let window_base = base.saturating_sub(tail.len() as u64);
        let mut buf = tail;
        buf.extend_from_slice(&chunk);
        let buf_len = buf.len();
        let chunk_end = base + take as u64;
        for i in 0..buf_len.saturating_sub(3) {
            if &buf[i..i + 4] != b"PK\x03\x04" {
                continue;
            }
            let abs = window_base + i as u64;
            if abs + 4 > chunk_end {
                // Chữ ký bắt đầu quá cuối chunk (thiếu 4 byte đủ).
                break;
            }
            if members.len() >= MAX_MEMBERS || total_bytes >= MAX_TOTAL_MEMBER_BYTES {
                break;
            }
            // Bỏ qua hit nằm trong member đã kiểm chứng (nested member).
            if occupied.iter().any(|&(s, e)| abs >= s && abs < e) {
                continue;
            }
            let Some(member) = validate_member(file, abs, span_end, file_len)? else {
                rejected += 1;
                continue;
            };
            total_bytes = total_bytes.saturating_add(member.payload.len() as u64);
            occupied.push((member.start, member.end));
            members.push(member);
        }
        tail = buf[buf_len.saturating_sub(4)..].to_vec();
        base += take as u64;
    }

    Ok(MemberScan { members, rejected })
}

/// Quét + dựng lại archive. `Ok(None)` khi không có member sống sót hoặc
/// archive dựng lại vượt khả năng của 32-bit ZIP — caller giữ hành vi cũ.
pub(crate) fn salvage_zip_members(
    file: &mut File,
    span_start: u64,
    span_end: u64,
    file_len: u64,
) -> io::Result<Option<MemberRebuild>> {
    let scan = scan_zip_members(file, span_start, span_end, file_len)?;
    if scan.members.is_empty() {
        return Ok(None);
    }
    Ok(Some(rebuild_archive(scan.members, scan.rejected)))
}

/// Kiểm chứng một member tại `start`. `None` khi bất kỳ cổng nào thất bại.
fn validate_member(
    file: &mut File,
    start: u64,
    span_end: u64,
    file_len: u64,
) -> io::Result<Option<SalvagedMember>> {
    // Header local tối thiểu 30 byte.
    let Some(header) = read_exact_at(file, start, 30)? else {
        return Ok(None);
    };
    if &header[..4] != b"PK\x03\x04" {
        return Ok(None);
    }
    let flags = u16::from_le_bytes([header[6], header[7]]);
    let method = u16::from_le_bytes([header[8], header[9]]);
    let time = u16::from_le_bytes([header[10], header[11]]);
    let date = u16::from_le_bytes([header[12], header[13]]);
    let crc = u32::from_le_bytes([header[14], header[15], header[16], header[17]]);
    let csize = u64::from(u32::from_le_bytes([
        header[18], header[19], header[20], header[21],
    ]));
    let usize_ = u64::from(u32::from_le_bytes([
        header[22], header[23], header[24], header[25],
    ]));
    let name_len = u64::from(u16::from_le_bytes([header[26], header[27]]));
    let extra_len = u64::from(u16::from_le_bytes([header[28], header[29]]));

    // Chỉ nhận stored/deflate; các method khác (bzip2, lzma…) là ngoài scope.
    if method != 0 && method != 8 {
        return Ok(None);
    }
    // Bit 3 = dữ liệu "streaming": sizes nằm ở data-descriptor cuối member,
    // local header vô dụng để định vị — bỏ qua an toàn.
    if flags & 0x0008 != 0 {
        return Ok(None);
    }
    if name_len == 0 || name_len > MAX_NAME || extra_len > MAX_NAME {
        return Ok(None);
    }
    if csize == 0 || csize > MAX_PACKED || usize_ > MAX_UNPACKED {
        return Ok(None);
    }
    let name_start = start + 30;
    let data_start = name_start + name_len + extra_len;
    let data_end = data_start + csize;
    if data_end > span_end || data_end > file_len {
        return Ok(None);
    }
    // Tên: không control bytes, không DEL, ≥ 1 ký tự chữ/hoặc số.
    let Some(name) = read_exact_at(file, name_start, name_len as usize)? else {
        return Ok(None);
    };
    if name.iter().any(|&b| b < 0x20 || b == 0x7f)
        || !name.iter().any(|b| b.is_ascii_alphanumeric())
    {
        return Ok(None);
    }
    let Some(extra) = read_exact_at(file, name_start + name_len, extra_len as usize)? else {
        return Ok(None);
    };
    let Some(payload) = read_exact_at(file, data_start, csize as usize)? else {
        return Ok(None);
    };
    match method {
        0 => {
            if crc32(0xffff_ffff, &payload) ^ 0xffff_ffff != crc {
                return Ok(None);
            }
        }
        8 => {
            let mut out = Vec::with_capacity(usize_ as usize + 8);
            if DeflateDecoder::new(&payload[..])
                .read_to_end(&mut out)
                .is_err()
            {
                return Ok(None);
            }
            if out.len() as u64 != usize_ {
                return Ok(None);
            }
            if crc32(0xffff_ffff, &out) ^ 0xffff_ffff != crc {
                return Ok(None);
            }
        }
        _ => unreachable!("method checked above"),
    }
    Ok(Some(SalvagedMember {
        start,
        end: data_end,
        name,
        method,
        flags,
        time,
        date,
        crc32: crc,
        compressed_size: csize,
        uncompressed_size: usize_,
        extra,
        payload,
    }))
}

fn read_exact_at(file: &mut File, offset: u64, length: usize) -> io::Result<Option<Vec<u8>>> {
    if length == 0 {
        return Ok(Some(Vec::new()));
    }
    let mut buf = vec![0u8; length];
    file.seek(SeekFrom::Start(offset))?;
    match file.read_exact(&mut buf) {
        Ok(()) => Ok(Some(buf)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

/// Dựng lại archive hoàn chỉnh từ các member đã kiểm chứng: local headers
/// (không mang offset, giữ nguyên verbatim) + fresh Central Directory
/// (LHO tính lại) + EOCD sạch.
fn rebuild_archive(members: Vec<SalvagedMember>, rejected: usize) -> MemberRebuild {
    let any_deflate = members.iter().any(|m| m.method == 8);
    let kept = members.len();
    let kept_names = member_names(&members);
    let mut out = Vec::with_capacity(
        members
            .iter()
            .map(|m| 30 + m.name.len() + m.extra.len() + m.payload.len())
            .sum::<usize>()
            + members.len() * 64
            + 64,
    );
    let mut lho: Vec<u64> = Vec::with_capacity(members.len());
    for member in &members {
        lho.push(out.len() as u64);
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&member.flags.to_le_bytes());
        out.extend_from_slice(&member.method.to_le_bytes());
        out.extend_from_slice(&member.time.to_le_bytes());
        out.extend_from_slice(&member.date.to_le_bytes());
        out.extend_from_slice(&member.crc32.to_le_bytes());
        out.extend_from_slice(&(member.compressed_size as u32).to_le_bytes());
        out.extend_from_slice(&(member.uncompressed_size as u32).to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(member.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&member.name);
        out.extend_from_slice(&member.extra);
        out.extend_from_slice(&member.payload);
    }
    let cd_start = out.len() as u64;
    for (member, &new_lho) in members.iter().zip(lho.iter()) {
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20u16.to_le_bytes()); // made by
        out.extend_from_slice(&20u16.to_le_bytes()); // needed
        out.extend_from_slice(&member.flags.to_le_bytes());
        out.extend_from_slice(&member.method.to_le_bytes());
        out.extend_from_slice(&member.time.to_le_bytes());
        out.extend_from_slice(&member.date.to_le_bytes());
        out.extend_from_slice(&member.crc32.to_le_bytes());
        out.extend_from_slice(&(member.compressed_size as u32).to_le_bytes());
        out.extend_from_slice(&(member.uncompressed_size as u32).to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&(member.extra.len() as u16).to_le_bytes());
        out.extend_from_slice(&[0u8; 6]); // comment len(2) + disk start(2) + internal attrs(2)
        out.extend_from_slice(&[0u8; 4]); // external attrs
        out.extend_from_slice(&(new_lho as u32).to_le_bytes());
        out.extend_from_slice(&member.name);
        out.extend_from_slice(&member.extra);
    }
    let cd_size = out.len() as u64 - cd_start;
    if members.len() as u64 > u64::from(u16::MAX) || cd_start + cd_size > u64::from(u32::MAX) {
        // Rebuilt archive vượt 32-bit ZIP (quá nhiều entries / quá lớn) —
        // không dựng được, báo rõ là mất.
        return MemberRebuild {
            bytes: Vec::new(),
            kept: 0,
            any_deflate,
            kept_names: Vec::new(),
            rejected,
        };
    }
    // EOCD sạch.
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0u8; 4]); // this disk + central disk
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd_size as u32).to_le_bytes());
    out.extend_from_slice(&(cd_start as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment length
    MemberRebuild {
        bytes: out,
        kept,
        any_deflate,
        kept_names,
        rejected,
    }
}

/// Tên member cho notes (tối đa 8).
fn member_names(members: &[SalvagedMember]) -> Vec<String> {
    members
        .iter()
        .take(8)
        .map(SalvagedMember::display_name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn crc_of(data: &[u8]) -> u32 {
        crc32(0xffff_ffff, data) ^ 0xffff_ffff
    }

    /// Dựng một member (local header + data) thô để test.
    fn local_member(name: &str, payload: &[u8], method: u16) -> Vec<u8> {
        let mut out = Vec::new();
        let crc = crc_of(payload);
        let (compressed_size, stored): (u32, Vec<u8>) = match method {
            0 => (payload.len() as u32, payload.to_vec()),
            8 => {
                let mut compressed = Vec::new();
                flate2::write::DeflateEncoder::new(&mut compressed, flate2::Compression::best())
                    .write_all(payload)
                    .unwrap();
                (compressed.len() as u32, compressed)
            }
            _ => unreachable!(),
        };
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0u16.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&compressed_size.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&stored);
        out
    }

    fn dump_to_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bxmap-zipmember-{name}-{}-{}.bin",
            std::process::id(),
            now_ms()
        ));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[test]
    fn scan_finds_and_verifies_deflate_and_stored_members() {
        let payload_a = b"alpha alpha alpha alpha alpha alpha alpha".to_vec();
        let payload_b = b"beta payload text, beta payload beta payload beta".to_vec();
        let m1 = local_member("docs/report.txt", &payload_a, 0);
        let m2 = local_member("docs/summary.bin", &payload_b, 8);
        let mut dump = vec![0xAA; 1500]; // head destroyed
        dump.extend_from_slice(&m1);
        dump.extend_from_slice(&m2);
        dump.extend_from_slice(&vec![0xBB; 500]); // CD+EOCD destroyed
        let len = dump.len() as u64;
        let path = dump_to_temp("basic", &dump);
        let mut file = File::open(&path).unwrap();
        let scan = scan_zip_members(&mut file, 0, len, len).unwrap();
        std::fs::remove_file(&path).ok();
        let members = scan.members;
        assert_eq!(members.len(), 2);
        assert_eq!(scan.rejected, 0);
        assert_eq!(members[0].name, b"docs/report.txt");
        assert_eq!(members[1].name, b"docs/summary.bin");
        assert_eq!(members[0].method, 0);
        assert_eq!(members[1].method, 8);
        assert_eq!(members[0].start, 1500);
        assert!(members
            .iter()
            .all(|m| m.payload.len() as u64 == m.compressed_size));
    }

    #[test]
    fn crc_mismatch_drops_the_member() {
        let payload = b"omega omega omega omega".to_vec();
        let mut member = local_member("doomed.txt", &payload, 0);
        // Đổi 1 byte trong data → CRC mismatch → member bị loại.
        let data_at = member.len() - payload.len();
        member[data_at] ^= 0xFF;
        let mut dump = vec![0xAA; 800];
        dump.extend_from_slice(&member);
        let len = dump.len() as u64;
        let path = dump_to_temp("crc", &dump);
        let mut file = File::open(&path).unwrap();
        let scan = scan_zip_members(&mut file, 0, len, len).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(scan.rejected, 1);
        assert!(scan.members.is_empty(), "CRC mismatch must drop the member");
    }

    #[test]
    fn members_inside_verified_members_are_not_double_counted() {
        let inner = local_member("inner.txt", b"ee", 0);
        let outer_payload = {
            let mut p = b"xxxx inner zip ---- ".to_vec();
            p.extend_from_slice(&inner);
            p.extend_from_slice(b" ---- xxxxxx");
            p
        };
        let outer = local_member("outer.zip", &outer_payload, 0);
        let mut dump = vec![0xAA; 100];
        dump.extend_from_slice(&outer);
        let len = dump.len() as u64;
        let path = dump_to_temp("nested", &dump);
        let mut file = File::open(&path).unwrap();
        let scan = scan_zip_members(&mut file, 0, len, len).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(
            scan.members.len(),
            1,
            "nested member must be suppressed by its host"
        );
        assert_eq!(scan.members[0].name, b"outer.zip");
    }

    #[test]
    fn rebuilt_archive_structure_round_trips() {
        let payload_a = b"AAAA content for member A".to_vec();
        let payload_b = b"BBBB content for member B with a longer body than A".to_vec();
        let m1 = local_member("a.txt", &payload_a, 0);
        let m2 = local_member("b.bin", &payload_b, 8);
        let mut dump = vec![0xAA; 1200];
        dump.extend_from_slice(&m1);
        dump.extend_from_slice(&m2);
        dump.extend_from_slice(&vec![0xBB; 300]); // CD+EOCD destroyed
        let len = dump.len() as u64;
        let path = dump_to_temp("roundtrip", &dump);
        let mut file = File::open(&path).unwrap();
        let rebuilt = salvage_zip_members(&mut file, 0, len, len)
            .unwrap()
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(rebuilt.kept, 2);
        // Archive dựng lại: signature đầu là local header, cuối là EOCD
        // với đúng 1 CD trỏ tới 2 entries.
        assert!(rebuilt.bytes.starts_with(b"PK\x03\x04"));
        let eocd_at = rebuilt
            .bytes
            .windows(4)
            .rposition(|w| w == b"PK\x05\x06")
            .expect("EOCD present");
        assert_eq!(eocd_at + 22, rebuilt.bytes.len());
        let entries_total =
            u16::from_le_bytes([rebuilt.bytes[eocd_at + 10], rebuilt.bytes[eocd_at + 11]]);
        let cd_offset = u32::from_le_bytes([
            rebuilt.bytes[eocd_at + 16],
            rebuilt.bytes[eocd_at + 17],
            rebuilt.bytes[eocd_at + 18],
            rebuilt.bytes[eocd_at + 19],
        ]) as usize;
        let cd_size = u32::from_le_bytes([
            rebuilt.bytes[eocd_at + 12],
            rebuilt.bytes[eocd_at + 13],
            rebuilt.bytes[eocd_at + 14],
            rebuilt.bytes[eocd_at + 15],
        ]) as usize;
        assert_eq!(entries_total, 2);
        assert_eq!(cd_offset + cd_size, eocd_at);
        assert_eq!(&rebuilt.bytes[cd_offset..cd_offset + 4], b"PK\x01\x02");
    }
}
