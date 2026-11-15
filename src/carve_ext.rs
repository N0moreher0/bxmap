//! Extension refinement for carved files (ROADMAP 8.10.3, batch B2).
//!
//! After a validator accepts a region, [`refine_ext`] looks at a few bounded
//! windows of that same region (head, ZIP central directory, OLE directory)
//! and picks a more specific extension than the kind's default: `dll`/`sys`
//! for PE, `docx`/`xlsx`/`pptx`/`odt`/`ods`/`odp`/`apk`/`jar` for ZIP,
//! `doc`/`xls`/`ppt`/`msg`/`msi` for OLE, `m4a`/`mov` for MP4 and `so` for ELF.
//!
//! Rules that keep the result honest:
//! - The extension is always a `&'static str` from this file, never text read
//!   from the carved bytes, so a name cannot carry path separators or junk.
//! - Evidence-only: when the structure does not prove the specific type, the
//!   kind's default (`zip`, `ole`, `exe`, ...) stays. Nothing is "upgraded"
//!   on a guess.
//! - Bounded work: every read is capped (64 KiB head, <= 1 MiB ZIP central
//!   directory, <= 256 OLE directory sectors, <= 64 KiB ELF program headers)
//!   and there is no extra pass over the dump.
//! - Never fails the carve: any read error or odd structure yields the
//!   default extension with source `fallback`.
//!
//! RIFF (avi/wav/webp), EBML (mkv/webm) and OGG (ogg/opus) are already told
//! apart by their own [`CarveKind`], so they need no sniff here.

use crate::carve::CarveKind;
use std::io::{self, Read, Seek, SeekFrom};

/// First window read for header based rules.
const HEAD_WINDOW: u64 = 64 * 1024;
/// ZIP end-of-central-directory record is at most 22 bytes plus a 65535 B comment.
const ZIP_EOCD_WINDOW: u64 = 65_557;
/// Largest central directory the sniff reads.
const ZIP_CD_CAP: u64 = 1 << 20;
/// Most central directory entries the sniff inspects.
const ZIP_ENTRY_CAP: usize = 4096;
/// Most OLE directory sectors followed (also breaks directory chain loops).
const OLE_DIR_SECTOR_CAP: usize = 256;
/// Most OLE directory names collected.
const OLE_NAME_CAP: usize = 1024;
/// Largest ELF program header table the sniff reads.
const ELF_PHDR_CAP: u64 = 64 * 1024;

/// The extension picked for a carved file and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExtChoice {
    /// Extension placed before `.carved` (`[a-z0-9]{1,8}`).
    pub ext: &'static str,
    /// `kind` (default of the kind, structure confirmed generic or no rule),
    /// `sniff:<rule>` (refined by evidence) or `fallback` (the sniff could not
    /// read enough structure, so the default stays).
    pub source: &'static str,
}

enum Sniff {
    Refined(&'static str, &'static str),
    /// Structure read fine and it is the generic type.
    Generic,
    /// Not enough or inconsistent structure to decide.
    Unsure,
}

/// Picks the extension for the `size` bytes at `base` in `r`.
///
/// Reads are clipped to `[base, base + size)` and bounded (see module docs).
/// Never panics and never returns an error: failures become `fallback`.
pub(crate) fn refine_ext<R: Read + Seek>(
    kind: CarveKind,
    r: &mut R,
    base: u64,
    size: u64,
) -> ExtChoice {
    let default = kind.default_ext();
    let sniffed = match kind {
        CarveKind::Pe => sniff_pe(r, base, size),
        CarveKind::Mp4 => sniff_mp4(r, base, size),
        CarveKind::Zip => sniff_zip(r, base, size),
        CarveKind::Ole => sniff_ole(r, base, size),
        CarveKind::Elf => sniff_elf(r, base, size),
        _ => {
            return ExtChoice {
                ext: default,
                source: "kind",
            }
        }
    };
    match sniffed {
        Ok(Sniff::Refined(ext, rule)) => ExtChoice { ext, source: rule },
        Ok(Sniff::Generic) => ExtChoice {
            ext: default,
            source: "kind",
        },
        Ok(Sniff::Unsure) | Err(_) => ExtChoice {
            ext: default,
            source: "fallback",
        },
    }
}

// --- byte helpers ------------------------------------------------------------

/// Reads up to `len` bytes at `rel` (relative to the region start), clipped to
/// the region. Returns fewer bytes (or none) when the region ends first.
fn read_at<R: Read + Seek>(
    r: &mut R,
    base: u64,
    size: u64,
    rel: u64,
    len: u64,
) -> io::Result<Vec<u8>> {
    if rel >= size {
        return Ok(Vec::new());
    }
    let len = len.min(size - rel);
    r.seek(SeekFrom::Start(base.saturating_add(rel)))?;
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

fn rd16(b: &[u8], o: usize, be: bool) -> Option<u16> {
    let a: [u8; 2] = b.get(o..o.checked_add(2)?)?.try_into().ok()?;
    Some(if be {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    })
}

fn rd32(b: &[u8], o: usize, be: bool) -> Option<u32> {
    let a: [u8; 4] = b.get(o..o.checked_add(4)?)?.try_into().ok()?;
    Some(if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    })
}

fn rd64(b: &[u8], o: usize, be: bool) -> Option<u64> {
    let a: [u8; 8] = b.get(o..o.checked_add(8)?)?.try_into().ok()?;
    Some(if be {
        u64::from_be_bytes(a)
    } else {
        u64::from_le_bytes(a)
    })
}

fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len())
        .rev()
        .find(|&i| &hay[i..i + needle.len()] == needle)
}

// --- PE ------------------------------------------------------------------------

/// `IMAGE_FILE_DLL` in the COFF characteristics.
const PE_FILE_DLL: u16 = 0x2000;
/// `IMAGE_SUBSYSTEM_NATIVE` (drivers).
const PE_SUBSYSTEM_NATIVE: u16 = 1;

fn sniff_pe<R: Read + Seek>(r: &mut R, base: u64, size: u64) -> io::Result<Sniff> {
    let head = read_at(r, base, size, 0, HEAD_WINDOW)?;
    let Some(lfanew) = rd32(&head, 0x3c, false) else {
        return Ok(Sniff::Unsure);
    };
    let p = lfanew as usize;
    if head.get(p..p.saturating_add(4)) != Some(&b"PE\0\0"[..]) {
        return Ok(Sniff::Unsure);
    }
    // COFF header starts at p + 4: characteristics at +18, optional header
    // size at +16, optional header at +20 (so p + 24 below).
    let Some(characteristics) = rd16(&head, p.saturating_add(22), false) else {
        return Ok(Sniff::Unsure);
    };
    if characteristics & PE_FILE_DLL != 0 {
        return Ok(Sniff::Refined("dll", "sniff:pe/dll"));
    }
    let optional_size = rd16(&head, p.saturating_add(20), false).unwrap_or(0);
    // Subsystem sits at offset 68 of the optional header for PE32 and PE32+.
    if optional_size >= 70
        && rd16(&head, p.saturating_add(24 + 68), false) == Some(PE_SUBSYSTEM_NATIVE)
    {
        return Ok(Sniff::Refined("sys", "sniff:pe/native"));
    }
    Ok(Sniff::Generic)
}

// --- MP4 -----------------------------------------------------------------------

fn sniff_mp4<R: Read + Seek>(r: &mut R, base: u64, size: u64) -> io::Result<Sniff> {
    let head = read_at(r, base, size, 0, 16)?;
    if head.len() < 12 || &head[4..8] != b"ftyp" {
        return Ok(Sniff::Unsure);
    }
    let brand = &head[8..12];
    if brand == b"M4A " {
        Ok(Sniff::Refined("m4a", "sniff:mp4/M4A"))
    } else if brand == b"qt  " {
        Ok(Sniff::Refined("mov", "sniff:mp4/qt"))
    } else {
        Ok(Sniff::Generic)
    }
}

// --- ZIP -----------------------------------------------------------------------

fn sniff_zip<R: Read + Seek>(r: &mut R, base: u64, size: u64) -> io::Result<Sniff> {
    // ODF stores `mimetype` first, uncompressed, so the local header is enough
    // even when the archive lost its tail.
    let first = read_at(r, base, size, 0, 1024)?;
    if let Some((ext, rule)) = zip_odf_ext(&first) {
        return Ok(Sniff::Refined(ext, rule));
    }

    let tail_len = size.min(ZIP_EOCD_WINDOW);
    let tail = read_at(r, base, size, size - tail_len, tail_len)?;
    let Some(pos) = rfind(&tail, b"PK\x05\x06") else {
        return Ok(Sniff::Unsure);
    };
    let eocd = &tail[pos..];
    let (Some(cd_size), Some(cd_off)) = (rd32(eocd, 12, false), rd32(eocd, 16, false)) else {
        return Ok(Sniff::Unsure);
    };
    let (cd_size, cd_off) = (u64::from(cd_size), u64::from(cd_off));
    if cd_size == 0 || cd_size > ZIP_CD_CAP || cd_off + cd_size > size {
        return Ok(Sniff::Unsure);
    }
    let cd = read_at(r, base, size, cd_off, cd_size)?;
    let names = zip_cd_names(&cd);
    if names.is_empty() {
        return Ok(Sniff::Unsure);
    }
    Ok(zip_name_ext(&names))
}

fn zip_odf_ext(first: &[u8]) -> Option<(&'static str, &'static str)> {
    if first.len() < 30 || &first[..4] != b"PK\x03\x04" {
        return None;
    }
    let method = rd16(first, 8, false)?;
    let csize = rd32(first, 18, false)? as usize;
    let name_len = rd16(first, 26, false)? as usize;
    let extra_len = rd16(first, 28, false)? as usize;
    if method != 0 || first.get(30..30 + name_len)? != b"mimetype" {
        return None;
    }
    let start = 30 + name_len + extra_len;
    let data = first.get(start..start.checked_add(csize)?)?;
    if data == b"application/vnd.oasis.opendocument.text" {
        Some(("odt", "sniff:zip/odf-text"))
    } else if data == b"application/vnd.oasis.opendocument.spreadsheet" {
        Some(("ods", "sniff:zip/odf-spreadsheet"))
    } else if data == b"application/vnd.oasis.opendocument.presentation" {
        Some(("odp", "sniff:zip/odf-presentation"))
    } else {
        None
    }
}

fn zip_cd_names(cd: &[u8]) -> Vec<&[u8]> {
    let mut names = Vec::new();
    let mut pos = 0usize;
    while names.len() < ZIP_ENTRY_CAP {
        let Some(rec) = cd.get(pos..) else { break };
        if rec.len() < 46 || &rec[..4] != b"PK\x01\x02" {
            break;
        }
        let name_len = rd16(rec, 28, false).unwrap_or(0) as usize;
        let extra_len = rd16(rec, 30, false).unwrap_or(0) as usize;
        let comment_len = rd16(rec, 32, false).unwrap_or(0) as usize;
        let Some(name) = rec.get(46..46 + name_len) else {
            break;
        };
        names.push(name);
        pos += 46 + name_len + extra_len + comment_len;
    }
    names
}

fn has_name(names: &[&[u8]], wanted: &[u8]) -> bool {
    names.contains(&wanted)
}

fn has_prefix(names: &[&[u8]], prefix: &[u8]) -> bool {
    names.iter().any(|n| n.starts_with(prefix))
}

fn zip_name_ext(names: &[&[u8]]) -> Sniff {
    if has_name(names, b"AndroidManifest.xml") && has_name(names, b"classes.dex") {
        return Sniff::Refined("apk", "sniff:zip/android");
    }
    if has_name(names, b"[Content_Types].xml") {
        if has_prefix(names, b"word/") {
            return Sniff::Refined("docx", "sniff:zip/word");
        }
        if has_prefix(names, b"xl/") {
            return Sniff::Refined("xlsx", "sniff:zip/excel");
        }
        if has_prefix(names, b"ppt/") {
            return Sniff::Refined("pptx", "sniff:zip/powerpoint");
        }
        return Sniff::Generic;
    }
    if has_name(names, b"META-INF/MANIFEST.MF") {
        return Sniff::Refined("jar", "sniff:zip/jar");
    }
    Sniff::Generic
}

// --- OLE / CFB -----------------------------------------------------------------

const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Sector ids at or above this are markers (free, end of chain, FAT, ...).
const OLE_MAX_SECTOR: u32 = 0xFFFF_FFFA;

fn sniff_ole<R: Read + Seek>(r: &mut R, base: u64, size: u64) -> io::Result<Sniff> {
    let hdr = read_at(r, base, size, 0, 512)?;
    if hdr.len() < 512 || hdr[..8] != OLE_MAGIC {
        return Ok(Sniff::Unsure);
    }
    let shift = rd16(&hdr, 0x1e, false).unwrap_or(0);
    if shift != 9 && shift != 12 {
        return Ok(Sniff::Unsure);
    }
    let ssz = 1u64 << shift;
    let first_dir = rd32(&hdr, 0x30, false).unwrap_or(u32::MAX);

    // FAT sector ids from the header DIFAT (the first 109). Directories whose
    // chain needs a later DIFAT sector fall back to the default `ole`.
    let mut fat_ids = Vec::new();
    for i in 0..109usize {
        let Some(id) = rd32(&hdr, 0x4c + 4 * i, false) else {
            break;
        };
        if id >= OLE_MAX_SECTOR {
            break;
        }
        fat_ids.push(id);
    }

    let mut names: Vec<String> = Vec::new();
    let mut sid = first_dir;
    let mut hops = 0usize;
    while sid < OLE_MAX_SECTOR && hops < OLE_DIR_SECTOR_CAP && names.len() < OLE_NAME_CAP {
        let sector = read_at(r, base, size, (u64::from(sid) + 1) * ssz, ssz)?;
        if sector.is_empty() {
            break;
        }
        for entry in sector.chunks_exact(128) {
            if entry[0x42] == 0 {
                continue;
            }
            let name_bytes = (rd16(entry, 0x40, false).unwrap_or(0) as usize).min(64);
            let units: Vec<u16> = (0..name_bytes.saturating_sub(2) / 2)
                .map(|i| u16::from_le_bytes([entry[2 * i], entry[2 * i + 1]]))
                .collect();
            names.push(String::from_utf16_lossy(&units));
        }
        hops += 1;
        match ole_next(r, base, size, ssz, &fat_ids, sid)? {
            Some(next) => sid = next,
            None => break,
        }
    }
    if names.is_empty() {
        return Ok(Sniff::Unsure);
    }

    let has = |wanted: &str| names.iter().any(|n| n.as_str() == wanted);
    if has("__properties_version1.0") {
        return Ok(Sniff::Refined("msg", "sniff:ole/msg"));
    }
    if has("WordDocument") {
        return Ok(Sniff::Refined("doc", "sniff:ole/word"));
    }
    if has("Workbook") || has("Book") {
        return Ok(Sniff::Refined("xls", "sniff:ole/excel"));
    }
    if has("PowerPoint Document") {
        return Ok(Sniff::Refined("ppt", "sniff:ole/powerpoint"));
    }
    // MSI table streams are named with a U+4840 prefix; every Windows
    // Installer package also carries the summary information stream.
    if has("\u{5}SummaryInformation") && names.iter().any(|n| n.starts_with('\u{4840}')) {
        return Ok(Sniff::Refined("msi", "sniff:ole/msi"));
    }
    Ok(Sniff::Generic)
}

fn ole_next<R: Read + Seek>(
    r: &mut R,
    base: u64,
    size: u64,
    ssz: u64,
    fat_ids: &[u32],
    sid: u32,
) -> io::Result<Option<u32>> {
    let per_sector = ssz / 4;
    let index = u64::from(sid) / per_sector;
    let within = u64::from(sid) % per_sector;
    let Some(&fat) = fat_ids.get(index as usize) else {
        return Ok(None);
    };
    let bytes = read_at(r, base, size, (u64::from(fat) + 1) * ssz + within * 4, 4)?;
    Ok(rd32(&bytes, 0, false))
}

// --- ELF -----------------------------------------------------------------------

const ELF_ET_DYN: u16 = 3;
const ELF_PT_INTERP: u32 = 3;

/// `so` only when the object is `ET_DYN` and has no `PT_INTERP` (a PIE
/// executable has one). A static-PIE executable also lacks it and is
/// reported as `so`: the names are an analyst hint, not a proof.
fn sniff_elf<R: Read + Seek>(r: &mut R, base: u64, size: u64) -> io::Result<Sniff> {
    let h = read_at(r, base, size, 0, 64)?;
    if h.len() < 20 || &h[..4] != b"\x7fELF" {
        return Ok(Sniff::Unsure);
    }
    let be = match h[5] {
        1 => false,
        2 => true,
        _ => return Ok(Sniff::Unsure),
    };
    let Some(e_type) = rd16(&h, 16, be) else {
        return Ok(Sniff::Unsure);
    };
    if e_type != ELF_ET_DYN {
        return Ok(Sniff::Generic);
    }
    let (phoff, phentsize, phnum) = match h[4] {
        1 => (
            rd32(&h, 28, be).map(u64::from),
            rd16(&h, 42, be),
            rd16(&h, 44, be),
        ),
        2 => (rd64(&h, 32, be), rd16(&h, 54, be), rd16(&h, 56, be)),
        _ => return Ok(Sniff::Unsure),
    };
    let (Some(phoff), Some(phentsize), Some(phnum)) = (phoff, phentsize, phnum) else {
        return Ok(Sniff::Unsure);
    };
    let entry = usize::from(phentsize);
    let table_len = u64::from(phentsize) * u64::from(phnum);
    if phnum == 0 || entry < 4 || table_len > ELF_PHDR_CAP {
        return Ok(Sniff::Unsure);
    }
    let table = read_at(r, base, size, phoff, table_len)?;
    if (table.len() as u64) < table_len {
        return Ok(Sniff::Unsure);
    }
    for i in 0..usize::from(phnum) {
        if rd32(&table, i * entry, be) == Some(ELF_PT_INTERP) {
            return Ok(Sniff::Generic);
        }
    }
    Ok(Sniff::Refined("so", "sniff:elf/dyn"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run(kind: CarveKind, bytes: &[u8]) -> ExtChoice {
        let mut c = Cursor::new(bytes.to_vec());
        refine_ext(kind, &mut c, 0, bytes.len() as u64)
    }

    fn pick(kind: CarveKind, bytes: &[u8]) -> (&'static str, &'static str) {
        let c = run(kind, bytes);
        (c.ext, c.source)
    }

    fn valid_ext(ext: &str) -> bool {
        (1..=8).contains(&ext.len())
            && ext
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    }

    // --- PE ---

    fn pe(characteristics: u16, subsystem: u16) -> Vec<u8> {
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let p = 0x80;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 20..p + 22].copy_from_slice(&0xF0u16.to_le_bytes());
        b[p + 22..p + 24].copy_from_slice(&characteristics.to_le_bytes());
        b[p + 24..p + 26].copy_from_slice(&0x20bu16.to_le_bytes());
        b[p + 24 + 68..p + 24 + 70].copy_from_slice(&subsystem.to_le_bytes());
        b
    }

    #[test]
    fn pe_exe_dll_and_driver() {
        assert_eq!(pick(CarveKind::Pe, &pe(0x0022, 3)), ("exe", "kind"));
        assert_eq!(pick(CarveKind::Pe, &pe(0x2022, 2)), ("dll", "sniff:pe/dll"));
        // A native-subsystem DLL (ntdll style) is still a dll.
        assert_eq!(pick(CarveKind::Pe, &pe(0x2022, 1)), ("dll", "sniff:pe/dll"));
        assert_eq!(
            pick(CarveKind::Pe, &pe(0x0022, 1)),
            ("sys", "sniff:pe/native")
        );
    }

    #[test]
    fn pe_with_a_bad_header_keeps_the_default() {
        let mut b = pe(0x2022, 2);
        b[0x3c..0x40].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(pick(CarveKind::Pe, &b), ("exe", "fallback"));
        let mut b = pe(0x2022, 2);
        b[0x80] = b'X';
        assert_eq!(pick(CarveKind::Pe, &b), ("exe", "fallback"));
        assert_eq!(
            pick(CarveKind::Pe, &pe(0x2022, 2)[..0x60]),
            ("exe", "fallback")
        );
    }

    #[test]
    fn sniff_respects_a_nonzero_base_and_the_region_end() {
        let body = pe(0x2022, 2);
        let mut dump = vec![0xAAu8; 100];
        dump.extend_from_slice(&body);
        dump.extend_from_slice(&[0xBB; 100]);
        let mut c = Cursor::new(dump);
        let got = refine_ext(CarveKind::Pe, &mut c, 100, body.len() as u64);
        assert_eq!((got.ext, got.source), ("dll", "sniff:pe/dll"));
    }

    // --- MP4 ---

    fn mp4(brand: &[u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 0, 0, 0x18];
        b.extend_from_slice(b"ftyp");
        b.extend_from_slice(brand);
        b.extend_from_slice(&[0u8; 12]);
        b
    }

    #[test]
    fn mp4_brands() {
        assert_eq!(
            pick(CarveKind::Mp4, &mp4(b"M4A ")),
            ("m4a", "sniff:mp4/M4A")
        );
        assert_eq!(pick(CarveKind::Mp4, &mp4(b"qt  ")), ("mov", "sniff:mp4/qt"));
        assert_eq!(pick(CarveKind::Mp4, &mp4(b"isom")), ("mp4", "kind"));
        assert_eq!(pick(CarveKind::Mp4, &[0u8; 32]), ("mp4", "fallback"));
    }

    // --- ZIP ---

    /// Stored-only ZIP with a central directory and an end record.
    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for (name, data) in entries {
            let offset = out.len() as u32;
            out.extend_from_slice(b"PK\x03\x04");
            out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver flags method time date
            out.extend_from_slice(&0u32.to_le_bytes()); // crc
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);

            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            cd.extend_from_slice(&0u32.to_le_bytes()); // crc
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
            cd.extend_from_slice(&offset.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = out.len() as u32;
        let cd_len = cd.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_len.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    #[test]
    fn zip_office_android_and_java() {
        let docx = zip(&[("[Content_Types].xml", b"x"), ("word/document.xml", b"x")]);
        assert_eq!(pick(CarveKind::Zip, &docx), ("docx", "sniff:zip/word"));
        let xlsx = zip(&[("[Content_Types].xml", b"x"), ("xl/workbook.xml", b"x")]);
        assert_eq!(pick(CarveKind::Zip, &xlsx), ("xlsx", "sniff:zip/excel"));
        let pptx = zip(&[
            ("[Content_Types].xml", b"x"),
            ("ppt/presentation.xml", b"x"),
        ]);
        assert_eq!(
            pick(CarveKind::Zip, &pptx),
            ("pptx", "sniff:zip/powerpoint")
        );
        let apk = zip(&[
            ("META-INF/MANIFEST.MF", b"x"),
            ("AndroidManifest.xml", b"x"),
            ("classes.dex", b"x"),
        ]);
        assert_eq!(pick(CarveKind::Zip, &apk), ("apk", "sniff:zip/android"));
        let jar = zip(&[("META-INF/MANIFEST.MF", b"x"), ("a/B.class", b"x")]);
        assert_eq!(pick(CarveKind::Zip, &jar), ("jar", "sniff:zip/jar"));
        let plain = zip(&[("notes.txt", b"hello")]);
        assert_eq!(pick(CarveKind::Zip, &plain), ("zip", "kind"));
        // Office-like container with no known part stays a plain zip.
        let odd = zip(&[("[Content_Types].xml", b"x"), ("visio/pages.xml", b"x")]);
        assert_eq!(pick(CarveKind::Zip, &odd), ("zip", "kind"));
    }

    #[test]
    fn zip_odf_by_mimetype_even_when_the_tail_is_gone() {
        for (mime, ext) in [
            (&b"application/vnd.oasis.opendocument.text"[..], "odt"),
            (
                &b"application/vnd.oasis.opendocument.spreadsheet"[..],
                "ods",
            ),
            (
                &b"application/vnd.oasis.opendocument.presentation"[..],
                "odp",
            ),
        ] {
            let z = zip(&[("mimetype", mime), ("content.xml", b"x")]);
            assert_eq!(run(CarveKind::Zip, &z).ext, ext);
            let cut = &z[..z.len() / 2];
            assert_eq!(run(CarveKind::Zip, cut).ext, ext);
        }
        let epub = zip(&[("mimetype", b"application/epub+zip"), ("a.xhtml", b"x")]);
        assert_eq!(pick(CarveKind::Zip, &epub), ("zip", "kind"));
    }

    #[test]
    fn zip_without_a_readable_central_directory_falls_back() {
        let docx = zip(&[("[Content_Types].xml", b"x"), ("word/document.xml", b"x")]);
        // Tail cut off: the central directory is gone.
        assert_eq!(
            pick(CarveKind::Zip, &docx[..docx.len() / 2]),
            ("zip", "fallback")
        );
        // End record pointing past the data.
        let mut lie = docx.clone();
        let n = lie.len();
        lie[n - 6..n - 2].copy_from_slice(&0x7fff_0000u32.to_le_bytes());
        assert_eq!(pick(CarveKind::Zip, &lie), ("zip", "fallback"));
    }

    // --- OLE ---

    fn ole(names: &[&str], cycle: bool) -> Vec<u8> {
        let mut b = vec![0u8; 512 * 3];
        b[..8].copy_from_slice(&OLE_MAGIC);
        b[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
        b[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        b[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        for i in 0..109usize {
            let v: u32 = if i == 0 { 0 } else { 0xFFFF_FFFF };
            b[0x4c + 4 * i..0x4c + 4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
        // FAT sector 0 lives at 512; the directory is sector 1 at 1024.
        for i in 0..128usize {
            b[512 + 4 * i..512 + 4 * i + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        }
        b[512..516].copy_from_slice(&0xFFFF_FFFDu32.to_le_bytes());
        let next: u32 = if cycle { 1 } else { 0xFFFF_FFFE };
        b[516..520].copy_from_slice(&next.to_le_bytes());
        let mut entry = |idx: usize, name: &str, ty: u8| {
            let e = 1024 + 128 * idx;
            let units: Vec<u16> = name.encode_utf16().collect();
            for (k, u) in units.iter().enumerate() {
                b[e + 2 * k..e + 2 * k + 2].copy_from_slice(&u.to_le_bytes());
            }
            let nlen = ((units.len() + 1) * 2) as u16;
            b[e + 0x40..e + 0x42].copy_from_slice(&nlen.to_le_bytes());
            b[e + 0x42] = ty;
        };
        entry(0, "Root Entry", 5);
        for (i, n) in names.iter().enumerate() {
            entry(i + 1, n, 2);
        }
        b
    }

    #[test]
    fn ole_office_outlook_and_installer() {
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["WordDocument"], false)),
            ("doc", "sniff:ole/word")
        );
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["Workbook"], false)),
            ("xls", "sniff:ole/excel")
        );
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["Book"], false)),
            ("xls", "sniff:ole/excel")
        );
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["PowerPoint Document"], false)),
            ("ppt", "sniff:ole/powerpoint")
        );
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["__properties_version1.0"], false)),
            ("msg", "sniff:ole/msg")
        );
        assert_eq!(
            pick(
                CarveKind::Ole,
                &ole(&["\u{5}SummaryInformation", "\u{4840}\u{3a}x"], false)
            ),
            ("msi", "sniff:ole/msi")
        );
        // Summary information alone (every Office file has it) is not an MSI.
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["\u{5}SummaryInformation"], false)),
            ("ole", "kind")
        );
        assert_eq!(pick(CarveKind::Ole, &ole(&["Foo"], false)), ("ole", "kind"));
    }

    #[test]
    fn ole_directory_loop_terminates_and_still_classifies() {
        let got = pick(CarveKind::Ole, &ole(&["WordDocument"], true));
        assert_eq!(got, ("doc", "sniff:ole/word"));
    }

    #[test]
    fn ole_with_a_broken_header_or_directory_falls_back() {
        let mut b = ole(&["WordDocument"], false);
        b[0x1e] = 7; // sector shift neither 9 nor 12
        assert_eq!(pick(CarveKind::Ole, &b), ("ole", "fallback"));
        let mut b = ole(&["WordDocument"], false);
        b[0x30..0x34].copy_from_slice(&0x00ff_ffffu32.to_le_bytes()); // dir far outside
        assert_eq!(pick(CarveKind::Ole, &b), ("ole", "fallback"));
        assert_eq!(
            pick(CarveKind::Ole, &ole(&["WordDocument"], false)[..300]),
            ("ole", "fallback")
        );
    }

    // --- ELF ---

    fn elf64(e_type: u16, p_type: u32) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 56];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&e_type.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        b[64..68].copy_from_slice(&p_type.to_le_bytes());
        b
    }

    #[test]
    fn elf_shared_object_versus_executables() {
        assert_eq!(pick(CarveKind::Elf, &elf64(3, 1)), ("so", "sniff:elf/dyn"));
        // PIE executable: ET_DYN with PT_INTERP.
        assert_eq!(pick(CarveKind::Elf, &elf64(3, 3)), ("elf", "kind"));
        assert_eq!(pick(CarveKind::Elf, &elf64(2, 1)), ("elf", "kind"));
        // Table claims more entries than the file holds.
        let mut b = elf64(3, 1);
        b[56..58].copy_from_slice(&1000u16.to_le_bytes());
        assert_eq!(pick(CarveKind::Elf, &b), ("elf", "fallback"));
    }

    #[test]
    fn elf32_big_endian_is_read_with_the_right_byte_order() {
        let mut b = vec![0u8; 52 + 32];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 1;
        b[5] = 2;
        b[16..18].copy_from_slice(&3u16.to_be_bytes());
        b[28..32].copy_from_slice(&52u32.to_be_bytes());
        b[42..44].copy_from_slice(&32u16.to_be_bytes());
        b[44..46].copy_from_slice(&1u16.to_be_bytes());
        b[52..56].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(pick(CarveKind::Elf, &b), ("so", "sniff:elf/dyn"));
    }

    // --- robustness ---

    #[test]
    fn garbage_never_panics_and_only_returns_whitelisted_extensions() {
        let mut noise = vec![0u8; 8192];
        let mut x = 0x1234_5678u32;
        for b in noise.iter_mut() {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let inputs: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0u8; 3],
            vec![0xFFu8; 1024],
            noise,
            b"PK\x05\x06".to_vec(),
        ];
        for kind in [
            CarveKind::Pe,
            CarveKind::Mp4,
            CarveKind::Zip,
            CarveKind::Ole,
            CarveKind::Elf,
            CarveKind::Png,
        ] {
            for input in &inputs {
                let got = run(kind, input);
                assert!(valid_ext(got.ext), "{kind:?}: {}", got.ext);
                assert!(
                    got.source == "kind"
                        || got.source == "fallback"
                        || got.source.starts_with("sniff:"),
                    "{kind:?}: {}",
                    got.source
                );
            }
        }
    }

    /// Cursor that remembers the span of bytes actually read, so a test can
    /// prove a sniff never looks outside its region.
    struct Spy {
        inner: Cursor<Vec<u8>>,
        lo: u64,
        hi: u64,
    }

    impl Read for Spy {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let at = self.inner.position();
            let n = self.inner.read(buf)?;
            if n > 0 {
                self.lo = self.lo.min(at);
                self.hi = self.hi.max(at + n as u64);
            }
            Ok(n)
        }
    }

    impl Seek for Spy {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// Extensions each kind may legally end up with.
    fn allowed(kind: CarveKind) -> &'static [&'static str] {
        match kind {
            CarveKind::Pe => &["exe", "dll", "sys"],
            CarveKind::Mp4 => &["mp4", "m4a", "mov"],
            CarveKind::Zip => &[
                "zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "apk", "jar",
            ],
            CarveKind::Ole => &["ole", "doc", "xls", "ppt", "msg", "msi"],
            CarveKind::Elf => &["elf", "so"],
            _ => &[],
        }
    }

    /// Deterministic mutation sweep (B7, ROADMAP 8.10.9 "header-offset bugs"):
    /// every valid fixture is truncated at every length and has each byte
    /// overwritten with a few hostile values. The sniff must not panic, must
    /// stay inside its region (also at a non-zero base with junk after it),
    /// and may only return an extension its kind is allowed to have.
    #[test]
    fn mutated_fixtures_never_panic_leave_the_region_or_pick_a_foreign_extension() {
        let fixtures: Vec<(CarveKind, Vec<u8>)> = vec![
            (CarveKind::Pe, pe(0x2022, 2)),
            (CarveKind::Pe, pe(0x0022, 1)),
            (CarveKind::Mp4, mp4(b"M4A ")),
            (CarveKind::Mp4, mp4(b"qt  ")),
            (
                CarveKind::Zip,
                zip(&[("[Content_Types].xml", b"x"), ("word/document.xml", b"x")]),
            ),
            (
                CarveKind::Zip,
                zip(&[("mimetype", b"application/vnd.oasis.opendocument.text")]),
            ),
            (
                CarveKind::Zip,
                zip(&[
                    ("META-INF/MANIFEST.MF", b"x"),
                    ("AndroidManifest.xml", b"x"),
                ]),
            ),
            (CarveKind::Ole, ole(&["WordDocument"], false)),
            (
                CarveKind::Ole,
                ole(&["\u{5}SummaryInformation", "\u{4840}\u{3a}x"], false),
            ),
            (CarveKind::Ole, ole(&["Workbook"], true)),
            (CarveKind::Elf, elf64(3, 1)),
        ];
        const HOSTILE: [u8; 4] = [0x00, 0xFF, 0x80, 0x7F];
        const BASE: u64 = 37;

        let check = |kind: CarveKind, bytes: &[u8]| {
            // Region at offset 0 and the same region inside a larger dump.
            let mut dump = vec![0xA5u8; BASE as usize];
            dump.extend_from_slice(bytes);
            dump.extend_from_slice(&[0x5Au8; 4096]);
            for (data, base) in [(bytes.to_vec(), 0u64), (dump, BASE)] {
                let mut spy = Spy {
                    inner: Cursor::new(data),
                    lo: u64::MAX,
                    hi: 0,
                };
                let got = refine_ext(kind, &mut spy, base, bytes.len() as u64);
                assert!(valid_ext(got.ext), "{kind:?}: {}", got.ext);
                assert!(
                    got.ext == kind.default_ext() || allowed(kind).contains(&got.ext),
                    "{kind:?} -> {}",
                    got.ext
                );
                assert!(
                    got.source == "kind"
                        || got.source == "fallback"
                        || got.source.starts_with("sniff:"),
                    "{kind:?}: {}",
                    got.source
                );
                if spy.hi > 0 {
                    assert!(
                        spy.lo >= base,
                        "{kind:?} read before the region ({})",
                        spy.lo
                    );
                    assert!(
                        spy.hi <= base + bytes.len() as u64,
                        "{kind:?} read past the region ({})",
                        spy.hi
                    );
                }
            }
        };

        for (kind, original) in &fixtures {
            check(*kind, original);
            for cut in 0..original.len() {
                check(*kind, &original[..cut]);
            }
            for pos in 0..original.len() {
                for v in HOSTILE {
                    if original[pos] == v {
                        continue;
                    }
                    let mut m = original.clone();
                    m[pos] = v;
                    check(*kind, &m);
                }
            }
        }
    }

    #[test]
    fn every_refined_extension_is_whitelisted() {
        for ext in [
            "dll", "sys", "m4a", "mov", "docx", "xlsx", "pptx", "odt", "ods", "odp", "apk", "jar",
            "doc", "xls", "ppt", "msg", "msi", "so",
        ] {
            assert!(valid_ext(ext), "{ext}");
        }
    }

    /// Manual check against a real installer:
    /// `BXMAP_REAL_MSI=path\to\file.msi cargo test --lib real_msi -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn real_msi_is_recognised() {
        let Ok(path) = std::env::var("BXMAP_REAL_MSI") else {
            return;
        };
        let mut f = std::fs::File::open(&path).unwrap();
        let len = f.metadata().unwrap().len();
        let got = refine_ext(CarveKind::Ole, &mut f, 0, len);
        println!("{path}: {} ({})", got.ext, got.source);
        assert_eq!((got.ext, got.source), ("msi", "sniff:ole/msi"));
    }

    #[test]
    fn kinds_without_a_rule_keep_their_default() {
        assert_eq!(pick(CarveKind::Png, b"\x89PNG\r\n\x1a\n"), ("png", "kind"));
        assert_eq!(pick(CarveKind::Webm, b"whatever"), ("webm", "kind"));
    }
}
