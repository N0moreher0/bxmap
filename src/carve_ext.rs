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
/// Most import descriptors we follow before giving up (the linker emits a few).
const PE_IMPORT_DESCRIPTOR_CAP: usize = 64;
/// Largest module name we read from the import table.
const PE_MODULE_NAME_MAX: usize = 256;
/// Kernel-mode images link the kernel itself (or the KMDF loader) — every
/// driver on Windows 10/11 does, so this is a much sharper discriminator
/// than the subsystem flag: it splits genuine drivers from native EXEs
/// (`smss.exe`, `csrss.exe`, …), which also use `SUBSYSTEM_NATIVE`.
const PE_KERNEL_MODULES: [&[u8]; 3] = [b"ntoskrnl.exe", b"wdf01000.sys", b"wdfldr.sys"];
/// Kernel API-set family (e.g. `ext-ms-win-ntos-clipsp-l1-1-0.dll`); only the
/// `ntos-` namespace is treated as kernel evidence (`ext-ms-win-fs-clfs` and
/// friends are left ambiguous and need one of the other kernel signals).
const PE_KERNEL_PREFIX: &[u8] = b"ext-ms-win-ntos-";
/// Win32 API-set family; every user-mode image imports these (or ntdll).
const PE_USER_PREFIX: &[u8] = b"api-ms-win-";
const PE_USER_MODULES: [&[u8]; 4] = [
    b"ntdll.dll",
    b"kernel32.dll",
    b"user32.dll",
    b"kernelbase.dll",
];
/// Kernel-mode section name observed in Windows 11 kernel images (`.sys`
/// and kernel-mode `.dll` alike). Measured on 4,773 real PEs: **every**
/// `.sys` has an `INIT` section (479/479), only 1.09% of `.dll` and 0.16% of
/// `.exe` do — the dlls that do are kernel images shipped with a .dll
/// extension (symcryptk.dll profile). Names that matched on Windows (PAGE,
/// GFIDS, PAGEDATA…) are redundant with INIT here and pull in false
/// positives; `.mrdata`/`.dodata` matched user-mode images, so they were
/// dropped outright. Memory dumps that scrub the import table keep the
/// headers, so this is usually the strongest surviving evidence.
const PE_KERNEL_SECTIONS: [&[u8]; 1] = [b"init"];

/// What the import table can prove about the image's subsystem family.
enum ImportScan {
    /// Kernel image (`.sys`): imports the kernel or KMDF, or a `ntos-` API set.
    Kernel,
    /// User-mode image (`.exe`): imports ntdll/kernel32 or `api-ms-win-*`.
    User,
    /// Nothing readable (no import directory, RVAs outside the sections,
    /// truncated region): fall back to the subsystem flag.
    Unknown,
}

struct PeSection {
    va: u32,
    raw_size: u32,
    raw_ptr: u32,
    /// Section name, lowercased and trimmed of trailing NULs/spaces.
    name: Vec<u8>,
}

fn pe_rva_to_file(sections: &[PeSection], rva: u32) -> Option<u64> {
    for s in sections {
        if rva >= s.va {
            let delta = u64::from(rva - s.va);
            if delta < u64::from(s.raw_size) {
                return Some(u64::from(s.raw_ptr) + delta);
            }
        }
    }
    None
}

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
    let optional_size = rd16(&head, p.saturating_add(20), false).unwrap_or(0);
    let magic = rd16(&head, p.saturating_add(24), false).unwrap_or(0);
    // The import table decides first: Windows 10/11 kernel drivers link the
    // kernel itself — and many of them also set IMAGE_FILE_DLL (ks.sys,
    // fltMgr.sys, …), so the DLL bit alone cannot tell a driver from a
    // user-mode library. A user-mode DLL never imports ntoskrnl.
    let sections = pe_sections(&head, p, optional_size);
    let scan = pe_import_scan(r, base, size, &head, p, magic, sections.as_deref());
    if matches!(scan, ImportScan::Kernel) {
        return Ok(Sniff::Refined("sys", "sniff:pe/kernel-import"));
    }
    // The import table proved nothing (typically RAM-dump PEs whose import
    // descriptors were zeroed): run the elimination ladder on what survived.
    // It outranks the DLL bit on purpose: the kernel images Windows ships
    // with a .dll extension (symcryptk.dll, the 0x3a8c000 Lab 6 case) set
    // IMAGE_FILE_DLL too.
    if let Some(refined) = pe_elimination(
        characteristics,
        &head,
        p,
        magic,
        sections.as_deref().unwrap_or(&[]),
    ) {
        return Ok(refined);
    }
    if characteristics & PE_FILE_DLL != 0 {
        return Ok(Sniff::Refined("dll", "sniff:pe/dll"));
    }
    if matches!(scan, ImportScan::User) {
        return Ok(Sniff::Refined("exe", "sniff:pe/user-import"));
    }
    // Subsystem sits at offset 68 of the optional header for PE32 and PE32+.
    if optional_size >= 70
        && rd16(&head, p.saturating_add(24 + 68), false) == Some(PE_SUBSYSTEM_NATIVE)
    {
        return Ok(Sniff::Refined("sys", "sniff:pe/native"));
    }
    Ok(Sniff::Generic)
}

/// Elimination ladder for PEs whose import table was unreadable (RAM dumps
/// that scrubbed the loader's descriptor pages). Runs only when
/// [`pe_import_scan`] yields `Unknown`, in order:
///
/// 1. A delay-load directory ⇒ user-mode image (kernel drivers never
///    delay-load): with the DLL bit ⇒ `.dll`, else `.exe`.
/// 2. Kernel-mode section names (`PAGE`, `PAGEDATA`, `INIT`, `GFIDS`,
///    `NONPAGED`, …) ⇒ kernel image ⇒ `.sys`. Measured on 4,773 real PEs
///    (Windows 11): every `.sys` has at least one, ~2% of `.dll` do too
///    (kernel-mode DLLs such as symcryptk.dll — also kernel images).
/// 3. `SUBSYSTEM_NATIVE` + DLL bit + no export directory ⇒ kernel image
///    with a `.dll` extension (symcryptk.dll profile) ⇒ `.sys`.
/// 4. Otherwise no evidence — the caller keeps the weak subsystem rule.
fn pe_elimination(
    characteristics: u16,
    head: &[u8],
    p: usize,
    magic: u16,
    sections: &[PeSection],
) -> Option<Sniff> {
    let directories_at = p.saturating_add(24 + if magic == 0x10b { 96 } else { 112 });
    let delay_rva = rd32(head, directories_at.saturating_add(13 * 8), false).unwrap_or(0);
    if delay_rva != 0 {
        return Some(if characteristics & PE_FILE_DLL != 0 {
            Sniff::Refined("dll", "sniff:pe/user-delay")
        } else {
            Sniff::Refined("exe", "sniff:pe/user-delay")
        });
    }
    if sections
        .iter()
        .any(|s| PE_KERNEL_SECTIONS.contains(&s.name.as_slice()))
    {
        return Some(Sniff::Refined("sys", "sniff:pe/kernel-section"));
    }
    let export_rva = rd32(head, directories_at, false).unwrap_or(0);
    if characteristics & PE_FILE_DLL != 0
        && export_rva == 0
        && rd16(head, p.saturating_add(24 + 68), false) == Some(PE_SUBSYSTEM_NATIVE)
    {
        return Some(Sniff::Refined("sys", "sniff:pe/kernel-noexports"));
    }
    None
}

/// Walk the import descriptor array and decide whether the image links the
/// kernel. Reads are bounded (≤ 64 descriptors, ≤ 256 B per name) and clipped
/// to the region like everything else here. `sections` is the already-parsed
/// section table (`None` when it does not fit the head window).
fn pe_import_scan<R: Read + Seek>(
    r: &mut R,
    base: u64,
    size: u64,
    head: &[u8],
    p: usize,
    magic: u16,
    sections: Option<&[PeSection]>,
) -> ImportScan {
    let directories_at = match magic {
        0x10b => p.saturating_add(24 + 96),  // PE32
        0x20b => p.saturating_add(24 + 112), // PE32+
        _ => return ImportScan::Unknown,
    };
    // Optional header holds at least one data directory.
    let count_at = match magic {
        0x10b => p.saturating_add(24 + 92),
        _ => p.saturating_add(24 + 108),
    };
    if rd32(head, count_at, false) == Some(0) {
        return ImportScan::Unknown;
    }
    let Some(sections) = sections else {
        return ImportScan::Unknown;
    };
    // Data directory 1 is the import table (RVAs are relative to image base).
    let Some(import_rva) = rd32(head, directories_at.saturating_add(8), false) else {
        return ImportScan::Unknown;
    };
    if import_rva == 0 {
        return ImportScan::Unknown;
    }
    let Some(import_off) = pe_rva_to_file(sections, import_rva) else {
        return ImportScan::Unknown;
    };
    let mut saw_user = false;
    for index in 0..PE_IMPORT_DESCRIPTOR_CAP {
        let at = import_off.saturating_add(index as u64 * 20);
        let Ok(desc) = read_at(r, base, size, at, 20) else {
            return ImportScan::Unknown;
        };
        if desc.len() < 20 {
            return ImportScan::Unknown;
        }
        let name_rva = rd32(&desc, 12, false).unwrap_or(0);
        // An all-zero descriptor terminates the array.
        if name_rva == 0 && rd32(&desc, 0, false) == Some(0) && rd32(&desc, 16, false) == Some(0) {
            return done(saw_user);
        }
        if name_rva == 0 {
            continue;
        }
        let Some(name_off) = pe_rva_to_file(sections, name_rva) else {
            continue;
        };
        let Ok(raw) = read_at(r, base, size, name_off, PE_MODULE_NAME_MAX as u64) else {
            continue;
        };
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        if end == 0 {
            continue;
        }
        let name = &raw[..end];
        if is_kernel_module(name) {
            return ImportScan::Kernel;
        }
        if is_user_module(name) {
            saw_user = true;
        }
    }
    done(saw_user)
}

fn done(saw_user: bool) -> ImportScan {
    if saw_user {
        ImportScan::User
    } else {
        ImportScan::Unknown
    }
}

/// Parse the section table out of the (already bounded) head window.
fn pe_sections(head: &[u8], p: usize, optional_size: u16) -> Option<Vec<PeSection>> {
    let nsect = rd16(head, p + 6, false)? as usize;
    if nsect == 0 || nsect > 96 {
        return None;
    }
    let table = p.saturating_add(24).saturating_add(optional_size as usize);
    let table_end = table.saturating_add(nsect.saturating_mul(40));
    if head.len() < table_end {
        return None;
    }
    let mut out = Vec::with_capacity(nsect);
    for index in 0..nsect {
        let at = table + index * 40;
        let raw_size = rd32(head, at + 16, false)?;
        let raw_ptr = rd32(head, at + 20, false)?;
        // Sections without raw data (BSS) never map RVAs; they are skipped but
        // kept for their names? No — a BSS section still may carry a kernel
        // name (.mrdata/.dodata are usually zero-initialised), so keep it.
        let mut name = head[at..at + 8].to_vec();
        let end = name
            .iter()
            .rposition(|&b| b != 0 && b != b' ')
            .map(|i| i + 1)
            .unwrap_or(0);
        name.truncate(end);
        let name = lower(&name);
        if raw_size > 0 {
            let va = rd32(head, at + 12, false)?;
            out.push(PeSection {
                va,
                raw_size,
                raw_ptr,
                name,
            });
        } else if !name.is_empty() {
            // No raw data: never maps an RVA, but the name still counts as
            // evidence for the elimination ladder.
            out.push(PeSection {
                va: 0,
                raw_size: 0,
                raw_ptr: 0,
                name,
            });
        }
    }
    Some(out)
}

fn lower(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn is_kernel_module(name: &[u8]) -> bool {
    let name = lower(name);
    PE_KERNEL_MODULES.contains(&name.as_slice()) || name.starts_with(PE_KERNEL_PREFIX)
}

fn is_user_module(name: &[u8]) -> bool {
    let name = lower(name);
    PE_USER_MODULES.contains(&name.as_slice()) || name.starts_with(PE_USER_PREFIX)
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
        // ntdll-style: a native-subsystem user DLL exports functions.
        let dirs = p + 24 + 112;
        b[p + 24 + 108..p + 24 + 112].copy_from_slice(&16u32.to_le_bytes());
        b[dirs..dirs + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        b[dirs + 4..dirs + 8].copy_from_slice(&0x100u32.to_le_bytes());
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

    /// PE32+ image with named sections and optional export/delay-load
    /// directories. The import directory stays absent (rva = 0): the fixture
    /// models RAM-dump PEs whose import descriptors were zeroed. Direction of
    /// the layout: header 0x00-0x200, sections raw at 0x200 + 0x200 * i.
    fn pe_layout(
        characteristics: u16,
        subsystem: u16,
        sections: &[&[u8]],
        exports: bool,
        delay: bool,
    ) -> Vec<u8> {
        let nsect = sections.len();
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let p = 0x80usize;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 6..p + 8].copy_from_slice(&(nsect as u16).to_le_bytes());
        b[p + 20..p + 22].copy_from_slice(&0xF0u16.to_le_bytes());
        b[p + 22..p + 24].copy_from_slice(&characteristics.to_le_bytes());
        let o = p + 24usize; // optional header
        b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        let dirs = o + 112;
        if exports {
            b[dirs..dirs + 4].copy_from_slice(&0x2000u32.to_le_bytes());
            b[dirs + 4..dirs + 8].copy_from_slice(&0x40u32.to_le_bytes());
        }
        if delay {
            let at = dirs + 13 * 8;
            b[at..at + 4].copy_from_slice(&0x2000u32.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&0x60u32.to_le_bytes());
        }
        b[o + 68..o + 70].copy_from_slice(&subsystem.to_le_bytes());
        for (i, name) in sections.iter().enumerate() {
            let at = o + 0xF0 + i * 40;
            let va = 0x1000u32 + i as u32 * 0x1000;
            let raw = 0x200usize + i * 0x200;
            let mut raw_size = 0x200u32;
            if name.starts_with(b"BSS") {
                raw_size = 0;
            }
            let mut slot = [0u8; 8];
            let copy_len = name.len().min(8);
            slot[..copy_len].copy_from_slice(&name[..copy_len]);
            b[at..at + 8].copy_from_slice(&slot);
            b[at + 8..at + 12].copy_from_slice(&0x100u32.to_le_bytes());
            b[at + 12..at + 16].copy_from_slice(&va.to_le_bytes());
            b[at + 16..at + 20].copy_from_slice(&raw_size.to_le_bytes());
            b[at + 20..at + 24].copy_from_slice(&(raw as u32).to_le_bytes());
            if b.len() < raw + raw_size as usize {
                b.resize(raw + raw_size as usize, 0);
            }
        }
        b
    }

    #[test]
    fn pe_delay_load_marks_the_image_user_mode() {
        // Delay-load directory ⇒ user image; the DLL bit maps the extension.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x2022, 1, &[b".text", b".rsrc"], false, true)
            ),
            ("dll", "sniff:pe/user-delay")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 1, &[b".text"], false, true)
            ),
            ("exe", "sniff:pe/user-delay")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 3, &[b".text"], false, true)
            ),
            ("exe", "sniff:pe/user-delay")
        );
    }

    #[test]
    fn pe_kernel_sections_mark_the_image_kernel() {
        // INIT: the anchor (100% of .sys on Windows 11, 1% of .dll).
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x2022, 1, &[b".text", b"INIT"], false, false)
            ),
            ("sys", "sniff:pe/kernel-section")
        );
        // Kernel evidence beats the DLL bit (symcryptk.dll style).
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 3, &[b".text", b"INIT"], false, false)
            ),
            ("sys", "sniff:pe/kernel-section")
        );
        // Mixed case section names are lowered for matching.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 1, &[b"Init"], false, false)
            ),
            ("sys", "sniff:pe/kernel-section")
        );
        // Other names are not evidence: they keep the weak/default rules.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 1, &[b".text", b"PAGEDATA"], false, false)
            ),
            ("sys", "sniff:pe/native")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 3, &[b".text", b"PAGEDATA"], false, false)
            ),
            ("exe", "kind")
        );
    }

    #[test]
    fn pe_native_dll_without_exports_is_kernel() {
        // The symcryptk.dll profile: DLL bit + SUBSYSTEM_NATIVE + no export
        // directory (kernel-mode image with a .dll extension).
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x2022, 1, &[b".text", b".rdata"], false, false)
            ),
            ("sys", "sniff:pe/kernel-noexports")
        );
        // Exports present: that evidence is gone, the DLL bit (or a weaker
        // rung) decides.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x2022, 1, &[b".text"], true, false)
            ),
            ("dll", "sniff:pe/dll")
        );
    }

    #[test]
    fn pe_no_elimination_evidence_keeps_the_old_rules() {
        // No delay, no kernel sections, exports present or not: left to the
        // weak subsystem rule / default, exactly as 8.10.12 behaved.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 1, &[b".text"], false, false)
            ),
            ("sys", "sniff:pe/native")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x0022, 3, &[b".text"], false, false)
            ),
            ("exe", "kind")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_layout(0x2022, 3, &[b".text"], false, false)
            ),
            ("dll", "sniff:pe/dll")
        );
    }

    /// Build a PE32+ image with two sections and an import table naming
    /// `modules`. Layout: MZ stub 0x00-0x80, PE signature at 0x80, COFF at
    /// 0x84, optional header at 0x98 (size 0xF0), section table at 0x188,
    /// `.text` raw at 0x200, `.idata` raw at 0x400.
    fn pe_with_imports(characteristics: u16, subsystem: u16, modules: &[&[u8]]) -> Vec<u8> {
        const LAYOUT: usize = 0x600;
        let mut b = vec![0u8; LAYOUT];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let p = 0x80usize;
        b[p..p + 4].copy_from_slice(b"PE\0\0");
        b[p + 6..p + 8].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
        b[p + 20..p + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // optSize
        b[p + 22..p + 24].copy_from_slice(&characteristics.to_le_bytes());
        let o = p + 24usize; // optional header (PE32+)
        b[o..o + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        b[o + 108..o + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
                                                                   // Idata section: va 0x2000, raw 0x400. Import directory = dir[1].
        b[o + 112 + 8..o + 112 + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        b[o + 112 + 12..o + 112 + 16].copy_from_slice(&0x60u32.to_le_bytes());
        let t = o + 0xF0; // section table
        let put_section =
            |slot: &mut [u8], name: &[u8; 8], va: u32, raw_size: u32, raw_ptr: u32| {
                slot[..8].copy_from_slice(name);
                slot[8..12].copy_from_slice(&0x100u32.to_le_bytes()); // vsize
                slot[12..16].copy_from_slice(&va.to_le_bytes());
                slot[16..20].copy_from_slice(&raw_size.to_le_bytes());
                slot[20..24].copy_from_slice(&raw_ptr.to_le_bytes());
            };
        put_section(&mut b[t..t + 40], b".text\0\0\0", 0x1000, 0x200, 0x200);
        put_section(&mut b[t + 40..t + 80], b".idata\0\0", 0x2000, 0x200, 0x400);
        let n = modules.len();
        let desc_bytes = (n + 1) as u32 * 20;
        let mut name_rva = 0x2000u32 + desc_bytes;
        let mut at = 0x400usize; // file offset of the descriptor array
        for module in modules {
            b[at + 12..at + 16].copy_from_slice(&name_rva.to_le_bytes());
            let file_at = 0x400usize + (name_rva - 0x2000) as usize;
            b[file_at..file_at + module.len()].copy_from_slice(module);
            name_rva += module.len() as u32 + 1; // NUL-terminated
            at += 20;
        }
        let _ = subsystem; // subsystem lives at o+68; set it here too
        b[o + 68..o + 70].copy_from_slice(&subsystem.to_le_bytes());
        b
    }

    #[test]
    fn pe_kernel_imports_are_drivers() {
        // Windows 10/11 kernel images link the kernel itself even when they
        // export nothing (disk.sys ships no export table at all).
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"ntoskrnl.exe"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
        // KMDF drivers import the framework loader.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"wdf01000.sys"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
        // Kernel API-set namespace is kernel evidence.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"ext-ms-win-ntos-clipsp-l1-1-0.dll"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
        // A driver whose GUI-looking subsystem would defeat the old rule.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 3, &[b"ntoskrnl.exe", b"hal.dll"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
        // Case-insensitive module names (the loader accepts both).
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"NTOSKRNL.EXE"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
    }

    #[test]
    fn pe_user_imports_are_not_drivers() {
        // smss.exe / csrss.exe style: SUBSYSTEM_NATIVE but pure user imports.
        assert_eq!(
            pick(CarveKind::Pe, &pe_with_imports(0x0022, 1, &[b"ntdll.dll"])),
            ("exe", "sniff:pe/user-import")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"ntdll.dll", b"csrsrv.dll"])
            ),
            ("exe", "sniff:pe/user-import")
        );
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 1, &[b"api-ms-win-core-processthreads-l1-1-1.dll"])
            ),
            ("exe", "sniff:pe/user-import")
        );
        // A user-mode image with mixed evidence: any user import claims it.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(
                    0x0022,
                    3,
                    &[b"kernel32.dll", b"kernelbase.dll", b"ntdll.dll"]
                )
            ),
            ("exe", "sniff:pe/user-import")
        );
    }

    #[test]
    fn pe_imports_beyond_the_region_fall_back_to_the_subsystem_flag() {
        // Import directory lands outside every section: nothing readable,
        // weak subsystem evidence applies (the old rule).
        let mut b = pe_with_imports(0x0022, 1, &[b"ntoskrnl.exe"]);
        let o = 0x80 + 24usize;
        b[o + 112 + 8..o + 112 + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        assert_eq!(pick(CarveKind::Pe, &b), ("sys", "sniff:pe/native"));
        // Same, but with a GUI subsystem: the generic default stays.
        let mut b = pe_with_imports(0x0022, 3, &[b"ntoskrnl.exe"]);
        let o = 0x80 + 24usize;
        b[o + 112 + 8..o + 112 + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        assert_eq!(pick(CarveKind::Pe, &b), ("exe", "kind"));
        // Region ends mid-descriptor-array: equally unreadable.
        let b = pe_with_imports(0x0022, 1, &[b"ntoskrnl.exe"])[..0x410].to_vec();
        assert_eq!(pick(CarveKind::Pe, &b), ("sys", "sniff:pe/native"));
        // No descriptors at all (empty array): fall back too.
        assert_eq!(
            pick(CarveKind::Pe, &pe_with_imports(0x0022, 1, &[])),
            ("sys", "sniff:pe/native")
        );
        // Kernel evidence beats subsystem — even a "user" subsystem.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x0022, 2, &[b"ntoskrnl.exe"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
    }

    #[test]
    fn pe_kernel_import_beats_the_dll_flag_and_dll_beats_user_imports() {
        // Windows drivers ship with IMAGE_FILE_DLL (ks.sys: 0x2022) — the
        // import table outranks the bit.
        assert_eq!(
            pick(
                CarveKind::Pe,
                &pe_with_imports(0x2022, 1, &[b"ntoskrnl.exe"])
            ),
            ("sys", "sniff:pe/kernel-import")
        );
        // A user-mode DLL imports user modules and keeps the DLL bit.
        assert_eq!(
            pick(CarveKind::Pe, &pe_with_imports(0x2022, 3, &[b"ntdll.dll"])),
            ("dll", "sniff:pe/dll")
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
