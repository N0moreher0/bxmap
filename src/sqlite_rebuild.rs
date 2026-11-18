//! ROADMAP 8.14.2 — reconstruct a SQLite database whose 100-byte file
//! header was destroyed (ransomware / bad sectors), from the surviving
//! pages.
//!
//! The SQLite file header ("SQLite format 3\0" + 84 bytes) lives in the
//! first 100 bytes of the file, i.e. inside page 1. Pages 2..N are ordinary
//! b-tree pages whose type bytes (`0x05`/`0x02` interior, `0x0D`/`0x0A`
//! leaf) sit at every `page_size` boundary. When the header is gone we can
//! therefore still:
//!
//! 1. recover `page_size` from the stride of surviving b-tree page type
//!    bytes (512, 1024, 2048, 4096, 8192, 16384, 32768 or 65536);
//! 2. deep-validate every surviving page (type byte and header layout:
//!    first freeblock, cell count, cell-content offset);
//! 3. rebuild a fresh, honest 100-byte header: magic, page size,
//!    legacy read/write version 1, UTF-8 text encoding, change counter 1,
//!    freelist empty, schema cookie 1, schema format 4 — everything we do
//!    not know is written as a standard default and recorded in the notes;
//! 4. ship the file with `role=Rebuilt`, tier 2, evidence
//!    `btree_pages_verified` — and only when **all** surviving pages pass.
//!    A single unreadable page drops the whole candidate: half a
//!    reconstructed database with a confident label would be worse than
//!    no artifact.
//!
//! The rebuilt file is real bytes: page 1's b-tree header starts at file
//! offset 100, *outside* the destroyed 100-byte region, so
//! `sqlite3 rebuilt.db '.dump'` works whenever the destruction stayed
//! within the first 100 bytes.
//!
//! Scope limits (documented, kept on purpose):
//!
//! * ZIP-style "one page corrupt in the middle" DBs are rejected as a
//!   whole (see above), not shipped half-labelled;
//! * freelist/overflow pages (all-zero or pointer-led) break the
//!   consecutive-run detection, so the carve ends at the last verified
//!   b-tree page and trailing pages are not included;
//! * if the destruction reached into page >= 2 the rebuilt file is
//!   structurally valid but its page 1 is garbage — the notes say so.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

/// First candidate page size (SQLite allows 512..65536).
const PAGE_SIZES: [u64; 8] = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536];
/// Minimum surviving consecutive b-tree pages required to rebuild a header.
const MIN_PAGES: u64 = 8;
/// Cap on hits collected in the scan phase (guards against pathological
/// dumps; real dumps hold ~1-2% plausible bytes).
const MAX_HITS: usize = 64 * 1024 * 1024;

/// One surviving b-tree page (verified layout).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SqliteCandidate {
    /// Absolute offset of the (destroyed) page 1 — the carve starts here.
    pub start: u64,
    /// Offset just past the last verified page.
    pub end: u64,
    /// Page size in bytes.
    pub page_size: u64,
    /// True when page 1's b-tree header (file offset 100+) is plausible,
    /// i.e. the destruction stayed inside the 100-byte file header.
    pub page1_tree_ok: bool,
}

impl SqliteCandidate {
    /// Total pages in the rebuilt file (page 1 + verified pages).
    pub(crate) fn page_count(&self) -> u64 {
        (self.end - self.start) / self.page_size
    }
}

/// Plausible b-tree page type bytes: interior table / interior index /
/// leaf index / leaf table.
#[inline(always)]
fn plausible_type_byte(byte: u8) -> bool {
    matches!(byte, 0x02 | 0x05 | 0x0A | 0x0D)
}

/// Deep plausibility check of one b-tree page (type byte + header layout).
/// `page` must hold exactly the page bytes. Page 1 (the destroyed header
/// page) is *not* checked here — callers skip it.
fn validate_page(page: &[u8]) -> bool {
    let page_size = page.len() as u64;
    let Some(&type_byte) = page.first() else {
        return false;
    };
    if !plausible_type_byte(type_byte) {
        return false;
    }
    let interior = matches!(type_byte, 0x02 | 0x05);
    let header_size: usize = if interior { 12 } else { 8 };
    if page.len() < header_size {
        return false;
    }
    let first_free = u16::from_be_bytes([page[1], page[2]]) as u64;
    // First freeblock: 0 (none), or inside the page and past the page
    // header — anything else is a damaged header.
    if first_free != 0 && (first_free < header_size as u64 || first_free >= page_size) {
        return false;
    }
    let cell_count = u64::from(u16::from_be_bytes([page[3], page[4]]));
    let content_start = u16::from_be_bytes([page[5], page[6]]) as u64;
    if cell_count == 0 {
        // An empty page may declare content start 0 (unused) or point past
        // the page header; nothing to verify beyond that.
        return content_start == 0 || content_start >= header_size as u64;
    }
    if content_start == 0 || content_start > page_size {
        return false;
    }
    // The cell pointer array sits right after the page header; cell
    // content must start after it.
    let array_end = header_size as u64 + cell_count * 2;
    if content_start < array_end {
        return false;
    }
    if interior {
        let right_pointer = u32::from_be_bytes([page[8], page[9], page[10], page[11]]);
        if right_pointer == 0 {
            return false;
        }
    }
    true
}

fn validate_page1_tree(page: &[u8]) -> bool {
    // Page 1's b-tree header lives at file offset 100, past the 100-byte
    // file header. Only meaningful when ≥ 112 bytes of page 1 survive.
    if page.len() < 112 {
        return false;
    }
    validate_page(&page[100..])
}

/// Stream every plausible byte offset in `[span_start, span_end)`.
fn collect_hits(file: &mut File, span_start: u64, span_end: u64) -> io::Result<Vec<u64>> {
    const CHUNK: usize = 8 << 20; // 8 MiB
    let mut hits = Vec::new();
    let mut offset = span_start;
    let mut buf = vec![0u8; CHUNK];
    while offset < span_end {
        let take = (span_end - offset).min(CHUNK as u64) as usize;
        let slice = &mut buf[..take];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(slice)?;
        for (index, &byte) in slice.iter().enumerate() {
            if plausible_type_byte(byte) {
                hits.push(offset + index as u64);
                if hits.len() >= MAX_HITS {
                    return Ok(hits); // caller treats overflow as no-candidate
                }
            }
        }
        offset += take as u64;
    }
    Ok(hits)
}

/// Find runs of plausible b-tree page type bytes (stride `page_size`),
/// then deep-validate the pages and keep only fully verified candidates.
pub(crate) fn find_sqlite_bodies(
    file: &mut File,
    span_start: u64,
    span_end: u64,
    file_len: u64,
    max_size: u64,
) -> io::Result<Vec<SqliteCandidate>> {
    let hits = collect_hits(file, span_start, span_end)?;
    if hits.len() >= MAX_HITS {
        return Ok(Vec::new());
    }
    let mut out: Vec<(u64, u64, u64)> = Vec::new();
    for page_size in PAGE_SIZES {
        // One residue class per stride; runs are built incrementally.
        let mask = page_size - 1; // all page sizes are powers of two
        let mut pending: HashMap<u64, (u64, u64, u64)> = HashMap::new(); // residue -> (first, count, last)
        for &h in &hits {
            let residue = h & mask;
            match pending.get_mut(&residue) {
                Some(entry) if entry.2.saturating_add(page_size) == h => {
                    entry.1 += 1;
                    entry.2 = h;
                }
                Some(_) => {
                    let finished = pending.insert(residue, (h, 1, h)).expect("entry exists");
                    if finished.1 >= MIN_PAGES {
                        out.push((finished.0, finished.1, page_size));
                    }
                }
                None => {
                    pending.insert(residue, (h, 1, h));
                }
            }
        }
        for (_, entry) in pending {
            if entry.1 >= MIN_PAGES {
                out.push((entry.0, entry.1, page_size));
            }
        }
    }
    // `out` holds (run_first, run_pages, page_size). Deep-validate and
    // build the file span for each.
    let mut candidates = Vec::new();
    for (run_first, run_pages, page_size) in out {
        let Some(candidate) = verify_layout(
            file, run_first, run_pages, page_size, span_start, span_end, file_len, max_size,
        )?
        else {
            continue;
        };
        candidates.push(candidate);
    }
    // Overlap between candidates from different strides: keep the larger
    // span, then the earlier one.
    candidates.sort_by(|a, b| {
        (b.end - b.start)
            .cmp(&(a.end - a.start))
            .then(a.start.cmp(&b.start))
    });
    let mut kept: Vec<SqliteCandidate> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let overlaps = kept
            .iter()
            .any(|k| candidate.start < k.end && k.start < candidate.end);
        if !overlaps {
            kept.push(candidate);
        }
    }
    Ok(kept)
}

/// Decide the file span and deep-validate every surviving page.
#[allow(clippy::too_many_arguments)]
fn verify_layout(
    file: &mut File,
    run_first: u64,
    run_pages: u64,
    page_size: u64,
    span_start: u64,
    span_end: u64,
    file_len: u64,
    max_size: u64,
) -> io::Result<Option<SqliteCandidate>> {
    let verified_end = run_first + run_pages * page_size;
    // Alignment: with the file header destroyed, page 1's type byte is gone
    // and the run starts at page 2. With the file intact, the run starts at
    // page 1 and the standard header path owns the file — skip it.
    let (start, page1_tree_ok) = if run_first == span_start {
        // The run begins at the carve span start: page 1 at dump offset 0.
        let mut page1 = vec![0u8; page_size as usize];
        match read_exact_at(file, run_first, page_size as usize)? {
            Some(bytes) => {
                page1.copy_from_slice(&bytes);
            }
            None => return Ok(None),
        }
        if has_magic(&page1[..16.min(page1.len())]) {
            return Ok(None); // intact header: normal path carves this file
        }
        (run_first, validate_page1_tree(&page1))
    } else {
        let slot = run_first
            .checked_sub(page_size)
            .filter(|&slot| slot >= span_start);
        let Some(slot) = slot else {
            return Ok(None);
        };
        let mut page1 = vec![0u8; page_size as usize];
        match read_exact_at(file, slot, page_size as usize)? {
            Some(bytes) => page1.copy_from_slice(&bytes),
            None => return Ok(None),
        }
        if has_magic(&page1[..16]) {
            return Ok(None); // intact header: normal path carves this file
        }
        (slot, validate_page1_tree(&page1))
    };
    // Deep-validate every surviving page (all must pass).
    let mut offset = run_first;
    let mut page_buf = vec![0u8; page_size as usize];
    while offset < verified_end {
        match read_exact_at(file, offset, page_size as usize)? {
            Some(bytes) => page_buf.copy_from_slice(&bytes),
            None => return Ok(None),
        }
        if !validate_page(&page_buf) {
            return Ok(None);
        }
        offset += page_size;
    }
    let total = verified_end - start;
    if total > max_size {
        return Ok(None);
    }
    if verified_end > span_end || verified_end > file_len {
        return Ok(None);
    }
    Ok(Some(SqliteCandidate {
        start,
        end: verified_end,
        page_size,
        page1_tree_ok,
    }))
}

fn has_magic(bytes: &[u8]) -> bool {
    bytes.starts_with(b"SQLite format 3\x00")
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

/// Build the fresh 100-byte header for a rebuilt database.
/// Unknown fields are written as standard defaults; see module docs.
pub(crate) fn rebuilt_header(page_size: u64, pages: u64) -> [u8; 100] {
    let mut h = [0u8; 100];
    h[..16].copy_from_slice(b"SQLite format 3\x00");
    let raw: u16 = if page_size == 65536 {
        1
    } else {
        page_size as u16
    };
    h[16..18].copy_from_slice(&raw.to_be_bytes());
    h[18] = 1; // file format write version: legacy (WAL state unknowable)
    h[19] = 1; // file format read version: legacy
    h[20] = 0; // reserved bytes per page
    h[21] = 64; // max embedded payload fraction
    h[22] = 32; // min embedded payload fraction
    h[23] = 32; // leaf payload fraction
    h[24..28].copy_from_slice(&1u32.to_be_bytes()); // change counter
    h[28..32].copy_from_slice(&(pages as u32).to_be_bytes()); // in-header DB size
    h[32..36].copy_from_slice(&0u32.to_be_bytes()); // freelist trunk page
    h[36..40].copy_from_slice(&0u32.to_be_bytes()); // freelist pages
    h[40..44].copy_from_slice(&1u32.to_be_bytes()); // schema cookie
    h[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format
    h[48..52].copy_from_slice(&0u32.to_be_bytes()); // default page cache size
    h[52..56].copy_from_slice(&0u32.to_be_bytes()); // largest root b-tree page
    h[56..60].copy_from_slice(&1u32.to_be_bytes()); // text encoding: UTF-8
    h[60..64].copy_from_slice(&0u32.to_be_bytes()); // user version
    h[64..68].copy_from_slice(&0u32.to_be_bytes()); // incremental vacuum: off
    h[68..72].copy_from_slice(&0u32.to_be_bytes()); // application id
                                                    // 72..92: reserved for expansion, all zero
    h[92..96].copy_from_slice(&1u32.to_be_bytes()); // version-valid-for
    h[96..100].copy_from_slice(&3045000u32.to_be_bytes()); // SQLITE_VERSION_NUMBER (3.45.0)
    h
}

/// Read the dump span and produce the rebuilt file bytes
/// (fresh header + surviving pages verbatim).
pub(crate) fn rebuild_bytes(file: &mut File, candidate: &SqliteCandidate) -> io::Result<Vec<u8>> {
    let size = candidate.end - candidate.start;
    let mut bytes = vec![0u8; size as usize];
    file.seek(SeekFrom::Start(candidate.start))?;
    file.read_exact(&mut bytes)?;
    let header = rebuilt_header(candidate.page_size, candidate.page_count());
    bytes[..100].copy_from_slice(&header);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sqlite_simple.db")
    }

    fn dump_to_temp(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "bxmap-sqlite-{name}-{}-{}.bin",
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

    fn probe(path: &PathBuf, max_size: u64) -> Vec<SqliteCandidate> {
        let len = std::fs::metadata(path).unwrap().len();
        let mut file = File::open(path).unwrap();
        find_sqlite_bodies(&mut file, 0, len, len, max_size).unwrap()
    }

    fn destroyed() -> Vec<u8> {
        let raw = std::fs::read(fixture_path()).unwrap();
        let mut bytes = raw;
        for byte in &mut bytes[..100] {
            *byte = 0xAA;
        }
        bytes
    }

    #[test]
    fn header_layout_matches_sqlite_spec() {
        let h = rebuilt_header(4096, 10);
        assert_eq!(&h[..16], b"SQLite format 3\x00");
        assert_eq!(u16::from_be_bytes([h[16], h[17]]), 4096);
        assert_eq!(h[18], 1);
        assert_eq!(h[19], 1);
        assert_eq!(h[20], 0);
        assert_eq!(h[21], 64);
        assert_eq!(h[22], 32);
        assert_eq!(h[23], 32);
        assert_eq!(u32::from_be_bytes(h[24..28].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(h[28..32].try_into().unwrap()), 10);
        assert_eq!(u32::from_be_bytes(h[56..60].try_into().unwrap()), 1); // UTF-8
        assert_eq!(u32::from_be_bytes(h[96..100].try_into().unwrap()), 3045000);
    }

    #[test]
    fn page_size_65536_is_encoded_as_one() {
        let h = rebuilt_header(65536, 8);
        assert_eq!(u16::from_be_bytes([h[16], h[17]]), 1);
    }

    #[test]
    fn destroyed_100_byte_header_is_rebuilt() {
        let bytes = destroyed();
        let path = dump_to_temp("destroyed", &bytes);
        let found = probe(&path, 1 << 30);
        std::fs::remove_file(&path).ok();
        assert_eq!(found.len(), 1, "exactly one candidate expected");
        let candidate = found[0];
        assert_eq!(candidate.start, 0);
        assert_eq!(candidate.page_size, 4096);
        assert_eq!(candidate.page_count(), 10);
        assert!(
            candidate.page1_tree_ok,
            "page 1 b-tree header survives the 100-byte destruction"
        );
        assert_eq!(candidate.end, 40960);
    }

    #[test]
    fn a_corrupted_interior_page_rejects_the_candidate() {
        let raw = destroyed();
        // Corrupt page 6's cell-content-start (deep validation must fail).
        let mut bytes = raw;
        let page6 = 6 * 4096;
        bytes[page6 + 5..page6 + 7].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let path = dump_to_temp("corrupt-page", &bytes);
        let found = probe(&path, 1 << 30);
        std::fs::remove_file(&path).ok();
        assert!(
            found.is_empty(),
            "a corrupt b-tree page must drop the candidate"
        );
    }

    #[test]
    fn an_intact_database_is_not_carved_by_the_probe() {
        let path = dump_to_temp("intact", &std::fs::read(fixture_path()).unwrap());
        let found = probe(&path, 1 << 30);
        std::fs::remove_file(&path).ok();
        assert!(
            found.is_empty(),
            "intact databases belong to the normal carve path"
        );
    }

    #[test]
    fn pseudo_random_junk_yields_no_candidates() {
        // 16 pages of deterministic junk with no b-tree structure.
        let mut rng = 0x2545F4914F6CDD1Du64;
        let bytes: Vec<u8> = (0..16 * 4096)
            .map(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                (rng >> 32) as u8
            })
            .collect();
        let path = dump_to_temp("junk", &bytes);
        let found = probe(&path, 1 << 30);
        std::fs::remove_file(&path).ok();
        assert!(found.is_empty());
    }

    #[test]
    fn rebuilt_file_contains_schema_and_passes_own_header_rules() {
        let bytes = destroyed();
        let path = dump_to_temp("rebuild", &bytes);
        let found = probe(&path, 1 << 30);
        let candidate = found[0];
        let mut file = File::open(&path).unwrap();
        let rebuilt = rebuild_bytes(&mut file, &candidate).unwrap();
        std::fs::remove_file(&path).ok();
        // Fresh header + untouched pages.
        assert_eq!(&rebuilt[..16], b"SQLite format 3\x00");
        assert_eq!(u32::from_be_bytes(rebuilt[28..32].try_into().unwrap()), 10);
        assert!(rebuilt
            .windows(b"CREATE TABLE people".len())
            .any(|w| w == b"CREATE TABLE people"));
        assert!(rebuilt
            .windows(b"person_0001".len())
            .any(|w| w == b"person_0001"));
        assert_eq!(rebuilt.len(), 40960);
        // Page 1's b-tree header at offset 100 must be the original type byte.
        assert!(matches!(rebuilt[100], 0x02 | 0x05 | 0x0A | 0x0D));
    }
}
