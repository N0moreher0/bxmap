//! ROADMAP 8.12.5: harvest complete (`Whole`) JPEGs from the dump itself and
//! lend their tables to a ruined sibling.
//!
//! The rebuild of a JPEG whose table chain was destroyed (8.12.4) guesses the
//! Huffman tables (Annex K) and the geometry (`cols` from the DC predictor
//! correlation). When a `Whole` JPEG from the *same source* exists — same
//! encoder, same tables, usually the same dimensions, e.g. a camera burst —
//! none of that guessing is needed: the sibling's `DQT`/`DHT`/`SOF`/`DRI` are
//! written into the rebuilt file verbatim (with the `Exif`/comment segments
//! stripped), and only the walker has to agree that the kept scan decodes to
//! exactly `rows × cols` MCUs ending at the `EOI`.
//!
//! Donors are collected by a light pre-pass over the dump (one matcher scan,
//! bounded header reads) and shared with every candidate in the same carve
//! run. A donor is only a parseable baseline 8-bit JPEG: nothing else is
//! required — wrong donors are rejected by the walker, and the estimation
//! path runs as a fallback.
//!
//! Scope limits (documented in the ROADMAP): donors with `DRI > 0` are
//! refused in this version (a restart-coded `DRI` donor needs the ruined
//! scan's restart phase, unknowable from inside it); progressive/arithmetic
//! donors never parse to `SOF0`/`SOF1` and are refused too.

use sha2::{Digest, Sha256};

use crate::jpeg_scan::{self, ComponentInfo, ComponentTables, HuffmanTable, ScanGeometry};

/// Largest header (SOI‥SOS) window read from a donor candidate.
/// `FF D8 … FF DA …` for reference files is usually < 64 KiB; 512 KiB is
/// generous and still bounded.
pub(crate) const MAX_DONOR_HEAD: u64 = 512 * 1024;
/// Donor cap per carve run (bounds memory and the walk cost per candidate).
pub(crate) const MAX_DONORS: usize = 64;

/// Structural segment markers kept in a donor header. Everything else
/// (`APPn`, `COM`, `APP0`) is stripped: the rebuilt file gets our own minimal
/// `JFIF` APP0, and nothing from the donor's EXIF/GPS is ever copied.
const STRUCTURAL_MARKERS: [u8; 6] = [0xDB, 0xDD, 0xC0, 0xC1, 0xC4, 0xDA];

/// A complete JPEG discovered in the dump whose tables and geometry can
/// rebuild a ruined sibling exactly (same encoder, usually the same
/// dimensions).
pub(crate) struct JpegDonor {
    /// Structural header segments (the bytes after the `SOI` marker), with
    /// every non-structural segment removed. `FF DA` (SOS) is always the last
    /// segment.
    header: Vec<u8>,
    /// SOF width/height — the donor's own dimensions. The ruined sibling must
    /// share them for the walker to consume the scan exactly; a mismatch is
    /// rejected by the walker, never silently accepted.
    pub width: u16,
    pub height: u16,
    /// Components in scan order (`h`, `v`, `tq`, `td`, `ta` as in the scan).
    pub components: Vec<ComponentInfo>,
    /// Index into `jpeg_probe::LAYOUTS` derived from the component 0
    /// sampling factors and the component count.
    pub layout_index: usize,
    /// First 4 bytes of the structural header's SHA-256, hex — a fingerprint
    /// the index/notes carry (`tables=donor:a1b2c3d4`).
    pub tag: String,
    /// The parsed Huffman tables (`[class * 4 + id]`).
    dht: [Option<HuffmanTable>; 8],
}

impl JpegDonor {
    /// Parse a header window read from the candidate position into a donor.
    /// Returns `None` for anything that is not a sequential 8-bit baseline
    /// JPEG with 1 or 3 components, known sampling and no `DRI` restart
    /// interval.
    pub(crate) fn from_head(bytes: &[u8]) -> Option<Self> {
        let (scan_start, geometry) = jpeg_scan::parse_geometry(bytes).ok()?;
        if geometry.dri != 0 {
            return None;
        }
        let dht = jpeg_scan::parse_huff_tables(bytes, scan_start).ok()?;
        for component in &geometry.components {
            if dht[component.td as usize].is_none() || dht[4 + component.ta as usize].is_none() {
                return None;
            }
        }
        let layout_index = layout_for(&geometry)?;
        let header = strip_metadata_segments(bytes.get(2..scan_start)?);
        let mut hasher = Sha256::new();
        hasher.update(&header);
        let tag = hex_encode(&hasher.finalize()[..4]);
        Some(JpegDonor {
            header,
            width: geometry.width,
            height: geometry.height,
            components: geometry.components,
            layout_index,
            tag,
            dht,
        })
    }

    /// The donor's MCU geometry (header dims, `dri = 0`).
    pub(crate) fn geometry(&self) -> ScanGeometry {
        ScanGeometry {
            width: self.width,
            height: self.height,
            components: self.components.clone(),
            dri: 0,
        }
    }

    /// The donor's Huffman tables, aligned to the component order.
    pub(crate) fn tables(&self) -> Vec<ComponentTables<'_>> {
        self.components
            .iter()
            .map(|component| ComponentTables {
                dc: self
                    .dht
                    .get(component.td as usize)
                    .and_then(|table| table.as_ref())
                    .expect("checked at harvest"),
                ac: self
                    .dht
                    .get(4 + component.ta as usize)
                    .and_then(|table| table.as_ref())
                    .expect("checked at harvest"),
            })
            .collect()
    }

    /// Structural segments (no `SOI`, no metadata) for re-injection into the
    /// rebuilt file.
    pub(crate) fn header_segments(&self) -> &[u8] {
        &self.header
    }
}

/// `SOI` stripped, structural segments only (`DQT`, `DRI`, `SOF*`, `DHT`,
/// `SOS`), bounded by the exact `SOS` segment end.
fn strip_metadata_segments(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 0usize;
    while offset + 2 <= bytes.len() {
        if bytes[offset] != 0xFF {
            break;
        }
        let marker = bytes[offset + 1];
        if marker == 0xFF || marker == 0x01 || (0xD0..=0xD7).contains(&marker) || marker == 0xD8 {
            offset += 2;
            continue;
        }
        if offset + 4 > bytes.len() {
            break;
        }
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 2 || offset + 2 + length > bytes.len() {
            break;
        }
        let whole = &bytes[offset..offset + 2 + length];
        if STRUCTURAL_MARKERS.contains(&marker) {
            out.extend_from_slice(whole);
        }
        offset += 2 + length;
        if marker == 0xDA {
            break;
        }
    }
    out
}

/// Map the component structure onto a `LAYOUTS` index: 1 component = gray,
/// 3 components = the luma sampling factor. Anything else is refused.
fn layout_for(geometry: &ScanGeometry) -> Option<usize> {
    match geometry.components.len() {
        1 => Some(0), // gray
        3 => {
            let luma = &geometry.components[0];
            [
                (1u8, 1u8, 1usize),
                (2, 1, 2),
                (2, 2, 3),
                (4, 1, 4),
                (4, 2, 5),
            ]
            .iter()
            .find(|&&(h, v, _)| luma.h == h && luma.v == v)
            .map(|&(_, _, index)| index)
        }
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixture_round_trips_through_the_donor_parser() {
        const RGB: &[u8] = include_bytes!("../tests/fixtures/baseline_160x120_q75.jpg");
        let donor = JpegDonor::from_head(RGB).expect("the baseline fixture must parse");
        assert_eq!(donor.width, 160);
        assert_eq!(donor.height, 120);
        assert_eq!(donor.components.len(), 3);
        assert_eq!(donor.layout_index, 3); // 4:2:0
        assert_eq!(donor.tag.len(), 8);
        // Structural segments only: every byte is inside a DQT/SOF/DHT/SOS.
        let mut offset = 0usize;
        let mut saw_sof = false;
        let mut saw_sos = false;
        while offset + 2 <= donor.header_segments().len() {
            assert_eq!(donor.header_segments()[offset], 0xFF);
            let marker = donor.header_segments()[offset + 1];
            assert!(
                STRUCTURAL_MARKERS.contains(&marker),
                "unexpected marker 0xFF{marker:02X} in the donor header"
            );
            let length = u16::from_be_bytes([
                donor.header_segments()[offset + 2],
                donor.header_segments()[offset + 3],
            ]) as usize;
            assert!(length >= 2);
            if matches!(marker, 0xC0 | 0xC1) {
                saw_sof = true;
            }
            if marker == 0xDA {
                saw_sos = true;
                break;
            }
            offset += 2 + length;
        }
        assert!(saw_sof && saw_sos);
        // Rebuilding tables from the donor must match its components.
        assert_eq!(donor.tables().len(), 3);
        assert_eq!(donor.geometry().width, 160);
        assert_eq!(donor.geometry().dri, 0);
    }

    #[test]
    fn garbage_never_becomes_a_donor() {
        let garbage = vec![0xAAu8; 4096];
        assert!(JpegDonor::from_head(&garbage).is_none());
        let empty: Vec<u8> = Vec::new();
        assert!(JpegDonor::from_head(&empty).is_none());
    }
}
