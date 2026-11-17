//! JPEG baseline entropy-coded scan walker (ROADMAP 8.12.3).
//!
//! This module does **not** decode pixels. It answers one question: given a
//! (possibly rebuilt) baseline/sequential Huffman JPEG, does the entropy
//! sector decode to exactly `mcu_cols × mcu_rows` MCUs and end right at the
//! end of scan with at most 7 padding bits (all 1s)?
//!
//! That single property is what separates a genuinely reconstructed JPEG
//! stream from random bytes that merely survive the stuffing oracle: a
//! wrong table, wrong geometry or a single flipped bit inside the scan
//! almost always desynchronises the Huffman decoder within a few MCUs and
//! either runs out of data or leaves the trailing-bits check unsatisfied.
//!
//! Scope (enforced by the callers via the SOF marker):
//! - SOF0 (baseline) / SOF1 (extended sequential), 8-bit precision only;
//! - Huffman entropy coding only (a `DAC` marker means arithmetic and is
//!   rejected before this module is called);
//! - 1..=4 components, interleaved single scan (baseline), restart support
//!   via `DRI` (`FF DD`) is recognised but not required;
//! - progressive (`SOF2`+) and arithmetic are out of scope on purpose.
//!
//! No dequantization, no IDCT, no colour transform. The tables come from
//! the file itself (`DHT`); nothing here is assumed. The Annex K tables
//! (T.81) are provided for callers that have no tables of their own —
//! ROADMAP 8.12.4 — built once into 16-bit lookups via `OnceLock`.

use std::fmt;
use std::sync::OnceLock;

/// Offset of the SOS marker plus one `(Cs, Td, Ta)` triple per component
/// (component id, DC Huffman table id, AC Huffman table id).
type SosTriples = (usize, Vec<(u8, u8, u8)>);

/// Why an entropy-sector walk gave up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkError {
    /// The scan ran out of bytes/bits before all MCUs were decoded.
    Truncated,
    /// A segment up front is malformed (bad SOF/DHT/SOS/DRI layout).
    InvalidSegment(String),
    /// Non-baseline coding process (progressive/arithmetic/lossless).
    UnsupportedCoding(String),
    /// A Huffman lookup missed: the data is not this table's coding.
    InvalidCode,
    /// The entropy bytes end in more than 7 trailing bits, or the trailing
    /// bits are not all 1s (encoder padding is always 1s).
    Padding,
    /// A `DRI`-declared restart marker did not arrive at the expected bit
    /// position (or arrived unexpectedly).
    RestartMismatch,
    /// Sanity cap: absurd geometry or MCU count (see `MAX_MCUS`).
    TooLarge,
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalkError::Truncated => write!(f, "scan ran out of data mid-MCU"),
            WalkError::InvalidSegment(reason) => write!(f, "invalid segment: {reason}"),
            WalkError::UnsupportedCoding(reason) => write!(f, "unsupported coding: {reason}"),
            WalkError::InvalidCode => write!(f, "Huffman decode hit an invalid code"),
            WalkError::Padding => write!(f, "scan does not end in ≤ 7 padding bits of 1s"),
            WalkError::RestartMismatch => write!(f, "restart marker does not land on an MCU edge"),
            WalkError::TooLarge => write!(f, "geometry exceeds the sanity cap"),
        }
    }
}

impl std::error::Error for WalkError {}

/// Geometry and tables recovered from a JPEG's own segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanGeometry {
    pub width: u16,
    pub height: u16,
    /// Per component (in SOS order): sampling (h, v) and table ids
    /// (DC, AC).
    pub components: Vec<ComponentInfo>,
    /// Restart interval from `DRI` (0 = no restart markers).
    pub dri: u16,
}

/// One component's layout inside an MCU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentInfo {
    /// Horizontal sampling factor (1..=4).
    pub h: u8,
    /// Vertical sampling factor (1..=4).
    pub v: u8,
    /// Quantisation table id (informational only; not used to decode).
    pub tq: u8,
    /// DC Huffman table id (0..=3).
    pub td: u8,
    /// AC Huffman table id (0..=3).
    pub ta: u8,
}

/// Largest supported component count.
pub const MAX_COMPONENTS: usize = 4;
/// Hard cap on decoded MCUs, mirroring the 8.12.8 safety rule.
pub const MAX_MCUS: u64 = 8_000_000;
/// Cap on the `dc_luma` vector (ROADMAP 8.12.3: the first 65_536 MCUs).
pub const DC_LUMA_CAP: usize = 65_536;
/// Cap on the `first_boundaries` vector (ROADMAP 8.12.3).
pub const FIRST_BOUNDARIES_CAP: usize = 1_100;

/// Result of an MCU walk (ROADMAP 8.12.3).
#[derive(Debug, Clone, PartialEq)]
pub struct WalkStats {
    /// Number of MCUs decoded.
    pub mcus: u64,
    /// Total 8×8 blocks decoded across all components.
    pub blocks: u64,
    /// Bit position right after the last fully decoded MCU (or at the point
    /// `err` was raised).
    pub end_bit: usize,
    /// Why the walk stopped; `None` when it reached `limit_mcus` cleanly.
    pub err: Option<WalkError>,
    /// Bit positions of MCU starts, in decode order, capped at
    /// `FIRST_BOUNDARIES_CAP` entries.
    pub first_boundaries: Vec<usize>,
    /// Running DC predictor of the luma component (component index 0) after
    /// each luma block, in decode order, capped at `DC_LUMA_CAP` entries.
    pub dc_luma: Vec<i32>,
    /// Restart markers consumed from the `restarts` slice passed in (an
    /// index into it, not a count of bytes).
    pub restarts_consumed: usize,
    /// Geometry the walk used.
    pub geometry: ScanGeometry,
}

/// One Huffman table as a 16-bit lookup.
pub(crate) struct HuffmanTable {
    /// `lut[next_16_bits]` → `(length_bits, symbol)`. A length of 0 means
    /// the code does not exist (invalid for this table).
    lut: Vec<(u8, u8)>,
}

impl HuffmanTable {
    /// Build the canonical 16-bit lookup from one `DHT` sub-table.
    /// `counts` is the 16-byte symbol-length table; `symbols` holds the
    /// `sum(counts)` symbol values in code order.
    fn build(counts: &[u8; 16], symbols: &[u8]) -> Result<Self, WalkError> {
        let total: usize = counts.iter().map(|&b| b as usize).sum();
        if total != symbols.len() {
            return Err(WalkError::InvalidSegment(format!(
                "DHT declares {total} symbols but the segment carries {}",
                symbols.len()
            )));
        }
        if total == 0 || total > 256 {
            return Err(WalkError::InvalidSegment(
                "DHT symbol count exceeds 256".to_string(),
            ));
        }
        // `code` is the next canonical code for the current length.
        let mut code: u32 = 0;
        let mut index = 0usize;
        let mut lut = vec![(0u8, 0u8); 1 << 16];
        for (length_index, &count) in counts.iter().enumerate() {
            let length = (length_index + 1) as u32;
            for _ in 0..count {
                let symbol = symbols[index];
                index += 1;
                if code >= (1u32 << length) {
                    // Over-subscribed: the counts are not a valid prefix
                    // code (a random table is caught here, not at decode).
                    return Err(WalkError::InvalidSegment(
                        "DHT counts overflow a length class".to_string(),
                    ));
                }
                let shift = 16 - length;
                let base = code << shift;
                let span = 1u32 << shift;
                for slot in lut
                    .iter_mut()
                    .take((base + span) as usize)
                    .skip(base as usize)
                {
                    *slot = (length as u8, symbol);
                }
                code += 1;
            }
            code <<= 1;
        }
        Ok(Self { lut })
    }
}

// --- ITU-T T.81 Annex K (K.3.1/K.3.2/K.3.3/K.3.4) -------------------------
// Byte-exact against every libjpeg-encoded fixture and camera_sample.jpg
// checked into this repo (see tests below).

pub(crate) const ANNEX_K_DC_LUMA_NR: [u8; 16] = [
    0x00, 0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub(crate) const ANNEX_K_DC_LUMA_VAL: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
];
pub(crate) const ANNEX_K_DC_CHROMA_NR: [u8; 16] = [
    0x00, 0x03, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
];
pub(crate) const ANNEX_K_DC_CHROMA_VAL: [u8; 12] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
];
pub(crate) const ANNEX_K_AC_LUMA_NR: [u8; 16] = [
    0x00, 0x02, 0x01, 0x03, 0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
];
pub(crate) const ANNEX_K_AC_LUMA_VAL: [u8; 162] = [
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06, 0x13, 0x51, 0x61, 0x07,
    0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08, 0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0,
    0x24, 0x33, 0x62, 0x72, 0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
    0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
    0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5,
    0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
    0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA,
];
pub(crate) const ANNEX_K_AC_CHROMA_NR: [u8; 16] = [
    0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x03, 0x04, 0x07, 0x05, 0x04, 0x04, 0x00, 0x01, 0x02, 0x77,
];
pub(crate) const ANNEX_K_AC_CHROMA_VAL: [u8; 162] = [
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41, 0x51, 0x07, 0x61, 0x71,
    0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91, 0xA1, 0xB1, 0xC1, 0x09, 0x23, 0x33, 0x52, 0xF0,
    0x15, 0x62, 0x72, 0xD1, 0x0A, 0x16, 0x24, 0x34, 0xE1, 0x25, 0xF1, 0x17, 0x18, 0x19, 0x1A, 0x26,
    0x27, 0x28, 0x29, 0x2A, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
    0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
    0x69, 0x6A, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3, 0xA4, 0xA5,
    0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3,
    0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
    0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8,
    0xF9, 0xFA,
];

/// The four Annex K tables, built into 16-bit lookups once.
pub(crate) struct AnnexK {
    pub dc_luma: HuffmanTable,
    pub dc_chroma: HuffmanTable,
    pub ac_luma: HuffmanTable,
    pub ac_chroma: HuffmanTable,
}

static ANNEX_K: OnceLock<AnnexK> = OnceLock::new();

/// The shared Annex K tables. The LUTs cost ~0.5 MiB (4 tables × 65 536 ×
/// 2 bytes) and are built once, on first use.
pub(crate) fn annex_k() -> &'static AnnexK {
    ANNEX_K.get_or_init(|| AnnexK {
        dc_luma: HuffmanTable::build(&ANNEX_K_DC_LUMA_NR, &ANNEX_K_DC_LUMA_VAL)
            .expect("ITU-T T.81 Annex K DC luma table must be valid"),
        dc_chroma: HuffmanTable::build(&ANNEX_K_DC_CHROMA_NR, &ANNEX_K_DC_CHROMA_VAL)
            .expect("ITU-T T.81 Annex K DC chroma table must be valid"),
        ac_luma: HuffmanTable::build(&ANNEX_K_AC_LUMA_NR, &ANNEX_K_AC_LUMA_VAL)
            .expect("ITU-T T.81 Annex K AC luma table must be valid"),
        ac_chroma: HuffmanTable::build(&ANNEX_K_AC_CHROMA_NR, &ANNEX_K_AC_CHROMA_VAL)
            .expect("ITU-T T.81 Annex K AC chroma table must be valid"),
    })
}

impl AnnexK {
    /// Map a scan's components onto the Annex K luma/chroma tables
    /// (component index 0 is treated as luma, the rest as chroma).
    pub(crate) fn for_components(&self, geometry: &ScanGeometry) -> Vec<ComponentTables<'_>> {
        geometry
            .components
            .iter()
            .enumerate()
            .map(|(index, _)| {
                if index == 0 {
                    ComponentTables {
                        dc: &self.dc_luma,
                        ac: &self.ac_luma,
                    }
                } else {
                    ComponentTables {
                        dc: &self.dc_chroma,
                        ac: &self.ac_chroma,
                    }
                }
            })
            .collect()
    }
}

/// Bit reader over the unstuffed entropy bytes.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn with_offset(data: &'a [u8], bit_pos: usize) -> Self {
        Self { data, bit_pos }
    }

    /// Bits still unread.
    fn remaining(&self) -> usize {
        self.data.len() * 8 - self.bit_pos
    }

    fn peek16(&self) -> u32 {
        // Read up to 16 bits MSB-first; missing bytes read as zero, which is
        // safe because a short lookahead only happens at the very end where
        // the decode is already committed to a result.
        let mut value: u32 = 0;
        for i in 0..16 {
            let abs = self.bit_pos + i;
            let byte = self.data.get(abs / 8).copied().unwrap_or(0);
            let bit = (byte >> (7 - (abs % 8))) & 1;
            value = (value << 1) | u32::from(bit);
        }
        value
    }

    fn skip(&mut self, n: usize) -> Result<(), WalkError> {
        if n > self.remaining() {
            return Err(WalkError::Truncated);
        }
        self.bit_pos += n;
        Ok(())
    }

    fn read_bits(&mut self, n: u32) -> Result<u32, WalkError> {
        if n as usize > self.remaining() {
            return Err(WalkError::Truncated);
        }
        let mut value: u32 = 0;
        for _ in 0..n {
            let byte = self.data[self.bit_pos / 8];
            let bit = (byte >> (7 - (self.bit_pos % 8))) & 1;
            value = (value << 1) | u32::from(bit);
            self.bit_pos += 1;
        }
        Ok(value)
    }
}

/// Stretch a Huffman size + value back to the signed coefficient.
fn extend(size: u32, bits: u32) -> i32 {
    debug_assert!(size <= 16);
    if size == 0 {
        return 0;
    }
    let threshold = 1u32 << (size - 1);
    if bits < threshold {
        bits as i32 - ((1u32 << size) as i32) + 1
    } else {
        bits as i32
    }
}

/// Parse the scan-relevant geometry from a fully built JPEG byte string.
/// Returns the scan start offset (absolute, inside `bytes`) and the geometry.
pub(crate) fn parse_geometry(bytes: &[u8]) -> Result<(usize, ScanGeometry), WalkError> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return Err(WalkError::InvalidSegment("missing SOI marker".to_string()));
    }
    let mut offset = 2usize;
    let mut width = None;
    let mut height = None;
    let mut dri: u16 = 0;
    let mut sos: Option<SosTriples> = None; // offset, (Cs, Td, Ta)
    let mut sof_components: Vec<(u8, u8, u8)> = Vec::new(); // id, sampling, tq
    loop {
        if offset + 2 > bytes.len() {
            return Err(WalkError::Truncated);
        }
        if bytes[offset] != 0xFF {
            return Err(WalkError::InvalidSegment(format!(
                "expected a marker at {offset:#x}, found {:#04x}",
                bytes[offset]
            )));
        }
        let marker = bytes[offset + 1];
        // Standalone markers carry no length.
        if marker == 0xFF || marker == 0x01 || (0xD0..=0xD7).contains(&marker) || marker == 0xD8 {
            offset += 2;
            continue;
        }
        if marker == 0xD9 {
            return Err(WalkError::InvalidSegment("EOI before any SOS".to_string()));
        }
        if offset + 4 > bytes.len() {
            return Err(WalkError::Truncated);
        }
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 2 || offset + 2 + length > bytes.len() {
            return Err(WalkError::InvalidSegment(format!(
                "marker 0xFF{marker:02X} has an implausible length"
            )));
        }
        let payload = offset + 4;
        let segment_end = offset + 2 + length;
        match marker {
            0xC0 | 0xC1 => {
                if width.is_some() {
                    return Err(WalkError::InvalidSegment("two SOF segments".to_string()));
                }
                if length < 8 {
                    return Err(WalkError::InvalidSegment("SOF too short".to_string()));
                }
                let precision = bytes[payload];
                if precision != 8 {
                    return Err(WalkError::UnsupportedCoding(format!(
                        "SOF precision {precision} (only 8-bit supported)"
                    )));
                }
                let h = u16::from_be_bytes([bytes[payload + 1], bytes[payload + 2]]);
                let w = u16::from_be_bytes([bytes[payload + 3], bytes[payload + 4]]);
                if h == 0 || w == 0 {
                    return Err(WalkError::InvalidSegment(
                        "SOF declares a zero extent".to_string(),
                    ));
                }
                let count = bytes[payload + 5] as usize;
                if !(1..=MAX_COMPONENTS).contains(&count) || payload + 6 + 3 * count > segment_end {
                    return Err(WalkError::InvalidSegment(
                        "SOF component table is implausible".to_string(),
                    ));
                }
                let mut comps = Vec::with_capacity(count);
                for i in 0..count {
                    let base = payload + 6 + 3 * i;
                    let id = bytes[base];
                    let sampling = bytes[base + 1];
                    let tq = bytes[base + 2];
                    let (sh, sv) = (sampling >> 4, sampling & 0x0F);
                    if sh == 0 || sv == 0 || sh > 4 || sv > 4 {
                        return Err(WalkError::InvalidSegment(
                            "SOF sampling factors out of range".to_string(),
                        ));
                    }
                    if tq > 3 {
                        return Err(WalkError::InvalidSegment(
                            "SOF quantisation table id out of range".to_string(),
                        ));
                    }
                    comps.push((id, sampling, tq));
                }
                width = Some(w);
                height = Some(h);
                sof_components = comps;
            }
            0xC2 | 0xC3 | 0xC5 | 0xC6 | 0xC7 | 0xC9 | 0xCA | 0xCB | 0xCD | 0xCE | 0xCF => {
                // Progressive, lossless, differential, ...
                return Err(WalkError::UnsupportedCoding(format!(
                    "SOF marker 0xFF{marker:02X} (only SOF0/SOF1 supported)"
                )));
            }
            0xCC => {
                return Err(WalkError::UnsupportedCoding(
                    "DAC marker: arithmetic coding".to_string(),
                ));
            }
            0xC4 => {}
            0xDD => {
                if length != 4 {
                    return Err(WalkError::InvalidSegment(
                        "DRI segment is not exactly 4 bytes".to_string(),
                    ));
                }
                dri = u16::from_be_bytes([bytes[payload], bytes[payload + 1]]);
            }
            0xDA => {
                if width.is_none() {
                    return Err(WalkError::InvalidSegment("SOS before SOF".to_string()));
                }
                let count = bytes[payload] as usize;
                if count == 0 || payload + 1 + 2 * count + 3 > segment_end {
                    return Err(WalkError::InvalidSegment(
                        "SOS component table is implausible".to_string(),
                    ));
                }
                if u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]])
                    != (6 + 2 * count) as u16
                {
                    return Err(WalkError::InvalidSegment(
                        "SOS length does not match its component count".to_string(),
                    ));
                }
                let mut comps = Vec::with_capacity(count);
                for i in 0..count {
                    let base = payload + 1 + 2 * i;
                    let cs = bytes[base];
                    let td_ta = bytes[base + 1];
                    let (td, ta) = (td_ta >> 4, td_ta & 0x0F);
                    if td > 3 || ta > 3 {
                        return Err(WalkError::InvalidSegment(
                            "SOS Huffman table id out of range".to_string(),
                        ));
                    }
                    comps.push((cs, td, ta));
                }
                sos = Some((offset, comps));
            }
            // DQT, APPn, COM and anything else: skipped by length. DQT is
            // checked for shape by the caller that built the file.
            _ => {}
        }
        if sos.is_some() {
            break;
        }
        offset = segment_end;
    }

    let (sos_offset, sos_components) =
        sos.ok_or_else(|| WalkError::InvalidSegment("no SOS segment found".to_string()))?;
    let width =
        width.ok_or_else(|| WalkError::InvalidSegment("no SOF segment found".to_string()))?;
    let height = height.ok_or_else(|| unreachable!("height is set with width"))?;

    // SOS order maps components onto the SOF table by component id.
    if sos_components.len() != sof_components.len() {
        return Err(WalkError::InvalidSegment(
            "SOS and SOF disagree on the component count".to_string(),
        ));
    }
    let mut components = Vec::with_capacity(sos_components.len());
    for &(cs, td, ta) in &sos_components {
        let entry = sof_components
            .iter()
            .find(|&&(id, _, _)| id == cs)
            .ok_or_else(|| {
                WalkError::InvalidSegment("SOS references a component missing from SOF".to_string())
            })?;
        let sampling = entry.1;
        components.push(ComponentInfo {
            h: sampling >> 4,
            v: sampling & 0x0F,
            tq: entry.2,
            td,
            ta,
        });
    }
    let scan_start = sos_offset
        + u16::from_be_bytes([bytes[sos_offset + 2], bytes[sos_offset + 3]]) as usize
        + 2;
    Ok((
        scan_start,
        ScanGeometry {
            width,
            height,
            components,
            dri,
        },
    ))
}

/// Collect the Huffman tables (up to 4 DC + 4 AC) from the `DHT` segments.
pub(crate) fn parse_huff_tables(
    bytes: &[u8],
    upto: usize,
) -> Result<[Option<HuffmanTable>; 8], WalkError> {
    let mut tables: [Option<HuffmanTable>; 8] = std::array::from_fn(|_| None);
    let mut offset = 2usize;
    while offset + 2 <= upto {
        if bytes[offset] != 0xFF {
            // Already inside the scan; nothing more to collect.
            break;
        }
        let marker = bytes[offset + 1];
        if marker == 0xFF || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            offset += 2;
            continue;
        }
        if offset + 4 > upto {
            break;
        }
        let length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        if length < 2 || offset + 2 + length > upto {
            break;
        }
        if marker != 0xC4 {
            offset += 2 + length;
            continue;
        }
        let mut inner = offset + 4;
        let segment_end = offset + 2 + length;
        while inner < segment_end {
            let tc_th = bytes[inner];
            inner += 1;
            let class = tc_th >> 4;
            let id = tc_th & 0x0F;
            if class > 1 || id > 3 {
                return Err(WalkError::InvalidSegment(
                    "DHT class/id out of range".to_string(),
                ));
            }
            if inner + 16 > segment_end {
                return Err(WalkError::InvalidSegment(
                    "DHT counts truncated".to_string(),
                ));
            }
            let mut counts = [0u8; 16];
            counts.copy_from_slice(&bytes[inner..inner + 16]);
            inner += 16;
            let total: usize = counts.iter().map(|&b| b as usize).sum();
            if inner + total > segment_end {
                return Err(WalkError::InvalidSegment(
                    "DHT symbols truncated".to_string(),
                ));
            }
            let symbols = &bytes[inner..inner + total];
            inner += total;
            let slot = (class as usize) * 4 + id as usize;
            tables[slot] = Some(HuffmanTable::build(&counts, symbols)?);
        }
        offset = segment_end;
    }
    Ok(tables)
}

/// Remove `FF 00` byte stuffing and note the restart markers. Returns the
/// entropy bytes plus the restart positions (byte offsets in the output).
pub(crate) fn unstuff(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::with_capacity(data.len());
    let mut rests = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b != 0xFF {
            out.push(b);
            i += 1;
            continue;
        }
        let next = data.get(i + 1).copied().unwrap_or(0);
        match next {
            0x00 => {
                // Byte stuffing: the encoder writes `FF 00` in the entropy
                // data to encode a genuine `FF` byte. The `00` is the
                // disambiguator, not a data byte.
                out.push(0xFF);
                i += 2;
            }
            0xFF => {
                // Fill byte before a marker: carries no entropy bits.
                i += 1;
            }
            0xD0..=0xD7 => {
                rests.push(out.len());
                i += 2;
            }
            // A real marker: the scan ends here. The caller already bounded
            // the slice to the EOI position, so this cannot happen; be
            // defensive anyway.
            _ => break,
        }
    }
    (out, rests)
}

/// Lenient cousin of [`unstuff`] for ROADMAP 8.12.4's *ruined-head* input,
/// where the slice may start inside random junk — any `FF xx` pair that
/// looks like a marker is then random bytes, not a boundary, and stopping
/// there would truncate the stream to the junk (nothing else finds the
/// surviving entropy). The caller already bounded the slice to the EOI
/// position, so no legal marker exists here either; but instead of
/// stopping we *emit both bytes verbatim*. That keeps the entropy data
/// byte-for-byte reconstructable, never loses an entropy byte, and lets
/// the probe's sync attempt fail fast on junk. Rationale on the details:
///
/// - `FF 00` is stuffing: emit one `FF`;
/// - `FF FF` is a fill byte: carries no entropy bits, skip it;
/// - `FF D0..D7` are restart markers: their *position* is recorded (a real
///   `DRI` scan must then bail out) but they carry no entropy bytes;
/// - anything else: the two bytes are junk that happens to look like a
///   marker: emit both so the dump→unstuffed mapping stays injective.
pub(crate) fn unstuff_lenient(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::with_capacity(data.len());
    let mut rests = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        let b = data[i];
        if b != 0xFF {
            out.push(b);
            i += 1;
            continue;
        }
        let next = data.get(i + 1).copied().unwrap_or(0);
        match next {
            0x00 => {
                out.push(0xFF);
                i += 2;
            }
            0xFF => {
                // Fill bytes before a marker: the pair carries no entropy
                // bits; skip both.
                i += 2;
            }
            0xD0..=0xD7 => {
                rests.push(out.len());
                i += 2;
            }
            _ => {
                // Junk that happens to look like a marker: keep both bytes.
                out.push(0xFF);
                if i + 1 < data.len() {
                    out.push(next);
                }
                i += 2;
            }
        }
    }
    (out, rests)
}

/// Borrowed per-component table set, aligned with `ScanGeometry::components`
/// (ROADMAP 8.12.3: callers need several table sources — the file's own
/// `DHT` segments, or the shared Annex K tables for probes without tables).
pub(crate) struct ComponentTables<'a> {
    pub dc: &'a HuffmanTable,
    pub ac: &'a HuffmanTable,
}

/// Decode one 8×8 block: the DC difference plus the AC coefficients, in
/// zig-zag order. No dequantization, no IDCT. Returns the DC predictor
/// increment; the AC coefficients are validated but discarded.
fn decode_block(
    reader: &mut BitReader<'_>,
    tables: &ComponentTables<'_>,
) -> Result<i32, WalkError> {
    // Reading past the end of the data is an error, never a decode.
    if reader.remaining() == 0 {
        return Err(WalkError::Truncated);
    }
    // DC coefficient: category, then the extra bits.
    let dc_code = tables.dc.lut[reader.peek16() as usize];
    if dc_code.0 == 0 {
        return Err(WalkError::InvalidCode);
    }
    reader.skip(dc_code.0 as usize)?;
    let size = dc_code.1 as u32;
    let extra = reader.read_bits(size)?;
    let diff = extend(size, extra);
    // AC coefficients, zig-zag order, up to 63.
    let mut k = 1usize;
    while k < 64 {
        let ac_code = tables.ac.lut[reader.peek16() as usize];
        if ac_code.0 == 0 {
            return Err(WalkError::InvalidCode);
        }
        reader.skip(ac_code.0 as usize)?;
        let symbol = ac_code.1;
        if symbol == 0x00 {
            // EOB: the rest of the block is zero.
            break;
        }
        if symbol == 0xF0 {
            // ZRL: 16 zeros.
            k += 16;
            continue;
        }
        let run = (symbol >> 4) as usize;
        let size = (symbol & 0x0F) as usize;
        k += run;
        if k >= 64 {
            return Err(WalkError::InvalidCode);
        }
        let extra = reader.read_bits(size as u32)?;
        let _coefficient = extend(size as u32, extra);
        k += 1;
    }
    Ok(diff)
}

/// Walk the entropy-coded MCUs (ROADMAP 8.12.3). `unstuffed` is the
/// stuffing-free entropy bytes; `restarts` holds the byte offsets of the
/// restart markers in that slice (as produced by `unstuff`). `tables` must
/// be aligned with `geometry.components`. `start_bit` is where the decode
/// begins (0 for a full scan; arbitrary for candidate probes). At most
/// `limit_mcus` MCUs are decoded. Errors are reported in `WalkStats::err`;
/// the function never panics and every loop is bounded by the remaining bits.
pub(crate) fn walk_mcus(
    unstuffed: &[u8],
    restarts: &[usize],
    geometry: &ScanGeometry,
    tables: &[ComponentTables<'_>],
    start_bit: usize,
    limit_mcus: u64,
) -> WalkStats {
    let mut stat = WalkStats {
        mcus: 0,
        blocks: 0,
        end_bit: start_bit.min(unstuffed.len() * 8),
        err: None,
        first_boundaries: Vec::with_capacity(limit_mcus.min(FIRST_BOUNDARIES_CAP as u64) as usize),
        dc_luma: Vec::with_capacity(limit_mcus.min(DC_LUMA_CAP as u64) as usize),
        restarts_consumed: 0,
        geometry: geometry.clone(),
    };
    if tables.len() != geometry.components.len() {
        // Internal contract violation; report it, never panic.
        stat.err = Some(WalkError::InvalidSegment(
            "walk_mcus: table/component count mismatch".to_string(),
        ));
        return stat;
    }
    let h_max = geometry.components.iter().map(|c| c.h).max().unwrap_or(1) as u16;
    let v_max = geometry.components.iter().map(|c| c.v).max().unwrap_or(1) as u16;
    let mcu_cols = u64::from(geometry.width).div_ceil(u64::from(h_max) * 8);
    let mcu_rows = u64::from(geometry.height).div_ceil(u64::from(v_max) * 8);
    let total_mcus = match mcu_cols.checked_mul(mcu_rows) {
        Some(total) if total > 0 && total <= MAX_MCUS => total,
        _ => {
            stat.err = Some(WalkError::TooLarge);
            return stat;
        }
    };
    let limit = limit_mcus.min(total_mcus) as usize;
    let mut reader = BitReader::with_offset(unstuffed, start_bit);
    let mut dc_pred = [0i32; MAX_COMPONENTS];
    let mut rest_index = 0usize;
    for _mcu in 0..limit {
        let mcu = _mcu as u64;
        if geometry.dri > 0 && mcu > 0 && mcu % u64::from(geometry.dri) == 0 {
            // The encoder pads to a byte boundary before each restart
            // marker and resets the DC predictors.
            let current_bit = reader.bit_pos;
            if current_bit % 8 != 0 {
                let pad = 8 - (current_bit % 8);
                let pad_bits = match reader.read_bits(pad as u32) {
                    Ok(bits) => bits,
                    Err(error) => {
                        stat.err = Some(error);
                        return finish(stat, reader.bit_pos, rest_index);
                    }
                };
                if pad_bits != (1u32 << pad) - 1 {
                    stat.err = Some(WalkError::Padding);
                    return finish(stat, reader.bit_pos, rest_index);
                }
            }
            let at = reader.bit_pos / 8;
            match rest_index {
                i if i < restarts.len() && restarts[i] == at => {
                    rest_index += 1;
                    dc_pred = [0; MAX_COMPONENTS];
                }
                _ => {
                    stat.err = Some(WalkError::RestartMismatch);
                    return finish(stat, reader.bit_pos, rest_index);
                }
            }
        }
        if stat.first_boundaries.len() < FIRST_BOUNDARIES_CAP {
            stat.first_boundaries.push(reader.bit_pos);
        }
        for (index, component) in geometry.components.iter().enumerate() {
            let h = component.h as usize;
            let v = component.v as usize;
            for _ in 0..(h * v) {
                let diff = match decode_block(&mut reader, &tables[index]) {
                    Ok(diff) => diff,
                    Err(error) => {
                        stat.err = Some(error);
                        return finish(stat, reader.bit_pos, rest_index);
                    }
                };
                dc_pred[index] = dc_pred[index].wrapping_add(diff);
                // Component 0 is the luma plane in interleaved scans.
                if index == 0 && stat.dc_luma.len() < DC_LUMA_CAP {
                    stat.dc_luma.push(dc_pred[index]);
                }
                stat.blocks += 1;
            }
        }
        stat.mcus += 1;
    }
    finish(stat, reader.bit_pos, rest_index)
}

/// Fill the final position fields of a finished walk.
fn finish(mut stat: WalkStats, end_bit: usize, restarts_consumed: usize) -> WalkStats {
    stat.end_bit = end_bit;
    stat.restarts_consumed = restarts_consumed;
    stat
}

/// Decode an entropy sector and check the MCU count and the end-of-scan
/// padding. `bytes` must start at SOI; the scan is everything from the end
/// of the SOS header up to (but excluding) the final `FF D9`.
pub fn verify_scan(bytes: &[u8]) -> Result<WalkStats, WalkError> {
    if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != 0xD8 {
        return Err(WalkError::InvalidSegment("missing SOI marker".to_string()));
    }
    let (scan_start, geometry) = parse_geometry(bytes)?;
    let Some(eoi) = bytes.windows(2).rposition(|w| w == [0xFF, 0xD9]) else {
        return Err(WalkError::Truncated);
    };
    if scan_start >= eoi {
        return Err(WalkError::Truncated);
    }
    let scan = &bytes[scan_start..eoi];
    let tables = parse_huff_tables(bytes, scan_start)?;
    for (index, component) in geometry.components.iter().enumerate() {
        let dc = &tables[component.td as usize];
        let ac = &tables[4 + component.ta as usize];
        if dc.is_none() || ac.is_none() {
            return Err(WalkError::InvalidSegment(format!(
                "component {index} references a missing Huffman table"
            )));
        }
    }
    let h_max = geometry.components.iter().map(|c| c.h).max().unwrap_or(1) as u16;
    let v_max = geometry.components.iter().map(|c| c.v).max().unwrap_or(1) as u16;
    let mcu_cols = u64::from(geometry.width).div_ceil(u64::from(h_max) * 8);
    let mcu_rows = u64::from(geometry.height).div_ceil(u64::from(v_max) * 8);
    let total_mcus = mcu_cols.checked_mul(mcu_rows).ok_or(WalkError::TooLarge)?;
    if total_mcus == 0 || total_mcus > MAX_MCUS {
        return Err(WalkError::TooLarge);
    }

    let component_tables: Vec<ComponentTables<'_>> = geometry
        .components
        .iter()
        .map(|component| ComponentTables {
            dc: tables[component.td as usize]
                .as_ref()
                .expect("checked above"),
            ac: tables[4 + component.ta as usize]
                .as_ref()
                .expect("checked above"),
        })
        .collect();
    let (unstuffed, restarts) = unstuff(scan);
    let stats = walk_mcus(
        &unstuffed,
        &restarts,
        &geometry,
        &component_tables,
        0,
        total_mcus,
    );
    if let Some(error) = stats.err {
        return Err(error);
    }
    // A trailing restart marker can sit right after the final MCU
    // (the encoder emits one when the MCU count is an exact multiple of
    // the restart interval).
    let mut cursor = stats.restarts_consumed;
    let mut reader = BitReader::with_offset(&unstuffed, stats.end_bit);
    if geometry.dri > 0 && cursor < restarts.len() {
        let current_bit = reader.bit_pos;
        if current_bit % 8 != 0 {
            let pad = 8 - (current_bit % 8);
            let pad_bits = reader.read_bits(pad as u32)?;
            if pad_bits != (1u32 << pad) - 1 {
                return Err(WalkError::Padding);
            }
        }
        let at = reader.bit_pos / 8;
        match cursor {
            i if i < restarts.len() && restarts[i] == at => {
                cursor += 1;
            }
            _ => return Err(WalkError::RestartMismatch),
        }
    }
    if geometry.dri > 0 && cursor != restarts.len() {
        return Err(WalkError::RestartMismatch);
    }
    let remaining = reader.remaining();
    if remaining > 7 {
        return Err(WalkError::Padding);
    }
    if remaining > 0 {
        let pad_bits = reader.read_bits(remaining as u32)?;
        if pad_bits != (1u32 << remaining) - 1 {
            return Err(WalkError::Padding);
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RGB: &[u8] = include_bytes!("../tests/fixtures/baseline_160x120_q75.jpg");
    const GRAY: &[u8] = include_bytes!("../tests/fixtures/baseline_gray_64x64_q80.jpg");

    #[test]
    fn verify_scan_accepts_a_real_baseline_jpeg() {
        let stats = verify_scan(RGB).expect("baseline fixture must verify");
        assert_eq!(stats.geometry.width, 160);
        assert_eq!(stats.geometry.height, 120);
        assert_eq!(stats.geometry.components.len(), 3);
        assert_eq!(stats.blocks, stats.mcus * 6); // 4:2:0: 1+1+1+1+1+1
                                                  // 160/16 x 120/16 = 10 x 8 (4:2:0 → h_max=2).
        assert_eq!(stats.mcus, 10 * 8);
    }

    #[test]
    fn verify_scan_accepts_a_real_grayscale_jpeg() {
        let stats = verify_scan(GRAY).expect("gray fixture must verify");
        assert_eq!(stats.geometry.width, 64);
        assert_eq!(stats.geometry.components.len(), 1);
        assert_eq!(stats.mcus, 8 * 8);
        assert_eq!(stats.blocks, stats.mcus);
    }

    #[test]
    fn verify_scan_rejects_a_flipped_padding_bit() {
        let mut corrupted = RGB.to_vec();
        // The last entropy byte is entirely encoder padding (all 1s);
        // corrupting it breaks the end-of-scan all-1s padding rule.
        let last = corrupted.len() - 3;
        corrupted[last] ^= 0x01;
        assert!(verify_scan(&corrupted).is_err());
    }

    #[test]
    fn verify_scan_rejects_a_truncated_scan() {
        let truncated = &RGB[..RGB.len() - 20];
        assert!(verify_scan(truncated).is_err());
    }

    // --- Annex K constants + OnceLock (ROADMAP 8.12.3) ------------------

    const ANNEX_K_TABLES: &[(&str, &[u8], &[u8])] = &[
        ("DC luma", &ANNEX_K_DC_LUMA_NR, &ANNEX_K_DC_LUMA_VAL),
        ("DC chroma", &ANNEX_K_DC_CHROMA_NR, &ANNEX_K_DC_CHROMA_VAL),
        ("AC luma", &ANNEX_K_AC_LUMA_NR, &ANNEX_K_AC_LUMA_VAL),
        ("AC chroma", &ANNEX_K_AC_CHROMA_NR, &ANNEX_K_AC_CHROMA_VAL),
    ];

    #[test]
    fn annex_k_symbol_counts_match_the_spec() {
        let expected = [12usize, 12, 162, 162];
        for ((name, counts, _values), expected) in ANNEX_K_TABLES.iter().zip(expected) {
            let total: usize = counts.iter().map(|&b| b as usize).sum();
            assert_eq!(total, expected, "{name}: symbol count mismatch");
        }
    }

    #[test]
    fn annex_k_kraft_sums_do_not_exceed_one() {
        for (name, counts, _values) in ANNEX_K_TABLES {
            let kraft: f64 = counts
                .iter()
                .enumerate()
                .map(|(index, &count)| count as f64 / (1u64 << (index + 1)) as f64)
                .sum();
            assert!(kraft <= 1.0 + 1e-9, "{name}: Kraft sum is {kraft}");
        }
    }

    #[test]
    fn annex_k_canonical_codes_are_unique_and_in_range() {
        // Independent canonical construction (no HuffmanTable::build):
        // every code must fit its length class and never repeat.
        for (name, counts, values) in ANNEX_K_TABLES {
            let mut code: u32 = 0;
            let mut seen = std::collections::HashSet::new();
            let mut index = 0usize;
            for (length_index, &count) in counts.iter().enumerate() {
                let length = (length_index + 1) as u32;
                for _ in 0..count {
                    let _symbol = values[index];
                    index += 1;
                    assert!(
                        code < (1u32 << length),
                        "{name}: code overflows length {length}"
                    );
                    assert!(
                        seen.insert((length, code)),
                        "{name}: duplicate code at length {length}"
                    );
                    code += 1;
                }
                code <<= 1;
            }
            assert_eq!(index, values.len(), "{name}: values length mismatch");
        }
    }

    #[test]
    fn annex_k_lut_maps_every_symbol_at_its_canonical_slot() {
        let annex = annex_k();
        let tables: [(&HuffmanTable, &[u8; 16], &[u8]); 4] = [
            (&annex.dc_luma, &ANNEX_K_DC_LUMA_NR, &ANNEX_K_DC_LUMA_VAL),
            (
                &annex.dc_chroma,
                &ANNEX_K_DC_CHROMA_NR,
                &ANNEX_K_DC_CHROMA_VAL,
            ),
            (&annex.ac_luma, &ANNEX_K_AC_LUMA_NR, &ANNEX_K_AC_LUMA_VAL),
            (
                &annex.ac_chroma,
                &ANNEX_K_AC_CHROMA_NR,
                &ANNEX_K_AC_CHROMA_VAL,
            ),
        ];
        for (table, counts, values) in tables {
            let mut code: u32 = 0;
            let mut index = 0usize;
            for (length_index, &count) in counts.iter().enumerate() {
                let length = (length_index + 1) as u32;
                for _ in 0..count {
                    let symbol = values[index];
                    index += 1;
                    let slot = (code << (16 - length)) as usize;
                    assert_eq!(
                        table.lut[slot],
                        (length as u8, symbol),
                        "table entry at slot {slot:#06x}"
                    );
                    code += 1;
                }
                code <<= 1;
            }
        }
    }

    #[test]
    fn annex_k_encode_decode_roundtrip() {
        // Canonical encode of every symbol, then an independent
        // 1-bit-at-a-time incremental decode; they must agree.
        struct BitWriter {
            bits: Vec<bool>,
        }
        impl BitWriter {
            fn write(&mut self, code: u32, length: u32) {
                for i in (0..length).rev() {
                    self.bits.push((code >> i) & 1 != 0);
                }
            }
        }
        for (name, counts, values) in ANNEX_K_TABLES {
            // (length, code) -> symbol (decode), and symbol -> (code, length) (encode)
            let mut decode_map = std::collections::HashMap::new();
            let mut encode_map = std::collections::HashMap::new();
            let mut code: u32 = 0;
            let mut index = 0usize;
            for (length_index, &count) in counts.iter().enumerate() {
                let length = (length_index + 1) as u32;
                for _ in 0..count {
                    let symbol = values[index];
                    index += 1;
                    decode_map.insert((length, code), symbol);
                    encode_map.insert(symbol, (code, length));
                    code += 1;
                }
                code <<= 1;
            }
            // encode every symbol in the table
            let mut writer = BitWriter { bits: Vec::new() };
            for &symbol in values.iter() {
                let &(c, l) = encode_map.get(&symbol).expect("symbol must have a code");
                writer.write(c, l);
            }
            // decode it back incrementally, one bit at a time
            let mut decoded = Vec::with_capacity(values.len());
            let mut pos = 0usize;
            while pos < writer.bits.len() {
                let mut code: u32 = 0;
                let mut length = 0u32;
                let mut found = false;
                while length < 16 {
                    assert!(
                        pos < writer.bits.len(),
                        "{name}: ran out of bits mid-symbol"
                    );
                    code = (code << 1) | u32::from(writer.bits[pos]);
                    pos += 1;
                    length += 1;
                    if let Some(&symbol) = decode_map.get(&(length, code)) {
                        decoded.push(symbol);
                        found = true;
                        break;
                    }
                }
                assert!(found, "{name}: no code match after 16 bits");
            }
            assert_eq!(decoded.as_slice(), *values, "{name}: roundtrip mismatch");
        }
    }

    #[test]
    fn annex_k_built_once() {
        assert!(std::ptr::eq(annex_k(), annex_k()));
    }

    #[test]
    fn annex_k_walk_matches_the_file_tables_on_libjpeg_fixtures() {
        // IJG-encoded fixtures embed the Annex K tables verbatim, so the
        // Annex K walk must agree with the file-table walk bit-for-bit.
        let (scan_start, geometry) = parse_geometry(RGB).unwrap();
        let eoi = RGB
            .windows(2)
            .rposition(|w| w == [0xFF, 0xD9])
            .expect("fixture ends with EOI");
        let (unstuffed, restarts) = unstuff(&RGB[scan_start..eoi]);
        let file_tables = parse_huff_tables(RGB, scan_start).unwrap();
        let file_refs: Vec<ComponentTables<'_>> = geometry
            .components
            .iter()
            .map(|c| ComponentTables {
                dc: file_tables[c.td as usize].as_ref().unwrap(),
                ac: file_tables[4 + c.ta as usize].as_ref().unwrap(),
            })
            .collect();
        let annex = annex_k();
        let annex_refs = annex.for_components(&geometry);
        let by_file = walk_mcus(&unstuffed, &restarts, &geometry, &file_refs, 0, MAX_MCUS);
        let by_annex = walk_mcus(&unstuffed, &restarts, &geometry, &annex_refs, 0, MAX_MCUS);
        assert_eq!(by_file.err, None);
        assert_eq!(by_annex.err, None);
        assert_eq!(by_file.mcus, by_annex.mcus);
        assert_eq!(by_file.blocks, by_annex.blocks);
        assert_eq!(by_file.end_bit, by_annex.end_bit);
        assert_eq!(by_file.dc_luma, by_annex.dc_luma);
        assert_eq!(by_file.first_boundaries, by_annex.first_boundaries);
        assert_eq!(by_file.mcus, 80); // 10 x 8 MCUs at 4:2:0
    }

    #[test]
    fn walk_mcus_respects_the_limit() {
        let (scan_start, geometry) = parse_geometry(RGB).unwrap();
        let eoi = RGB
            .windows(2)
            .rposition(|w| w == [0xFF, 0xD9])
            .expect("fixture ends with EOI");
        let (unstuffed, restarts) = unstuff(&RGB[scan_start..eoi]);
        let file_tables = parse_huff_tables(RGB, scan_start).unwrap();
        let file_refs: Vec<ComponentTables<'_>> = geometry
            .components
            .iter()
            .map(|c| ComponentTables {
                dc: file_tables[c.td as usize].as_ref().unwrap(),
                ac: file_tables[4 + c.ta as usize].as_ref().unwrap(),
            })
            .collect();
        let stats = walk_mcus(&unstuffed, &restarts, &geometry, &file_refs, 0, 10);
        assert_eq!(stats.err, None);
        assert_eq!(stats.mcus, 10);
        assert_eq!(stats.first_boundaries.len(), 10);
        // 4:2:0: four luma blocks (hence four DC predictions) per MCU.
        assert_eq!(stats.dc_luma.len(), 40);
    }

    #[test]
    fn walk_mcus_rejects_a_table_component_count_mismatch() {
        let (scan_start, geometry) = parse_geometry(RGB).unwrap();
        let eoi = RGB
            .windows(2)
            .rposition(|w| w == [0xFF, 0xD9])
            .expect("fixture ends with EOI");
        let (unstuffed, restarts) = unstuff(&RGB[scan_start..eoi]);
        let annex = annex_k();
        let refs = vec![ComponentTables {
            dc: &annex.dc_luma,
            ac: &annex.ac_luma,
        }]; // one component's worth for a 3-component scan
        let stats = walk_mcus(&unstuffed, &restarts, &geometry, &refs, 0, MAX_MCUS);
        assert!(stats.err.is_some());
    }

    #[test]
    fn walk_mcus_never_panics_on_garbage() {
        let (scan_start, geometry) = parse_geometry(RGB).unwrap();
        let eoi = RGB
            .windows(2)
            .rposition(|w| w == [0xFF, 0xD9])
            .expect("fixture ends with EOI");
        let garbage = vec![0xAAu8; eoi - scan_start];
        let file_tables = parse_huff_tables(RGB, scan_start).unwrap();
        let refs: Vec<ComponentTables<'_>> = geometry
            .components
            .iter()
            .map(|c| ComponentTables {
                dc: file_tables[c.td as usize].as_ref().unwrap(),
                ac: file_tables[4 + c.ta as usize].as_ref().unwrap(),
            })
            .collect();
        let stats = walk_mcus(&garbage, &[], &geometry, &refs, 0, MAX_MCUS);
        assert!(stats.err.is_some() || stats.mcus > 0);
    }

    #[test]
    fn caps_hold_on_a_real_scan() {
        let stats = verify_scan(RGB).unwrap();
        assert_eq!(stats.first_boundaries.len(), stats.mcus as usize);
        assert_eq!(stats.dc_luma.len(), stats.mcus as usize * 4); // 4:2:0
        assert!(stats.first_boundaries.len() <= FIRST_BOUNDARIES_CAP);
        assert!(stats.dc_luma.len() <= DC_LUMA_CAP);
    }

    #[test]
    fn unstuff_lenient_emits_junk_verbatim() {
        // `FF 09` is junk (not a legal marker): both bytes are emitted so
        // the dump→unstuffed mapping stays injective.
        let (out, rests) = unstuff_lenient(&[0xFF, 0x09, 0x01, 0xFF, 0x00, 0x02]);
        assert_eq!(out, vec![0xFF, 0x09, 0x01, 0xFF, 0x02]);
        assert!(rests.is_empty());
        // Fill bytes FF FF carry no entropy bits.
        let (out, _) = unstuff_lenient(&[0xAB, 0xFF, 0xFF, 0xCD]);
        assert_eq!(out, vec![0xAB, 0xCD]);
        // Restart markers are located but carry no entropy bytes.
        let (out, rests) = unstuff_lenient(&[0x11, 0xFF, 0xD0, 0x22]);
        assert_eq!(out, vec![0x11, 0x22]);
        assert_eq!(rests, vec![1]);
        // A truncated trailing FF is kept, not dropped.
        let (out, _) = unstuff_lenient(&[0x00, 0xFF]);
        assert_eq!(out, vec![0x00, 0xFF]);
    }

    #[test]
    fn unstuff_lenient_roundtrip_with_unstuff_on_clean_scans() {
        let eoi = RGB
            .windows(2)
            .rposition(|w| w == [0xFF, 0xD9])
            .expect("fixture ends with EOI");
        let (scan_start, _) = parse_geometry(RGB).unwrap();
        let (strict, _) = unstuff(&RGB[scan_start..eoi]);
        let (lenient, _) = unstuff_lenient(&RGB[scan_start..eoi]);
        assert_eq!(strict, lenient);
    }
}
