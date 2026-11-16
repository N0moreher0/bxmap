//! JPEG baseline entropy-coded scan walker (ROADMAP 8.12.3 foundation).
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
//! the file itself (`DHT`); nothing here is assumed.

use std::fmt;

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

/// Result of a successful walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkStats {
    /// Number of MCUs decoded (`mcu_cols × mcu_rows`).
    pub mcus: u64,
    /// Total 8×8 blocks decoded across all components.
    pub blocks: u64,
    /// Geometry the scan claims.
    pub geometry: ScanGeometry,
}

/// Largest supported component count.
pub const MAX_COMPONENTS: usize = 4;
/// Hard cap on decoded MCUs, mirroring the 8.12.8 safety rule.
pub const MAX_MCUS: u64 = 8_000_000;

/// One Huffman table as a 16-bit lookup.
struct HuffmanTable {
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

/// Bit reader over the unstuffed entropy bytes.
struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
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
fn parse_geometry(bytes: &[u8]) -> Result<(usize, ScanGeometry), WalkError> {
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
fn parse_huff_tables(bytes: &[u8], upto: usize) -> Result<[Option<HuffmanTable>; 8], WalkError> {
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
fn unstuff(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
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

    let (unstuffed, restarts) = unstuff(scan);
    let mut reader = BitReader::new(&unstuffed);
    let mut dc_pred = [0i32; MAX_COMPONENTS];
    let mut rest_index = 0usize;
    let mut blocks: u64 = 0;

    for mcu in 0..total_mcus {
        if geometry.dri > 0 && mcu > 0 && mcu % u64::from(geometry.dri) == 0 {
            // The encoder pads to a byte boundary before each restart
            // marker and resets the DC predictors.
            let current_bit = reader.bit_pos;
            if current_bit % 8 != 0 {
                let pad = 8 - (current_bit % 8);
                let pad_bits = reader.read_bits(pad as u32)?;
                if pad_bits != (1u32 << pad) - 1 {
                    return Err(WalkError::Padding);
                }
            }
            let at = reader.bit_pos / 8;
            match rest_index {
                i if i < restarts.len() && restarts[i] == at => {
                    rest_index += 1;
                    dc_pred = [0; MAX_COMPONENTS];
                }
                _ => return Err(WalkError::RestartMismatch),
            }
        }
        for (index, component) in geometry.components.iter().enumerate() {
            let h = component.h as usize;
            let v = component.v as usize;
            for _ in 0..(h * v) {
                let dc_huffman = tables[component.td as usize]
                    .as_ref()
                    .ok_or_else(|| WalkError::InvalidSegment("missing DC table".to_string()))?;
                let ac_huffman = tables[4 + component.ta as usize]
                    .as_ref()
                    .ok_or_else(|| WalkError::InvalidSegment("missing AC table".to_string()))?;
                // DC coefficient: category, then the extra bits.
                let dc_code = dc_huffman.lut[reader.peek16() as usize];
                if dc_code.0 == 0 {
                    return Err(WalkError::InvalidCode);
                }
                reader.skip(dc_code.0 as usize)?;
                let size = dc_code.1 as u32;
                let extra = reader.read_bits(size)?;
                let diff = extend(size, extra);
                dc_pred[index] = dc_pred[index].wrapping_add(diff);
                // AC coefficients, zig-zag order, up to 63.
                let mut k = 1usize;
                while k < 64 {
                    let ac_code = ac_huffman.lut[reader.peek16() as usize];
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
                blocks += 1;
            }
        }
    }
    if geometry.dri > 0 && rest_index < restarts.len() {
        // A trailing restart after the very last MCU: encoders emit one when
        // the MCU count is an exact multiple of the restart interval.
        let current_bit = reader.bit_pos;
        if current_bit % 8 != 0 {
            let pad = 8 - (current_bit % 8);
            let pad_bits = reader.read_bits(pad as u32)?;
            if pad_bits != (1u32 << pad) - 1 {
                return Err(WalkError::Padding);
            }
        }
        let at = reader.bit_pos / 8;
        match rest_index {
            i if i < restarts.len() && restarts[i] == at => {
                rest_index += 1;
            }
            _ => return Err(WalkError::RestartMismatch),
        }
    }
    if geometry.dri > 0 && rest_index != restarts.len() {
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
    Ok(WalkStats {
        mcus: total_mcus,
        blocks,
        geometry,
    })
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
}
