//! Estimated rebuild of a baseline JPEG whose table chain was destroyed
//! (ROADMAP 8.12.4). Everything here is an **estimate**, never an exact
//! reconstruction:
//!
//! - the Huffman tables are the ITU-T T.81 Annex K / IJG defaults
//!   (built into every libjpeg encoder), *assumed* to apply;
//! - the quantization table is the IJG quality-90 table (`assumed q90`),
//!   computed from the Annex K base tables with the IJG scaling rule;
//! - the geometry (`cols × rows` MCUs) is estimated from the statistics of
//!   the surviving luma DC predictor series (Pearson lagged correlation +
//!   a seam test on block boundaries);
//! - nothing is decrypted and no pixels are decoded. The result is cut,
//!   shifted to a byte boundary and re-stuffed back into a JPEG that must
//!   pass the same two gates as the exact rebuild (own validator + the MCU
//!   walker); `confidence` only ever reflects the DC statistics.
//!
//! Pipeline, all bounded, nothing panics:
//! 1. The caller hands us the stuffing-clean scan (no `RSTn`) and the
//!    destroyed-region size estimate.
//! 2. **Bit-sync probe**: for every byte in the first 16 KiB of the scan,
//!    every one of the 8 bit phases and each of the 6 common baseline
//!    layouts, walk the Annex K tables for 64 MCUs; candidates must
//!    survive without an error.
//! 3. **Standard boundary**: candidates must also decode for effectively
//!    the whole remainder of the scan. Pairs of same-layout candidates
//!    ≥ 2 KiB apart that converge to the same first MCU boundary (and
//!    agree for the next ≥ 64 MCUs) define the *standard boundary*;
//!    MCU statistics are counted from there. A candidate merely passing
//!    the probe by luck never pairs up with an independent one.
//! 4. **cols estimate**: Pearson correlation of the per-MCU luma DC
//!    predictor series (lag `c ∈ [8, min(1024, N/5)]`); any lag whose
//!    correlation ≥ 0.30 and whose block-level seam ratio (mean |ΔDC|
//!    across `i ≡ 0 mod fpm·c`) ≥ 1.5 qualifies; the winner is the
//!    highest-correlation candidate (ties → smallest lag). corr ≥ 0.55 →
//!    `medium`; [0.30, 0.55) → `low`; otherwise the image is rejected
//!    rather than guessed.
//! 5. **Row alignment**: `skip = N mod cols` MCUs are dropped from the
//!    standard boundary, `rows = (N - skip) / cols`; geometry gates
//!    (each side ≥ 64 px, aspect ratio within 0.1..10, ≥ 5 rows) apply.
//! 6. The kept scan is copied **bit-exactly** from the standard boundary
//!    plus `skip` MCUs up to the end of the `rows × cols`-th MCU, padded
//!    with 1 bits, re-stuffed and assembled into a file.
//!
//! The `RSTn`/`DRI` case is out of scope for P1 and always rejected with
//! `dri: needs donor`; keep the plain `Tail`. Custom camera Huffman tables
//! simply decode to nothing useful and are rejected with `custom_dht?`.

use std::sync::OnceLock;

use crate::jpeg_scan::{annex_k, walk_mcus, ComponentInfo, ScanGeometry, WalkStats, MAX_MCUS};

/// Largest scan window probed (bytes of entropy data, bit phases aside).
pub const PROBE_WINDOW_BYTES: usize = 16 * 1024;
/// Minimum MCU agreement length for the common-boundary rule.
pub const CONVERGED_MCUS: u64 = 64;
/// Minimum probe output (64 MCUs). Candidates below this are discarded.
const PROBE_MCUS: u64 = 64;
/// Minimum MCUs from the standard boundary to EOI we accept.
const MIN_MCUS_FROM_BOUNDARY: u64 = 64;
/// Lag bounds for the cols correlation.
const MIN_LAG: usize = 8;
const MAX_LAG: usize = 1024;
/// Correlation floor; below it there is no usable row signal.
const MIN_CORR: f32 = 0.30;
/// Correlation at/above which we may claim `medium` confidence.
const MEDIUM_CORR: f32 = 0.55;
/// Seam ratio floor (mean |ΔDC| across the row join ≥ this × intra-row).
const MIN_SEAM: f32 = 1.5;
/// MCU rows required before we rebuild.
const MIN_ROWS: u64 = 5;
/// Each image side must be at least this large.
const MIN_SIDE_PX: u64 = 64;
/// Aspect ratio bounds (w/h).
const MIN_ASPECT: f64 = 0.1;
const MAX_ASPECT: f64 = 10.0;

/// Why the estimated rebuild refused. The string form is a grep-able
/// token (`rebuild=estimate:...`) written into the file's index notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EstimatedReject {
    /// Scan carries `RSTn` markers: P1 does not rebuild those.
    NeedsDonor,
    /// Nothing decoded: probably camera-optimised or arithmetic/progressive.
    CustomTables,
    /// Two independent anchors never agreed on a boundary for 64 MCUs.
    NoConvergedBoundary,
    /// No lag had corr ≥ 0.30 and seam ≥ 1.5 (flat/graphics/noise texture).
    NoRowSignal,
    /// The surviving scan holds too few MCUs to estimate anything.
    TooFewMcus,
    /// Geometry gates failed (side < 64 px, aspect outside 0.1..10, rows < 5).
    GeometryUnreasonable,
    /// The kept scan misses the EOI padding by more than a byte, or the
    /// bit copy did not end where the walker says the last MCU ends.
    WalkerMismatch,
}

impl std::fmt::Display for EstimatedReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            EstimatedReject::NeedsDonor => "dri: needs donor",
            EstimatedReject::CustomTables => "custom_dht?",
            EstimatedReject::NoConvergedBoundary => "no_converged_boundary",
            EstimatedReject::NoRowSignal => "no_row_signal",
            EstimatedReject::TooFewMcus => "too_few_mcus",
            EstimatedReject::GeometryUnreasonable => "geometry_unreasonable",
            EstimatedReject::WalkerMismatch => "walker_mismatch",
        };
        f.write_str(token)
    }
}

impl std::error::Error for EstimatedReject {}

/// Estimated-rebuild confidence; only ever reflects the DC statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EstimatedConfidence {
    Medium,
    Low,
}

/// The output of a successful estimate: everything the carver needs to
/// write the file, plus the index metadata.
#[derive(Debug)]
pub(crate) struct Analysis {
    /// Layout (index into `LAYOUTS`).
    pub layout_index: usize,
    /// Layout label, e.g. `4:2:0` (same strings as the ROADMAP notes).
    pub layout_label: &'static str,
    /// Estimated MCUs per row.
    pub cols: u32,
    /// Estimated full rows kept (`(N - skip) / cols`).
    pub rows: u32,
    /// MCUs dropped from the standard boundary to align whole rows.
    pub skip_mcus: u64,
    /// MCUs kept in the rebuilt image (`total_mcus - skip_mcus`).
    pub kept_mcus: u64,
    /// Bit offset of the first kept MCU (standard boundary + skip).
    pub kept_start_bit: usize,
    /// Bit offset right after the last kept MCU.
    pub kept_end_bit: usize,
    /// Pearson correlation at the selected lag.
    pub corr: f32,
    /// Block-level seam ratio at the selected lag.
    pub seam: f32,
    /// `medium` (corr ≥ 0.55) or `low` (0.30..0.55).
    pub confidence: EstimatedConfidence,
    /// Estimated rows lost to the destroyed head (label estimate).
    pub lost_rows_est: u32,
    /// Absolute dump offset of the kept scan start (as in `{offset:08x}`).
    pub kept_dump_offset: u64,
}

/// The six common baseline layouts (photo content lives almost entirely
/// in 4:2:0; the rest are cheap to try).
#[derive(Clone, Copy)]
pub(crate) struct LayoutSpec {
    pub label: &'static str,
    /// Luma horizontal sampling factor.
    pub luma_h: u8,
    /// Luma vertical sampling factor.
    pub luma_v: u8,
    /// True for 3-component YCbCr layouts.
    pub color: bool,
}

const LAYOUTS: [LayoutSpec; 6] = [
    LayoutSpec {
        label: "gray",
        luma_h: 1,
        luma_v: 1,
        color: false,
    },
    LayoutSpec {
        label: "4:4:4",
        luma_h: 1,
        luma_v: 1,
        color: true,
    },
    LayoutSpec {
        label: "4:2:2",
        luma_h: 2,
        luma_v: 1,
        color: true,
    },
    LayoutSpec {
        label: "4:2:0",
        luma_h: 2,
        luma_v: 2,
        color: true,
    },
    LayoutSpec {
        label: "4:1:1",
        luma_h: 4,
        luma_v: 1,
        color: true,
    },
    LayoutSpec {
        label: "4:1:0",
        luma_h: 4,
        luma_v: 2,
        color: true,
    },
];

/// Geometry for the probe: large enough to cover any realistic scan
/// (row counts up to 4096 MCUs per axis, capped by `MAX_MCUS`), small
/// enough that the total MCU cap never fires for real inputs.
fn probe_geometry(layout_index: usize) -> ScanGeometry {
    let layout = &LAYOUTS[layout_index];
    let component = |h: u8, v: u8, tq: u8, td: u8, ta: u8| ComponentInfo { h, v, tq, td, ta };
    if layout.color {
        ScanGeometry {
            width: 2048,
            height: 2048,
            components: vec![
                component(layout.luma_h, layout.luma_v, 0, 0, 0),
                component(1, 1, 1, 1, 1),
                component(1, 1, 1, 1, 1),
            ],
            dri: 0,
        }
    } else {
        ScanGeometry {
            width: 2048,
            height: 2048,
            components: vec![component(1, 1, 0, 0, 0)],
            dri: 0,
        }
    }
}

/// The layout's MCU width in pixels.
fn mcu_width_px(layout_index: usize) -> u64 {
    u64::from(LAYOUTS[layout_index].luma_h) * 8
}

/// The layout's MCU height in pixels.
fn mcu_height_px(layout_index: usize) -> u64 {
    u64::from(LAYOUTS[layout_index].luma_v) * 8
}

/// Luma blocks per MCU for the layout.
fn luma_blocks_per_mcu(layout_index: usize) -> usize {
    let layout = &LAYOUTS[layout_index];
    usize::from(layout.luma_h) * usize::from(layout.luma_v)
}

/// --- IJG quality-90 quantization tables -----------------------------------
///
/// The T.81 Annex K base tables, scaled with the IJG quality rule
/// (implementation detail of `jcparam.c`): for quality ≥ 50,
/// `scale = 200 - 2·q` and each entry is
/// `clamp((base·scale + 50) / 100, 1, 255)`. The DQT payload is written in
/// zig-zag order (`jpeg_natural_order`).
const BASE_LUMA: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];

/// Annex K base chrominance quantisation table, natural order.
const BASE_CHROMA: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// `jpeg_natural_order` from libjpeg: the natural index of each position
/// in the zig-zag scan.
const NATURAL_ORDER: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// The DQT payload bytes for quality 90, zig-zag order (luma, chroma).
/// Computed once; the tests compare them against the bytes `cjpeg
/// -quality 90` wrote in the repo fixtures.
pub(crate) fn q90_tables() -> &'static [[u8; 64]; 2] {
    static Q90: OnceLock<[[u8; 64]; 2]> = OnceLock::new();
    Q90.get_or_init(|| {
        const SCALE: u32 = 200 - 2 * 90; // = 20, per jcparam.c for quality ≥ 50
        let mut tables = [[0u8; 64]; 2];
        for (which, base) in [BASE_LUMA, BASE_CHROMA].iter().enumerate() {
            for (zigzag, &natural_index) in NATURAL_ORDER.iter().enumerate() {
                let value = u32::from(base[natural_index]);
                let scaled = (value * SCALE + 50) / 100;
                tables[which][zigzag] = scaled.clamp(1, 255) as u8;
            }
        }
        tables
    })
}

// --- Bit-sync probe and common-boundary rule -------------------------------
//
// Every bit position of the window is a legal candidate anchor for the
// decoder (the Annex K tables are too dense to reject anything syntactically
// — a random stream "decodes" forever). The reliable discriminator is the
// spec's common-boundary notion: a boundary position shared by many
// independent 64-MCU walks. Junk walks desynchronise into unique paths and
// never repeat positions; the true MCU boundary sequence is walked by every
// chain that resynchronised into the real entropy stream, so it stands out
// in the frequency map. The earliest frequent position is the standard
// boundary (a true MCU boundary of the surviving scan); MCUs are counted
// from there. This replaced the earlier pair-greedy search, which kept
// only the first ≥ 2 KiB partner and depended on luck to land on a
// resynchronised chain.

/// True when both lists contain every boundary starting at `start` for at
/// least `count` consecutive entries.
fn boundaries_agree(a: &[usize], b: &[usize], start: usize, count: usize) -> bool {
    let mut i = a.partition_point(|&pos| pos < start);
    let mut j = b.partition_point(|&pos| pos < start);
    let mut same = 0usize;
    while i < a.len() && j < b.len() {
        if a[i] != b[j] {
            return false;
        }
        same += 1;
        if same >= count {
            return true;
        }
        i += 1;
        j += 1;
    }
    same >= 16
}

/// A converged layout + boundary pair from the bit-sync probe.
#[derive(Debug, Clone, Copy)]
struct Converged {
    layout_index: usize,
    boundary: usize,
}

/// Probe one layout: anchors are enumerated in one pass straight into a
/// frequency map (no per-anchor allocations survive the pass), and a
/// candidate is produced when the walk statistics agree on a shared
/// resynchronisation boundary. Layouts are tried one at a time by
/// [`analyze`] in [3, 2, 1, 4, 5, 0] order (most likely first), so a
/// passing candidate never pays for the remaining layouts. Returns the
/// candidate (if any) and whether any 64-MCU anchor was found.
fn probe_layout(unstuffed: &[u8], layout_index: usize) -> (Option<Converged>, bool) {
    /// A boundary position shared by at least this many 64-MCU walks is a
    /// shared resync point of independent chains — a true MCU boundary.
    const FREQ_MIN: u32 = 32;
    /// Minimum size of the frequent set before we trust it as a chain.
    const MIN_FREQ_POSITIONS: usize = 16;
    let window_bytes = unstuffed.len().min(PROBE_WINDOW_BYTES);
    let annex = annex_k();
    let geometry = probe_geometry(layout_index);
    let tables = annex.for_components(&geometry);
    let mut anchors = 0usize;
    let mut freq: std::collections::HashMap<usize, u32> = std::collections::HashMap::new();
    for byte in 0..window_bytes {
        for phase in 0..8usize {
            let start_bit = byte * 8 + phase;
            let stats = walk_mcus(unstuffed, &[], &geometry, &tables, start_bit, PROBE_MCUS);
            if stats.err.is_some() || stats.mcus != PROBE_MCUS {
                continue;
            }
            anchors += 1;
            for &pos in &stats.first_boundaries {
                *freq.entry(pos).or_default() += 1;
            }
        }
    }
    if anchors < 2 {
        return (None, anchors > 0);
    }
    let mut frequent: Vec<usize> = freq
        .iter()
        .filter(|(_, &count)| count >= FREQ_MIN)
        .map(|(&pos, _)| pos)
        .collect();
    frequent.sort_unstable();
    if frequent.len() < MIN_FREQ_POSITIONS {
        return (None, true);
    }
    let boundary = frequent[0];
    // Two independent chains must agree for ≥ 64 positions from the
    // boundary (the spec's common-boundary evidence). Re-walk two
    // anchors that contain the boundary — only needed for this layout.
    let mut chain_a: Option<Vec<usize>> = None;
    let mut chain_b: Option<Vec<usize>> = None;
    'verify: for byte in 0..window_bytes {
        for phase in 0..8usize {
            let start_bit = byte * 8 + phase;
            let stats = walk_mcus(unstuffed, &[], &geometry, &tables, start_bit, PROBE_MCUS);
            if stats.err.is_some() || stats.mcus != PROBE_MCUS {
                continue;
            }
            if stats.first_boundaries.binary_search(&boundary).is_ok() {
                if chain_a.is_none() {
                    chain_a = Some(stats.first_boundaries);
                } else {
                    chain_b = Some(stats.first_boundaries);
                    break 'verify;
                }
            }
        }
    }
    let (Some(chain_a), Some(chain_b)) = (chain_a, chain_b) else {
        return (None, true);
    };
    if !boundaries_agree(&chain_a, &chain_b, boundary, CONVERGED_MCUS as usize) {
        return (None, true);
    }
    (
        Some(Converged {
            layout_index,
            boundary,
        }),
        true,
    )
}

// --- cols estimation from the luma DC predictor -----------------------------

/// Pearson correlation between `x[i]` and `x[i + lag]` over the overlapping
/// prefix of `x`. Returns 0 for degenerate (constant) inputs.
fn pearson(x: &[i32], lag: usize) -> f32 {
    let n = x.len().saturating_sub(lag);
    if n < 8 {
        return 0.0;
    }
    let mut sum_x = 0f64;
    let mut sum_y = 0f64;
    for i in 0..n {
        sum_x += f64::from(x[i]);
        sum_y += f64::from(x[i + lag]);
    }
    let mean_x = sum_x / n as f64;
    let mean_y = sum_y / n as f64;
    let mut cov = 0f64;
    let mut var_x = 0f64;
    let mut var_y = 0f64;
    for i in 0..n {
        let dx = f64::from(x[i]) - mean_x;
        let dy = f64::from(x[i + lag]) - mean_y;
        cov += dx * dy;
        var_x += dx * dx;
        var_y += dy * dy;
    }
    if var_x <= 0.0 || var_y <= 0.0 {
        return 0.0;
    }
    (cov / (var_x.sqrt() * var_y.sqrt())) as f32
}

/// Block-level seam ratio with the row-join class search: the entropy
/// scan we analyse starts at an arbitrary resynchronisation point, so the
/// true row joins can sit at any of the `cols` residue classes
/// `i ≡ k·fpm (mod fpm·cols)`. The ratio is computed for every such class
/// and the best is returned; classes that are not MCU-aligned are ignored
/// (luma blocks per MCU is `fpm`, row joins happen at block indices that
/// are multiples of `fpm`).
fn seam_block(dc_blocks: &[i32], fpm: usize, cols: usize, skip_blocks: usize) -> f32 {
    let modulus = fpm.saturating_mul(cols);
    if modulus == 0 || dc_blocks.len() <= skip_blocks + 1 {
        return 0.0;
    }
    // Sum |ΔDC| and sample counts per residue class of `i mod modulus`.
    // Only classes that are multiples of `fpm` can be row joins.
    let mut sums = vec![0f64; modulus];
    let mut counts = vec![0u64; modulus];
    let mut total_sum = 0f64;
    let mut total_n = 0u64;
    for i in (skip_blocks + 1)..dc_blocks.len() {
        let delta = (i64::from(dc_blocks[i]) - i64::from(dc_blocks[i - 1])).unsigned_abs() as f64;
        let class = i % modulus;
        sums[class] += delta;
        counts[class] += 1;
        total_sum += delta;
        total_n += 1;
    }
    let mut best = 0f32;
    for k in 0..cols {
        let class = k * fpm;
        let cross_sum = sums[class];
        let cross_n = counts[class];
        let intra_sum = total_sum - cross_sum;
        let intra_n = total_n - cross_n;
        if cross_n == 0 || intra_n == 0 || intra_sum == 0.0 {
            continue;
        }
        let ratio = (cross_sum / cross_n as f64) / (intra_sum / intra_n as f64);
        if ratio as f32 > best {
            best = ratio as f32;
        }
    }
    best
}

/// One estimate candidate (lag) with its evidence.
#[derive(Clone, Copy)]
struct ColsEstimate {
    cols: usize,
    corr: f32,
    seam: f32,
}

/// Collapse the block-level DC predictor series to per-MCU values (the
/// predictor after the last luma block of each MCU), skipping the first
/// `skip_mcus` entries.
fn per_mcu_series(dc_blocks: &[i32], fpm: usize, skip_mcus: usize) -> Vec<i32> {
    let blocks_needed = (skip_mcus + 1).saturating_mul(fpm);
    if dc_blocks.len() <= blocks_needed {
        return Vec::new();
    }
    dc_blocks
        .iter()
        .skip(blocks_needed - fpm)
        .step_by(fpm)
        .copied()
        .collect()
}

/// Estimate the MCU row length, the alignment skip and the confidence.
/// `naive` N is the MCU count from the standard boundary to EOI.
fn estimate_cols(dc_blocks: &[i32], fpm: usize) -> Result<ColsEstimate, EstimatedReject> {
    let mcu_series = per_mcu_series(dc_blocks, fpm, 32);
    let n = mcu_series.len();
    if n < 64 {
        return Err(EstimatedReject::TooFewMcus);
    }
    let max_lag = MAX_LAG.min(n / 5).max(MIN_LAG);
    let skip_blocks = 32 * fpm;
    // All lags that pass both gates.
    let mut passers: Vec<ColsEstimate> = Vec::new();
    for cols in MIN_LAG..=max_lag {
        let corr = pearson(&mcu_series, cols);
        if corr < MIN_CORR {
            continue;
        }
        let seam = seam_block(dc_blocks, fpm, cols, skip_blocks);
        if seam < MIN_SEAM {
            continue;
        }
        passers.push(ColsEstimate { cols, corr, seam });
    }
    // Spec rule: keep the peak correlation, then take the SMALLEST lag
    // whose correlation is within 0.97 of the peak (ties/near-ties lost to
    // the seam test are already gone). This nails the fundamental period
    // (camera: peak .77@39 rejected by the seam test → 40 wins).
    let peak = passers
        .iter()
        .map(|estimate| estimate.corr)
        .fold(0f32, f32::max);
    let threshold = peak * 0.97;
    passers
        .into_iter()
        .find(|estimate| estimate.corr >= threshold)
        .ok_or(EstimatedReject::NoRowSignal)
}

/// Bit offset of the first bit at/after `bit` that belongs to an MCU
/// boundary recorded in `boundaries`. Returns `None` when fewer than
/// `skip + 1` boundaries exist (the scan is shorter than the skip).
fn boundary_after(boundaries: &[usize], skip_mcus: u64) -> Option<usize> {
    let index = usize::try_from(skip_mcus).ok()?;
    boundaries.get(index).copied()
}

/// Map an unstuffed byte position back to a dump offset relative to the
/// start of the scan (lenient sibling of `unstuff`'s pass).
fn dump_offset_of_unstuffed_byte(scan: &[u8], unstuffed_target: usize) -> u64 {
    let mut dump = 0u64;
    let mut out = 0usize;
    let mut i = 0usize;
    while i < scan.len() && out < unstuffed_target {
        if scan[i] != 0xFF {
            out += 1;
            dump += 1;
            i += 1;
            continue;
        }
        match scan.get(i + 1).copied().unwrap_or(0) {
            0x00 => {
                out += 1;
                dump += 2;
                i += 2;
            }
            0xFF => {
                dump += 1;
                i += 1;
            }
            0xD0..=0xD7 => {
                // Restart markers carry no entropy bits.
                dump += 2;
                i += 2;
            }
            _ => {
                // Junk that looks like a marker: both bytes were emitted.
                out += 2;
                dump += 2;
                i += 2;
            }
        }
    }
    dump
}

// --- The analysis entry point and the rebuilt file --------------------------

/// Parameters the carver passes in.
pub(crate) struct ScanInput<'a> {
    /// The entropy-coded bytes from the run start up to (but excluding)
    /// the EOI. May begin inside random junk from the destroyed head.
    pub scan: &'a [u8],
    /// Absolute dump offset of `scan[0]` (the run start).
    pub run_start_abs: u64,
}

/// Bit offset of the first kept MCU for an alignment skip.
fn kept_start_bit(walk: &WalkStats, skip_mcus: u64) -> Option<usize> {
    boundary_after(&walk.first_boundaries, skip_mcus)
}

/// Estimate the image with one converged (layout, boundary) candidate.
/// Returns the analysis or a reject reason; the caller tries the
/// candidates in order until one passes every gate.
fn estimate_candidate(
    input: &ScanInput<'_>,
    unstuffed: &[u8],
    restarts: &[usize],
    Converged {
        layout_index,
        boundary,
    }: Converged,
) -> Result<Analysis, EstimatedReject> {
    // Restart markers we find anywhere before the kept MCU are junk that
    // happened to have a marker shape; only markers at or past the kept
    // boundary belong to the real scan (a `DRI`-coded image, which P1
    // refuses: keep the plain Tail).
    let geometry = probe_geometry(layout_index);
    let annex = annex_k();
    let tables = annex.for_components(&geometry);
    let walk = walk_mcus(unstuffed, &[], &geometry, &tables, boundary, MAX_MCUS);
    let total_mcus = walk.mcus;
    if total_mcus < MIN_MCUS_FROM_BOUNDARY {
        return Err(EstimatedReject::TooFewMcus);
    }
    let fpm = luma_blocks_per_mcu(layout_index);
    let estimate = estimate_cols(&walk.dc_luma, fpm)?;
    let cols = estimate.cols as u64;
    let skip_mcus = total_mcus % cols;
    let kept_mcus = total_mcus - skip_mcus;
    let rows = kept_mcus / cols;
    // Geometry gates.
    let width = cols * mcu_width_px(layout_index);
    let height = rows * mcu_height_px(layout_index);
    if width < MIN_SIDE_PX || height < MIN_SIDE_PX {
        return Err(EstimatedReject::GeometryUnreasonable);
    }
    let aspect = width as f64 / height as f64;
    if !(MIN_ASPECT..=MAX_ASPECT).contains(&aspect) {
        return Err(EstimatedReject::GeometryUnreasonable);
    }
    if rows < MIN_ROWS {
        return Err(EstimatedReject::GeometryUnreasonable);
    }
    // The kept scan starts after `skip_mcus` whole MCUs from the standard
    // boundary. `first_boundaries` is capped; practically skip is tiny.
    let kept_start =
        kept_start_bit(&walk, skip_mcus).ok_or(EstimatedReject::GeometryUnreasonable)?;
    // Only markers at/after the kept boundary are real `DRI` evidence.
    if restarts
        .iter()
        .any(|&restart| restart.saturating_mul(8) >= kept_start)
    {
        return Err(EstimatedReject::NeedsDonor);
    }
    // Confirm the kept scan decodes to exactly `rows × cols` MCUs and then
    // ends at the EOI padding. This is the definitive gate before building.
    let kept_geometry = ScanGeometry {
        width: u16::try_from(width).unwrap_or(u16::MAX),
        height: u16::try_from(height).unwrap_or(u16::MAX),
        components: geometry.components,
        dri: 0,
    };
    let kept_tables = annex.for_components(&kept_geometry);
    let kept_walk = walk_mcus(
        unstuffed,
        &[],
        &kept_geometry,
        &kept_tables,
        kept_start,
        rows.saturating_mul(cols),
    );
    if kept_walk.err.is_some() || kept_walk.mcus != rows * cols {
        return Err(EstimatedReject::WalkerMismatch);
    }
    // Bytes per MCU are needed for the `lost_rows_est` label.
    let kept_bytes = (kept_walk.end_bit - kept_start) as f64 / 8.0;
    let bytes_per_mcu = if kept_mcus == 0 {
        return Err(EstimatedReject::TooFewMcus);
    } else {
        kept_bytes / kept_mcus as f64
    };
    // Rows lost to the destroyed head: the junk/alignment prefix before
    // the first kept MCU, measured in whole MCUs (label estimate only —
    // the true row count before the first kept MCU is not recoverable
    // from inside the scan). Counted as whole MCUs over the bytes per MCU.
    let prefix_bytes = kept_start as f64 / 8.0;
    let prefix_mcus = prefix_bytes / bytes_per_mcu;
    let lost_rows_est = (prefix_mcus / cols as f64).round() as u32;
    let confidence = if estimate.corr >= MEDIUM_CORR {
        EstimatedConfidence::Medium
    } else {
        EstimatedConfidence::Low
    };
    // End-of-data trailing bits are *not* gated here: the kept MCUs are
    // copied bit-exactly into the rebuilt scan (padded with 1s up to a
    // byte boundary), and the rebuilt file then passes the same gates as
    // the exact rebuild — own validator + `verify_scan`, which requires
    // exactly `rows × cols` MCUs ending with ≤ 7 all-1s padding bits.
    // The bits after the kept scan belong to the dropped head region and
    // are not part of the reconstruction.
    Ok(Analysis {
        layout_index,
        layout_label: LAYOUTS[layout_index].label,
        cols: estimate.cols as u32,
        rows: rows as u32,
        skip_mcus,
        kept_mcus,
        kept_start_bit: kept_start,
        kept_end_bit: kept_walk.end_bit,
        corr: estimate.corr,
        seam: estimate.seam,
        confidence,
        lost_rows_est,
        kept_dump_offset: input.run_start_abs
            + dump_offset_of_unstuffed_byte(input.scan, kept_start / 8),
    })
}

/// Analyze a survived scan and, on success, describe the rebuilt file.
/// Layouts are probed one at a time in the order most likely to produce
/// photo content (4:2:0 first); the first layout whose candidate passes
/// every gate wins, so a passing candidate never pays for probing the
/// rest. The final byte-level build happens in [`build_file`].
pub(crate) fn analyze(input: &ScanInput<'_>) -> Result<Analysis, EstimatedReject> {
    let (unstuffed, restarts) = crate::jpeg_scan::unstuff_lenient(input.scan);
    let layout_order = [3usize, 2, 1, 4, 5, 0];
    let mut found_any_anchor = false;
    let mut first_reject: Option<EstimatedReject> = None;
    for layout_index in layout_order {
        let (candidate, any_anchor) = probe_layout(&unstuffed, layout_index);
        found_any_anchor |= any_anchor;
        let Some(candidate) = candidate else {
            continue;
        };
        match estimate_candidate(input, &unstuffed, &restarts, candidate) {
            Ok(analysis) => return Ok(analysis),
            // A `DRI`-coded scan is a hard stop for every layout.
            Err(EstimatedReject::NeedsDonor) => return Err(EstimatedReject::NeedsDonor),
            Err(reject) => {
                if first_reject.is_none() {
                    first_reject = Some(reject);
                }
            }
        }
    }
    Err(first_reject.unwrap_or(if found_any_anchor {
        EstimatedReject::NoConvergedBoundary
    } else {
        EstimatedReject::CustomTables
    }))
}

// --- Building the rebuilt file ---------------------------------------------

/// Copy bits `[start_bit, end_bit)` of `data` into a fresh byte vector. The
/// final partial byte is padded with 1 bits (encoder padding).
fn extract_bits(data: &[u8], start_bit: usize, end_bit: usize) -> Vec<u8> {
    debug_assert!(end_bit <= data.len() * 8);
    let bit_len = end_bit.saturating_sub(start_bit);
    let mut out = Vec::with_capacity(bit_len / 8 + 2);
    let mut accumulator: u8 = 0;
    let mut filled: u32 = 0;
    for bit_index in start_bit..end_bit {
        let byte = data[bit_index / 8];
        let bit = (byte >> (7 - (bit_index % 8))) & 1;
        accumulator = (accumulator << 1) | bit;
        filled += 1;
        if filled == 8 {
            out.push(accumulator);
            accumulator = 0;
            filled = 0;
        }
    }
    if filled > 0 {
        accumulator <<= 8 - filled;
        accumulator |= 0xFF >> filled; // encoder pad: all 1s
        out.push(accumulator);
    }
    out
}

/// Insert `FF 00` after every `FF` (the entropy-coded data must be
/// byte-stuffed like any encoder writes it).
fn restuff(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 64);
    for &byte in data {
        out.push(byte);
        if byte == 0xFF {
            out.push(0x00);
        }
    }
    out
}

fn push_u16_be(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn dqt_segment(id: u8, table: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(67);
    out.extend_from_slice(&[0xFF, 0xDB, 0x00, 0x43, id]);
    out.extend_from_slice(table);
    out
}

fn sof0_segment(width: u32, height: u32, components: &[(u8, u8, u8)]) -> Vec<u8> {
    let length = 8 + 3 * components.len() as u16;
    let mut out = Vec::with_capacity(4 + length as usize);
    out.extend_from_slice(&[0xFF, 0xC0]);
    push_u16_be(&mut out, length);
    out.push(8); // precision
    push_u16_be(&mut out, height as u16);
    push_u16_be(&mut out, width as u16);
    out.push(components.len() as u8);
    for &(id, sampling, tq) in components {
        out.push(id);
        out.push(sampling);
        out.push(tq);
    }
    out
}

fn dht_segment(id: u8, counts: &[u8; 16], values: &[u8]) -> Vec<u8> {
    let length = 2 + 1 + 16 + values.len() as u16;
    let mut out = Vec::with_capacity(4 + length as usize);
    out.extend_from_slice(&[0xFF, 0xC4]);
    push_u16_be(&mut out, length);
    out.push(id);
    out.extend_from_slice(counts);
    out.extend_from_slice(values);
    out
}

fn sos_segment(component_ids: &[u8]) -> Vec<u8> {
    let length = 6 + 2 * component_ids.len() as u16;
    let mut out = Vec::with_capacity(4 + length as usize);
    out.extend_from_slice(&[0xFF, 0xDA]);
    push_u16_be(&mut out, length);
    out.push(component_ids.len() as u8);
    for (index, id) in component_ids.iter().enumerate() {
        out.push(*id);
        out.push(if index == 0 { 0x00 } else { 0x11 }); // td/ta: luma 0/0, chroma 1/1
    }
    out.extend_from_slice(&[0x00, 0x3F, 0x00]); // Ss=0, Se=63, Ah/Al=0
    out
}

/// The four Annex K tables as four standalone DHT segments (ids 0x00, 0x10,
/// 0x01, 0x11).
fn annex_k_dht_segments() -> Vec<u8> {
    use crate::jpeg_scan::{
        ANNEX_K_AC_CHROMA_NR, ANNEX_K_AC_CHROMA_VAL, ANNEX_K_AC_LUMA_NR, ANNEX_K_AC_LUMA_VAL,
        ANNEX_K_DC_CHROMA_NR, ANNEX_K_DC_CHROMA_VAL, ANNEX_K_DC_LUMA_NR, ANNEX_K_DC_LUMA_VAL,
    };
    let mut out = Vec::with_capacity(4 * 32 + 2 * 176);
    out.extend_from_slice(&dht_segment(
        0x00,
        &ANNEX_K_DC_LUMA_NR,
        &ANNEX_K_DC_LUMA_VAL,
    ));
    out.extend_from_slice(&dht_segment(
        0x10,
        &ANNEX_K_AC_LUMA_NR,
        &ANNEX_K_AC_LUMA_VAL,
    ));
    out.extend_from_slice(&dht_segment(
        0x01,
        &ANNEX_K_DC_CHROMA_NR,
        &ANNEX_K_DC_CHROMA_VAL,
    ));
    out.extend_from_slice(&dht_segment(
        0x11,
        &ANNEX_K_AC_CHROMA_NR,
        &ANNEX_K_AC_CHROMA_VAL,
    ));
    out
}

/// Build the rebuilt JPEG: `SOI` + minimal APP0 + assumed `q90` DQTs +
/// `SOF0` + Annex K DHTs + `SOS` + the bit-exact kept scan + `EOI`.
pub(crate) fn build_file(input: &ScanInput<'_>, analysis: &Analysis, jfif_app0: &[u8]) -> Vec<u8> {
    let layout_index = analysis.layout_index;
    let layout = &LAYOUTS[layout_index];
    let q90 = q90_tables();
    let (unstuffed, _) = crate::jpeg_scan::unstuff_lenient(input.scan);
    let width = u64::from(analysis.cols) * mcu_width_px(layout_index);
    let height = u64::from(analysis.rows) * mcu_height_px(layout_index);
    let components: Vec<(u8, u8, u8)> = if layout.color {
        vec![
            (1, (layout.luma_h << 4) | layout.luma_v, 0),
            (2, 0x11, 1),
            (3, 0x11, 1),
        ]
    } else {
        vec![(1, 0x11, 0)]
    };
    let ids: Vec<u8> = components.iter().map(|&(id, _, _)| id).collect();
    let mut bytes = Vec::with_capacity(input.scan.len() + 1024);
    bytes.extend_from_slice(&[0xFF, 0xD8]);
    bytes.extend_from_slice(jfif_app0);
    bytes.extend_from_slice(&dqt_segment(0, &q90[0]));
    bytes.extend_from_slice(&dqt_segment(1, &q90[1]));
    bytes.extend_from_slice(&sof0_segment(width as u32, height as u32, &components));
    bytes.extend_from_slice(&annex_k_dht_segments());
    bytes.extend_from_slice(&sos_segment(&ids));
    // The kept scan: bit-exact copy, padded with 1s, re-stuffed.
    let kept_bits = extract_bits(&unstuffed, analysis.kept_start_bit, analysis.kept_end_bit);
    bytes.extend_from_slice(&restuff(&kept_bits));
    bytes.extend_from_slice(&[0xFF, 0xD9]);
    bytes
}

// --- Tests ------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q90_tables_match_ijg_q90_bytes() {
        // Byte-exact against `cjpeg -quality 90 -baseline` (ITU-T T.81
        // Annex K bases scaled per jcparam.c with quality=90).
        const EXPECT_LUMA: [u8; 64] = [
            3, 2, 2, 3, 2, 2, 3, 3, 3, 3, 4, 3, 3, 4, 5, 8, 5, 5, 4, 4, 5, 10, 7, 7, 6, 8, 12, 10,
            12, 12, 11, 10, 11, 11, 13, 14, 18, 16, 13, 14, 17, 14, 11, 11, 16, 22, 16, 17, 19, 20,
            21, 21, 21, 12, 15, 23, 24, 22, 20, 24, 18, 20, 21, 20,
        ];
        const EXPECT_CHROMA: [u8; 64] = {
            let mut table = [20u8; 64];
            let head = [3u8, 4, 4, 5, 4, 5, 9, 5, 5, 9, 20, 13, 11, 13];
            let mut i = 0;
            while i < head.len() {
                table[i] = head[i];
                i += 1;
            }
            table
        };
        let q90 = q90_tables();
        assert_eq!(q90[0], EXPECT_LUMA);
        assert_eq!(q90[1], EXPECT_CHROMA);
    }

    #[test]
    fn boundaries_agree_requires_consecutive_runs() {
        let a = [10, 20, 30, 40, 50, 60, 70, 80];
        let b = [10, 20, 30, 40, 50, 60, 70, 80];
        assert!(boundaries_agree(&a, &b, 10, 8));
        let c = [10, 20, 99, 40, 50, 60, 70, 80];
        assert!(!boundaries_agree(&a, &c, 10, 8));
        // Common suffix shorter than the requested run falls back to >= 16.
        let d = [90, 10, 20];
        let e = [90, 10, 20, 30, 40, 50, 60, 70];
        assert!(boundaries_agree(&d, &e, 10, 2));
    }

    #[test]
    fn seam_block_finds_row_joins_at_any_phase() {
        // Constant luma DC with a jump every `fpm * cols` blocks: the join
        // must be found even when the series does not start at a join.
        let fpm = 4usize;
        let cols = 40usize;
        let blocks = 400usize;
        let mut dc = vec![0i32; blocks];
        let shift = 8; // join at i ≡ 8 mod fpm*cols, an MCU-aligned class
        let mut level = 0i32;
        for (i, slot) in dc.iter_mut().enumerate().take(blocks) {
            if i % (fpm * cols) == shift {
                level += 100;
            }
            // Small intra-row variation so the baseline is non-zero (like
            // real photo content), keeping the joins dominant.
            *slot = level + (i % 3) as i32;
        }
        let seam = seam_block(&dc, fpm, cols, 0);
        assert!(seam >= 2.0, "seam should flag the 100-unit jumps: {seam}");
        let flat_noise: Vec<i32> = (0..blocks as i32).map(|i| i % 3).collect();
        let seam_flat = seam_block(&flat_noise, fpm, cols, 0);
        assert!(
            seam_flat < 2.0,
            "flat noise should not trip the seam: {seam_flat}"
        );
    }

    #[test]
    fn pearson_perfect_correlation() {
        let x: Vec<i32> = (0..200).collect();
        assert!(pearson(&x, 3) > 0.99);
        let constant = vec![7i32; 64];
        assert_eq!(pearson(&constant, 3), 0.0);
    }
}
