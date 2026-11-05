use bxmap::{scan_entropy_from_file_with_options, EntropyRegion, EntropyScanOptions};

/// Default entropy threshold (bits/byte).
pub const ENTROPY_THRESHOLD: f64 = 7.2;
/// Default max payload bytes kept per entropy region.
pub const ENTROPY_MAX_DATA: usize = 4096;
/// Max entropy regions buffered in the non-streaming path.
pub const MAX_ENTROPY_REPORTS: usize = 12;

/// True when an entropy region overlaps the requested byte range (or no range
/// was requested).
pub fn entropy_region_in_range(
    region: &EntropyRegion,
    range_active: bool,
    range_start: u64,
    range_end: u64,
) -> bool {
    if !range_active {
        return true;
    }
    let region_end = region.offset.saturating_add(region.length as u64);
    region.offset < range_end && region_end > range_start
}

/// Collect entropy regions into a Vec (non-streaming path), optionally
/// restricted to a byte range and capped at MAX_ENTROPY_REPORTS.
pub fn collect_entropy_regions(
    path: &str,
    options: EntropyScanOptions,
    range_active: bool,
    range_start: u64,
    range_end: u64,
) -> std::io::Result<Vec<(EntropyRegion, Vec<u8>, bool)>> {
    let mut out = Vec::new();
    scan_entropy_from_file_with_options(path, options, |region, data, data_truncated| {
        if out.len() < MAX_ENTROPY_REPORTS
            && entropy_region_in_range(&region, range_active, range_start, range_end)
        {
            out.push((region, data.to_vec(), data_truncated));
        }
    })?;
    Ok(out)
}

/// Stream entropy regions through a callback (streaming path).
pub fn stream_entropy_regions<F: FnMut(EntropyRegion, &[u8], bool)>(
    path: &str,
    options: EntropyScanOptions,
    mut on_region: F,
) -> std::io::Result<usize> {
    scan_entropy_from_file_with_options(path, options, |region, data, data_truncated| {
        on_region(region, data, data_truncated);
    })
}
