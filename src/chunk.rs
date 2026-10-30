//! Chunked file reading with a configurable overlap.
//!
//! Every streaming scanner needs the same shape: read the file in fixed
//! windows while keeping a few trailing bytes so a match that straddles an
//! I/O boundary is still visible. This module owns that loop so each new
//! scanner (magic bytes today, carving later) does not re-implement the carry
//! bookkeeping and get the offsets subtly wrong.

use std::fs::File;
use std::io::{self, BufReader, Read};

/// Default window size for streaming scanners (64 KiB).
pub const CHUNK_SIZE: usize = 1 << 16;

/// One window handed to a chunk callback.
#[derive(Debug, Clone, Copy)]
pub struct Chunk<'a> {
    /// Absolute file offset of `data[0]`.
    pub offset: u64,
    /// Window bytes, including the overlap prefix.
    pub data: &'a [u8],
    /// Leading bytes already delivered by the previous window. A match that
    /// starts before this index was reported there, so callers should skip it
    /// to avoid duplicates.
    pub overlap: usize,
}

impl Chunk<'_> {
    /// Absolute file offset of a byte index inside `data`.
    pub fn offset_of(&self, index: usize) -> u64 {
        self.offset + index as u64
    }

    /// True when `index` is new data rather than a re-delivered overlap byte.
    pub fn is_new(&self, index: usize) -> bool {
        index >= self.overlap
    }

    /// True when a match ending at `end` reaches new data. Matches that end
    /// inside the overlap prefix were already visible to the previous window,
    /// so scanners must skip them to avoid duplicate hits.
    pub fn spans_new_bytes(&self, end: usize) -> bool {
        end > self.overlap
    }
}

/// Read `path` in `chunk_size` windows, retaining up to `overlap` trailing
/// bytes between windows.
///
/// `on_chunk` returns `false` to stop early (limit reached). `overlap` is
/// clamped to `chunk_size`, and `chunk_size` to at least one byte.
pub fn for_each_chunk<F>(
    path: &str,
    chunk_size: usize,
    overlap: usize,
    mut on_chunk: F,
) -> io::Result<()>
where
    F: FnMut(Chunk<'_>) -> bool,
{
    let chunk_size = chunk_size.max(1);
    let overlap = overlap.min(chunk_size);
    let mut reader = BufReader::with_capacity(chunk_size, File::open(path)?);
    let mut buffer = vec![0u8; chunk_size];
    let mut carry: Vec<u8> = Vec::new();
    let mut window_start = 0u64;
    loop {
        // Fill the window completely so offsets are predictable; `read` alone
        // may return short reads and turn one logical chunk into several.
        let mut filled = 0usize;
        while filled < chunk_size {
            let read = reader.read(&mut buffer[filled..])?;
            if read == 0 {
                break;
            }
            filled += read;
        }
        if filled == 0 {
            return Ok(());
        }
        let mut window = Vec::with_capacity(carry.len() + filled);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&buffer[..filled]);
        let carried = carry.len();
        let keep = window.len().min(overlap);
        let chunk = Chunk {
            offset: window_start,
            data: &window,
            overlap: carried,
        };
        if !on_chunk(chunk) {
            return Ok(());
        }
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
        window_start += (window.len() - keep) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("bxmap-chunk-{}-{}.bin", name, std::process::id()));
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn windows_cover_the_file_exactly_once() {
        let data: Vec<u8> = (0..1000u32).map(|value| value as u8).collect();
        let path = write_temp("cover", &data);
        let mut seen = Vec::new();
        for_each_chunk(path.to_str().unwrap(), 256, 8, |chunk| {
            for (index, byte) in chunk.data.iter().enumerate() {
                if chunk.is_new(index) {
                    seen.push((chunk.offset_of(index), *byte));
                }
            }
            true
        })
        .unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(seen.len(), data.len());
        for (index, (offset, byte)) in seen.iter().enumerate() {
            assert_eq!(*offset, index as u64);
            assert_eq!(*byte, data[index]);
        }
    }

    #[test]
    fn overlap_is_redelivered_but_flagged() {
        let data: Vec<u8> = (0..600u32).map(|value| value as u8).collect();
        let path = write_temp("overlap", &data);
        let mut windows = Vec::new();
        for_each_chunk(path.to_str().unwrap(), 256, 16, |chunk| {
            windows.push((chunk.offset, chunk.data.len(), chunk.overlap));
            true
        })
        .unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(windows.len(), 3, "{windows:?}");
        assert_eq!(windows[0], (0, 256, 0));
        assert_eq!(windows[1], (240, 272, 16));
        // Last window: 16 overlap bytes + the remaining 88 new bytes.
        assert_eq!(windows[2], (496, 104, 16));
    }

    #[test]
    fn callback_can_stop_early() {
        let data = vec![0u8; 4096];
        let path = write_temp("stop", &data);
        let mut windows = 0;
        for_each_chunk(path.to_str().unwrap(), 256, 0, |_| {
            windows += 1;
            windows < 2
        })
        .unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(windows, 2);
    }

    #[test]
    fn empty_file_yields_no_windows() {
        let path = write_temp("empty", &[]);
        let mut windows = 0;
        for_each_chunk(path.to_str().unwrap(), 256, 8, |_| {
            windows += 1;
            true
        })
        .unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(windows, 0);
    }
}
