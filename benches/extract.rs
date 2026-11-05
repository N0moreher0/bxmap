//! Criterion benchmarks for the string extraction hot path.
//!
//! By default builds a deterministic 256 MiB synthetic "memory dump" (ASCII
//! markers every 4 KiB, LCG noise elsewhere) in a temp file and benchmarks the
//! three scan entry points against it. Numbers are reproducible across machines
//! and contain no real data. Set `BXMAP_BENCH_DUMP` to a real dump path (e.g. a
//! `*.raw` memory image) to benchmark a specific file instead.

use bxmap::{
    extract_strings_from_file_parallel_streaming_with_encodings_progress,
    extract_strings_from_file_parallel_with_encodings,
    extract_strings_from_file_with_noise_config_and_encodings, EncodingFilter, ExtractedString,
    NoiseConfig,
};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::io::Write;
use std::path::PathBuf;

/// Size of the synthetic dump used for every benchmark (256 MiB).
const DUMP_SIZE: usize = 256 * 1024 * 1024;

/// Build a deterministic synthetic dump (LCG, seeded) and write it to a temp
/// file. Returns the file path.
fn write_synthetic_dump() -> PathBuf {
    let dir = std::env::temp_dir().join("bxmap-bench");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("bench_dump_256m.bin");

    if !path.exists() {
        let mut data = Vec::with_capacity(DUMP_SIZE);
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut pos = 0usize;
        while pos < DUMP_SIZE {
            // Every ~4 KiB insert a known ASCII string so the scanner has real
            // work to do.
            if pos % 4096 == 0 && pos + 24 <= DUMP_SIZE {
                let s = b"bxmap_bench_marker_string_0123456789\x00";
                data.extend_from_slice(s);
                pos += s.len();
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            } else {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                data.push((state >> 32) as u8);
                pos += 1;
            }
        }
        data.truncate(DUMP_SIZE);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&data)
            .unwrap();
    }
    path
}

fn bench_dump_path() -> &'static PathBuf {
    static PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    PATH.get_or_init(|| {
        if let Ok(p) = std::env::var("BXMAP_BENCH_DUMP") {
            let p = p.trim().to_string();
            if !p.is_empty() {
                return std::path::PathBuf::from(p);
            }
        }
        write_synthetic_dump()
    })
}

fn bench_sequential(c: &mut Criterion) {
    c.bench_function("extract_sequential_256MiB", |b| {
        b.iter(|| {
            let out = extract_strings_from_file_with_noise_config_and_encodings(
                black_box(bench_dump_path().to_str().unwrap()),
                black_box(4),
                black_box(100_000),
                black_box(NoiseConfig::default()),
                black_box(EncodingFilter::all()),
            )
            .unwrap();
            black_box(out.len());
        })
    });
}

fn bench_parallel_buffered(c: &mut Criterion) {
    c.bench_function("extract_parallel_buffered_256MiB", |b| {
        b.iter(|| {
            let out = extract_strings_from_file_parallel_with_encodings(
                black_box(bench_dump_path().to_str().unwrap()),
                black_box(4),
                black_box(100_000),
                black_box(NoiseConfig::default()),
                black_box(EncodingFilter::all()),
            )
            .unwrap();
            black_box(out.len());
        })
    });
}

fn bench_parallel_streaming(c: &mut Criterion) {
    c.bench_function("extract_parallel_streaming_256MiB", |b| {
        b.iter(|| {
            let mut count = 0usize;
            extract_strings_from_file_parallel_streaming_with_encodings_progress(
                black_box(bench_dump_path().to_str().unwrap()),
                black_box(4),
                black_box(100_000),
                black_box(NoiseConfig::default()),
                black_box(EncodingFilter::all()),
                black_box(
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1),
                ),
                &mut |_result: ExtractedString| {
                    count += 1;
                },
                &mut |_scanned: u64| {},
            )
            .unwrap();
            black_box(count);
        })
    });
}

criterion_group!(
    benches,
    bench_sequential,
    bench_parallel_buffered,
    bench_parallel_streaming
);
criterion_main!(benches);
