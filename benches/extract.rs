//! Criterion benchmarks for the scanner hot path.
//!
//! These measure the CPU-bound scan itself (no disk I/O) so changes to the
//! run detection can be compared without the OS page cache muddying the
//! numbers. Run with:
//!
//! ```text
//! cargo bench --no-default-features
//! ```
//!
//! For end-to-end throughput on a real file (I/O + parsing + output), use
//! `bench/bench.py`.

use bxmap::{
    extract_strings_from_file_parallel_with_encodings, extract_strings_with_encodings,
    EncodingFilter, NoiseConfig,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

/// Realistic mixed memory-dump payload: printable runs separated by binary
/// junk, with both ASCII and UTF-16LE strings.
fn corpus(target_bytes: usize) -> Vec<u8> {
    let ascii = [
        b"C:\\Windows\\System32\\kernel32.dll".as_slice(),
        b"http://update.example.com/payload.exe".as_slice(),
        b"password=SuperSecret123".as_slice(),
        b"Software\\Microsoft\\Windows\\CurrentVersion\\Run".as_slice(),
        b"SELECT * FROM users WHERE id = 42".as_slice(),
    ];
    let utf16: Vec<Vec<u8>> = [
        "RAR password=ExtractMeIfYouCan2024!",
        "TEMP=C:\\Users\\victim\\AppData\\Local\\Temp",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows",
    ]
    .iter()
    .map(|text| {
        text.encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect()
    })
    .collect();

    let mut data = Vec::with_capacity(target_bytes);
    let mut index = 0usize;
    while data.len() < target_bytes {
        // Binary junk (the bulk of a real dump).
        let junk_len = 37 + (index * 17) % 200;
        data.extend((0..junk_len).map(|offset| ((index + offset) % 256) as u8 | 0x80));
        // An ASCII run.
        data.extend_from_slice(ascii[index % ascii.len()]);
        data.extend_from_slice(&[0, 0, 0]);
        // A UTF-16LE run.
        data.extend_from_slice(&utf16[index % utf16.len()]);
        data.extend_from_slice(&[0, 0, 0, 0]);
        index += 1;
    }
    data.truncate(target_bytes);
    data
}

fn bench_in_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("scan_memory");
    let size = 8 * 1024 * 1024;
    let data = corpus(size);
    group.throughput(Throughput::Bytes(data.len() as u64));

    for (label, encodings) in [
        ("all", EncodingFilter::all()),
        ("ascii", EncodingFilter::ascii()),
        ("utf16", EncodingFilter::utf16()),
    ] {
        group.bench_with_input(BenchmarkId::new("encodings", label), &data, |b, data| {
            b.iter(|| {
                black_box(extract_strings_with_encodings(
                    black_box(data),
                    4,
                    usize::MAX,
                    encodings,
                ))
            })
        });
    }
    group.finish();
}

fn bench_parallel_file(c: &mut Criterion) {
    // A file-based benchmark so the region split + rayon scheduling is
    // measured too. The file is created once and reused across iterations
    // (the OS page cache is warm, which is the interesting case for
    // CPU-bound scanning).
    let dir = std::env::temp_dir().join("bxmap-bench");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("corpus.bin");
    if !path.exists() {
        std::fs::write(&path, corpus(64 * 1024 * 1024)).unwrap();
    }
    let path_str = path.to_string_lossy().to_string();

    let mut group = c.benchmark_group("scan_file_parallel");
    group.throughput(Throughput::Bytes(64 * 1024 * 1024));
    group.sample_size(10);
    group.bench_function("64MiB", |b| {
        b.iter(|| {
            black_box(extract_strings_from_file_parallel_with_encodings(
                &path_str,
                4,
                usize::MAX,
                NoiseConfig::default(),
                EncodingFilter::all(),
            ))
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_in_memory, bench_parallel_file);
criterion_main!(benches);
