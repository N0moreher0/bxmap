use bxmap::classifier::{detect_secrets, detect_secrets_detailed};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn secret_benchmark(c: &mut Criterion) {
    let texts = [
        "password=hunter2hunter2",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST",
        "xoxb-TEST-TEST-TEST",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop",
        "api_key=sk-live-abcdefghijklmnopqrstuvwxyz012345",
        "Token: GetTokenInformation",
        "Token: Malloc",
        "Password: false,",
        "ApiKey=function(a){return a}",
        "normal string with no secrets at all",
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "DB_PASSWORD=SuperSecret123!",
        "GITHUB_TOKEN=ghp-TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST",
    ];

    c.bench_function("detect_secrets_batch", |b| {
        b.iter(|| {
            for text in &texts {
                black_box(detect_secrets(black_box(text)));
            }
        })
    });

    c.bench_function("detect_secrets_detailed_batch", |b| {
        b.iter(|| {
            for text in &texts {
                black_box(detect_secrets_detailed(black_box(text)));
            }
        })
    });
}

criterion_group!(benches, secret_benchmark);
criterion_main!(benches);
