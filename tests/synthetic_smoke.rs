mod common;

#[test]
fn synthetic_dump_smoke() {
    let data = common::synthetic::synthetic_dump();
    assert_eq!(data.len(), 64 * 1024);
}
