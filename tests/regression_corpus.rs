// Regression tests against the synthetic corpus.
//
// The corpus is generated (no real dump data) and has a fixed layout, so the
// expectations are exact: every planted string must be found at its offset,
// and the background must not produce anything.

mod common;

use bxmap::{extract_strings_with_encodings, EncodingFilter};
use common::corpus::synthetic_corpus;

/// Minimum string length used by the corpus tests.
const MIN_LEN: usize = 6;

/// Every planted string must be reported, at the offset it was planted at.
#[test]
fn every_planted_string_is_found_at_its_offset() {
    let corpus = synthetic_corpus();
    let found =
        extract_strings_with_encodings(&corpus.data, MIN_LEN, 100_000, EncodingFilter::all());
    let missing: Vec<&common::corpus::Expected> = corpus
        .expected
        .iter()
        .filter(|want| {
            !found.iter().any(|s| {
                s.offset == want.offset && s.encoding == want.encoding && s.text == want.text
            })
        })
        .collect();
    // Only the neighbourhood of a missing string is printed: the corpus also
    // produces decoded noise in other encodings.
    let nearby: Vec<&bxmap::ExtractedString> = found
        .iter()
        .filter(|s| {
            missing
                .iter()
                .any(|m| s.offset.abs_diff(m.offset) < 64)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "missing: {missing:?}\nnearby: {nearby:#?}\ntotal found: {}",
        found.len()
    );
}

/// The ASCII view of the corpus is exactly the planted ASCII strings: the
/// generated background must not produce a single extra string.
#[test]
fn the_ascii_view_is_exactly_the_planted_ascii() {
    let corpus = synthetic_corpus();
    let found =
        extract_strings_with_encodings(&corpus.data, MIN_LEN, 100_000, EncodingFilter::ascii());
    let got: Vec<(u64, String)> = found.iter().map(|s| (s.offset, s.text.clone())).collect();
    let want: Vec<(u64, String)> = corpus
        .expected
        .iter()
        .filter(|e| e.encoding == "ascii")
        .map(|e| (e.offset, e.text.to_string()))
        .collect();
    assert_eq!(want, got);
}

/// The corpus is stable: building it twice gives the same bytes.
#[test]
fn the_corpus_is_deterministic() {
    assert_eq!(synthetic_corpus().data, synthetic_corpus().data);
}

/// The planted cloud key is still detected as a secret, and the card number
/// next to it is a valid card (issuer prefix + Luhn).
#[test]
fn the_planted_credentials_are_recognised() {
    use bxmap::classifier::{classify, detect_secrets};

    let corpus = synthetic_corpus();
    let text = String::from_utf8_lossy(&corpus.data);

    let secrets = detect_secrets(&text);
    assert!(
        secrets.iter().any(|m| m.typ == "AWS_ACCESS_KEY"),
        "cloud key not detected: {secrets:?}"
    );

    let card = "4532015112830366";
    let card_class = classify(card).expect("card number should be classified");
    assert_eq!(card_class.typ, "CREDIT_CARD");
}
