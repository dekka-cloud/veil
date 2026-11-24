//! Loads the tiny fixture model (tests/fixtures/make_tiny.py) and checks verification,
//! windowing, decoding and the threshold end to end through ONNX Runtime.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::fs;
use std::path::{Path, PathBuf};

use veil_core::{DetectionContext, Detector};
use veil_inference::{Model, ModelDetector, ModelError, Options};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tiny")
}

fn load() -> Model {
    Model::load(fixture(), Options::default())
        .unwrap_or_else(|e| panic!("the fixture should load: {e}"))
}

/// A copy of the fixture with one file replaced, in a fresh temporary directory.
fn tampered(name: &str, file: &str, contents: &[u8]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("veil-inference-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("{e}"));
    for f in ["model.onnx", "tokenizer.json", "manifest.yaml"] {
        fs::copy(fixture().join(f), dir.join(f)).unwrap_or_else(|e| panic!("{e}"));
    }
    fs::write(dir.join(file), contents).unwrap_or_else(|e| panic!("{e}"));
    dir
}

#[test]
fn finds_names_and_addresses_as_byte_spans() {
    let text = "call Ama Mensah , Kofi lives in Osu .";
    let got = load().predict(text).unwrap_or_else(|e| panic!("{e}"));
    let spans: Vec<(&str, &str)> = got
        .iter()
        .map(|p| (p.label.as_str(), &text[p.start..p.end]))
        .collect();
    assert_eq!(
        spans,
        vec![
            ("PERSON_NAME", "Ama Mensah"),
            ("PERSON_NAME", "Kofi"),
            ("ADDRESS", "Osu")
        ]
    );
    assert!(got.iter().all(|p| p.score > 0.9));
}

#[test]
fn offsets_are_bytes_in_text_with_multibyte_characters() {
    let text = "ɛyɛ Ama Mensah ɔno";
    let got = load().predict(text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got.len(), 1);
    assert_eq!(&text[got[0].start..got[0].end], "Ama Mensah");
    assert_eq!(got[0].start, "ɛyɛ ".len());
}

#[test]
fn drops_spans_below_the_threshold() {
    let got = load()
        .predict("call Kwame on 0241234567")
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        got.iter().map(|p| p.label.as_str()).collect::<Vec<_>>(),
        vec!["GH_MOBILE_NUMBER"]
    );
}

#[test]
fn long_text_is_split_into_windows_without_losing_spans() {
    // The fixture's window holds eight tokens, so this text needs several.
    let text = "call Ama Mensah in Osu . ".repeat(12);
    let got = load().predict(&text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(got.iter().filter(|p| p.label == "PERSON_NAME").count(), 12);
    assert_eq!(got.iter().filter(|p| p.label == "ADDRESS").count(), 12);
    assert!(got
        .iter()
        .filter(|p| p.label == "PERSON_NAME")
        .all(|p| &text[p.start..p.end] == "Ama Mensah"));
}

#[test]
fn the_detector_reports_model_findings() {
    let d = ModelDetector::new(load());
    assert_eq!(d.info().id, "veil-ner-tiny-v0.0.1");
    let findings = d
        .detect("call Ama Mensah", &DetectionContext::default())
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].entity_type.as_str(), "PERSON_NAME");
    assert_eq!(findings[0].detector, "veil-ner-tiny-v0.0.1");
}

#[test]
fn empty_text_finds_nothing() {
    assert!(load()
        .predict("   ")
        .unwrap_or_else(|e| panic!("{e}"))
        .is_empty());
}

#[test]
fn refuses_a_model_that_does_not_match_its_checksum() {
    let dir = tampered("checksum", "model.onnx", b"not a model");
    assert!(matches!(
        Model::load(&dir, Options::default()),
        Err(ModelError::Checksum { .. })
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn refuses_labels_that_do_not_match_the_graph() {
    let manifest =
        fs::read_to_string(fixture().join("manifest.yaml")).unwrap_or_else(|e| panic!("{e}"));
    let fewer = manifest.replace("  - I-GH_MOBILE_NUMBER\n", "");
    let dir = tampered("labels", "manifest.yaml", fewer.as_bytes());
    assert!(matches!(
        Model::load(&dir, Options::default()),
        Err(ModelError::Labels(_))
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn refuses_a_model_that_needs_a_newer_veil() {
    let manifest =
        fs::read_to_string(fixture().join("manifest.yaml")).unwrap_or_else(|e| panic!("{e}"));
    let newer = manifest.replace("veil: 0.1.0", "veil: 99.0.0");
    let dir = tampered("runtime", "manifest.yaml", newer.as_bytes());
    assert!(matches!(
        Model::load(&dir, Options::default()),
        Err(ModelError::Runtime { .. })
    ));
    let _ = fs::remove_dir_all(dir);
}

/// Runs a real exported model, such as veil-ner-nano. Ignored by default because the
/// weights aren't in the repository:
/// `VEIL_TEST_MODEL_DIR=/path/to/model cargo test -p veil-inference -- --ignored`
#[test]
#[ignore = "needs a real model in VEIL_TEST_MODEL_DIR"]
fn real_model_finds_a_ghanaian_name() {
    let Some(dir) = std::env::var_os("VEIL_TEST_MODEL_DIR") else {
        panic!("set VEIL_TEST_MODEL_DIR")
    };
    let model = Model::load(dir, Options::default()).unwrap_or_else(|e| panic!("{e}"));
    let text = "Please send the statement to Abena Owusu-Ansah at her house in Kumasi.";
    let got = model.predict(text).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        got.iter()
            .any(|p| p.label == "PERSON_NAME" && text[p.start..p.end].contains("Abena")),
        "{got:?}"
    );
}
