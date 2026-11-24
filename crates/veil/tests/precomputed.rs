//! A model that runs outside Rust, as it does in a browser: its findings are computed first
//! and handed to the engine through a `PrecomputedDetector`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::path::PathBuf;

use veil::{PolicyContext, Profile, Veil};
use veil_inference::{Model, Options, Pipeline, PrecomputedDetector};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../veil-inference/tests/fixtures/tiny")
}

fn pipeline() -> Pipeline {
    let dir = fixture();
    let manifest = std::fs::read(dir.join("manifest.yaml")).unwrap();
    let tokenizer = std::fs::read(dir.join("tokenizer.json")).unwrap();
    Pipeline::from_bytes(&manifest, &tokenizer, 8).unwrap()
}

#[test]
fn findings_handed_in_are_used_for_the_text_they_were_computed_on() {
    let text = "call Ama Mensah , Kofi lives in Osu .";
    let native = Model::load(fixture(), Options::default()).unwrap();
    let pipeline = pipeline();
    let detector = PrecomputedDetector::new(&pipeline);
    let findings = pipeline.findings(native.predict(text).unwrap()).unwrap();
    detector.provide(HashMap::from([(text.to_string(), findings)]));

    let veil = Veil::builder()
        .country("gh")
        .model(detector)
        .profile(Profile::Hybrid)
        .build()
        .unwrap();
    let out = veil.protect(text, &PolicyContext::default()).unwrap();
    assert_eq!(out.profile_used, Profile::Hybrid);
    let names: Vec<&str> = out
        .findings
        .iter()
        .filter(|f| f.entity_type.as_str() == "PERSON_NAME")
        .map(|f| &text[f.span.start..f.span.end])
        .collect();
    assert_eq!(names, vec!["Ama Mensah", "Kofi"]);
}

#[test]
fn a_text_the_model_never_saw_falls_back_to_the_rules_and_says_so() {
    let pipeline = pipeline();
    let detector = PrecomputedDetector::new(&pipeline);
    let veil = Veil::builder()
        .country("gh")
        .model(detector)
        .profile(Profile::Hybrid)
        .build()
        .unwrap();
    let result = veil.detect("Call me on 024 123 4567").unwrap();
    assert_eq!(result.profile_used, Profile::Rules);
    assert!(result.warnings.iter().any(|w| w.contains("rules fallback")));
    assert!(result
        .findings
        .iter()
        .any(|f| f.entity_type.as_str() == "GH_MOBILE_NUMBER"));
}
