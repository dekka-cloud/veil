//! The nano and hybrid profiles with a stand-in model: rules win on structured types and on
//! overlaps, a failing model falls back to rules with a warning, and profiles without a model
//! are refused.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use veil_core::{
    DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo, Engine, EntityType,
    Finding, Profile, Registry, Span, ValidationState, VeilError,
};

/// A rule that reports "0241234567" as a validated mobile number.
#[derive(Debug)]
struct Phone;

impl Detector for Phone {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "test-phone-v1",
            description: "test",
            entity_types: vec![EntityType::GH_MOBILE_NUMBER],
            jurisdiction: None,
            method: DetectionMethod::PatternAndValidation,
        }
    }

    fn detect(&self, text: &str, _: &DetectionContext) -> Result<Vec<Finding>, DetectionError> {
        Ok(text
            .match_indices("0241234567")
            .filter_map(|(i, m)| Span::new(i, i + m.len()).ok())
            .map(|s| {
                Finding::new(EntityType::GH_MOBILE_NUMBER, s, "test-phone-v1")
                    .validation(ValidationState::Valid)
                    .confidence(0.99)
            })
            .collect())
    }
}

/// A model that labels words it was told about, or fails when asked to.
#[derive(Debug)]
struct Model {
    words: Vec<(&'static str, &'static str)>,
    fail: bool,
}

impl Detector for Model {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "test-model-v1",
            description: "test",
            entity_types: Vec::new(),
            jurisdiction: None,
            method: DetectionMethod::Model,
        }
    }

    fn detect(&self, text: &str, _: &DetectionContext) -> Result<Vec<Finding>, DetectionError> {
        if self.fail {
            return Err(DetectionError::new("inference failed"));
        }
        let mut out = Vec::new();
        for (word, label) in &self.words {
            for (i, m) in text.match_indices(word) {
                let span =
                    Span::new(i, i + m.len()).map_err(|e| DetectionError::new(e.to_string()))?;
                out.push(
                    Finding::new(EntityType::new(label), span, "test-model-v1").confidence(0.9),
                );
            }
        }
        Ok(out)
    }
}

fn engine(words: Vec<(&'static str, &'static str)>, fail: bool) -> Engine {
    Engine::new(Registry::new().with(Phone)).with_model(Box::new(Model { words, fail }))
}

fn found(engine: &Engine, text: &str, profile: Profile) -> Vec<(String, String)> {
    let r = engine
        .detect_with(text, &DetectionContext::default(), profile)
        .unwrap_or_else(|e| panic!("{e}"));
    r.findings
        .iter()
        .map(|f| (f.entity_type.to_string(), f.detector.clone()))
        .collect()
}

const TEXT: &str = "Ama Mensah on 0241234567";

#[test]
fn rules_ignore_the_model() {
    let e = engine(vec![("Ama Mensah", "PERSON_NAME")], false);
    assert_eq!(
        found(&e, TEXT, Profile::Rules),
        vec![("GH_MOBILE_NUMBER".into(), "test-phone-v1".into())]
    );
}

#[test]
fn nano_is_the_model_alone() {
    let e = engine(
        vec![
            ("Ama Mensah", "PERSON_NAME"),
            ("0241234567", "GH_MOBILE_NUMBER"),
        ],
        false,
    );
    let r = e
        .detect_with(TEXT, &DetectionContext::default(), Profile::Nano)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.profile_used, Profile::Nano);
    assert!(r.findings.iter().all(|f| f.detector == "test-model-v1"));
    assert_eq!(r.findings.len(), 2);
}

#[test]
fn hybrid_adds_the_model_and_lets_rules_decide_structured_types() {
    // The model also calls the number a mobile number and part of it an account number: the
    // first is a structured type, the second overlaps a rules finding, so both go.
    let e = engine(
        vec![
            ("Ama Mensah", "PERSON_NAME"),
            ("0241234567", "GH_MOBILE_NUMBER"),
            ("024123", "BANK_ACCOUNT_NUMBER"),
        ],
        false,
    );
    let r = e
        .detect_with(TEXT, &DetectionContext::default(), Profile::Hybrid)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(r.profile_used, Profile::Hybrid);
    let got: Vec<(String, String)> = r
        .findings
        .iter()
        .map(|f| (f.entity_type.to_string(), f.detector.clone()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("PERSON_NAME".into(), "test-model-v1".into()),
            ("GH_MOBILE_NUMBER".into(), "test-phone-v1".into())
        ]
    );
}

#[test]
fn a_failing_model_falls_back_to_rules_with_a_warning() {
    let e = engine(vec![], true);
    for profile in [Profile::Hybrid, Profile::Nano] {
        let r = e
            .detect_with(TEXT, &DetectionContext::default(), profile)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(r.profile_used, Profile::Rules);
        assert_eq!(r.findings.len(), 1);
        assert!(
            r.warnings.iter().any(|w| w.contains("rules fallback")),
            "{:?}",
            r.warnings
        );
    }
}

#[test]
fn profiles_without_a_model_are_refused() {
    let e = Engine::new(Registry::new().with(Phone));
    for profile in [Profile::Nano, Profile::Hybrid, Profile::Deep] {
        assert!(
            matches!(e.detect_with(TEXT, &DetectionContext::default(), profile), Err(VeilError::ProfileUnavailable(p)) if p == profile)
        );
    }
    assert!(!engine(vec![], false).supports(Profile::Deep));
}
