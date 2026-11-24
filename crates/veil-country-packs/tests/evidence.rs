//! The Ghana pack against its specification: every detector's entities have an evidence level
//! in the identifier registry, the pack manifest copies those levels exactly, findings carry
//! them, and no Ghana Card PIN is ever reported as more than a format match.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeMap;

use proptest::prelude::*;
use veil_core::{DetectionContext, Engine, EvidenceLevel, Registry, ValidationState};
use veil_country_packs::gh;

const REGISTRY: &str = include_str!("../../../country-packs/gh/identifiers.yaml");

#[derive(serde::Deserialize)]
struct RegistryFile {
    entities: Vec<Entry>,
}

#[derive(serde::Deserialize)]
struct Entry {
    code: String,
    validation_state: String,
    evidence_level: Option<String>,
}

fn registry() -> BTreeMap<String, Entry> {
    let r: RegistryFile = serde_yaml_ng::from_str(REGISTRY).unwrap();
    r.entities
        .into_iter()
        .map(|e| (e.code.clone(), e))
        .collect()
}

fn pack() -> Registry {
    let mut r = Registry::new();
    gh::register(&mut r).unwrap();
    r
}

#[test]
fn every_detector_entity_has_a_registry_entry_and_matching_level() {
    let reg = registry();
    let manifest = gh::manifest().unwrap();
    for d in pack().detectors() {
        let info = d.info();
        for entity in &info.entity_types {
            let code = entity.as_str();
            let entry = reg.get(code).unwrap_or_else(|| {
                panic!(
                    "{} reports {code}, which the identifier registry doesn't list",
                    info.id
                )
            });
            let registry_level = entry
                .evidence_level
                .as_deref()
                .unwrap_or_else(|| panic!("the registry entry for {code} has no evidence_level"));
            let manifest_level = manifest.evidence.get(code).unwrap_or_else(|| {
                panic!(
                    "{} reports {code}, which manifest.toml gives no evidence level",
                    info.id
                )
            });
            assert_eq!(
                manifest_level.as_str(),
                registry_level.to_ascii_uppercase(),
                "manifest.toml and the identifier registry disagree on {code}'s evidence level"
            );
        }
    }
    for (code, level) in &manifest.evidence {
        let entry = reg.get(code).unwrap_or_else(|| {
            panic!("manifest.toml lists {code}, which the identifier registry doesn't")
        });
        assert_eq!(
            Some(level.as_str().to_ascii_lowercase()),
            entry.evidence_level,
            "{code}"
        );
    }
}

#[test]
fn every_registry_entry_has_a_known_level() {
    for (code, e) in registry() {
        let level = e
            .evidence_level
            .unwrap_or_else(|| panic!("{code} has no evidence_level"));
        assert!(
            matches!(
                level.as_str(),
                "issuer_confirmed" | "international_standard" | "secondary" | "unpublished"
            ),
            "{code}: {level}"
        );
        // An identifier with no published format can't be validated against one.
        if level == "unpublished" {
            assert!(
                matches!(e.validation_state.as_str(), "UNVERIFIED" | "VALID"),
                "{code} is unpublished but claims {}",
                e.validation_state
            );
        }
    }
}

#[test]
fn findings_carry_their_entity_evidence_level() {
    let manifest = gh::manifest().unwrap();
    let engine = Engine::new(pack());
    let text = "Call 024 123 4567 or 0302 123 456. Ghana Card GHA-123456789-0, address GA-543-0125, TIN P0012345678, \
                plate GR 1234-23 on my car, account number 1234567890123, passport no G1234567, voter ID 1234567890.";
    let found = engine
        .detect(text, &DetectionContext::default())
        .unwrap()
        .findings;
    assert!(found.len() >= 6, "{found:?}");
    for f in found {
        assert_eq!(
            f.evidence,
            manifest.evidence.get(f.entity_type.as_str()).copied(),
            "{}",
            f.entity_type
        );
        assert!(
            f.evidence.is_some(),
            "{} has no evidence level",
            f.entity_type
        );
    }
}

fn card_validations(text: &str) -> Vec<ValidationState> {
    let mut r = Registry::new();
    gh::register(&mut r).unwrap();
    let engine = Engine::new(r);
    engine
        .detect(text, &DetectionContext::default())
        .unwrap()
        .findings
        .into_iter()
        .filter(|f| f.entity_type.as_str() == "GH_GHANA_CARD_PIN")
        .map(|f| f.validation)
        .collect()
}

/// The check character's algorithm isn't published, so a Ghana Card PIN can match the format
/// but never pass a check, and must never be reported VALID. Format recognition is not
/// identity verification.
#[test]
fn ghana_card_pins_are_never_valid() {
    for text in [
        "Ghana Card GHA-123456789-0",
        "GHA-12345678-K",
        "my NIA number is GHA 123456789 0",
        "GHA1234567890",
        "Non-citizen card NGA-123456789-1",
        "TIN GHA-723451904-3",
        "SSNIT number GHA-723451904-3",
    ] {
        let v = card_validations(text);
        assert!(!v.is_empty(), "no Ghana Card PIN found in {text:?}");
        assert!(
            v.iter().all(|s| *s == ValidationState::ValidFormat),
            "{text:?}: {v:?}"
        );
    }
    assert_eq!(
        gh::manifest().unwrap().evidence.get("GH_GHANA_CARD_PIN"),
        Some(&EvidenceLevel::IssuerConfirmed)
    );
}

proptest! {
    #[test]
    fn no_generated_pin_is_valid(prefix in "(GHA|NGA|TGO|CIV|BFA)", digits in "[0-9]{8,9}", check in "[0-9A-Z]", sep in "(-| |)", context in "(Ghana Card |NIA PIN |ID |)") {
        let text = format!("{context}{prefix}{sep}{digits}{sep}{check}");
        for v in card_validations(&text) {
            prop_assert_eq!(v, ValidationState::ValidFormat);
        }
    }
}
