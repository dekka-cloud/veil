//! The facade: one call from text to protected output, and what happens when a scan
//! can't complete.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use veil::{EngineConfig, Policy, PolicyContext, Profile, Veil};

fn policy(on_failure: &str) -> Policy {
    Policy::from_yaml(&format!(
        "version: 1\nname: t\non_failure: {on_failure}\ndefault_action: redact\n"
    ))
    .unwrap()
}

#[test]
fn protect_uses_default_protection() {
    let veil = Veil::builder().country("gh").build().unwrap();
    let out = veil
        .protect(
            "Email ama@example.com or call 024 123 4567",
            &PolicyContext::default(),
        )
        .unwrap();
    assert_eq!(
        out.protected.output.as_deref(),
        Some("Email [EMAIL_ADDRESS] or call 024 *** 4567")
    );
    assert!(out.scanned && !out.protected.blocked);
    assert_eq!(
        out.protected.policy.as_ref().unwrap().name,
        "default-protection"
    );
    let blocked = veil
        .protect("GHA-723451904-3", &PolicyContext::default())
        .unwrap();
    assert!(blocked.protected.blocked && blocked.protected.output.is_none());
}

#[test]
fn closed_blocks_when_the_scan_fails() {
    let veil = Veil::builder()
        .policy(policy("closed"))
        .config(EngineConfig {
            max_input_bytes: 8,
            ..EngineConfig::default()
        })
        .build()
        .unwrap();
    let out = veil
        .protect("far more than eight bytes", &PolicyContext::default())
        .unwrap();
    assert!(out.protected.blocked && out.protected.output.is_none() && !out.scanned);
    assert!(out.protected.warnings[0].contains("blocked"));
}

#[test]
fn open_lets_text_through_with_a_warning() {
    let veil = Veil::builder()
        .policy(policy("open"))
        .config(EngineConfig {
            max_input_bytes: 8,
            ..EngineConfig::default()
        })
        .build()
        .unwrap();
    let text = "call 024 123 4567 please";
    let out = veil.protect(text, &PolicyContext::default()).unwrap();
    assert_eq!(out.protected.output.as_deref(), Some(text));
    assert!(!out.protected.blocked && !out.scanned);
    assert!(out.protected.warnings[0].contains("not scanned"));
}

#[test]
fn rules_fallback_runs_the_rules_and_says_so() {
    let veil = Veil::builder()
        .policy(policy("rules_fallback"))
        .profile(Profile::Hybrid)
        .build()
        .unwrap();
    let out = veil
        .protect("call 024 123 4567", &PolicyContext::default())
        .unwrap();
    assert_eq!(
        out.protected.output.as_deref(),
        Some("call [GH_MOBILE_NUMBER]")
    );
    assert_eq!(out.profile_used, Profile::Rules);
    assert!(out.protected.warnings[0].contains("not a complete hybrid scan"));
}

#[test]
fn a_missing_model_is_closed_without_fallback() {
    let veil = Veil::builder()
        .policy(policy("closed"))
        .profile(Profile::Hybrid)
        .build()
        .unwrap();
    let out = veil
        .protect("call 024 123 4567", &PolicyContext::default())
        .unwrap();
    assert!(out.protected.blocked);
}

#[test]
fn tokenised_replies_can_be_restored() {
    let veil = Veil::builder()
        .policy(Policy::uniform(veil::Action::Tokenize))
        .build()
        .unwrap();
    let out = veil
        .protect("Ama's number is 024 123 4567", &PolicyContext::default())
        .unwrap();
    assert_eq!(
        out.protected.output.as_deref(),
        Some("Ama's number is [GH_MOBILE_NUMBER_1]")
    );
    let reply = "I'll text [GH_MOBILE_NUMBER_1] now.";
    assert_eq!(out.restore.restore(reply), "I'll text 024 123 4567 now.");
}

#[test]
fn the_built_in_policy_cases_pass() {
    let veil = Veil::builder().build().unwrap();
    let cases = include_str!("../../../policies/default-protection.cases.jsonl");
    for line in cases.lines().filter(|l| !l.trim().is_empty()) {
        let case: serde_json::Value = serde_json::from_str(line).unwrap();
        let out = veil
            .protect(case["input"].as_str().unwrap(), &PolicyContext::default())
            .unwrap();
        if let Some(blocked) = case["blocked"].as_bool() {
            assert_eq!(out.protected.blocked, blocked, "{line}");
        }
        if let Some(output) = case["output"].as_str() {
            assert_eq!(out.protected.output.as_deref(), Some(output), "{line}");
        }
    }
}

/// The tiny fixture model from veil-inference, which labels "Ama Mensah" as a name.
#[cfg(feature = "model")]
fn tiny() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../veil-inference/tests/fixtures/tiny")
}

#[cfg(feature = "model")]
#[test]
fn hybrid_adds_model_names_to_rules_findings() {
    let veil = Veil::builder()
        .country("gh")
        .model_dir(tiny())
        .profile(Profile::Hybrid)
        .build()
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        veil.supports(Profile::Nano)
            && veil.supports(Profile::Hybrid)
            && !veil.supports(Profile::Deep)
    );
    let text = "call Ama Mensah on 024 123 4567";
    let d = veil.detect(text).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(d.profile_used, Profile::Hybrid);
    let got: Vec<(&str, &str)> = d
        .findings
        .iter()
        .map(|f| (f.entity_type.as_str(), &text[f.span.start..f.span.end]))
        .collect();
    assert_eq!(
        got,
        vec![
            ("PERSON_NAME", "Ama Mensah"),
            ("GH_MOBILE_NUMBER", "024 123 4567")
        ]
    );

    let nano = veil
        .detect_with(text, Profile::Nano)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(nano.findings.len(), 1);
    let rules = veil
        .detect_with(text, Profile::Rules)
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(rules.findings.len(), 1);
    assert!(veil.entity_types().contains(&"PERSON_NAME".to_string()));

    let out = veil
        .protect(text, &PolicyContext::default())
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(!out
        .protected
        .output
        .as_deref()
        .unwrap_or_default()
        .contains("Mensah"));
}

#[cfg(feature = "model")]
#[test]
fn a_model_directory_that_fails_verification_stops_the_build() {
    let err = Veil::builder()
        .model_dir("/nonexistent/model")
        .build()
        .map(|_| ())
        .unwrap_err();
    assert!(matches!(err, veil::BuildError::Model(_)), "{err}");
}
