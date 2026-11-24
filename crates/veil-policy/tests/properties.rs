//! Property tests for transformation: arbitrary Unicode, any non-overlapping findings.

// Tests and examples may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use veil_core::{EntityType, Finding, Span};
use veil_policy::{protect, Action};

fn findings_for(text: &str, cuts: &[usize]) -> Vec<Finding> {
    let mut b: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    b.push(text.len());
    let mut points: Vec<usize> = cuts.iter().map(|c| b[c % b.len()]).collect();
    points.sort_unstable();
    points.dedup();
    points
        .chunks(2)
        .filter(|p| p.len() == 2 && p[0] < p[1])
        .map(|p| {
            Finding::new(
                EntityType::GH_MOBILE_NUMBER,
                Span::new(p[0], p[1]).unwrap(),
                "test",
            )
        })
        .collect()
}

proptest! {
    /// Detect leaves the text byte-for-byte unchanged.
    #[test]
    fn detect_changes_nothing(text in "\\PC{0,60}", cuts in prop::collection::vec(0usize..200, 0..10)) {
        let findings = findings_for(&text, &cuts);
        let out = protect(&text, &findings, |_| Action::Detect).unwrap();
        prop_assert_eq!(out.output.as_deref(), Some(text.as_str()));
    }

    /// Redaction and masking keep every byte outside the findings, in order, and always
    /// produce valid UTF-8.
    #[test]
    fn transformations_keep_unaffected_text(text in "\\PC{0,60}", cuts in prop::collection::vec(0usize..200, 0..10), mask in any::<bool>()) {
        let findings = findings_for(&text, &cuts);
        let action = if mask { Action::Mask } else { Action::Redact };
        let out = protect(&text, &findings, |_| action).unwrap().output.unwrap();
        let mut rest = out.as_str();
        let mut cursor = 0;
        for f in &findings {
            let keep = &text[cursor..f.span.start];
            prop_assert!(rest.starts_with(keep), "lost text before a finding");
            rest = &rest[keep.len()..];
            cursor = f.span.end;
            if !mask {
                let placeholder = "[GH_MOBILE_NUMBER]";
                prop_assert!(rest.starts_with(placeholder));
                rest = &rest[placeholder.len()..];
            } else {
                let masked_len = text[f.span.start..f.span.end].chars().count();
                let skip: usize = rest.chars().take(masked_len).map(char::len_utf8).sum();
                rest = &rest[skip..];
            }
        }
        prop_assert_eq!(rest, &text[cursor..]);
    }

    /// Block withholds the whole output whenever anything was found.
    #[test]
    fn block_withholds_output(text in "\\PC{1,40}", cuts in prop::collection::vec(0usize..200, 2..6)) {
        let findings = findings_for(&text, &cuts);
        let out = protect(&text, &findings, |_| Action::Block).unwrap();
        prop_assert_eq!(out.blocked, !findings.is_empty());
        prop_assert_eq!(out.output.is_none(), !findings.is_empty());
    }
}

#[test]
fn overlapping_findings_are_refused() {
    let text = "024 123 4567";
    let a = Finding::new(EntityType::GH_MOBILE_NUMBER, Span::new(0, 7).unwrap(), "a");
    let b = Finding::new(EntityType::GH_MOBILE_NUMBER, Span::new(4, 12).unwrap(), "b");
    assert!(protect(text, &[a, b], |_| Action::Redact).is_err());
}

#[test]
fn decisions_never_carry_values() {
    let text = "call 024 123 4567";
    let f = Finding::new(
        EntityType::GH_MOBILE_NUMBER,
        Span::new(5, 17).unwrap(),
        "gh-phone-v1",
    );
    let out = protect(text, &[f], |_| Action::Redact).unwrap();
    let json = serde_json_like(&out.decisions);
    assert!(!json.contains("123"), "a decision leaked the value: {json}");
}

fn serde_json_like<T: std::fmt::Debug>(v: &T) -> String {
    format!("{v:?}")
}
