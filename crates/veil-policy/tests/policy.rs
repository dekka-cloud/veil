//! The policy language: parsing, validation, precedence, tokenisation and audit records.

// Tests may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use veil_core::{Category, EntityType, Family, Finding, Sensitivity, Span, ValidationState};
use veil_policy::{apply, Action, Policy, PolicyContext, BUILTIN};

fn phone(start: usize, end: usize) -> Finding {
    Finding::new(
        EntityType::GH_MOBILE_NUMBER,
        Span::new(start, end).unwrap(),
        "gh-phone-v1",
    )
    .category(Category::PersonalIdentifier)
    .sensitivity(Sensitivity::Personal)
    .validation(ValidationState::ValidFormat)
    .confidence(0.95)
    .label("MOBILE_MONEY")
}

fn key(start: usize, end: usize) -> Finding {
    Finding::new(
        EntityType::new("AWS_ACCESS_KEY_ID"),
        Span::new(start, end).unwrap(),
        "secrets-v1",
    )
    .family(Family::Secret)
    .category(Category::Credential)
    .sensitivity(Sensitivity::HighlySensitive)
    .validation(ValidationState::ValidFormat)
    .confidence(0.97)
}

#[test]
fn builtin_policies_parse() {
    for (name, source) in BUILTIN {
        Policy::from_yaml(source)
            .unwrap_or_else(|e| panic!("built-in policy {name} is invalid: {e}"));
        assert!(Policy::builtin(name).is_some());
    }
}

#[test]
fn the_default_policy_masks_phones_blocks_cards_and_redacts_the_rest() {
    let p = Policy::builtin("default-protection").unwrap();
    let ctx = PolicyContext::default();
    assert_eq!(p.decide(&phone(0, 12), &ctx).0, Action::Mask);
    assert_eq!(p.decide(&key(0, 20), &ctx).0, Action::Block);
    let card = Finding::new(
        EntityType::GH_GHANA_CARD_PIN,
        Span::new(0, 15).unwrap(),
        "gh-ghana-card-v1",
    );
    assert_eq!(p.decide(&card, &ctx).0, Action::Block);
    let email = Finding::new(
        EntityType::EMAIL_ADDRESS,
        Span::new(0, 5).unwrap(),
        "email-v1",
    );
    let (action, rule) = p.decide(&email, &ctx);
    assert_eq!(
        (action, rule),
        (Action::Redact, None),
        "the default action applies when nothing matches"
    );
}

#[test]
fn block_beats_a_more_specific_rule() {
    let p = Policy::from_yaml(
        "version: 1\nname: t\nrules:\n  - match: {entity_types: [GH_MOBILE_NUMBER], context_labels: [MOBILE_MONEY]}\n    action: allow\n  - match: {categories: [PERSONAL_IDENTIFIER]}\n    action: block\n",
    )
    .unwrap();
    assert_eq!(
        p.decide(&phone(0, 12), &PolicyContext::default()).0,
        Action::Block
    );
}

#[test]
fn entity_beats_context_beats_category() {
    let src = "version: 1\nname: t\nrules:\n  - match: {categories: [PERSONAL_IDENTIFIER]}\n    action: redact\n  - match: {context_labels: [MOBILE_MONEY]}\n    action: tokenize\n  - match: {entity_types: [GH_MOBILE_NUMBER]}\n    action: mask\n";
    let p = Policy::from_yaml(src).unwrap();
    let (action, rule) = p.decide(&phone(0, 12), &PolicyContext::default());
    assert_eq!(action, Action::Mask);
    assert_eq!(rule.unwrap().index, 2);
}

#[test]
fn request_attributes_match_the_context() {
    let src = "version: 1\nname: t\ndefault_action: allow\nrules:\n  - match: {destinations: [openai], entity_types: [GH_MOBILE_NUMBER]}\n    action: redact\n";
    let p = Policy::from_yaml(src).unwrap();
    let to = |d: &str| PolicyContext {
        destination: Some(d.into()),
        ..Default::default()
    };
    assert_eq!(p.decide(&phone(0, 12), &to("openai")).0, Action::Redact);
    assert_eq!(p.decide(&phone(0, 12), &to("private")).0, Action::Allow);
    assert_eq!(
        p.decide(&phone(0, 12), &PolicyContext::default()).0,
        Action::Allow,
        "a missing attribute never matches"
    );
}

#[test]
fn thresholds_match() {
    let src = "version: 1\nname: t\ndefault_action: detect\nrules:\n  - match: {min_confidence: 0.96}\n    action: redact\n  - match: {min_validation: VALID, families: [PII]}\n    action: mask\n";
    let p = Policy::from_yaml(src).unwrap();
    assert_eq!(
        p.decide(&phone(0, 12), &PolicyContext::default()).0,
        Action::Detect,
        "0.95 is under 0.96 and VALID_FORMAT is under VALID"
    );
}

#[test]
fn problems_are_reported_at_their_paths() {
    let cases = [
        ("version: 2\nname: t\n", "version"),
        ("version: 1\nname: ''\n", "name"),
        ("version: 1\nrules:\n  - match: {}\n    action: mask\n", "rules[0].match"),
        ("version: 1\nrules:\n  - match: {min_confidence: 2}\n    action: mask\n", "rules[0].match.min_confidence"),
        ("version: 1\nrules:\n  - match: {entity_types: [phone]}\n    action: mask\n", "rules[0].match.entity_types[0]"),
        ("version: 1\nrules:\n  - id: a\n    match: {min_confidence: 0.5}\n    action: mask\n  - id: a\n    match: {min_confidence: 0.5}\n    action: mask\n", "rules[1].id"),
        ("version: 1\nrules:\n  - match: {categories: [NOPE]}\n    action: mask\n", "rules[0].match.categories[0]"),
        ("version: 1\nrules:\n  - match: {min_confidence: 0.5}\n    action: nuke\n", "rules[0].action"),
        ("version: 1\nrulez: []\n", "rulez"),
    ];
    for (src, path) in cases {
        let err = Policy::from_yaml(src).expect_err(src);
        assert!(
            err.issues.iter().any(|i| i.path == path),
            "expected an issue at {path} for {src:?}, got {:?}",
            err.issues
        );
    }
}

#[test]
fn tokens_are_numbered_per_value_and_restore() {
    let text = "Call 024 123 4567, then 055 765 4321, then 024 123 4567 again";
    let findings = vec![phone(5, 17), phone(24, 36), phone(43, 55)];
    let out = apply(text, &findings, |_| (Action::Tokenize, None)).unwrap();
    let output = out.protected.output.clone().unwrap();
    assert_eq!(
        output,
        "Call [GH_MOBILE_NUMBER_1], then [GH_MOBILE_NUMBER_2], then [GH_MOBILE_NUMBER_1] again"
    );
    assert_eq!(out.restore.len(), 2);
    assert_eq!(out.restore.restore(&output), text);
    assert_eq!(
        out.restore.restore("Reply: I called [GH_MOBILE_NUMBER_2]."),
        "Reply: I called 055 765 4321."
    );
    assert!(
        !format!("{:?}", out.restore).contains("4567"),
        "Debug output must hide values"
    );
}

#[test]
fn decisions_and_results_never_carry_values() {
    let text = concat!("key AK", "IA2E3A7FQB4ZXC6DWY and phone 024 123 4567");
    let findings = vec![key(4, 24), phone(35, 47)];
    for p in [
        Policy::builtin("default-protection").unwrap(),
        Policy::uniform(Action::Tokenize),
        Policy::uniform(Action::Detect),
    ] {
        let out = p
            .protect(text, &findings, &PolicyContext::default())
            .unwrap();
        let mut json = serde_json::to_string(&out.protected.decisions).unwrap();
        json.push_str(&serde_json::to_string(&out.protected.policy).unwrap());
        assert!(
            !json.contains("AKIA2E3") && !json.contains("4567"),
            "a value leaked: {json}"
        );
    }
}

fn arb_rule() -> impl Strategy<Value = String> {
    let entity = prop::sample::select(vec![
        "",
        "entity_types: [GH_MOBILE_NUMBER]",
        "entity_types: [GH_MOBILE_NUMBER, EMAIL_ADDRESS]",
    ]);
    let context = prop::sample::select(vec![
        "",
        "context_labels: [MOBILE_MONEY]",
        "detectors: [gh-phone-v1]",
    ]);
    let category = prop::sample::select(vec![
        "",
        "categories: [PERSONAL_IDENTIFIER]",
        "min_confidence: 0.5",
    ]);
    let action = prop::sample::select(vec![
        "detect", "allow", "mask", "redact", "tokenize", "block",
    ]);
    (entity, context, category, action).prop_filter_map(
        "a rule needs a condition",
        |(e, c, k, a)| {
            let parts: Vec<&str> = [e, c, k].into_iter().filter(|s| !s.is_empty()).collect();
            (!parts.is_empty())
                .then(|| format!("  - match: {{{}}}\n    action: {a}\n", parts.join(", ")))
        },
    )
}

proptest! {
    /// Precedence, not file order, decides: reversing the rules changes the result only
    /// when two matching rules tie exactly, and then the first listed wins.
    #[test]
    fn rule_order_only_breaks_exact_ties(rules in prop::collection::vec(arb_rule(), 1..6)) {
        let forward = format!("version: 1\nname: t\nrules:\n{}", rules.concat());
        let mut reversed_rules = rules.clone();
        reversed_rules.reverse();
        let backward = format!("version: 1\nname: t\nrules:\n{}", reversed_rules.concat());
        let (f, b) = (Policy::from_yaml(&forward).unwrap(), Policy::from_yaml(&backward).unwrap());
        let finding = phone(0, 12);
        let ctx = PolicyContext::default();
        let (fa, fr) = f.decide(&finding, &ctx);
        let (ba, br) = b.decide(&finding, &ctx);
        let tie = match (&fr, &br) {
            (Some(x), Some(y)) => rules[x.index] != rules[rules.len() - 1 - y.index],
            _ => false,
        };
        if !tie {
            prop_assert_eq!(fa, ba);
        }
    }
}
