//! Property tests for the offset contract and resolution.

// Tests and examples may panic on a broken assumption; library code may not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use veil_core::engine::resolve;
use veil_core::{EntityType, Finding, Span, ValidationState};

fn boundaries(text: &str) -> Vec<usize> {
    let mut b: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
    b.push(text.len());
    b
}

proptest! {
    /// A span validates exactly when both ends are character boundaries within the text,
    /// and slicing a valid span never panics.
    #[test]
    fn spans_validate_only_on_boundaries(text in "\\PC{0,40}", a in 0usize..200, b in 0usize..200) {
        let (start, end) = (a.min(b), a.max(b));
        let span = Span::new(start, end).unwrap();
        let ok = end <= text.len() && text.is_char_boundary(start) && text.is_char_boundary(end);
        prop_assert_eq!(span.validate(&text).is_ok(), ok);
        prop_assert_eq!(span.slice(&text).is_ok(), ok);
    }

    /// Resolution keeps no overlapping findings, sorts them by position, and gives the
    /// same answer whatever order the detectors reported in.
    #[test]
    fn resolution_is_deterministic_and_non_overlapping(
        text in "[a-z0-9 ]{1,60}",
        picks in prop::collection::vec((0usize..100, 0usize..100, 0u8..3, 0u8..5, 0u8..4), 0..12),
        seed in any::<u64>(),
    ) {
        let b = boundaries(&text);
        let entities = [EntityType::GH_MOBILE_NUMBER, EntityType::EMAIL_ADDRESS, EntityType::GH_DIGITAL_ADDRESS];
        let states = [ValidationState::Unverified, ValidationState::ValidFormat, ValidationState::Valid, ValidationState::NotApplicable, ValidationState::Invalid];
        let findings: Vec<Finding> = picks.iter().map(|&(x, y, e, v, c)| {
            let (s, t) = (b[x % b.len()], b[y % b.len()]);
            let span = Span::new(s.min(t), s.max(t)).unwrap();
            Finding::new(entities[e as usize].clone(), span, format!("d{e}")).validation(states[v as usize]).confidence(0.5 + f32::from(c) / 10.0)
        }).filter(|f| !f.span.is_empty()).collect();

        let once = resolve(findings.clone());
        let mut shuffled = findings;
        let n = shuffled.len();
        if n > 1 {
            let mut s = seed;
            for i in (1..n).rev() {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                shuffled.swap(i, (s >> 33) as usize % (i + 1));
            }
        }
        let twice = resolve(shuffled);
        prop_assert_eq!(&once, &twice);
        for w in once.windows(2) {
            prop_assert!(w[0].span.end <= w[1].span.start, "overlap or disorder: {:?}", w);
        }
    }
}

mod normalisation {
    use proptest::prelude::*;
    use veil_core::Normalized;

    const INVISIBLE: &[&str] = &["\u{200B}", "\u{200D}", "\u{2060}", "\u{FEFF}", "\u{00AD}"];

    proptest! {
        /// Every span of the normalised copy maps to a valid span of the original on
        /// character boundaries, and mapping the whole copy covers what it came from.
        #[test]
        fn spans_map_back_to_the_original(
            parts in prop::collection::vec(("[a-z0-9 ]{0,6}", prop::sample::select(INVISIBLE.to_vec()), "[０-９]{0,3}"), 1..8),
            a in 0usize..200,
            b in 0usize..200,
        ) {
            let original: String = parts.iter().flat_map(|(x, z, w)| [x.as_str(), *z, w.as_str()]).collect();
            let n = Normalized::of(&original).unwrap();
            prop_assert!(!INVISIBLE.iter().any(|z| n.text.contains(z)));
            let len = n.text.len();
            if len == 0 {
                return Ok(());
            }
            let bounds: Vec<usize> = n.text.char_indices().map(|(i, _)| i).chain(std::iter::once(len)).collect();
            let (s, e) = (bounds[a % bounds.len()], bounds[b % bounds.len()]);
            let (s, e) = (s.min(e), s.max(e));
            if s < e {
                let (os, oe) = n.to_original(s, e).unwrap();
                prop_assert!(os < oe && oe <= original.len());
                prop_assert!(original.is_char_boundary(os) && original.is_char_boundary(oe));
            }
            let (os, oe) = n.to_original(0, len).unwrap();
            prop_assert!(original[..os].chars().all(|c| INVISIBLE.iter().any(|z| z.starts_with(c))));
            prop_assert!(original[oe..].chars().all(|c| INVISIBLE.iter().any(|z| z.starts_with(c))));
        }
    }
}
