use regex::Regex;
use serde::Deserialize;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use super::{parse, GHANA_CARD, JURISDICTION};
use crate::context::{isolated, mentions, window};
use crate::{pattern, PackError};

#[derive(Debug, Deserialize)]
struct Format {
    citizen_prefix: String,
    body_digits_min: usize,
    body_digits_max: usize,
    context: Vec<String>,
    labels: std::collections::BTreeMap<String, Vec<String>>,
}

/// Ghana Card PINs such as `GHA-123456789-0` or `GHA-12345678-K`. Citizens' PINs start
/// with GHA; a non-citizen card starts with another nationality code and is reported only
/// in the hyphenated form with a Ghana Card word nearby, since three letters and digits
/// are common in other references. The check character's algorithm isn't published, so
/// matches are VALID_FORMAT, never VALID.
#[derive(Debug)]
pub struct GhanaCardDetector {
    citizen: Regex,
    other: Regex,
    context: Vec<String>,
    labels: std::collections::BTreeMap<String, Vec<String>>,
}

impl GhanaCardDetector {
    pub fn new() -> Result<Self, PackError> {
        let f: Format = parse("gh/ghana-card.toml", GHANA_CARD)?;
        let body = format!(r"\d{{{},{}}}", f.body_digits_min, f.body_digits_max);
        let citizen = pattern(&format!(
            r"(?i){}[ \-]?{body}[ \-]?[0-9A-Z]",
            regex::escape(&f.citizen_prefix)
        ));
        let other = pattern(&format!(r"[A-Z]{{3}}-{body}-[0-9A-Z]"));
        Ok(Self {
            citizen,
            other,
            context: f.context,
            labels: f.labels,
        })
    }

    fn accept(&self, text: &str, start: usize, end: usize) -> bool {
        // A match followed by "-x" or " digit" is the start of something longer.
        let continues = text.get(end..).is_some_and(|rest| {
            let mut chars = rest.chars();
            match chars.next() {
                Some('-') => chars.next().is_some_and(|c| c.is_ascii_alphanumeric()),
                Some(' ') => chars.next().is_some_and(|c| c.is_ascii_digit()),
                _ => false,
            }
        });
        isolated(text, start, end) && !continues
    }
}

impl Detector for GhanaCardDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "gh-ghana-card-v1",
            description: "Ghana Card PINs, for citizens (GHA-…) and, with context, non-citizens",
            entity_types: vec![EntityType::GH_GHANA_CARD_PIN],
            jurisdiction: Some(JURISDICTION),
            method: DetectionMethod::Contextual,
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::new();
        let labels = &self.labels;
        let mut push = |start: usize, end: usize, confidence: f32| -> Result<(), DetectionError> {
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            let mut f = Finding::new(EntityType::GH_GHANA_CARD_PIN, span, "gh-ghana-card-v1")
                .category(Category::PersonalIdentifier)
                .sensitivity(Sensitivity::HighlySensitive)
                .jurisdiction(JURISDICTION)
                .validation(ValidationState::ValidFormat)
                .confidence(confidence);
            let near = window(text, start, end, 50);
            for (label, words) in labels {
                if mentions(&near, words) {
                    f = f.label(label.clone());
                    if label == "HEALTH" {
                        f = f.category(Category::HealthInformation);
                    }
                }
            }
            out.push(f);
            Ok(())
        };
        for m in self.citizen.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            if !self.accept(text, start, end) {
                continue;
            }
            let canonical = m.as_str().matches('-').count() == 2;
            let near = mentions(&window(text, start, end, 50), &self.context);
            push(
                start,
                end,
                if canonical {
                    0.97
                } else if near {
                    0.93
                } else {
                    0.85
                },
            )?;
        }
        for m in self.other.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            if m.as_str()
                .get(..3)
                .is_some_and(|p| p.eq_ignore_ascii_case("GHA"))
                || !self.accept(text, start, end)
            {
                continue;
            }
            if mentions(&window(text, start, end, 50), &self.context) {
                push(start, end, 0.85)?;
            }
        }
        Ok(out)
    }
}
