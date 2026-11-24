use regex::Regex;
use serde::Deserialize;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use super::{parse, DIGITAL_ADDRESS, JURISDICTION};
use crate::context::{isolated, mentions, window};
use crate::{pattern, PackError};

#[derive(Debug, Deserialize)]
struct Format {
    regions: Vec<(String, String)>,
    districts: Vec<(String, String)>,
    context: Vec<String>,
}

/// GhanaPost GPS digital addresses such as `AK-039-5028` or `AKW-039-5028`. The district
/// code must be one GhanaPostGPS publishes. The hyphenated form is reported on its own;
/// other spellings (`AK0395028`, `AK 039 5028`) need a nearby address word, because codes
/// of that shape are common elsewhere. A match is a location identifier and says nothing
/// about whether the address is anyone's home.
#[derive(Debug)]
pub struct DigitalAddressDetector {
    re: Regex,
    districts: std::collections::HashSet<String>,
    context: Vec<String>,
}

impl DigitalAddressDetector {
    pub fn new() -> Result<Self, PackError> {
        let f: Format = parse("gh/digital-address.toml", DIGITAL_ADDRESS)?;
        let letters: std::collections::HashSet<String> = f
            .regions
            .iter()
            .map(|(l, _)| l.to_ascii_uppercase())
            .collect();
        let districts = f
            .districts
            .into_iter()
            .map(|(c, _)| c.to_ascii_uppercase())
            .filter(|c| c.get(..1).is_some_and(|l| letters.contains(l)))
            .collect();
        Ok(Self {
            re: pattern(r"(?i)[A-Z][A-Z0-9]{1,2}[ \-]?\d{3,4}[ \-]?\d{4}"),
            districts,
            context: f.context,
        })
    }

    /// Splits a candidate into district code and digits, trying a three-character code
    /// first, and returns the code when it's a published one and the digits fit.
    fn district(&self, candidate: &str) -> Option<String> {
        let upper = candidate.to_ascii_uppercase();
        for len in [3, 2] {
            let (code, rest) = (upper.get(..len)?, upper.get(len..)?);
            let digits: String = rest.chars().filter(|c| *c != '-' && *c != ' ').collect();
            let well_formed =
                digits.chars().all(|c| c.is_ascii_digit()) && (7..=8).contains(&digits.len());
            let separated_after_code = rest.starts_with(['-', ' '])
                || !rest.contains(['-', ' '])
                || rest.chars().next().is_some_and(|c| c.is_ascii_digit());
            if well_formed && separated_after_code && self.districts.contains(code) {
                return Some(code.to_string());
            }
        }
        None
    }
}

impl Detector for DigitalAddressDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "gh-digital-address-v1",
            description: "GhanaPost GPS digital addresses",
            entity_types: vec![EntityType::GH_DIGITAL_ADDRESS],
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
        for m in self.re.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            if !isolated(text, start, end) {
                continue;
            }
            let s = m.as_str();
            if self.district(s).is_none() {
                continue;
            }
            let hyphenated = s.matches('-').count() == 2;
            let near = mentions(&window(text, start, end, 50), &self.context);
            let confidence = match (hyphenated, near) {
                (true, true) => 0.95,
                (true, false) => 0.85,
                (false, true) => 0.8,
                (false, false) => continue,
            };
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(
                Finding::new(
                    EntityType::GH_DIGITAL_ADDRESS,
                    span,
                    "gh-digital-address-v1",
                )
                .category(Category::LocationIdentifier)
                .category(Category::QuasiIdentifier)
                .sensitivity(Sensitivity::Personal)
                .jurisdiction(JURISDICTION)
                .validation(ValidationState::ValidFormat)
                .confidence(confidence),
            );
        }
        Ok(out)
    }
}
