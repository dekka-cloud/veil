use std::net::{Ipv4Addr, Ipv6Addr};

use regex::Regex;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use crate::{boundary, pattern};

/// IPv4 addresses. Candidates must parse as an address and stand apart from longer dotted
/// numbers such as version strings (`1.2.3.4.5`).
#[derive(Debug)]
pub struct Ipv4Detector {
    re: Regex,
}

impl Ipv4Detector {
    pub fn new() -> Self {
        Self {
            re: pattern(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
        }
    }
}

impl Default for Ipv4Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Ipv4Detector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "ipv4-v1",
            description: "IPv4 addresses",
            entity_types: vec![EntityType::IP_ADDRESS],
            jurisdiction: None,
            method: DetectionMethod::PatternAndValidation,
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
            // A dot before, or a dot followed by a digit after, means a longer dotted number
            // such as a version string. A dot that ends a sentence is fine.
            let glued_before =
                boundary::before(text, start).is_some_and(|c| c.is_alphanumeric() || c == '.');
            let next = boundary::after(text, end);
            let dotted_on = next == Some('.')
                && text
                    .get(end + 1..)
                    .and_then(|s| s.chars().next())
                    .is_some_and(|c| c.is_ascii_digit());
            if glued_before || next.is_some_and(char::is_alphanumeric) || dotted_on {
                continue;
            }
            if m.as_str().parse::<Ipv4Addr>().is_err() {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(
                Finding::new(EntityType::IP_ADDRESS, span, "ipv4-v1")
                    .category(Category::QuasiIdentifier)
                    .sensitivity(Sensitivity::Personal)
                    .validation(ValidationState::ValidFormat)
                    .confidence(0.9),
            );
        }
        Ok(out)
    }
}

/// IPv6 addresses, accepted only when the candidate parses as one. Clock times such as
/// `12:30:45` don't parse and are left alone.
#[derive(Debug)]
pub struct Ipv6Detector {
    re: Regex,
}

impl Ipv6Detector {
    pub fn new() -> Self {
        Self {
            re: pattern(
                r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})?",
            ),
        }
    }
}

impl Default for Ipv6Detector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for Ipv6Detector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "ipv6-v1",
            description: "IPv6 addresses",
            entity_types: vec![EntityType::IP_ADDRESS],
            jurisdiction: None,
            method: DetectionMethod::PatternAndValidation,
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let s = m.as_str();
            let (start, end) = (m.start(), m.end());
            let glued = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == ':');
            if glued(boundary::before(text, start)) || glued(boundary::after(text, end)) {
                continue;
            }
            // At least two hex groups, so "a::" style fragments in prose aren't reported.
            if s.split(':').filter(|g| !g.is_empty()).count() < 2 || s.parse::<Ipv6Addr>().is_err()
            {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(
                Finding::new(EntityType::IP_ADDRESS, span, "ipv6-v1")
                    .category(Category::QuasiIdentifier)
                    .sensitivity(Sensitivity::Personal)
                    .validation(ValidationState::ValidFormat)
                    .confidence(0.9),
            );
        }
        Ok(out)
    }
}
