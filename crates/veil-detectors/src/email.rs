use regex::Regex;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use crate::{boundary, pattern};

/// Email addresses in the common `local@domain.tld` form. Quoted local parts and IP
/// literals are rare in conversational text and aren't matched.
///
/// Scanning starts from each `@`, so text without one costs a single pass, and the local
/// part is read backwards from the `@` rather than tried at every position.
#[derive(Debug)]
pub struct EmailDetector {
    domain: Regex,
}

impl EmailDetector {
    pub fn new() -> Self {
        Self {
            domain: pattern(
                r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}",
            ),
        }
    }
}

fn local_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

impl Default for EmailDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn plausible(m: &str) -> bool {
    let Some((local, domain)) = m.split_once('@') else {
        return false;
    };
    !local.contains("..") && !local.ends_with('.') && domain.len() <= 253 && !domain.contains("..")
}

impl Detector for EmailDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "email-v1",
            description: "Email addresses",
            entity_types: vec![EntityType::EMAIL_ADDRESS],
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
        let bytes = text.as_bytes();
        for (at, _) in text.match_indices('@') {
            // Read the local part backwards, at most 64 characters, starting alphanumeric.
            let mut start = at;
            while start > 0
                && at - start < 64
                && bytes.get(start - 1).copied().is_some_and(local_char)
            {
                start -= 1;
            }
            while start < at && !bytes.get(start).is_some_and(u8::is_ascii_alphanumeric) {
                start += 1;
            }
            if start == at {
                continue;
            }
            let Some(rest) = text.get(at + 1..) else {
                continue;
            };
            let Some(d) = self.domain.find(rest) else {
                continue;
            };
            let end = at + 1 + d.end();
            if boundary::before(text, start)
                .is_some_and(|c| c.is_alphanumeric() || c == '.' || c == '@')
            {
                continue;
            }
            let Some(candidate) = text.get(start..end) else {
                continue;
            };
            if !plausible(candidate) {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(
                Finding::new(EntityType::EMAIL_ADDRESS, span, "email-v1")
                    .category(Category::PersonalIdentifier)
                    .sensitivity(Sensitivity::Personal)
                    .validation(ValidationState::ValidFormat)
                    .confidence(0.97),
            );
        }
        Ok(out)
    }
}
