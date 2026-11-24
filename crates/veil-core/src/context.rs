use serde::{Deserialize, Serialize};

/// What the caller knows about the input, used by detectors as hints.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionContext {
    /// ISO 3166-1 alpha-2 codes, such as `GH`. Empty means every loaded pack applies.
    pub countries: Vec<String>,
    /// BCP 47 language tags, such as `en`, `tw`, `ee` or `gaa`.
    pub languages: Vec<String>,
}

impl DetectionContext {
    pub fn country(mut self, code: &str) -> Self {
        self.countries.push(code.to_ascii_uppercase());
        self
    }

    pub fn wants_country(&self, code: &str) -> bool {
        self.countries.is_empty() || self.countries.iter().any(|c| c.eq_ignore_ascii_case(code))
    }
}
