//! A finding is evidence: what kind of detail, where, from which detector, and how strongly
//! validated. It never holds the matched text.

use serde::{Deserialize, Serialize};

use crate::entity::{Category, EntityType, Family, Jurisdiction, Sensitivity};
use crate::span::Span;

/// How strongly a detector validated what it found. Format validation never
/// means the identifier exists or belongs to anyone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationState {
    /// The candidate failed validation. Kept only when a detector reports rejected candidates.
    Invalid,
    /// Not checked beyond the pattern, usually because no published specification exists.
    Unverified,
    NotApplicable,
    /// Matches the documented format.
    ValidFormat,
    /// Passes a documented structural check such as a checksum.
    Valid,
}

impl ValidationState {
    /// Strength used to break ties between overlapping findings.
    pub fn strength(self) -> u8 {
        match self {
            Self::Invalid => 0,
            Self::NotApplicable => 1,
            Self::Unverified => 2,
            Self::ValidFormat => 3,
            Self::Valid => 4,
        }
    }
}

/// How well the format a detector matches is documented, from Veil's identifier registry
/// (`country-packs/gh/identifiers.yaml`). It describes the specification behind a
/// detector, which is separate from how strongly one finding was validated against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceLevel {
    /// The issuing body publishes the format, directly or through a filing it made.
    IssuerConfirmed,
    /// An international standard defines the format.
    InternationalStandard,
    /// Only maintained secondary references describe the format.
    Secondary,
    /// No format is published; detection rests on context alone.
    Unpublished,
}

impl EvidenceLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuerConfirmed => "ISSUER_CONFIRMED",
            Self::InternationalStandard => "INTERNATIONAL_STANDARD",
            Self::Secondary => "SECONDARY",
            Self::Unpublished => "UNPUBLISHED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub entity_type: EntityType,
    #[serde(default)]
    pub family: Family,
    pub span: Span,
    pub categories: Vec<Category>,
    pub sensitivity: Sensitivity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<Jurisdiction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_labels: Vec<String>,
    /// For rules, a fixed score per validation outcome; for models, a calibrated probability.
    pub confidence: f32,
    pub validation: ValidationState,
    /// How well the format behind the detector is documented, for detectors that have an
    /// entry in an identifier registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidenceLevel>,
    /// The detector's id and version, such as `gh-phone-v1`.
    pub detector: String,
}

impl Finding {
    pub fn new(entity_type: EntityType, span: Span, detector: impl Into<String>) -> Self {
        Self {
            entity_type,
            family: Family::Pii,
            span,
            categories: Vec::new(),
            sensitivity: Sensitivity::Personal,
            jurisdiction: None,
            context_labels: Vec::new(),
            confidence: 0.5,
            validation: ValidationState::Unverified,
            evidence: None,
            detector: detector.into(),
        }
    }

    pub fn family(mut self, family: Family) -> Self {
        self.family = family;
        self
    }

    pub fn category(mut self, category: Category) -> Self {
        if !self.categories.contains(&category) {
            self.categories.push(category);
        }
        self
    }

    pub fn sensitivity(mut self, sensitivity: Sensitivity) -> Self {
        self.sensitivity = sensitivity;
        self
    }

    pub fn jurisdiction(mut self, jurisdiction: Jurisdiction) -> Self {
        self.jurisdiction = Some(jurisdiction);
        self
    }

    pub fn label(mut self, label: impl Into<String>) -> Self {
        let label = label.into();
        if !self.context_labels.contains(&label) {
            self.context_labels.push(label);
        }
        self
    }

    pub fn confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    pub fn validation(mut self, validation: ValidationState) -> Self {
        self.validation = validation;
        self
    }

    pub fn evidence(mut self, evidence: EvidenceLevel) -> Self {
        self.evidence = Some(evidence);
        self
    }
}
