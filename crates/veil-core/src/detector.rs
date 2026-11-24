//! The detector interface and the registry that holds detectors.

use serde::Serialize;

use crate::context::DetectionContext;
use crate::entity::{EntityType, Jurisdiction};
use crate::error::DetectionError;
use crate::finding::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethod {
    /// A pattern alone.
    Pattern,
    /// A pattern confirmed by a format or checksum validator.
    PatternAndValidation,
    /// A pattern that needs surrounding words to be reported.
    Contextual,
    /// A statistical model.
    Model,
}

/// What a detector is, for listings and audit records.
#[derive(Debug, Clone, Serialize)]
pub struct DetectorInfo {
    /// Stable id including its version, such as `gh-phone-v1`.
    pub id: &'static str,
    pub description: &'static str,
    pub entity_types: Vec<EntityType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<Jurisdiction>,
    pub method: DetectionMethod,
}

pub trait Detector: Send + Sync + std::fmt::Debug {
    fn info(&self) -> DetectorInfo;

    fn id(&self) -> &'static str {
        self.info().id
    }

    /// Finds candidates in `text`. Spans must refer to `text` as given.
    fn detect(
        &self,
        text: &str,
        context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError>;
}

#[derive(Debug, Default)]
pub struct Registry {
    detectors: Vec<Box<dyn Detector>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a detector. A second detector with the same id replaces the first.
    pub fn register(&mut self, detector: Box<dyn Detector>) {
        let id = detector.id();
        self.detectors.retain(|d| d.id() != id);
        self.detectors.push(detector);
    }

    pub fn with(mut self, detector: impl Detector + 'static) -> Self {
        self.register(Box::new(detector));
        self
    }

    pub fn detectors(&self) -> impl Iterator<Item = &dyn Detector> {
        self.detectors.iter().map(|d| d.as_ref())
    }

    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}
