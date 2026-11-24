//! Core of Dekka Veil: the offset contract, the entity model, findings, the detector
//! interface and the pipeline that runs detectors and resolves what they find.
//!
//! Veil reports evidence, never values. A [`Finding`] says what kind of detail was found,
//! where (as a [`Span`] of the original text), by which detector, and how strongly it was
//! validated. It never carries the matched text, so findings are safe to log.

pub mod context;
pub mod detector;
pub mod engine;
pub mod entity;
pub mod error;
pub mod finding;
pub mod normalize;
pub mod span;

pub use context::DetectionContext;
pub use detector::{DetectionMethod, Detector, DetectorInfo, Registry};
pub use engine::{DetectionResult, Engine, EngineConfig, Profile, STRUCTURED};
pub use entity::{Category, EntityType, Family, Jurisdiction, Sensitivity};
pub use error::{DetectionError, VeilError};
pub use finding::{EvidenceLevel, Finding, ValidationState};
pub use normalize::Normalized;
pub use span::Span;
