use thiserror::Error;

/// An error from a single detector. The engine reports it rather than hiding it.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{reason}")]
pub struct DetectionError {
    pub reason: String,
}

impl DetectionError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum VeilError {
    #[error("the input is {size} bytes, over the {limit} byte limit")]
    InputTooLarge { size: usize, limit: usize },
    #[error("span {start}..{end} is invalid: {reason}")]
    InvalidSpan {
        start: usize,
        end: usize,
        reason: &'static str,
    },
    #[error("detector {detector} failed: {source}")]
    DetectorFailed {
        detector: String,
        source: DetectionError,
    },
    #[error("no detector is registered for country {0}")]
    UnsupportedCountry(String),
    #[error("the {0:?} profile needs a model, and none is configured")]
    ProfileUnavailable(crate::engine::Profile),
    #[error("the scan was cancelled")]
    Cancelled,
}
