//! The offset contract.
//!
//! Spans are zero-based, half-open `[start, end)` UTF-8 byte offsets into the original
//! input. Both ends must fall on character boundaries. Every span is checked against the
//! text before it is used to slice it, so a bad span is an error rather than a panic.

use serde::{Deserialize, Serialize};

use crate::error::VeilError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// A span, refused when `start > end`. Use [`Span::validate`] to check it against text.
    pub fn new(start: usize, end: usize) -> Result<Self, VeilError> {
        if start > end {
            return Err(VeilError::InvalidSpan {
                start,
                end,
                reason: "start is after end",
            });
        }
        Ok(Self { start, end })
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn overlaps(&self, other: &Span) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn contains(&self, other: &Span) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Checks the span lies within `text` on character boundaries.
    pub fn validate(&self, text: &str) -> Result<(), VeilError> {
        if self.start > self.end {
            return Err(VeilError::InvalidSpan {
                start: self.start,
                end: self.end,
                reason: "start is after end",
            });
        }
        if self.end > text.len() {
            return Err(VeilError::InvalidSpan {
                start: self.start,
                end: self.end,
                reason: "ends past the input",
            });
        }
        if !text.is_char_boundary(self.start) || !text.is_char_boundary(self.end) {
            return Err(VeilError::InvalidSpan {
                start: self.start,
                end: self.end,
                reason: "not on a character boundary",
            });
        }
        Ok(())
    }

    /// The text the span covers, after validating it.
    pub fn slice<'a>(&self, text: &'a str) -> Result<&'a str, VeilError> {
        self.validate(text)?;
        text.get(self.start..self.end)
            .ok_or(VeilError::InvalidSpan {
                start: self.start,
                end: self.end,
                reason: "not on a character boundary",
            })
    }
}
