//! Detectors defined entirely by data in `country-packs/gh/patterns.toml`: a pattern, an
//! optional prefix allowlist, context words, and how strongly the format is sourced.

use regex::Regex;
use serde::Deserialize;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use super::{parse, JURISDICTION, PATTERNS};
use crate::context::{isolated, mentions, window};
use crate::{pattern, PackError};

#[derive(Debug, Deserialize)]
struct File {
    detector: Vec<Spec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    id: String,
    description: String,
    entity: String,
    pattern: String,
    #[serde(default)]
    prefix_length: usize,
    #[serde(default)]
    prefixes: Vec<String>,
    categories: Vec<Category>,
    sensitivity: Sensitivity,
    validation: ValidationState,
    #[serde(default)]
    context: Vec<String>,
    /// Words that mark a match as belonging to an organisation or the state rather than a
    /// person, such as a bus or an accident report. A match near one isn't reported.
    #[serde(default)]
    public_context: Vec<String>,
    /// Words that tie a match to a person, such as "my car" or "registered to". They win
    /// over `public_context`, so a personal plate in a news story is still reported.
    #[serde(default)]
    owner_context: Vec<String>,
    requires_context: bool,
    #[serde(default = "default_window")]
    window: usize,
    confidence: f32,
    confidence_with_context: f32,
    #[allow(dead_code)]
    source: String,
}

fn default_window() -> usize {
    50
}

#[derive(Debug)]
pub struct PatternDetector {
    id: &'static str,
    description: &'static str,
    entity: EntityType,
    re: Regex,
    spec: Spec,
}

/// Every detector in the pack's pattern file.
pub fn detectors() -> Result<Vec<PatternDetector>, PackError> {
    let file: File = parse("gh/patterns.toml", PATTERNS)?;
    Ok(file
        .detector
        .into_iter()
        .map(|spec| {
            // Ids and descriptions live as long as the program, like built-in detectors'.
            let id: &'static str = Box::leak(spec.id.clone().into_boxed_str());
            let description: &'static str = Box::leak(spec.description.clone().into_boxed_str());
            let entity = EntityType(std::borrow::Cow::Owned(spec.entity.clone()));
            PatternDetector {
                id,
                description,
                entity,
                re: pattern(&spec.pattern),
                spec,
            }
        })
        .collect())
}

impl Detector for PatternDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: self.id,
            description: self.description,
            entity_types: vec![self.entity.clone()],
            jurisdiction: Some(JURISDICTION),
            method: if self.spec.requires_context {
                DetectionMethod::Contextual
            } else {
                DetectionMethod::PatternAndValidation
            },
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let s = &self.spec;
        let mut out = Vec::new();
        // A detector that needs context can't report anything when none of its words
        // appear anywhere, which is the common case, so skip the pattern scan.
        if s.requires_context {
            let lower = text.to_lowercase();
            if !s.context.iter().any(|w| lower.contains(w.as_str())) {
                return Ok(out);
            }
        }
        for m in self.re.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            if !isolated(text, start, end) {
                continue;
            }
            if !s.prefixes.is_empty()
                && !m
                    .as_str()
                    .get(..s.prefix_length)
                    .is_some_and(|p| s.prefixes.iter().any(|x| x == p))
            {
                continue;
            }
            let around = window(text, start, end, s.window);
            let near = !s.context.is_empty() && mentions(&around, &s.context);
            if !s.public_context.is_empty()
                && mentions(&around, &s.public_context)
                && !mentions(&around, &s.owner_context)
            {
                continue;
            }
            if s.requires_context && !near {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            let mut f = Finding::new(self.entity.clone(), span, self.id)
                .sensitivity(s.sensitivity)
                .jurisdiction(JURISDICTION)
                .validation(s.validation)
                .confidence(if near {
                    s.confidence_with_context
                } else {
                    s.confidence
                });
            for c in &s.categories {
                f = f.category(*c);
            }
            out.push(f);
        }
        Ok(out)
    }
}
