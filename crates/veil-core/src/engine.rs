//! The detection pipeline: run every applicable detector, check every span against the
//! original text, then resolve duplicates and overlaps into one deterministic list.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::context::DetectionContext;
use crate::detector::{Detector, Registry};
use crate::error::VeilError;
use crate::finding::Finding;

/// Which detection profile runs. `nano` runs the contextual model alone and
/// `hybrid` runs rules and model together; both need a model (see [`Engine::with_model`]).
/// Asking for a profile without one is refused rather than silently answered with rules
/// alone. `deep` has no runtime yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Rules,
    Nano,
    Deep,
    Hybrid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    /// Inputs larger than this are refused. Default 1 MiB.
    pub max_input_bytes: usize,
    /// Run detectors on a normalised copy (see [`crate::normalize`]) and map spans back.
    /// On by default.
    pub normalize: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            normalize: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetectionResult {
    pub findings: Vec<Finding>,
    pub profile_used: Profile,
    /// True when detectors ran on a normalised copy of the input. Spans still refer to
    /// the original text.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub normalized: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Entity types the rules validate with patterns and checksums. In the hybrid profile the
/// rules alone decide these, and the model's findings of them are dropped.
pub const STRUCTURED: &[&str] = &[
    "GH_MOBILE_NUMBER",
    "GH_LANDLINE_NUMBER",
    "GH_GHANA_CARD_PIN",
    "GH_DIGITAL_ADDRESS",
    "GH_TAX_IDENTIFIER",
    "GH_VEHICLE_REGISTRATION",
    "EMAIL_ADDRESS",
    "PAYMENT_CARD_PAN",
    "IP_ADDRESS",
];

#[derive(Debug)]
pub struct Engine {
    registry: Registry,
    config: EngineConfig,
    model: Option<Box<dyn Detector>>,
}

impl Engine {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            config: EngineConfig::default(),
            model: None,
        }
    }

    /// Adds the contextual model the `nano` and `hybrid` profiles run.
    pub fn with_model(mut self, model: Box<dyn Detector>) -> Self {
        self.model = Some(model);
        self
    }

    pub fn model(&self) -> Option<&dyn Detector> {
        self.model.as_deref()
    }

    /// Whether `profile` can run on this engine.
    pub fn supports(&self, profile: Profile) -> bool {
        match profile {
            Profile::Rules => true,
            Profile::Nano | Profile::Hybrid => self.model.is_some(),
            Profile::Deep => false,
        }
    }

    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    pub fn detect(
        &self,
        text: &str,
        context: &DetectionContext,
    ) -> Result<DetectionResult, VeilError> {
        self.detect_with(text, context, Profile::Rules)
    }

    /// Runs detection with `profile`. Any rule's failure fails the whole call, so a caller
    /// that enforces privacy never mistakes a partial scan for a complete one. If the model
    /// fails, the rules' result is returned with `profile_used: rules` and a warning saying
    /// the model didn't run, which a caller can treat as it treats the rules fallback. A
    /// scan cancelled through [`crate::Cancel`] fails as a whole in either part.
    pub fn detect_with(
        &self,
        text: &str,
        context: &DetectionContext,
        profile: Profile,
    ) -> Result<DetectionResult, VeilError> {
        if !self.supports(profile) {
            return Err(VeilError::ProfileUnavailable(profile));
        }
        if text.len() > self.config.max_input_bytes {
            return Err(VeilError::InputTooLarge {
                size: text.len(),
                limit: self.config.max_input_bytes,
            });
        }
        let Some(model) = self.model.as_deref().filter(|_| profile != Profile::Rules) else {
            return self.rules(text, context);
        };
        let found = model.detect(text, context).and_then(|found| {
            for f in &found {
                f.span.validate(text).map_err(|_| {
                    crate::error::DetectionError::new(
                        "returned a span outside the input or off a character boundary",
                    )
                })?;
            }
            Ok(found)
        });
        let model_findings = match found {
            Ok(f) => f,
            Err(e) => {
                let mut result = self.rules(text, context)?;
                result
                    .warnings
                    .push(format!("the model failed ({e}), so only the rules ran; this is a rules fallback, not a {profile:?} scan"));
                return Ok(result);
            }
        };
        let model_findings: Vec<Finding> = model_findings
            .into_iter()
            .filter(|f| !f.span.is_empty())
            .collect();
        if profile == Profile::Nano {
            return Ok(DetectionResult {
                findings: resolve(model_findings),
                profile_used: profile,
                normalized: false,
                warnings: Vec::new(),
            });
        }
        let mut result = self.rules(text, context)?;
        let mut merged = result.findings;
        let rules_end = merged.len();
        for f in model_findings {
            let overlaps = merged
                .iter()
                .take(rules_end)
                .any(|r| f.span.start < r.span.end && r.span.start < f.span.end);
            if !STRUCTURED.contains(&f.entity_type.as_str()) && !overlaps {
                merged.push(f);
            }
        }
        result.findings = resolve(merged);
        result.profile_used = profile;
        Ok(result)
    }

    /// The rules alone.
    fn rules(&self, text: &str, context: &DetectionContext) -> Result<DetectionResult, VeilError> {
        if text.len() > self.config.max_input_bytes {
            return Err(VeilError::InputTooLarge {
                size: text.len(),
                limit: self.config.max_input_bytes,
            });
        }
        if crate::cancel::cancelled() {
            return Err(VeilError::Cancelled);
        }
        let normalized = if self.config.normalize {
            crate::normalize::Normalized::of(text)
        } else {
            None
        };
        let scan: &str = normalized.as_ref().map_or(text, |n| n.text.as_str());
        let mut candidates = Vec::new();
        for detector in self.registry.detectors() {
            if crate::cancel::cancelled() {
                return Err(VeilError::Cancelled);
            }
            let info = detector.info();
            if let Some(j) = &info.jurisdiction {
                if !context.wants_country(j.as_str()) {
                    continue;
                }
            }
            let found =
                detector
                    .detect(scan, context)
                    .map_err(|source| VeilError::DetectorFailed {
                        detector: info.id.to_string(),
                        source,
                    })?;
            let bad_span = || VeilError::DetectorFailed {
                detector: info.id.to_string(),
                source: crate::error::DetectionError::new(
                    "returned a span outside the input or off a character boundary",
                ),
            };
            for mut finding in found {
                finding.span.validate(scan).map_err(|_| bad_span())?;
                if finding.span.is_empty() {
                    continue;
                }
                if let Some(n) = &normalized {
                    let (start, end) = n
                        .to_original(finding.span.start, finding.span.end)
                        .ok_or_else(bad_span)?;
                    finding.span = crate::span::Span::new(start, end)?;
                }
                finding.span.validate(text).map_err(|_| bad_span())?;
                candidates.push(finding);
            }
        }
        Ok(DetectionResult {
            findings: resolve(candidates),
            profile_used: Profile::Rules,
            normalized: normalized.is_some(),
            warnings: Vec::new(),
        })
    }
}

/// Merges duplicates and resolves overlaps deterministically.
///
/// Findings with the same span and entity type merge, keeping the strongest validation,
/// the highest confidence and every context label. Where spans overlap otherwise, one
/// finding wins: stronger validation, then higher confidence, then the longer span, then
/// the entity code and detector id, so the result never depends on detector order.
pub fn resolve(mut candidates: Vec<Finding>) -> Vec<Finding> {
    candidates.sort_by(|a, b| {
        a.span
            .cmp(&b.span)
            .then_with(|| a.entity_type.cmp(&b.entity_type))
            .then_with(|| a.detector.cmp(&b.detector))
    });

    let mut merged: Vec<Finding> = Vec::with_capacity(candidates.len());
    for f in candidates {
        match merged.last_mut() {
            Some(last) if last.span == f.span && last.entity_type == f.entity_type => {
                if f.validation.strength() > last.validation.strength() {
                    last.validation = f.validation;
                    last.evidence = f.evidence;
                    last.detector = f.detector.clone();
                }
                last.confidence = last.confidence.max(f.confidence);
                for label in f.context_labels {
                    if !last.context_labels.contains(&label) {
                        last.context_labels.push(label);
                    }
                }
                for c in f.categories {
                    if !last.categories.contains(&c) {
                        last.categories.push(c);
                    }
                }
                last.sensitivity = last.sensitivity.max(f.sensitivity);
            }
            _ => merged.push(f),
        }
    }

    // Strongest first, then keep each finding that doesn't overlap one already kept.
    let mut ranked: Vec<Finding> = merged;
    ranked.sort_by(rank);
    // Kept spans don't overlap each other, so ordered by start they're also ordered by end,
    // and a new span can only collide with its nearest neighbours on either side.
    let mut taken: BTreeMap<usize, usize> = BTreeMap::new();
    let mut kept: Vec<Finding> = Vec::with_capacity(ranked.len());
    for f in ranked {
        let (start, end) = (f.span.start, f.span.end);
        let left = taken
            .range(..=start)
            .next_back()
            .is_some_and(|(_, &e)| e > start);
        let right = taken.range(start..).next().is_some_and(|(&s, _)| s < end);
        if !left && !right {
            taken.insert(start, end);
            kept.push(f);
        }
    }
    kept.sort_by(|a, b| {
        a.span
            .cmp(&b.span)
            .then_with(|| a.entity_type.cmp(&b.entity_type))
    });
    kept
}

fn rank(a: &Finding, b: &Finding) -> Ordering {
    b.validation
        .strength()
        .cmp(&a.validation.strength())
        .then_with(|| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
        })
        .then_with(|| b.span.len().cmp(&a.span.len()))
        .then_with(|| a.span.cmp(&b.span))
        .then_with(|| a.entity_type.cmp(&b.entity_type))
        .then_with(|| a.detector.cmp(&b.detector))
}
