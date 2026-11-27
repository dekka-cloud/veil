//! Dekka Veil's single entry point.
//!
//! ```
//! use veil::{PolicyContext, Veil};
//!
//! let veil = Veil::builder().country("gh").build().unwrap();
//! let out = veil.protect("Please call 024 123 4567", &PolicyContext::default()).unwrap();
//! assert_eq!(out.protected.output.as_deref(), Some("Please call 024 *** 4567"));
//! ```
//!
//! The builder loads country packs and a policy (`default-protection` unless you choose
//! another). `protect` detects, decides and transforms in one call, and applies the
//! policy's `on_failure` rule when a scan can't complete, so a caller never mistakes an
//! unchecked text for a checked one.
//!
//! With the `model` feature (on by default), `model_dir` loads Veil's contextual model for
//! the `nano` and `hybrid` profiles:
//!
//! ```no_run
//! use veil::{Profile, Veil};
//!
//! let veil = Veil::builder().model_dir("models/veil-ner-nano").profile(Profile::Hybrid).build().unwrap();
//! ```

pub mod api;

use std::collections::BTreeMap;
use std::path::PathBuf;

use thiserror::Error;
use veil_core::Registry;
pub use veil_core::{
    Cancel, DetectionContext, DetectionError, DetectionResult, Detector, DetectorInfo, Engine,
    EngineConfig, Finding, Profile, VeilError,
};
pub use veil_country_packs::{PackError, PACKS};
use veil_policy::TokenState;
pub use veil_policy::{
    Action, Decision, Enforcement, Policy, PolicyContext, PolicyError, PolicyRef, Protected,
    RestoreMap,
};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error("there is no built-in policy called {0}")]
    UnknownPolicy(String),
    #[error("couldn't load the model: {0}")]
    Model(String),
}

#[derive(Debug, Default)]
pub struct Builder {
    extra: Vec<Box<dyn Detector>>,
    countries: Vec<String>,
    policy: Option<Policy>,
    builtin: Option<String>,
    profile: Profile,
    config: Option<EngineConfig>,
    model_dir: Option<PathBuf>,
    model_threads: Option<usize>,
    model: Option<Box<dyn Detector>>,
}

impl Builder {
    /// Loads Veil's contextual model from a directory holding `model.onnx`, `tokenizer.json`
    /// and `manifest.yaml`, for the `nano` and `hybrid` profiles. The build fails if the
    /// files don't match the manifest's checksums, or if this build has no `model` feature.
    pub fn model_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.model_dir = Some(dir.into());
        self
    }

    /// Threads one inference may use. One by default.
    pub fn model_threads(mut self, threads: usize) -> Self {
        self.model_threads = Some(threads);
        self
    }

    /// Adds a country pack, such as `gh`. With none, every pack this build ships applies.
    pub fn country(mut self, code: &str) -> Self {
        self.countries.push(code.to_ascii_uppercase());
        self
    }

    pub fn policy(mut self, policy: Policy) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Uses a built-in policy by name, such as `default-protection`.
    pub fn builtin_policy(mut self, name: &str) -> Self {
        self.builtin = Some(name.to_string());
        self
    }

    /// Uses `detector` as the contextual model for the `nano` and `hybrid` profiles, for a
    /// model that runs outside this build's ONNX Runtime. [`Builder::model_dir`] wins if
    /// both are set.
    pub fn model(mut self, detector: impl Detector + 'static) -> Self {
        self.model = Some(Box::new(detector));
        self
    }

    /// Registers an extra detector alongside the built-in ones, such as an
    /// organisation-specific identifier.
    pub fn detector(mut self, detector: impl Detector + 'static) -> Self {
        self.extra.push(Box::new(detector));
        self
    }

    pub fn profile(mut self, profile: Profile) -> Self {
        self.profile = profile;
        self
    }

    pub fn config(mut self, config: EngineConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub fn build(self) -> Result<Veil, BuildError> {
        let mut registry: Registry = veil_detectors::general();
        let packs: Vec<String> = if self.countries.is_empty() {
            PACKS.iter().map(|s| s.to_string()).collect()
        } else {
            self.countries.clone()
        };
        for code in &packs {
            veil_country_packs::register(code, &mut registry)?;
        }
        for detector in self.extra {
            registry.register(detector);
        }
        let policy = match (self.policy, self.builtin) {
            (Some(p), _) => p,
            (None, Some(name)) => Policy::builtin(&name).ok_or(BuildError::UnknownPolicy(name))?,
            (None, None) => Policy::builtin("default-protection")
                .ok_or_else(|| BuildError::UnknownPolicy("default-protection".into()))?,
        };
        let mut engine = Engine::new(registry);
        if let Some(config) = self.config {
            engine = engine.with_config(config);
        }
        if let Some(dir) = &self.model_dir {
            engine = load_model(engine, dir, self.model_threads)?;
        } else if let Some(model) = self.model {
            engine = engine.with_model(model);
        }
        let context = self
            .countries
            .iter()
            .fold(DetectionContext::default(), |c, code| c.country(code));
        Ok(Veil {
            engine,
            policy,
            profile: self.profile,
            context,
        })
    }
}

#[cfg(feature = "model")]
fn load_model(
    engine: Engine,
    dir: &std::path::Path,
    threads: Option<usize>,
) -> Result<Engine, BuildError> {
    let mut options = veil_inference::Options::default();
    if let Some(t) = threads {
        options.threads = t.max(1);
    }
    let model = veil_inference::ModelDetector::load(dir, options)
        .map_err(|e| BuildError::Model(format!("{}: {e}", dir.display())))?;
    Ok(engine.with_model(Box::new(model)))
}

#[cfg(not(feature = "model"))]
fn load_model(_: Engine, dir: &std::path::Path, _: Option<usize>) -> Result<Engine, BuildError> {
    Err(BuildError::Model(format!(
        "{}: this build of Veil has no model support (the `model` feature is off)",
        dir.display()
    )))
}

#[derive(Debug)]
pub struct Veil {
    engine: Engine,
    policy: Policy,
    profile: Profile,
    context: DetectionContext,
}

/// Everything one protection call produced. `restore` holds original values and is never
/// serialised; drop it when the request ends.
#[derive(Debug)]
pub struct Outcome {
    pub protected: Protected,
    pub findings: Vec<Finding>,
    pub restore: RestoreMap,
    pub profile_used: Profile,
    /// False when the text wasn't scanned, which only `on_failure: open` allows.
    pub scanned: bool,
}

impl Veil {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Detection only, with the configured profile and countries.
    pub fn detect(&self, text: &str) -> Result<DetectionResult, VeilError> {
        self.engine.detect_with(text, &self.context, self.profile)
    }

    /// Detection only, with a profile other than the configured one.
    pub fn detect_with(&self, text: &str, profile: Profile) -> Result<DetectionResult, VeilError> {
        self.engine.detect_with(text, &self.context, profile)
    }

    /// The profile calls use unless they ask for another.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Whether `profile` can run here: rules always can, nano and hybrid need a model.
    pub fn supports(&self, profile: Profile) -> bool {
        self.engine.supports(profile)
    }

    /// Detects, decides and transforms. A failed scan follows the policy's `on_failure`,
    /// and one cancelled through [`Cancel`] is an error.
    pub fn protect(&self, text: &str, ctx: &PolicyContext) -> Result<Outcome, VeilError> {
        let mut warnings = Vec::new();
        let detection = match self.engine.detect_with(text, &self.context, self.profile) {
            Ok(d) => d,
            Err(VeilError::ProfileUnavailable(p))
                if self.policy.on_failure == Enforcement::RulesFallback =>
            {
                warnings.push(format!("the {p:?} profile is unavailable, so only the rules ran; this is not a complete hybrid scan"));
                match self.engine.detect_with(text, &self.context, Profile::Rules) {
                    Ok(d) => d,
                    Err(VeilError::Cancelled) => return Err(VeilError::Cancelled),
                    Err(e) => return Ok(self.failed(text, &e, warnings)),
                }
            }
            // A cancelled scan is an error under every `on_failure`, so the text is never
            // handed back as though the policy had let it through.
            Err(VeilError::Cancelled) => return Err(VeilError::Cancelled),
            Err(e) => return Ok(self.failed(text, &e, warnings)),
        };
        let mut applied = self.policy.protect(text, &detection.findings, ctx)?;
        warnings.extend(detection.warnings.iter().cloned());
        applied.protected.warnings = warnings;
        let profile_used = detection.profile_used;
        Ok(Outcome {
            protected: applied.protected,
            findings: detection.findings,
            restore: applied.restore,
            profile_used,
            scanned: true,
        })
    }

    fn failed(&self, text: &str, error: &VeilError, mut warnings: Vec<String>) -> Outcome {
        let open = self.policy.on_failure == Enforcement::Open;
        warnings.push(if open {
            format!("not scanned because {error}; the policy allows the text through unchecked")
        } else {
            format!("blocked because the scan couldn't complete: {error}")
        });
        Outcome {
            protected: Protected {
                output: open.then(|| text.to_string()),
                blocked: !open,
                decisions: Vec::new(),
                policy: Some(self.policy.reference()),
                warnings,
            },
            findings: Vec::new(),
            restore: RestoreMap::default(),
            profile_used: self.profile,
            scanned: false,
        }
    }

    /// Protects several texts in one request under `policy`, sharing placeholder numbering
    /// across them. Any blocked text blocks them all. The restore map is returned only when
    /// the request asks for it and `allow_restore` is true.
    pub fn protect_segments(
        &self,
        req: &api::ProtectRequest,
        policy: &Policy,
        allow_restore: bool,
    ) -> Result<api::ProtectResponse, api::ApiError> {
        use api::{ApiError, ProtectResponse, SegmentOut, Summary};
        let enforcement = req.enforcement.unwrap_or(Enforcement::Closed);
        let profile = req.profile.unwrap_or(self.profile);
        if !self.engine.supports(profile) && enforcement != Enforcement::RulesFallback {
            return Err(ApiError::ProfileUnavailable(profile));
        }
        let dctx = self.context_for(req.country.as_deref());
        let ctx = req.context.to_policy_context();
        let mut tokens = TokenState::default();
        let mut warnings = Vec::new();
        let mut segments = Vec::with_capacity(req.segments.len());
        let mut summary = Summary::default();
        let mut blocked = false;
        let mut profile_used = profile;
        for (i, text) in req.segments.iter().enumerate() {
            let detection = match self.engine.detect_with(text, &dctx, profile) {
                Ok(d) => Some(d),
                Err(VeilError::InputTooLarge { size, limit }) => {
                    return Err(ApiError::InputTooLarge { size, limit })
                }
                // Whoever cancelled has stopped waiting, so no enforcement mode carries on
                // to the segments that are left.
                Err(VeilError::Cancelled) => {
                    return Err(ApiError::ScanFailed(VeilError::Cancelled.to_string()))
                }
                Err(VeilError::ProfileUnavailable(p))
                    if enforcement == Enforcement::RulesFallback =>
                {
                    warnings.push(format!("the {p:?} profile is unavailable, so only the rules ran; this is not a complete hybrid scan"));
                    Some(
                        self.engine
                            .detect_with(text, &dctx, Profile::Rules)
                            .map_err(|e| {
                                ApiError::ScanFailed(format!("the scan couldn't complete: {e}"))
                            })?,
                    )
                }
                Err(e) if enforcement == Enforcement::Open => {
                    warnings.push(format!("segment {i} wasn't scanned because {e}; the open enforcement mode let it through unchecked"));
                    None
                }
                Err(e) => {
                    return Err(ApiError::ScanFailed(format!(
                        "the scan couldn't complete: {e}"
                    )))
                }
            };
            let Some(detection) = detection else {
                segments.push(SegmentOut {
                    output: Some(text.clone()),
                    decisions: Vec::new(),
                });
                continue;
            };
            profile_used = detection.profile_used;
            warnings.extend(detection.warnings.iter().cloned());
            let protected = policy
                .protect_shared(text, &detection.findings, &ctx, &mut tokens)
                .map_err(|e| ApiError::Internal(format!("couldn't apply the policy: {e}")))?;
            blocked |= protected.blocked;
            let decisions: Vec<api::DecisionOut> = protected
                .decisions
                .iter()
                .map(|d| api::decision_out(d, &detection.findings))
                .collect();
            for d in &decisions {
                summary.findings += 1;
                *summary.by_entity.entry(d.entity_type.clone()).or_default() += 1;
                *summary
                    .by_action
                    .entry(d.action.as_str().to_ascii_uppercase())
                    .or_default() += 1;
            }
            segments.push(SegmentOut {
                output: protected.output,
                decisions,
            });
        }
        if blocked {
            for s in &mut segments {
                s.output = None;
            }
        }
        let restore = match (req.restore, allow_restore, blocked) {
            (true, true, false) => {
                let map = tokens.restore_map();
                Some(
                    map.placeholders()
                        .filter_map(|p| map.value(p).map(|v| (p.to_string(), v.to_string())))
                        .collect::<BTreeMap<_, _>>(),
                )
            }
            (true, false, _) => {
                warnings.push(
                    "restore was requested, but this host doesn't allow returning original values"
                        .to_string(),
                );
                None
            }
            _ => None,
        };
        Ok(ProtectResponse {
            blocked,
            segments,
            policy: api::PolicyOut {
                name: Some(policy.name.clone()),
                revision: api::revision(policy),
            },
            summary,
            warnings,
            profile_used,
            restore,
        })
    }

    /// Detection only, for several texts.
    pub fn detect_segments(
        &self,
        req: &api::DetectRequest,
    ) -> Result<api::DetectResponse, api::ApiError> {
        use api::ApiError;
        let profile = req.profile.unwrap_or(self.profile);
        if !self.engine.supports(profile) {
            return Err(ApiError::ProfileUnavailable(profile));
        }
        let dctx = self.context_for(req.country.as_deref());
        let mut segments = Vec::with_capacity(req.segments.len());
        let mut warnings = Vec::new();
        let mut profile_used = profile;
        for text in &req.segments {
            let d = match self.engine.detect_with(text, &dctx, profile) {
                Ok(d) => d,
                Err(VeilError::InputTooLarge { size, limit }) => {
                    return Err(ApiError::InputTooLarge { size, limit })
                }
                Err(e) => {
                    return Err(ApiError::ScanFailed(format!(
                        "the scan couldn't complete: {e}"
                    )))
                }
            };
            profile_used = d.profile_used;
            warnings.extend(d.warnings.iter().cloned());
            segments.push(api::DetectSegment {
                findings: d
                    .findings
                    .into_iter()
                    .map(|finding| api::FindingOut {
                        finding,
                        offset_unit: "utf8_byte",
                    })
                    .collect(),
            });
        }
        Ok(api::DetectResponse {
            segments,
            profile_used,
            warnings,
        })
    }

    /// The entity types this instance's detectors can report.
    pub fn entity_types(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .engine
            .registry()
            .detectors()
            .chain(self.engine.model())
            .flat_map(|d| d.info().entity_types.into_iter().map(|e| e.to_string()))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn context_for(&self, country: Option<&str>) -> DetectionContext {
        match country {
            Some(c) if !c.trim().is_empty() => DetectionContext::default().country(c),
            _ => self.context.clone(),
        }
    }
}
