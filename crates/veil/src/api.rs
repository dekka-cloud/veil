//! A JSON-friendly request and response contract for protecting and detecting text, which
//! the Python and JavaScript libraries share so every binding answers in exactly the same
//! shape. Nothing here detects anything: it maps requests onto [`crate::Veil`].
//!
//! Responses never carry the values Veil found. The one exception is the restore map,
//! which a caller must ask for and the host must explicitly allow.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use veil_core::{Finding, Span, ValidationState};
use veil_policy::{Action, Enforcement, Policy, PolicyContext, RuleRef};

/// The most segments one request may carry.
pub const MAX_SEGMENTS: usize = 64;

/// Which policy decides: a built-in by name, or a policy written in YAML.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize)]
#[serde(untagged)]
pub enum PolicySpec {
    Named { name: String },
    Yaml { yaml: String },
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self::Named {
            name: "default-protection".to_string(),
        }
    }
}

/// Request attributes that policy rules can match on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestContext {
    #[serde(default)]
    pub destination_provider: Option<String>,
    #[serde(default)]
    pub application: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

impl RequestContext {
    pub fn to_policy_context(&self) -> PolicyContext {
        PolicyContext {
            destination: self.destination_provider.clone(),
            application: self.application.clone(),
            environment: self.environment.clone(),
            purpose: self.purpose.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectRequest {
    pub segments: Vec<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub policy: PolicySpec,
    #[serde(default)]
    pub context: RequestContext,
    /// Overrides the policy's `on_failure` for this request. Closed when absent.
    #[serde(default)]
    pub enforcement: Option<Enforcement>,
    #[serde(default)]
    pub restore: bool,
    /// `rules`, `nano` or `hybrid`. The host's default, rules unless configured otherwise,
    /// when absent.
    #[serde(default)]
    pub profile: Option<veil_core::Profile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectRequest {
    pub segments: Vec<String>,
    #[serde(default)]
    pub country: Option<String>,
    #[serde(default)]
    pub context: RequestContext,
    /// `rules`, `nano` or `hybrid`. The host's default, rules unless configured otherwise,
    /// when absent.
    #[serde(default)]
    pub profile: Option<veil_core::Profile>,
}

/// One decision, joined with the strength of the finding behind it. Never the value.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecisionOut {
    pub entity_type: String,
    pub span: Span,
    pub offset_unit: &'static str,
    pub action: Action,
    pub rule: Option<RuleRef>,
    pub detector: String,
    pub validation: ValidationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<veil_core::EvidenceLevel>,
    pub confidence: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SegmentOut {
    pub output: Option<String>,
    pub decisions: Vec<DecisionOut>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyOut {
    pub name: Option<String>,
    pub revision: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Summary {
    pub findings: usize,
    pub by_entity: BTreeMap<String, usize>,
    pub by_action: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProtectResponse {
    pub blocked: bool,
    pub segments: Vec<SegmentOut>,
    pub policy: PolicyOut,
    pub summary: Summary,
    pub warnings: Vec<String>,
    pub profile_used: veil_core::Profile,
    /// Placeholder to original value. Only present when the caller asked for it and the
    /// host allows it, because it holds the personal information the call protected.
    pub restore: Option<BTreeMap<String, String>>,
}

/// A finding with the unit its offsets are in.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FindingOut {
    #[serde(flatten)]
    pub finding: Finding,
    pub offset_unit: &'static str,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetectSegment {
    pub findings: Vec<FindingOut>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DetectResponse {
    pub segments: Vec<DetectSegment>,
    pub profile_used: veil_core::Profile,
    pub warnings: Vec<String>,
}

/// Why a request couldn't be answered. Each maps onto one error code in the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    BadRequest(String),
    InputTooLarge {
        size: usize,
        limit: usize,
    },
    InvalidPolicy(Vec<veil_policy::Issue>),
    /// A scan couldn't complete and the enforcement mode doesn't allow the text through.
    ScanFailed(String),
    /// The request asked for a profile this host has no model for.
    ProfileUnavailable(veil_core::Profile),
    Internal(String),
}

impl ApiError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::InputTooLarge { .. } => "input_too_large",
            Self::InvalidPolicy(_) => "invalid_policy",
            Self::ScanFailed(_) => "scan_failed",
            Self::ProfileUnavailable(_) => "profile_unavailable",
            Self::Internal(_) => "internal",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::BadRequest(m) | Self::ScanFailed(m) | Self::Internal(m) => m.clone(),
            Self::InputTooLarge { size, limit } => {
                format!("the segments total {size} bytes, over the {limit} byte limit")
            }
            Self::InvalidPolicy(_) => "the policy is invalid".to_string(),
            Self::ProfileUnavailable(p) => {
                format!(
                    "the {} profile needs a model, and this host has none; use the rules profile or ask for enforcement rules_fallback",
                    profile_name(*p)
                )
            }
        }
    }

    /// The message with whatever detail the error carries, such as each problem in an
    /// invalid policy, for bindings that raise one error with one string.
    pub fn describe(&self) -> String {
        match self {
            Self::InvalidPolicy(issues) if !issues.is_empty() => {
                let detail: Vec<String> = issues
                    .iter()
                    .map(|i| format!("{}: {}", i.path, i.message))
                    .collect();
                format!("{}: {}", self.message(), detail.join("; "))
            }
            _ => self.message(),
        }
    }
}

/// A profile as requests spell it.
pub fn profile_name(p: veil_core::Profile) -> &'static str {
    match p {
        veil_core::Profile::Rules => "rules",
        veil_core::Profile::Nano => "nano",
        veil_core::Profile::Deep => "deep",
        veil_core::Profile::Hybrid => "hybrid",
    }
}

/// Checks the segment count and total size before any work is done.
pub fn check_segments(segments: &[String], max_input_bytes: usize) -> Result<(), ApiError> {
    if segments.is_empty() {
        return Err(ApiError::BadRequest(
            "segments must hold at least one string".into(),
        ));
    }
    if segments.len() > MAX_SEGMENTS {
        return Err(ApiError::BadRequest(format!(
            "segments holds {} strings, over the limit of {MAX_SEGMENTS}",
            segments.len()
        )));
    }
    let size: usize = segments.iter().map(String::len).sum();
    if size > max_input_bytes {
        return Err(ApiError::InputTooLarge {
            size,
            limit: max_input_bytes,
        });
    }
    Ok(())
}

/// Compiles a policy spec into a policy, reporting every problem with its path.
pub fn compile_policy(spec: &PolicySpec) -> Result<Policy, ApiError> {
    match spec {
        PolicySpec::Named { name } => Policy::builtin(name).ok_or_else(|| {
            ApiError::InvalidPolicy(vec![veil_policy::Issue {
                path: "policy.name".into(),
                message: format!("there is no built-in policy called {name:?}; use a built-in name or write the policy in YAML"),
            }])
        }),
        PolicySpec::Yaml { yaml } => Policy::from_yaml(yaml).map_err(|e| ApiError::InvalidPolicy(e.issues)),
    }
}

/// A built-in policy, for listings.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PolicyInfo {
    pub name: String,
    pub revision: String,
    pub description: String,
}

pub fn builtin_policies() -> Vec<PolicyInfo> {
    veil_policy::BUILTIN
        .iter()
        .filter_map(|(name, source)| {
            let policy = Policy::from_yaml(source).ok()?;
            Some(PolicyInfo {
                name: name.to_string(),
                revision: revision(&policy),
                description: Policy::describe(source),
            })
        })
        .collect()
}

/// A policy's revision, or its schema version when it names none.
pub fn revision(policy: &Policy) -> String {
    policy
        .revision
        .clone()
        .unwrap_or_else(|| format!("v{}", policy.version))
}

/// The result of validating a policy written in YAML.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Validation {
    pub valid: bool,
    pub errors: Vec<veil_policy::Issue>,
}

pub fn validate_policy(yaml: &str) -> Validation {
    match Policy::from_yaml(yaml) {
        Ok(_) => Validation {
            valid: true,
            errors: Vec::new(),
        },
        Err(e) => Validation {
            valid: false,
            errors: e.issues,
        },
    }
}

/// One entry of the entity taxonomy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntityInfo {
    pub code: String,
    pub family: String,
    pub categories: Vec<String>,
    pub sensitivity: String,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    pub description: String,
}

#[derive(Debug, Deserialize)]
struct TaxonomyFile {
    entity: Vec<EntityInfo>,
}

const TAXONOMY: &str = include_str!("../taxonomy.toml");

/// Every entity Veil can report, with its default categories and sensitivity.
pub fn entities() -> Vec<EntityInfo> {
    toml::from_str::<TaxonomyFile>(TAXONOMY)
        .map(|t| t.entity)
        .unwrap_or_default()
}

/// A country pack this build ships.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CountryInfo {
    pub code: String,
    pub name: String,
    pub version: String,
    pub taxonomy_version: String,
    pub entities: Vec<String>,
    pub languages: Vec<String>,
}

pub fn countries() -> Vec<CountryInfo> {
    let mut out = Vec::new();
    if let Ok(m) = veil_country_packs::gh::manifest() {
        out.push(CountryInfo {
            code: m.id.to_ascii_uppercase(),
            name: m.name,
            version: m.version,
            taxonomy_version: m.taxonomy_version,
            entities: m.entities,
            languages: m.languages,
        });
    }
    out
}

pub(crate) fn decision_out(d: &veil_policy::Decision, findings: &[Finding]) -> DecisionOut {
    let finding = findings
        .iter()
        .find(|f| f.span == d.span && f.entity_type == d.entity_type);
    DecisionOut {
        entity_type: d.entity_type.to_string(),
        span: d.span,
        offset_unit: "utf8_byte",
        action: d.action,
        rule: d.rule.clone(),
        detector: d.detector.clone(),
        validation: finding.map_or(ValidationState::Unverified, |f| f.validation),
        evidence: finding.and_then(|f| f.evidence),
        confidence: finding.map_or(0.0, |f| f.confidence),
    }
}

/// The unit a binding reports spans in. Veil works in UTF-8 bytes; a language binding can
/// switch its responses to the units its own strings are indexed by, so `text[start:end]`
/// in Python or `text.slice(start, end)` in JavaScript gives back the detected value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetUnit {
    Utf8Byte,
    /// Unicode scalar values, as Python indexes `str`.
    CodePoint,
    /// UTF-16 code units, as JavaScript indexes strings.
    Utf16,
}

impl OffsetUnit {
    pub fn name(self) -> &'static str {
        match self {
            Self::Utf8Byte => "utf8_byte",
            Self::CodePoint => "code_point",
            Self::Utf16 => "utf16",
        }
    }
}

/// Maps the byte offsets of one text onto another unit.
struct Index {
    // (byte offset, unit offset) at every character boundary, and at the end.
    marks: Vec<(usize, usize)>,
}

impl Index {
    fn of(text: &str, unit: OffsetUnit) -> Self {
        let mut marks = Vec::with_capacity(text.len() + 1);
        let mut at = 0;
        for (byte, c) in text.char_indices() {
            marks.push((byte, at));
            at += match unit {
                OffsetUnit::Utf8Byte => c.len_utf8(),
                OffsetUnit::CodePoint => 1,
                OffsetUnit::Utf16 => c.len_utf16(),
            };
        }
        marks.push((text.len(), at));
        Self { marks }
    }

    fn get(&self, byte: usize) -> usize {
        match self.marks.binary_search_by_key(&byte, |&(b, _)| b) {
            Ok(i) | Err(i) => self.marks.get(i).map_or(byte, |&(_, u)| u),
        }
    }
}

impl ProtectResponse {
    /// Reports every span in `unit`, counted against `segments`, the request's texts in order.
    pub fn reindex(&mut self, segments: &[String], unit: OffsetUnit) {
        if unit == OffsetUnit::Utf8Byte {
            return;
        }
        for (segment, text) in self.segments.iter_mut().zip(segments) {
            let index = Index::of(text, unit);
            for d in &mut segment.decisions {
                d.span.start = index.get(d.span.start);
                d.span.end = index.get(d.span.end);
                d.offset_unit = unit.name();
            }
        }
    }
}

impl DetectResponse {
    /// Reports every span in `unit`, counted against `segments`, the request's texts in order.
    pub fn reindex(&mut self, segments: &[String], unit: OffsetUnit) {
        if unit == OffsetUnit::Utf8Byte {
            return;
        }
        for (segment, text) in self.segments.iter_mut().zip(segments) {
            let index = Index::of(text, unit);
            for f in &mut segment.findings {
                f.finding.span.start = index.get(f.finding.span.start);
                f.finding.span.end = index.get(f.finding.span.end);
                f.offset_unit = unit.name();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Index, OffsetUnit};

    #[test]
    fn offsets_follow_each_languages_own_string_units() {
        // "ɛ" is 2 bytes and 1 code point; "🙂" is 4 bytes, 1 code point and 2 UTF-16 units.
        let text = "ɛ🙂Ama";
        let byte_of_ama = text.find("Ama").unwrap_or(0);
        assert_eq!(Index::of(text, OffsetUnit::CodePoint).get(byte_of_ama), 2);
        assert_eq!(Index::of(text, OffsetUnit::Utf16).get(byte_of_ama), 3);
        assert_eq!(Index::of(text, OffsetUnit::Utf16).get(text.len()), 6);
    }
}
