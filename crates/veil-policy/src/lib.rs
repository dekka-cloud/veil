//! What happens to each finding, and the transformation that applies it.
//!
//! Detection and policy stay separate: a finding is evidence, and a
//! [`Policy`] decides what to do with it. [`apply`] carries out the decisions on the text,
//! copying everything outside the findings unchanged.

mod mask;
pub mod policy;
mod restore;

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use veil_core::{EntityType, Finding, Span, VeilError};

pub use policy::{
    Enforcement, Issue, Match, Policy, PolicyContext, PolicyError, PolicyRef, Rule, RuleRef,
    BUILTIN,
};
pub use restore::RestoreMap;

/// Placeholder numbering shared by several texts in one request, so the same value gets
/// the same placeholder in every text, along with the restore map for all of them.
#[derive(Debug, Default)]
pub struct TokenState {
    numbers: HashMap<String, (usize, HashMap<String, usize>)>,
    restore: RestoreMap,
}

impl TokenState {
    pub fn restore_map(&self) -> &RestoreMap {
        &self.restore
    }

    pub fn into_restore_map(self) -> RestoreMap {
        self.restore
    }

    fn placeholder(&mut self, entity: &str, value: &str) -> String {
        let (next, seen) = self.numbers.entry(entity.to_string()).or_default();
        let n = match seen.get(value) {
            Some(n) => *n,
            None => {
                *next += 1;
                seen.insert(value.to_string(), *next);
                *next
            }
        };
        let placeholder = format!("[{entity}_{n}]");
        self.restore.insert(&placeholder, value);
        placeholder
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    /// Report the finding and leave the text alone.
    Detect,
    Allow,
    /// Keep part of the value, such as `024 *** 4567`.
    Mask,
    /// Replace the value with a typed placeholder, such as `[GH_MOBILE_NUMBER]`.
    Redact,
    /// Replace the value with a numbered placeholder, such as `[GH_MOBILE_NUMBER_1]`. The
    /// same value gets the same number within one request, and the caller can restore it.
    Tokenize,
    /// Refuse the whole input.
    Block,
}

impl Action {
    pub const ALL: [Action; 6] = [
        Action::Detect,
        Action::Allow,
        Action::Mask,
        Action::Redact,
        Action::Tokenize,
        Action::Block,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::Allow => "allow",
            Self::Mask => "mask",
            Self::Redact => "redact",
            Self::Tokenize => "tokenize",
            Self::Block => "block",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str().eq_ignore_ascii_case(s.trim()))
            .ok_or_else(|| {
                format!("unknown action {s:?}; use detect, allow, mask, redact, tokenize or block")
            })
    }
}

/// Actions are written in any case in policies, such as `block` or `BLOCK`.
impl<'de> Deserialize<'de> for Action {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A policy applying one action to every finding, for simple command-line use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UniformPolicy(pub Action);

impl UniformPolicy {
    pub fn decide(&self, _finding: &Finding) -> Action {
        self.0
    }
}

/// One applied decision, without the value it applied to.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Decision {
    pub entity_type: EntityType,
    pub span: Span,
    pub action: Action,
    pub detector: String,
    /// The policy rule that decided, or none when the default action applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleRef>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Protected {
    /// The transformed text, or none when the input was blocked.
    pub output: Option<String>,
    pub blocked: bool,
    pub decisions: Vec<Decision>,
    /// The policy that decided, for audit records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// The result of [`apply`]: the protected output, and the map that restores tokenised
/// values. The map holds the original values, so it is never serialised and should live
/// only as long as the request that made it.
#[derive(Debug)]
pub struct Applied {
    pub protected: Protected,
    pub restore: RestoreMap,
}

/// Applies a decision to each finding. Findings must not overlap, which
/// [`veil_core::engine::resolve`] guarantees; overlapping input is refused rather than
/// guessed at. Text outside the findings is copied unchanged.
pub fn apply(
    text: &str,
    findings: &[Finding],
    decide: impl Fn(&Finding) -> (Action, Option<RuleRef>),
) -> Result<Applied, VeilError> {
    let mut tokens = TokenState::default();
    let protected = apply_shared(text, findings, decide, &mut tokens)?;
    Ok(Applied {
        protected,
        restore: tokens.into_restore_map(),
    })
}

/// [`apply`] for one of several texts in a request: tokenised values are numbered in
/// `tokens`, so numbering carries across texts. Blocked texts add nothing to the map.
pub fn apply_shared(
    text: &str,
    findings: &[Finding],
    decide: impl Fn(&Finding) -> (Action, Option<RuleRef>),
    tokens: &mut TokenState,
) -> Result<Protected, VeilError> {
    let mut ordered: Vec<&Finding> = findings.iter().collect();
    ordered.sort_by_key(|f| f.span);
    let mut decisions = Vec::with_capacity(ordered.len());
    let mut previous_end = 0;
    for f in &ordered {
        f.span.validate(text)?;
        if f.span.start < previous_end {
            return Err(VeilError::InvalidSpan {
                start: f.span.start,
                end: f.span.end,
                reason: "overlaps another finding",
            });
        }
        previous_end = f.span.end;
        let (action, rule) = decide(f);
        decisions.push(Decision {
            entity_type: f.entity_type.clone(),
            span: f.span,
            action,
            detector: f.detector.clone(),
            rule,
        });
    }
    if decisions.iter().any(|d| d.action == Action::Block) {
        return Ok(Protected {
            output: None,
            blocked: true,
            decisions,
            policy: None,
            warnings: Vec::new(),
        });
    }
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    for d in &decisions {
        let value = d.span.slice(text)?;
        out.push_str(Span::new(cursor, d.span.start)?.slice(text)?);
        match d.action {
            Action::Detect | Action::Allow => out.push_str(value),
            Action::Redact => {
                out.push('[');
                out.push_str(d.entity_type.as_str());
                out.push(']');
            }
            Action::Mask => out.push_str(&mask::mask(&d.entity_type, value)),
            Action::Tokenize => out.push_str(&tokens.placeholder(d.entity_type.as_str(), value)),
            Action::Block => {}
        }
        cursor = d.span.end;
    }
    out.push_str(Span::new(cursor, text.len())?.slice(text)?);
    Ok(Protected {
        output: Some(out),
        blocked: false,
        decisions,
        policy: None,
        warnings: Vec::new(),
    })
}

/// [`apply`] with a plain action per finding, discarding the restore map.
pub fn protect(
    text: &str,
    findings: &[Finding],
    decide: impl Fn(&Finding) -> Action,
) -> Result<Protected, VeilError> {
    apply(text, findings, |f| (decide(f), None)).map(|a| a.protected)
}
