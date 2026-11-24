//! The policy language.
//!
//! A policy is YAML: a schema `version`, a `name`, a `default_action`, what to do when a
//! scan can't complete (`on_failure`), and `rules`. Each rule has a `match` and an
//! `action`. Every condition in a match must hold, and a list condition holds when any of
//! its values does.
//!
//! When several rules match a finding, precedence decides, never the order of the file.
//! A matching `block` rule always wins. Otherwise a rule naming entity types beats
//! a contextual rule (context labels, detectors, jurisdictions or request attributes),
//! which beats a category rule (categories, families, sensitivity, validation or
//! confidence). Within a tier the more specific rule wins: more conditions, then fewer
//! entity types. Only a complete tie falls back to the rule listed first. The default
//! action applies when nothing matches.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use veil_core::{Category, Family, Finding, Sensitivity, ValidationState, VeilError};

use crate::{apply, apply_shared, Action, Applied, Protected, TokenState};

/// The only schema version this build reads.
pub const SCHEMA_VERSION: u32 = 1;

/// Policies that ship with Veil, by name.
pub const BUILTIN: &[(&str, &str)] = &[(
    "default-protection",
    include_str!("../../../policies/default-protection.yaml"),
)];

/// What happens when a scan a policy depends on can't complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    /// Refuse the request. The safe default for anything leaving your systems.
    #[default]
    Closed,
    /// Let the original text through, with a warning saying it wasn't checked.
    Open,
    /// When a model profile is unavailable, continue with the rules alone and say so.
    /// Any other failure is treated as closed.
    RulesFallback,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "unnamed")]
    pub name: String,
    /// A free-form revision, such as a date, recorded with every decision.
    #[serde(default)]
    pub revision: Option<String>,
    #[serde(default = "default_action")]
    pub default_action: Action,
    #[serde(default)]
    pub on_failure: Enforcement,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

fn unnamed() -> String {
    "unnamed".to_string()
}

fn default_action() -> Action {
    Action::Detect
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "match")]
    pub conditions: Match,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default)]
    pub entity_types: Vec<String>,
    #[serde(default)]
    pub categories: Vec<Category>,
    #[serde(default)]
    pub families: Vec<Family>,
    #[serde(default)]
    pub min_sensitivity: Option<Sensitivity>,
    #[serde(default)]
    pub min_validation: Option<ValidationState>,
    #[serde(default)]
    pub min_confidence: Option<f32>,
    #[serde(default)]
    pub jurisdictions: Vec<String>,
    #[serde(default)]
    pub detectors: Vec<String>,
    #[serde(default)]
    pub context_labels: Vec<String>,
    #[serde(default)]
    pub destinations: Vec<String>,
    #[serde(default)]
    pub applications: Vec<String>,
    #[serde(default)]
    pub environments: Vec<String>,
    #[serde(default)]
    pub purposes: Vec<String>,
}

/// Facts about the request rather than the text, which rules can match on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Where the text is going, such as `anthropic` or `openai`.
    pub destination: Option<String>,
    pub application: Option<String>,
    pub environment: Option<String>,
    pub purpose: Option<String>,
}

/// Which rule decided, by its position in the policy and its id if it has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleRef {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// The policy that decided, recorded with its decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRef {
    pub name: String,
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

/// A problem in a policy, addressed by its path, such as `rules[2].match.min_confidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    pub issues: Vec<Issue>,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self
            .issues
            .iter()
            .map(|i| {
                if i.path.is_empty() {
                    i.message.clone()
                } else {
                    format!("{}: {}", i.path, i.message)
                }
            })
            .collect();
        write!(f, "the policy is invalid: {}", lines.join("; "))
    }
}

impl std::error::Error for PolicyError {}

/// The YAML library starts some messages with its own path (`rules[0].match: …`), which
/// the issue already carries, so drop it.
fn strip_location(message: &str) -> String {
    match message.split_once(": ") {
        Some((head, rest))
            if !head.is_empty()
                && head
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '[' | ']')) =>
        {
            rest.to_string()
        }
        _ => message.to_string(),
    }
}

impl Match {
    fn is_empty(&self) -> bool {
        self.condition_count() == 0
    }

    fn condition_count(&self) -> usize {
        [
            !self.entity_types.is_empty(),
            !self.categories.is_empty(),
            !self.families.is_empty(),
            self.min_sensitivity.is_some(),
            self.min_validation.is_some(),
            self.min_confidence.is_some(),
            !self.jurisdictions.is_empty(),
            !self.detectors.is_empty(),
            !self.context_labels.is_empty(),
            !self.destinations.is_empty(),
            !self.applications.is_empty(),
            !self.environments.is_empty(),
            !self.purposes.is_empty(),
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    fn is_contextual(&self) -> bool {
        !(self.jurisdictions.is_empty()
            && self.detectors.is_empty()
            && self.context_labels.is_empty()
            && self.destinations.is_empty()
            && self.applications.is_empty()
            && self.environments.is_empty()
            && self.purposes.is_empty())
    }

    pub fn matches(&self, f: &Finding, ctx: &PolicyContext) -> bool {
        let any = |list: &[String], value: Option<&str>| {
            list.is_empty() || value.is_some_and(|v| list.iter().any(|x| x.eq_ignore_ascii_case(v)))
        };
        (self.entity_types.is_empty()
            || self
                .entity_types
                .iter()
                .any(|e| e == f.entity_type.as_str()))
            && (self.categories.is_empty()
                || self.categories.iter().any(|c| f.categories.contains(c)))
            && (self.families.is_empty() || self.families.contains(&f.family))
            && self.min_sensitivity.is_none_or(|s| f.sensitivity >= s)
            && self
                .min_validation
                .is_none_or(|v| f.validation.strength() >= v.strength())
            && self.min_confidence.is_none_or(|c| f.confidence >= c)
            && any(
                &self.jurisdictions,
                f.jurisdiction.as_ref().map(|j| j.as_str()),
            )
            && (self.detectors.is_empty() || self.detectors.iter().any(|d| d == &f.detector))
            && (self.context_labels.is_empty()
                || self
                    .context_labels
                    .iter()
                    .any(|l| f.context_labels.contains(l)))
            && any(&self.destinations, ctx.destination.as_deref())
            && any(&self.applications, ctx.application.as_deref())
            && any(&self.environments, ctx.environment.as_deref())
            && any(&self.purposes, ctx.purpose.as_deref())
    }
}

impl Rule {
    /// The precedence tier: 0 block, 1 entity, 2 contextual, 3 category.
    fn tier(&self) -> u8 {
        if self.action == Action::Block {
            0
        } else if !self.conditions.entity_types.is_empty() {
            1
        } else if self.conditions.is_contextual() {
            2
        } else {
            3
        }
    }

    /// Lower sorts first: tier, then more conditions, then fewer entity types.
    fn precedence(&self) -> (u8, std::cmp::Reverse<usize>, usize) {
        let entities = if self.conditions.entity_types.is_empty() {
            usize::MAX
        } else {
            self.conditions.entity_types.len()
        };
        (
            self.tier(),
            std::cmp::Reverse(self.conditions.condition_count()),
            entities,
        )
    }
}

impl Policy {
    /// Parses and validates a policy. Every problem is reported with its path.
    pub fn from_yaml(source: &str) -> Result<Self, PolicyError> {
        let de = serde_yaml_ng::Deserializer::from_str(source);
        let policy: Policy = serde_path_to_error::deserialize(de).map_err(|e| {
            let path = e.path().to_string();
            let path = if path == "." { String::new() } else { path };
            PolicyError {
                issues: vec![Issue {
                    path,
                    message: strip_location(&e.into_inner().to_string()),
                }],
            }
        })?;
        policy.validate()?;
        Ok(policy)
    }

    /// A policy that ships with Veil, such as `default-protection`.
    pub fn builtin(name: &str) -> Option<Self> {
        BUILTIN
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, src)| Self::from_yaml(src).ok())
    }

    /// One action for everything, for simple command-line use.
    pub fn uniform(action: Action) -> Self {
        Self {
            version: SCHEMA_VERSION,
            name: format!("uniform-{action}"),
            revision: None,
            default_action: action,
            on_failure: Enforcement::Closed,
            rules: Vec::new(),
        }
    }

    pub fn reference(&self) -> PolicyRef {
        PolicyRef {
            name: self.name.clone(),
            version: self.version,
            revision: self.revision.clone(),
        }
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let mut issues = Vec::new();
        if self.version != SCHEMA_VERSION {
            issues.push(Issue {
                path: "version".into(),
                message: format!("must be {SCHEMA_VERSION}, the schema this build reads"),
            });
        }
        if self.name.trim().is_empty() {
            issues.push(Issue {
                path: "name".into(),
                message: "can't be empty".into(),
            });
        }
        let mut ids = HashSet::new();
        for (i, rule) in self.rules.iter().enumerate() {
            let at = |field: &str| format!("rules[{i}].{field}");
            if let Some(id) = &rule.id {
                if !ids.insert(id.as_str()) {
                    issues.push(Issue {
                        path: at("id"),
                        message: format!("{id:?} is used by an earlier rule"),
                    });
                }
            }
            let m = &rule.conditions;
            if m.is_empty() {
                issues.push(Issue {
                    path: at("match"),
                    message: "needs at least one condition; use default_action for everything else"
                        .into(),
                });
            }
            if let Some(c) = m.min_confidence {
                if !(0.0..=1.0).contains(&c) || c.is_nan() {
                    issues.push(Issue {
                        path: at("match.min_confidence"),
                        message: "must be between 0 and 1".into(),
                    });
                }
            }
            for (j, e) in m.entity_types.iter().enumerate() {
                let ok = e.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && e.chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                if !ok {
                    issues.push(Issue {
                        path: format!("rules[{i}].match.entity_types[{j}]"),
                        message: format!("{e:?} isn't an entity code such as GH_MOBILE_NUMBER"),
                    });
                }
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(PolicyError { issues })
        }
    }

    /// The action for one finding and the rule that chose it.
    pub fn decide(&self, finding: &Finding, ctx: &PolicyContext) -> (Action, Option<RuleRef>) {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.conditions.matches(finding, ctx))
            .min_by_key(|(i, r)| (r.precedence(), *i))
            .map_or((self.default_action, None), |(i, r)| {
                (
                    r.action,
                    Some(RuleRef {
                        index: i,
                        id: r.id.clone(),
                    }),
                )
            })
    }

    /// Decides every finding and applies the decisions to `text`.
    pub fn protect(
        &self,
        text: &str,
        findings: &[Finding],
        ctx: &PolicyContext,
    ) -> Result<Applied, VeilError> {
        let mut applied = apply(text, findings, |f| self.decide(f, ctx))?;
        applied.protected.policy = Some(self.reference());
        Ok(applied)
    }

    /// [`Policy::protect`] for one of several texts in a request, numbering tokenised
    /// values in the shared `tokens`.
    pub fn protect_shared(
        &self,
        text: &str,
        findings: &[Finding],
        ctx: &PolicyContext,
        tokens: &mut TokenState,
    ) -> Result<Protected, VeilError> {
        let mut protected = apply_shared(text, findings, |f| self.decide(f, ctx), tokens)?;
        protected.policy = Some(self.reference());
        Ok(protected)
    }

    /// The description written in the policy's leading comment lines, if any.
    pub fn describe(source: &str) -> String {
        source
            .lines()
            .take_while(|l| l.trim_start().starts_with('#') || l.trim().is_empty())
            .filter_map(|l| l.trim_start().strip_prefix('#'))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_string()
    }
}
