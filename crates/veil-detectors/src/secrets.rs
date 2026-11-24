//! Secrets: credentials that grant access, such as private keys and API tokens. They
//! form their own family, apart from personal information, and the default
//! policy blocks them.

use regex::Regex;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Family, Finding, Sensitivity, Span, ValidationState,
};

use crate::{boundary, pattern};

pub const PRIVATE_KEY: EntityType = EntityType::new("PRIVATE_KEY");
pub const JWT: EntityType = EntityType::new("JWT");
pub const AWS_ACCESS_KEY_ID: EntityType = EntityType::new("AWS_ACCESS_KEY_ID");
pub const GITHUB_TOKEN: EntityType = EntityType::new("GITHUB_TOKEN");
pub const STRIPE_SECRET_KEY: EntityType = EntityType::new("STRIPE_SECRET_KEY");
pub const SLACK_TOKEN: EntityType = EntityType::new("SLACK_TOKEN");
pub const SLACK_WEBHOOK_URL: EntityType = EntityType::new("SLACK_WEBHOOK_URL");
pub const SECRET: EntityType = EntityType::new("SECRET");

/// How far after a private key header to look for its end line.
const KEY_BLOCK_LIMIT: usize = 16 * 1024;

#[derive(Debug)]
pub struct SecretDetector {
    key_header: Regex,
    /// Each token pattern with literals, one of which must appear in the text for the
    /// pattern to be worth running, so text without them costs only a substring search.
    tokens: Vec<(EntityType, Regex, ValidationState, &'static [&'static str])>,
    jwt: Regex,
    assignment: Regex,
}

impl SecretDetector {
    pub fn new() -> Self {
        let valid = ValidationState::ValidFormat;
        Self {
            key_header: pattern(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
            tokens: vec![
                (
                    AWS_ACCESS_KEY_ID,
                    pattern(r"(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z2-7]{16}"),
                    valid,
                    &[
                        "AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA",
                        "AIPA",
                    ],
                ),
                (
                    GITHUB_TOKEN,
                    pattern(
                        r"gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}",
                    ),
                    valid,
                    &["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"],
                ),
                (
                    STRIPE_SECRET_KEY,
                    pattern(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247}"),
                    valid,
                    &["k_live_", "k_test_"],
                ),
                (
                    SLACK_WEBHOOK_URL,
                    pattern(
                        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,12}/B[A-Z0-9]{6,12}/[A-Za-z0-9]{16,32}",
                    ),
                    valid,
                    &["hooks.slack.com"],
                ),
                (
                    SLACK_TOKEN,
                    pattern(r"xox[abposr]-[A-Za-z0-9]{8,}(?:-[A-Za-z0-9]{4,})+"),
                    valid,
                    &["xox"],
                ),
            ],
            jwt: pattern(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
            // ASCII-only case folding for the keys keeps the regex engine's literal
            // prefilters working; Unicode folding would also accept the Kelvin sign as K.
            assignment: pattern(
                r#"(?i-u:password|passwd|pwd|pass|secret|client_secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key)["']?[ \t]{0,3}[:=][ \t]{0,3}["']?[^\s"'&,;<>{}()\[\]]{4,200}"#,
            ),
        }
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn secret(
    entity: EntityType,
    start: usize,
    end: usize,
    validation: ValidationState,
    confidence: f32,
    detector: &str,
) -> Result<Finding, DetectionError> {
    let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
    Ok(Finding::new(entity, span, detector)
        .family(Family::Secret)
        .category(Category::Credential)
        .sensitivity(Sensitivity::HighlySensitive)
        .validation(validation)
        .confidence(confidence))
}

/// Decodes unpadded base64url, enough to read a JWT header. Returns none on bad input.
fn base64url(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// A value that's obviously a placeholder rather than a secret.
fn placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let first = value.chars().next();
    let same = value.chars().all(|c| Some(c) == first);
    same || value.starts_with(['$', '%', '<', '{', '[', '*'])
        || [
            "your",
            "example",
            "redacted",
            "placeholder",
            "xxxx",
            "dummy",
            "sample",
        ]
        .iter()
        .any(|w| lower.contains(w))
        || [
            "null",
            "none",
            "true",
            "false",
            "undefined",
            "required",
            "optional",
            "string",
        ]
        .contains(&lower.as_str())
}

impl Detector for SecretDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "secrets-v1",
            description:
                "Private keys, JWTs, cloud and SaaS tokens, and password or key assignments",
            entity_types: vec![
                PRIVATE_KEY,
                JWT,
                AWS_ACCESS_KEY_ID,
                GITHUB_TOKEN,
                STRIPE_SECRET_KEY,
                SLACK_TOKEN,
                SLACK_WEBHOOK_URL,
                SECRET,
            ],
            jurisdiction: None,
            method: DetectionMethod::PatternAndValidation,
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::new();
        if text.contains("PRIVATE KEY-----") {
            for m in self.key_header.find_iter(text) {
                let window_end = (m.end() + KEY_BLOCK_LIMIT).min(text.len());
                let after = text
                    .get(m.end()..window_end)
                    .or_else(|| text.get(m.end()..))
                    .unwrap_or_default();
                let end = after
                    .find("-----END ")
                    .and_then(|i| {
                        after.get(i..).and_then(|rest| {
                            rest.find("PRIVATE KEY-----")
                                .map(|j| m.end() + i + j + "PRIVATE KEY-----".len())
                        })
                    })
                    .unwrap_or(m.end());
                out.push(secret(
                    PRIVATE_KEY,
                    m.start(),
                    end,
                    ValidationState::Valid,
                    0.99,
                    "secrets-v1",
                )?);
            }
        }
        for (entity, re, validation, literals) in &self.tokens {
            if !literals.iter().any(|l| text.contains(l)) {
                continue;
            }
            for m in re.find_iter(text) {
                if !boundary::isolated(text, m.start(), m.end()) && entity != &SLACK_WEBHOOK_URL {
                    continue;
                }
                out.push(secret(
                    entity.clone(),
                    m.start(),
                    m.end(),
                    *validation,
                    0.97,
                    "secrets-v1",
                )?);
            }
        }
        if text.contains("eyJ") {
            for m in self.jwt.find_iter(text) {
                let header = m.as_str().split('.').next().unwrap_or_default();
                let decoded = base64url(header)
                    .and_then(|b| String::from_utf8(b).ok())
                    .unwrap_or_default();
                if decoded.contains("\"alg\"") && boundary::isolated(text, m.start(), m.end()) {
                    out.push(secret(
                        JWT,
                        m.start(),
                        m.end(),
                        ValidationState::Valid,
                        0.97,
                        "secrets-v1",
                    )?);
                }
            }
        }
        for m in self.assignment.find_iter(text) {
            // The key runs up to the first quote, space, colon or equals sign, and the value
            // starts after the separator and any opening quote.
            let found = m.as_str();
            let key_len = found
                .find(['"', '\'', ' ', '\t', ':', '='])
                .unwrap_or(found.len());
            let after_key = found.get(key_len..).unwrap_or_default();
            let value_offset = key_len
                + after_key
                    .find(|c: char| !matches!(c, '"' | '\'' | ' ' | '\t' | ':' | '='))
                    .unwrap_or(after_key.len());
            let (key, value) = (
                found.get(..key_len).unwrap_or_default(),
                found.get(value_offset..).unwrap_or_default(),
            );
            if value.is_empty()
                || boundary::before(text, m.start()).is_some_and(char::is_alphanumeric)
                || placeholder(value)
            {
                continue;
            }
            let start = m.start() + value_offset;
            out.push(
                secret(
                    SECRET,
                    start,
                    m.end(),
                    ValidationState::Unverified,
                    0.8,
                    "secrets-v1",
                )?
                .label(format!("ASSIGNED_TO:{}", key.to_ascii_lowercase())),
            );
        }
        Ok(out)
    }
}
