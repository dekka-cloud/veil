use regex::Regex;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Family, Finding, Sensitivity, Span, ValidationState,
};

use crate::pattern;

/// Query parameters whose names say they carry credentials.
const CREDENTIAL_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "pass",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "session_id",
    "sid",
    "sig",
    "signature",
    "code",
];

/// Query parameters whose names say they carry personal details.
const PERSONAL_PARAMS: &[&str] = &[
    "phone",
    "msisdn",
    "mobile",
    "tel",
    "telephone",
    "email",
    "mail",
    "e-mail",
    "card",
    "pan",
    "pin",
    "ghanacard",
    "ghana_card",
    "nid",
    "national_id",
    "ssn",
    "ssnit",
    "tin",
    "account",
    "acct",
    "account_number",
    "dob",
    "birthdate",
    "name",
    "first_name",
    "firstname",
    "last_name",
    "lastname",
    "surname",
    "fullname",
    "full_name",
    "address",
    "gps",
    "digital_address",
];

/// Values of URL query parameters that carry credentials or personal details, such as
/// `?phone=0241234567` or `&access_token=…`. The parameter value is reported, not the
/// whole URL. Other detectors that recognise the value itself report it with a stronger
/// validation, which wins when they overlap.
#[derive(Debug)]
pub struct UrlParameterDetector {
    re: Regex,
}

impl UrlParameterDetector {
    pub const CREDENTIAL: EntityType = EntityType::new("URL_CREDENTIAL");
    pub const PERSONAL: EntityType = EntityType::new("URL_PERSONAL_DATA");

    pub fn new() -> Self {
        Self {
            re: pattern(r#"https?://[^\s<>"'`]+"#),
        }
    }
}

impl Default for UrlParameterDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Detector for UrlParameterDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "url-parameter-v1",
            description: "URL query parameters that carry credentials or personal details",
            entity_types: vec![Self::CREDENTIAL, Self::PERSONAL],
            jurisdiction: None,
            method: DetectionMethod::Contextual,
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let url = m
                .as_str()
                .trim_end_matches(['.', ',', ')', ']', ';', '!', '?']);
            let Some(q) = url.find('?') else { continue };
            let query_start = m.start() + q + 1;
            let query = url.get(q + 1..).unwrap_or_default();
            let query = query.split('#').next().unwrap_or_default();
            let mut offset = query_start;
            for pair in query.split(['&', ';']) {
                let here = offset;
                offset += pair.len() + 1;
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };
                if value.is_empty() {
                    continue;
                }
                let lower = name.to_ascii_lowercase();
                let (entity, category, family, sensitivity) =
                    if CREDENTIAL_PARAMS.contains(&lower.as_str()) {
                        (
                            Self::CREDENTIAL,
                            Category::Credential,
                            Family::Secret,
                            Sensitivity::HighlySensitive,
                        )
                    } else if PERSONAL_PARAMS.contains(&lower.as_str()) {
                        (
                            Self::PERSONAL,
                            Category::PersonalIdentifier,
                            Family::Pii,
                            Sensitivity::Personal,
                        )
                    } else {
                        continue;
                    };
                let start = here + name.len() + 1;
                let span = Span::new(start, start + value.len())
                    .map_err(|e| DetectionError::new(e.to_string()))?;
                out.push(
                    Finding::new(entity, span, "url-parameter-v1")
                        .family(family)
                        .category(category)
                        .sensitivity(sensitivity)
                        .validation(ValidationState::Unverified)
                        .confidence(0.7)
                        .label(format!("URL_PARAMETER:{lower}")),
                );
            }
        }
        Ok(out)
    }
}
