use regex::Regex;
use serde::Deserialize;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use super::{parse, JURISDICTION, NUMBERING};
use crate::context::{isolated, mentions, window};
use crate::{pattern, PackError};

#[derive(Debug, Deserialize)]
struct Numbering {
    country_code: String,
    nsn_length: usize,
    mobile_pattern: String,
    fixed_line_pattern: String,
    /// Words that mark a fixed line as an organisation's (see `numbering.toml`).
    #[serde(default)]
    public_context: Vec<String>,
    /// Words that tie a fixed line to a person; they win over `public_context`.
    #[serde(default)]
    owner_context: Vec<String>,
}

/// Words that suggest a mobile number is being used as a mobile money wallet.
const MOMO_WORDS: &[&str] = &[
    "momo",
    "mobile money",
    "mtn money",
    "telecel cash",
    "vodafone cash",
    "at money",
    "airteltigo money",
    "e-cash",
    "ecash",
    "wallet",
    "send money",
    "send the money",
    "transfer",
    "pay ",
    "payment",
    "merchant",
];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum Kind {
    Mobile,
    Landline,
}

/// Ghanaian mobile and fixed-line numbers, written nationally (`024 123 4567`) or with the
/// country code (`+233 24 123 4567`, `00233…`, `+233 (0)24…`).
#[derive(Debug)]
pub struct PhoneDetector {
    re: Regex,
    country_code: String,
    nsn_length: usize,
    mobile: Regex,
    fixed_line: Regex,
    momo: Vec<String>,
    /// Another country's calling code just before a national-looking number, as in `+1 024…`.
    foreign_code: Regex,
    public: Vec<String>,
    owner: Vec<String>,
}

impl PhoneDetector {
    pub fn new() -> Result<Self, PackError> {
        let n: Numbering = parse("gh/numbering.toml", NUMBERING)?;
        let mobile = pattern(&format!("^(?:{})$", n.mobile_pattern));
        let fixed_line = pattern(&format!("^(?:{})$", n.fixed_line_pattern));
        let sep = r"[ .\-]?";
        let re = pattern(&format!(
            r"(?:\+|00)233{sep}(?:\(0\){sep})?\d{{2,3}}{sep}\d{{3}}{sep}\d{{3,4}}|\b233\d{{9}}|\(?0\d{{2,3}}\)?{sep}\d{{3}}{sep}\d{{3,4}}"
        ));
        Ok(Self {
            re,
            country_code: n.country_code,
            nsn_length: n.nsn_length,
            mobile,
            fixed_line,
            momo: MOMO_WORDS.iter().map(|s| s.to_string()).collect(),
            foreign_code: pattern(r"\+\d{1,3}[ \-]?$"),
            public: n.public_context,
            owner: n.owner_context,
        })
    }

    /// The national significant number, if the digits form one.
    pub(super) fn nsn(&self, raw: &str) -> Option<String> {
        let digits: String = raw.chars().filter(char::is_ascii_digit).collect();
        let cc = &self.country_code;
        let rest = if let Some(r) = digits.strip_prefix(&format!("00{cc}")) {
            r.to_string()
        } else if let Some(r) = digits.strip_prefix(cc.as_str()).filter(|_| {
            raw.trim_start().starts_with('+')
                || digits.len() == cc.len() + self.nsn_length
                || digits.len() == cc.len() + self.nsn_length + 1
        }) {
            r.to_string()
        } else {
            digits.strip_prefix('0')?.to_string()
        };
        // "+233 (0)24…" keeps a trunk zero after the country code.
        let rest = if rest.len() == self.nsn_length + 1 {
            rest.strip_prefix('0')?.to_string()
        } else {
            rest
        };
        (rest.len() == self.nsn_length).then_some(rest)
    }

    /// Whether a fixed line at `start..end` belongs to an organisation: its sentence names an
    /// organisation or a public line and nothing ties it to a person.
    pub(super) fn is_public_line(&self, text: &str, start: usize, end: usize) -> bool {
        let around = window(text, start, end, 80);
        mentions(&around, &self.public) && !mentions(&around, &self.owner)
    }

    /// The finding for a number of `kind` at `span`, labelled as a mobile money wallet when the
    /// words around a mobile number say so.
    pub(super) fn finding(
        &self,
        text: &str,
        span: Span,
        kind: Kind,
        detector: &'static str,
    ) -> Finding {
        let entity = if kind == Kind::Mobile {
            EntityType::GH_MOBILE_NUMBER
        } else {
            EntityType::GH_LANDLINE_NUMBER
        };
        let mut f = Finding::new(entity, span, detector)
            .category(Category::PersonalIdentifier)
            .sensitivity(Sensitivity::Personal)
            .jurisdiction(JURISDICTION)
            .validation(ValidationState::ValidFormat)
            .confidence(if kind == Kind::Mobile { 0.95 } else { 0.85 });
        if kind == Kind::Mobile && mentions(&window(text, span.start, span.end, 60), &self.momo) {
            f = f
                .label("MOBILE_MONEY")
                .category(Category::FinancialInformation);
        }
        f
    }

    pub(super) fn classify(&self, nsn: &str) -> Option<Kind> {
        if self.mobile.is_match(nsn) {
            Some(Kind::Mobile)
        } else if self.fixed_line.is_match(nsn) {
            Some(Kind::Landline)
        } else {
            None
        }
    }
}

/// The last `n` bytes before `end`, widened to a character boundary. Look-behind checks
/// must stay this local, or each match would rescan the whole text before it.
fn tail(text: &str, end: usize, n: usize) -> &str {
    let mut from = end.saturating_sub(n);
    while from > 0 && !text.is_char_boundary(from) {
        from -= 1;
    }
    text.get(from..end).unwrap_or_default()
}

impl Detector for PhoneDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "gh-phone-v1",
            description: "Ghanaian mobile and fixed-line numbers, checked against libphonenumber's Ghana metadata",
            entity_types: vec![EntityType::GH_MOBILE_NUMBER, EntityType::GH_LANDLINE_NUMBER],
            jurisdiction: Some(JURISDICTION),
            method: DetectionMethod::PatternAndValidation,
        }
    }

    fn detect(
        &self,
        text: &str,
        _context: &DetectionContext,
    ) -> Result<Vec<Finding>, DetectionError> {
        let mut out = Vec::new();
        for m in self.re.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            let lead = text.get(..start).and_then(|s| s.chars().next_back());
            if !isolated(text, start, end)
                || lead == Some('+')
                || self.foreign_code.is_match(tail(text, start, 8))
            {
                continue;
            }
            let Some(nsn) = self.nsn(m.as_str()) else {
                continue;
            };
            let Some(kind) = self.classify(&nsn) else {
                continue;
            };
            if kind == Kind::Landline && self.is_public_line(text, start, end) {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(self.finding(text, span, kind, "gh-phone-v1"));
        }
        Ok(out)
    }
}
