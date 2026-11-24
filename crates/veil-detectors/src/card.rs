use regex::Regex;
use veil_core::{
    Category, DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo,
    EntityType, Finding, Sensitivity, Span, ValidationState,
};

use crate::{boundary, pattern};

/// Payment card numbers: 13 to 19 digits, optionally grouped with spaces or hyphens, that
/// pass the Luhn check and start with a known card-network prefix. Both checks are needed,
/// because one in ten random digit strings passes Luhn alone.
#[derive(Debug)]
pub struct PaymentCardDetector {
    re: Regex,
}

impl PaymentCardDetector {
    pub fn new() -> Self {
        Self {
            re: pattern(r"\d(?:[ -]?\d){12,18}"),
        }
    }
}

impl Default for PaymentCardDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// The Luhn (mod 10) checksum over ASCII digits.
pub fn luhn(digits: &[u8]) -> bool {
    let mut sum = 0u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let mut v = u32::from(d - b'0');
        if i % 2 == 1 {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

fn prefix(digits: &[u8], n: usize) -> u32 {
    digits
        .iter()
        .take(n)
        .fold(0, |acc, d| acc * 10 + u32::from(d - b'0'))
}

/// Whether the number starts with a prefix and length used by a major card network.
pub fn known_network(digits: &[u8]) -> bool {
    let len = digits.len();
    let p1 = prefix(digits, 1);
    let p2 = prefix(digits, 2);
    let p3 = prefix(digits, 3);
    let p4 = prefix(digits, 4);
    let p6 = prefix(digits, 6);
    let visa = p1 == 4 && matches!(len, 13 | 16 | 19);
    let mastercard = ((51..=55).contains(&p2) || (2221..=2720).contains(&p4)) && len == 16;
    let amex = (p2 == 34 || p2 == 37) && len == 15;
    let discover =
        (p4 == 6011 || p2 == 65 || (644..=649).contains(&p3)) && (16..=19).contains(&len);
    let jcb = (3528..=3589).contains(&p4) && (16..=19).contains(&len);
    let unionpay = p2 == 62 && (16..=19).contains(&len);
    let diners = (p2 == 36 || p2 == 38 || (300..=305).contains(&p3)) && (14..=19).contains(&len);
    // Verve, common in West Africa.
    let verve = ((506_099..=506_198).contains(&p6)
        || (650_002..=650_027).contains(&p6)
        || (507_865..=507_964).contains(&p6))
        && (16..=19).contains(&len);
    visa || mastercard || amex || discover || jcb || unionpay || diners || verve
}

impl Detector for PaymentCardDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "payment-card-v1",
            description: "Payment card numbers that pass the Luhn check",
            entity_types: vec![EntityType::PAYMENT_CARD_PAN],
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
        for m in self.re.find_iter(text) {
            let (start, end) = (m.start(), m.end());
            if !boundary::isolated(text, start, end) {
                continue;
            }
            let digits: Vec<u8> = m.as_str().bytes().filter(u8::is_ascii_digit).collect();
            if !luhn(&digits) || !known_network(&digits) {
                continue;
            }
            let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
            out.push(
                Finding::new(EntityType::PAYMENT_CARD_PAN, span, "payment-card-v1")
                    .category(Category::FinancialInformation)
                    .category(Category::PersonalIdentifier)
                    .sensitivity(Sensitivity::HighlySensitive)
                    .validation(ValidationState::Valid)
                    .confidence(0.96),
            );
        }
        Ok(out)
    }
}
