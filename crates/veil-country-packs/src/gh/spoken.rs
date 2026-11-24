//! Phone numbers read aloud, as speech transcripts write them: "zero two four, one two three,
//! four five six seven", "oh five five double four…", or the same in Twi, Fante, Ewe or Ga. The
//! digit words come from `country-packs/gh/spoken-digits.toml`, which names a source for each
//! language. Digit groups may mix with words ("024 one two three…").
//!
//! A run of digit words counts only when it ends in exactly a Ghanaian number, ten digits with
//! the trunk 0 or twelve starting with the country code, that the numbering plan accepts as a
//! mobile or fixed line, and when at least two of its tokens are words. That rules out ordinary
//! sentences that happen to use a number word, and leaves numbers written in figures alone to
//! gh-phone-v1.

use std::collections::HashMap;

use serde::Deserialize;
use veil_core::{
    DetectionContext, DetectionError, DetectionMethod, Detector, DetectorInfo, EntityType, Finding,
    Span,
};

use super::phone::{Kind, PhoneDetector};
use super::{parse, JURISDICTION, SPOKEN_DIGITS};
use crate::PackError;

#[derive(Debug, Deserialize)]
struct File {
    language: Vec<Language>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Language {
    #[allow(dead_code)]
    code: String,
    #[allow(dead_code)]
    source: String,
    /// `digits[d]` lists the words for digit `d`.
    digits: Vec<Vec<String>>,
    /// Words that repeat the next digit, such as "double" (2) and "triple" (3).
    #[serde(default)]
    repeat: HashMap<String, usize>,
    /// Words that stand for the `+` of an international number, such as "plus".
    #[serde(default)]
    plus: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Piece {
    /// Digits, and whether they were spelled as a word.
    Digits(String, bool),
    Repeat(usize),
    Plus,
}

#[derive(Debug)]
struct Token {
    start: usize,
    end: usize,
    piece: Piece,
}

/// Longest digit group written in figures that may sit inside a spoken number, as in "024".
const MAX_FIGURES: usize = 4;
/// Most tokens a spoken number can take: twelve digits, each a word, plus `plus` and slack.
const MAX_TOKENS: usize = 16;

#[derive(Debug)]
pub struct SpokenPhoneDetector {
    phone: PhoneDetector,
    words: HashMap<String, Piece>,
    /// The longest word in `words`, in bytes, so longer words are passed over at once.
    longest: usize,
}

impl SpokenPhoneDetector {
    pub fn new() -> Result<Self, PackError> {
        let file: File = parse("gh/spoken-digits.toml", SPOKEN_DIGITS)?;
        let mut words = HashMap::new();
        for lang in file.language {
            if lang.digits.len() != 10 {
                return Err(PackError::Data {
                    file: "gh/spoken-digits.toml",
                    reason: format!("{} lists {} digits, not 10", lang.code, lang.digits.len()),
                });
            }
            for (d, list) in lang.digits.iter().enumerate() {
                for w in list {
                    words.insert(w.to_lowercase(), Piece::Digits(d.to_string(), true));
                }
            }
            for (w, n) in lang.repeat {
                words.insert(w.to_lowercase(), Piece::Repeat(n));
            }
            for w in lang.plus {
                words.insert(w.to_lowercase(), Piece::Plus);
            }
        }
        let longest = words.keys().map(String::len).max().unwrap_or(0);
        Ok(Self {
            phone: PhoneDetector::new()?,
            words,
            longest,
        })
    }

    fn piece(&self, word: &str) -> Option<Piece> {
        if word.bytes().all(|b| b.is_ascii_digit()) {
            return (word.len() <= MAX_FIGURES).then(|| Piece::Digits(word.to_string(), false));
        }
        // Most words in a text are neither digit words nor capitalised, so look the word up as
        // it is and lower-case it only when it has capitals, which spares an allocation per word.
        if word.len() > self.longest {
            return None;
        }
        if let Some(p) = self.words.get(word) {
            return Some(p.clone());
        }
        word.chars()
            .any(char::is_uppercase)
            .then(|| self.words.get(&word.to_lowercase()).cloned())
            .flatten()
    }

    /// Words and figure groups that may belong to a spoken number, in order. A gap of
    /// anything but spaces, commas and hyphens ends a run, which is marked by a `None`.
    fn tokens(&self, text: &str) -> Vec<Option<Token>> {
        let mut out = Vec::new();
        let mut word_start: Option<usize> = None;
        let mut gap_ok = true;
        let flush = |out: &mut Vec<Option<Token>>, start: usize, end: usize, gap_ok: bool| {
            let piece = text.get(start..end).and_then(|w| self.piece(w));
            match piece {
                Some(piece) => {
                    if !gap_ok {
                        out.push(None);
                    }
                    out.push(Some(Token { start, end, piece }));
                }
                None => out.push(None),
            }
        };
        for (i, c) in text.char_indices() {
            let in_word = c.is_alphanumeric()
                || ('\u{0300}'..='\u{036f}').contains(&c)
                || c == '\''
                || c == '’';
            match (in_word, word_start) {
                (true, None) => word_start = Some(i),
                (false, Some(s)) => {
                    flush(&mut out, s, i, gap_ok);
                    word_start = None;
                    gap_ok = true;
                }
                _ => {}
            }
            if !in_word && !matches!(c, ' ' | ',' | '-' | '\t') {
                gap_ok = false;
            }
        }
        if let Some(s) = word_start {
            flush(&mut out, s, text.len(), gap_ok);
        }
        out
    }
}

/// The digits a run of tokens spells, or None if a repeat word isn't followed by a digit.
fn spell(run: &[&Token]) -> Option<(String, bool, usize)> {
    let mut digits = String::new();
    let mut words = 0;
    let mut plus = false;
    let mut repeat = 1;
    for (i, t) in run.iter().enumerate() {
        match &t.piece {
            Piece::Plus if i == 0 => plus = true,
            Piece::Plus => return None,
            Piece::Repeat(n) => {
                if repeat != 1 {
                    return None;
                }
                repeat = *n;
                words += 1;
            }
            Piece::Digits(d, word) => {
                if repeat != 1 && d.len() != 1 {
                    return None;
                }
                for _ in 0..repeat {
                    digits.push_str(d);
                }
                repeat = 1;
                words += usize::from(*word);
            }
        }
    }
    (repeat == 1).then_some((digits, plus, words))
}

impl Detector for SpokenPhoneDetector {
    fn info(&self) -> DetectorInfo {
        DetectorInfo {
            id: "gh-phone-spoken-v1",
            description:
                "Ghanaian phone numbers read aloud as digit words, in English, Akan, Ewe and Ga",
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
        let tokens = self.tokens(text);
        for run in tokens.split(Option::is_none) {
            let run: Vec<&Token> = run.iter().flatten().collect();
            // The number must run to the end of the digit words, so ten digits followed by more
            // aren't a phone number; leading tokens that aren't part of it, as in "room 12 zero
            // two four…", may be dropped. A number never takes more than sixteen tokens.
            let from = run.len().saturating_sub(MAX_TOKENS);
            for i in from..run.len() {
                let (Some(first), Some(last)) = (run.get(i), run.last()) else {
                    break;
                };
                let Some((digits, plus, words)) = spell(run.get(i..).unwrap_or_default()) else {
                    continue;
                };
                let target = if digits.starts_with("233") { 12 } else { 10 };
                if words < 2
                    || digits.len() != target
                    || !(digits.starts_with('0') || digits.starts_with("233"))
                {
                    continue;
                }
                let raw = if plus { format!("+{digits}") } else { digits };
                let Some(kind) = self
                    .phone
                    .nsn(&raw)
                    .and_then(|nsn| self.phone.classify(&nsn))
                else {
                    continue;
                };
                let (start, end) = (first.start, last.end);
                if kind == Kind::Landline && self.phone.is_public_line(text, start, end) {
                    break;
                }
                let span = Span::new(start, end).map_err(|e| DetectionError::new(e.to_string()))?;
                out.push(self.phone.finding(text, span, kind, "gh-phone-spoken-v1"));
                break;
            }
        }
        Ok(out)
    }
}
