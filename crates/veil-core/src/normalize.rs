//! Input normalisation.
//!
//! Detectors see a cleaned copy of the text: zero-width and other invisible format
//! characters removed, unusual spaces turned into ordinary ones, dashes into hyphens, and
//! fullwidth or Arabic-Indic digits into ASCII digits. Every byte of the copy remembers the
//! original character it came from, so each span found in the copy maps back to the exact
//! original text, including any invisible characters inside it. The original text is never
//! changed.

/// What a character becomes in the normalised copy.
enum Fold {
    Keep,
    Drop,
    To(char),
}

fn fold(c: char) -> Fold {
    match c {
        // Zero-width and invisible format characters, including the soft hyphen, the
        // Mongolian vowel separator, word joiners, the byte-order mark and bidi controls.
        '\u{00AD}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{2069}'
        | '\u{FEFF}' => Fold::Drop,
        // Spaces that look ordinary but aren't.
        '\u{00A0}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => {
            Fold::To(' ')
        }
        // Hyphens and dashes people paste into numbers.
        '\u{2010}'..='\u{2015}' | '\u{2212}' | '\u{FE63}' | '\u{FF0D}' => Fold::To('-'),
        '\u{FF0B}' => Fold::To('+'),
        // Fullwidth, Arabic-Indic and Extended Arabic-Indic digits.
        '\u{FF10}'..='\u{FF19}' => digit(c as u32 - 0xFF10),
        '\u{0660}'..='\u{0669}' => digit(c as u32 - 0x0660),
        '\u{06F0}'..='\u{06F9}' => digit(c as u32 - 0x06F0),
        _ => Fold::Keep,
    }
}

fn digit(n: u32) -> Fold {
    char::from_digit(n, 10).map_or(Fold::Keep, Fold::To)
}

/// A normalised copy of a text with a map back to the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub text: String,
    /// For each byte of `text`, the original start and end of the character it came from.
    origin: Vec<(u32, u32)>,
}

impl Normalized {
    /// The copy, or `None` when the text needs no change, which is the common case and
    /// costs one scan with no allocation.
    pub fn of(original: &str) -> Option<Self> {
        if !original.chars().any(|c| !matches!(fold(c), Fold::Keep))
            || original.len() > u32::MAX as usize
        {
            return None;
        }
        let mut text = String::with_capacity(original.len());
        let mut origin = Vec::with_capacity(original.len());
        for (i, c) in original.char_indices() {
            let range = (i as u32, (i + c.len_utf8()) as u32);
            let out = match fold(c) {
                Fold::Drop => continue,
                Fold::Keep => c,
                Fold::To(r) => r,
            };
            text.push(out);
            origin.extend(std::iter::repeat_n(range, out.len_utf8()));
        }
        Some(Self { text, origin })
    }

    /// Maps a span of the copy to the original text: from the start of the first
    /// character to the end of the last, so invisible characters between them are inside.
    pub fn to_original(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        if start >= end {
            return None;
        }
        let first = self.origin.get(start)?;
        let last = self.origin.get(end - 1)?;
        Some((first.0 as usize, last.1 as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_needs_no_copy() {
        assert!(Normalized::of("call 024 123 4567").is_none());
    }

    #[test]
    fn spans_map_back_over_invisible_characters() {
        let original = "call 024\u{200B}123 4567";
        let n = Normalized::of(original).unwrap_or_else(|| unreachable!());
        assert_eq!(n.text, "call 024123 4567");
        let (s, e) = n.to_original(5, n.text.len()).unwrap_or_default();
        assert_eq!(original.get(s..e), Some("024\u{200B}123 4567"));
    }

    #[test]
    fn digits_and_spaces_fold() {
        let n = Normalized::of("０２４\u{00A0}１２３").unwrap_or_else(|| unreachable!());
        assert_eq!(n.text, "024 123");
    }
}
