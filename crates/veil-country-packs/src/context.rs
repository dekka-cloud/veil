//! Looks for context words near a match, within a window measured in bytes and widened
//! to the nearest character boundaries.

/// The text around a match, lower-cased. It reaches at most `radius` bytes each way and
/// stops at a sentence end, a line break, or another number, so a context word belongs to
/// the identifier nearest to it ("send the MoMo to 055… or call 020…" labels only the first).
pub fn window(text: &str, start: usize, end: usize, radius: usize) -> String {
    let mut from = start.saturating_sub(radius);
    while from > 0 && !text.is_char_boundary(from) {
        from -= 1;
    }
    let mut to = (end + radius).min(text.len());
    while to < text.len() && !text.is_char_boundary(to) {
        to += 1;
    }
    let before = text.get(from..start).unwrap_or_default();
    let after = text.get(end..to).unwrap_or_default();
    let before = match last_break(before) {
        Some(i) => before.get(i..).unwrap_or_default(),
        None => before,
    };
    let after = match first_break(after) {
        Some(i) => after.get(..i).unwrap_or_default(),
        None => after,
    };
    format!("{before} {after}").to_lowercase()
}

/// A break is a line break, `!`, `?`, `;`, a digit, or a full stop followed by whitespace.
fn is_break_at(s: &str, i: usize, c: char) -> bool {
    match c {
        '\n' | '\r' | '!' | '?' | ';' => true,
        '.' => s
            .get(i + 1..)
            .and_then(|r| r.chars().next())
            .is_none_or(char::is_whitespace),
        c => c.is_ascii_digit(),
    }
}

/// The byte index just after the last break, so the returned slice excludes it.
fn last_break(s: &str) -> Option<usize> {
    s.char_indices()
        .filter(|&(i, c)| is_break_at(s, i, c))
        .map(|(i, c)| i + c.len_utf8())
        .next_back()
}

fn first_break(s: &str) -> Option<usize> {
    s.char_indices()
        .find(|&(i, c)| is_break_at(s, i, c))
        .map(|(i, _)| i)
}

/// Whether the window contains any of the words as a whole word or phrase, so `tin`
/// doesn't match inside `destination`.
pub fn mentions(window: &str, words: &[String]) -> bool {
    words.iter().any(|w| contains_word(window, w.trim()))
}

fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    haystack.match_indices(word).any(|(i, _)| {
        let before = haystack.get(..i).and_then(|s| s.chars().next_back());
        let after = haystack
            .get(i + word.len()..)
            .and_then(|s| s.chars().next());
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

pub fn isolated(text: &str, start: usize, end: usize) -> bool {
    let before = text.get(..start).and_then(|s| s.chars().next_back());
    let after = text.get(end..).and_then(|s| s.chars().next());
    !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
}
