//! Checks on the characters around a match, which the `regex` crate can't express
//! without look-around.

/// The character just before `start`, if any.
pub fn before(text: &str, start: usize) -> Option<char> {
    text.get(..start).and_then(|s| s.chars().next_back())
}

/// The character at `end`, if any.
pub fn after(text: &str, end: usize) -> Option<char> {
    text.get(end..).and_then(|s| s.chars().next())
}

/// True when the match isn't glued to letters or digits on either side.
pub fn isolated(text: &str, start: usize, end: usize) -> bool {
    !before(text, start).is_some_and(char::is_alphanumeric)
        && !after(text, end).is_some_and(char::is_alphanumeric)
}
